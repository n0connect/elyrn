package handlers

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/encryption"
	"elyrn/internal/identity"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/pow"
	"elyrn/internal/store"
	"elyrn/internal/utils"
)

var (
	authLogger     = utils.NewLogger("AUTH")
	userRepository = store.NewUserRepository()
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting RegisterHandler")

	// Handle HEAD requests (used by browsers/tools for link previews, health checks, etc.)
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for registration endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodPost {
		apperr.Write(w, "RegisterHandler", apperr.MethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	// Parse request body
	var req models.RegisterRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		// Empty body is OK - treat as generate AccountNumber only (confirm=false)
		authLogger.Debug("Empty or invalid body, treating as AccountNumber generation request")
		req.Confirm = false
	}

	// SECURITY: PoW is validated here and only here, for both phases, on the exact struct
	// the handler acts on (no second parser that could disagree about the body)
	phase := "registration phase 1"
	if req.Confirm {
		phase = "registration phase 2"
	}
	if !requireProofOfWork(w, req.PoW, phase) {
		return
	}

	// PHASE 1 (confirm=false) shows a fresh AccountNumber and a pending token; PHASE 2
	// (confirm=true) redeems the token and creates the account
	if req.Confirm {
		confirmRegistration(w, req.PendingToken)
		return
	}
	issueAccountNumber(w)
}

// issueAccountNumber is registration phase 1: it generates an AccountNumber, keeps only what
// phase 2 needs (derived auth key and public key) under a pending id, and answers the number
// once with a signed pending token. No account exists yet.
func issueAccountNumber(w http.ResponseWriter) {
	authLogger.Debug("Phase 1: Generating AccountNumber preview (no account creation)")

	// Generate AccountNumber (256-bit CSPRNG, base64url encoded)
	accountNumber, err := utils.GenerateAccountNumber()
	if err != nil {
		apperr.WriteError(w, "GenerateAccountNumber", err)
		return
	}

	// Everything phase 2 needs is derived now, so the AccountNumber itself (which also
	// seeds the user's E2E identity) leaves server memory with this response
	pending := auth.PendingIdentity{}
	if pending.AuthKey, err = identity.DeriveAuthKey(accountNumber); err != nil {
		apperr.WriteError(w, "DeriveAuthKey", err)
		return
	}
	if pending.PublicKey, err = identity.DerivePublicKey(accountNumber); err != nil {
		apperr.WriteError(w, "DerivePublicKey", err)
		return
	}

	// Compute lookup for collision check (almost impossible)
	lookup, err := auth.ComputeAccountLookup(pending.AuthKey)
	if err != nil {
		apperr.WriteError(w, "ComputeAccountLookup", err)
		return
	}

	// Check for collision - regenerate if needed (very unlikely but safe)
	exists, err := userRepository.ExistsByAccountLookup(lookup)
	if err != nil {
		apperr.WriteError(w, "ExistsByAccountLookup", err)
		return
	}
	if exists {
		// A 256-bit collision: practically impossible, answered as a plain server fault
		apperr.Write(w, "RegisterHandler", apperr.AccountCollision)
		return
	}

	// Generate pending ID and store AccountNumber server-side
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		apperr.WriteError(w, "GeneratePendingID", err)
		return
	}

	// Keep the derived identity (not the AccountNumber) until the user confirms
	// A full store answers 503 (apperr.PendingStoreFull), anything else 500
	if err := auth.StorePendingRegistration(pendingID, pending); err != nil {
		apperr.WriteError(w, "StorePendingRegistration", err)
		return
	}

	// Generate pending registration token (contains pending ID, not AccountNumber)
	pendingToken, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		apperr.WriteError(w, "SignPendingRegistrationToken", err)
		return
	}

	responseData := models.RegisterResponse{
		Success:       true,
		Message:       "Account number generated - click continue to create account",
		AccountNumber: accountNumber,
		PendingToken:  pendingToken,
		Confirmed:     false,
	}
	utils.EncodeJSONResponse(w, responseData, http.StatusOK)
	authLogger.LogResponse(http.StatusOK, "AccountNumber preview generated with pending token")
}

// confirmRegistration is registration phase 2: it redeems a pending token and creates the
// account from the identity derived in phase 1, then opens a session.
func confirmRegistration(w http.ResponseWriter, pendingToken string) {
	authLogger.Debug("Phase 2: Confirming account creation")

	// SECURITY: RegisterHandler validated a fresh, single-use phase 2 PoW: no phase 1 replay,
	// and every Argon2id run below is paid for

	if pendingToken == "" {
		apperr.Write(w, "RegisterHandler", apperr.PendingTokenRequired)
		return
	}

	// The pending registration stays redeemable until the account exists: every failure
	// below leaves it in place for a retry (with a fresh proof of work) until it expires
	pendingID, pending, err := auth.VerifyPendingRegistrationToken(pendingToken)
	if err != nil {
		// SECURITY: Generic error message to prevent information leakage
		// Don't distinguish between expired and invalid tokens
		apperr.Write(w, "VerifyPendingRegistrationToken", apperr.PendingTokenInvalid)
		return
	}
	authKey, publicKey := pending.AuthKey, pending.PublicKey

	// Compute lookup and hash
	lookup, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		apperr.WriteError(w, "ComputeAccountLookup", err)
		return
	}

	// Check if account already exists (race condition or replay attack)
	exists, err := userRepository.ExistsByAccountLookup(lookup)
	if err != nil {
		apperr.WriteError(w, "ExistsByAccountLookup", err)
		return
	}
	if exists {
		// SECURITY: Generic error message to prevent enumeration
		// Don't reveal that account exists - use same message as invalid token
		auth.CompletePendingRegistration(pendingID)
		apperr.Write(w, "RegisterHandler", apperr.AccountExists)
		return
	}

	// ErrBusy (saturated Argon2id) answers 503 (apperr.Argon2Busy), anything else 500
	user, err := newAccountRecord(lookup, authKey, publicKey)
	if err != nil {
		apperr.WriteError(w, "newAccountRecord", err)
		return
	}

	if err := userRepository.Create(user); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// A concurrent confirmation of the same token created it first
			auth.CompletePendingRegistration(pendingID)
			apperr.Write(w, "UserRepository.Create", apperr.AccountExists)
			return
		}
		apperr.WriteError(w, "UserRepository.Create", err)
		return
	}
	auth.CompletePendingRegistration(pendingID)
	authLogger.Debug("New identity registered")

	// Immediate login: the session token goes into the HttpOnly cookie and nowhere else
	// (without a token the account still exists: the user logs in with the account number)
	if token, err := auth.SignToken(user.UUID, user.SessionEpoch); err != nil {
		authLogger.LogError("SignToken", err)
	} else {
		auth.SetAuthCookie(w, token)
	}

	// SECURITY: Don't return the AccountNumber again (already shown once in phase 1)
	utils.EncodeJSONResponse(w, models.RegisterResponse{
		Success:   true,
		Message:   "Account created successfully",
		Confirmed: true,
	}, http.StatusCreated)
	authLogger.LogResponse(http.StatusCreated, "Account created successfully")
}

// newAccountRecord builds the row for a new account: the Argon2id hash of the auth key (stored
// only, login does not read it: S-07), an internal id and a fresh per-user key wrapped under
// the active master key. Every failure keeps its cause (ErrBusy among them) for apperr.
func newAccountRecord(lookup, authKey, publicKey string) (*models.User, error) {
	accountHash, err := auth.HashAccountNumber(authKey)
	if err != nil {
		return nil, fmt.Errorf("HashAccountNumber: %w", err)
	}
	// Internal UUID: the JWT subject and the key every other table refers to
	internalUUID, err := utils.GenerateInternalID()
	if err != nil {
		return nil, fmt.Errorf("GenerateInternalID: %w", err)
	}
	userAESKey, err := encryption.GenerateUserAESKey()
	if err != nil {
		return nil, fmt.Errorf("GenerateUserAESKey: %w", err)
	}
	encryptedUserKey, err := encryption.EncryptWithMasterKey(hex.EncodeToString(userAESKey))
	if err != nil {
		return nil, fmt.Errorf("EncryptWithMasterKey: %w", err)
	}
	// ZERO-TRUST: the identity public key was derived server-side in phase 1 from the
	// AccountNumber, never accepted from the client
	return &models.User{
		UUID:          internalUUID,
		AccountLookup: lookup,
		AccountHash:   accountHash,
		PublicKey:     publicKey,
		EncryptedKey:  encryptedUserKey,
		MasterKeyID:   encryption.ActiveMasterKeyID(),
	}, nil
}

// requireProofOfWork admits a request only with an issued, unused, unexpired solution at the
// issued difficulty (consuming it), and otherwise writes 412 (missing) or 403 (invalid).
func requireProofOfWork(w http.ResponseWriter, solution *models.PoWSolution, action string) bool {
	if solution == nil {
		apperr.Write(w, "requireProofOfWork:"+action, apperr.PoWRequired)
		return false
	}
	if !pow.ValidateSolution(solution) {
		apperr.Write(w, "requireProofOfWork:"+action, apperr.PoWInvalid)
		return false
	}
	return true
}

func PoWChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting PoWChallengeHandler")

	// Handle HEAD requests
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for PoW challenge endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodGet {
		apperr.Write(w, "PoWChallengeHandler", apperr.MethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	// Rate-limit key: HMAC(client IP) with a per-boot secret (forwarded headers trusted only from TRUSTED_PROXIES)
	// ErrRateLimited answers 429, ErrCapacity 503 (apperr sentinel table), anything else 500
	client, err := middleware.ClientKey(r)
	if err != nil {
		apperr.WriteError(w, "ClientKey", err)
		return
	}
	challenge, err := pow.GenerateChallenge(client)
	if err != nil {
		apperr.WriteError(w, "GenerateChallenge", err)
		return
	}

	authLogger.Debug("Generated PoW challenge with difficulty: %d", challenge.Difficulty)

	responseData := models.PoWChallengeResponse{
		Success:   true,
		Message:   "PoW challenge generated successfully",
		Challenge: challenge,
	}

	utils.EncodeJSONResponse(w, responseData, http.StatusOK)
	authLogger.LogResponse(http.StatusOK, "PoW challenge generated successfully")
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	authLogger.LogRequest(r.Method)
	authLogger.Debug("Starting LoginHandler")

	// Handle HEAD requests (used by browsers/tools for link previews, health checks, etc.)
	if r.Method == http.MethodHead {
		authLogger.Debug("Handling HEAD request for login endpoint")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.Method != http.MethodPost {
		apperr.Write(w, "LoginHandler", apperr.MethodNotAllowed)
		return
	}

	// Prevent caching of sensitive responses
	w.Header().Set("Cache-Control", "no-store")

	var req models.LoginRequest
	if err := utils.DecodeJSONRequest(r, &req); err != nil {
		apperr.Write(w, "LoginHandler: DecodeJSONRequest", apperr.LoginBodyInvalid)
		return
	}
	// SECURITY: Validate auth key format (exactly 32 bytes, base64url) before any database operations
	// The client sends HKDF(AccountNumber, "noaddx/auth"); the AccountNumber itself never leaves the browser
	if !identity.ValidateEncodedKey(req.AuthKey) {
		apperr.Write(w, "LoginHandler: ValidateEncodedKey", apperr.LoginKeyMalformed)
		return
	}

	// Compute lookup for database query (only reached if format is valid)
	lookup, err := auth.ComputeAccountLookup(req.AuthKey)
	if err != nil {
		apperr.WriteCause(w, "LoginHandler: ComputeAccountLookup", apperr.LoginLookupFailed, err)
		return
	}

	// Apply per-account rate limit using lookup hash
	if !middleware.AllowAccountLookup(lookup) {
		apperr.Write(w, "LoginHandler: AllowAccountLookup", apperr.RateLimited)
		return
	}

	// Find user by lookup. An unreachable database says so: answering "invalid credentials"
	// would tell the user their only key is worthless (and says nothing about the account)
	user, err := userRepository.FindByAccountLookup(lookup)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		apperr.Write(w, "FindByAccountLookup", apperr.StoreUnavailable)
		return
	}

	// SECURITY: the key is proven by the keyed lookup alone, compared in constant time. No
	// Argon2id and no decoy hash: the auth key is 256 bits of HKDF output, so there is no
	// low-entropy secret to slow down, and "an account exists for this key" is learnable only
	// by holding the key. Both paths still do the same work: one HMAC, one query, one compare
	// against a fixed-length value (the stored lookup, or a stand-in when no row matched).
	stored := ""
	if user != nil {
		stored = user.AccountLookup
	}
	if !auth.AccountLookupMatches(lookup, stored) {
		apperr.Write(w, "LoginHandler: AccountLookupMatches", apperr.LoginNoAccount)
		return
	}

	// Accounts created before the E2E identity existed cannot chat: treat as invalid
	if !identity.ValidateEncodedKey(user.PublicKey) {
		apperr.Write(w, "LoginHandler: legacy record", apperr.LoginLegacyAccount)
		return
	}

	authLogger.Debug("Successful login")

	// Generate JWT token (using internal UUID as subject)
	token, err := auth.SignToken(user.UUID, user.SessionEpoch)
	if err != nil {
		apperr.WriteError(w, "SignToken", err)
		return
	}

	// SECURITY: the session token goes into the HttpOnly cookie and nowhere else
	auth.SetAuthCookie(w, token)
	utils.EncodeJSONResponse(w, models.LoginResponse{Success: true, Message: "Login successful"}, http.StatusOK)
	authLogger.LogResponse(http.StatusOK, "LoginHandler completed successfully")
}
