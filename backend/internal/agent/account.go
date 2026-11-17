package agent

import (
	"context"
	"net/http"
	"strconv"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/pow"
	"elyrn/internal/utils"
)

const maxMessageTTLDays = 3650

// ensureAccount creates the account on first use; it reports whether it did.
func (a *Agent) ensureAccount(ctx context.Context) (bool, error) {
	if err := a.requireWritable(); err != nil {
		return false, err
	}
	if a.authKey != "" {
		return false, nil
	}
	if a.origin == "" {
		return false, fail(CodeServerMissing, nil)
	}
	return true, a.register(ctx)
}

// ensureSession logs in when there is no checked session (creating the account first, or
// finishing a registration an earlier run left unconfirmed). A session counts only once /me
// has been checked: both the cookie and the limits it reported must be there.
func (a *Agent) ensureSession(ctx context.Context) error {
	if a.session != nil && a.limits != nil {
		return nil
	}
	created, err := a.ensureAccount(ctx)
	if err != nil || created {
		return err
	}
	if a.pendingToken != "" {
		return a.confirm(ctx, a.pendingToken)
	}
	return a.login(ctx)
}

// endSession forgets the session and what /me reported: the next call logs in again.
func (a *Agent) endSession() {
	a.session, a.limits = nil, nil
}

// endSessionOnError is deferred by every step that establishes a session: whatever it got
// before failing (a cookie from a server that then failed the /me check) is not a session.
func (a *Agent) endSessionOnError(err *error) {
	if *err != nil {
		a.endSession()
	}
}

// register runs both phases. The AccountNumber and the pending token are written to the
// identity file between them, as a person saves the number before confirming: a confirmation
// that fails or is interrupted is finished by the next call or the next run (ensureSession),
// while the server still holds the registration.
func (a *Agent) register(ctx context.Context) error {
	phase1, err := a.registerPreview(ctx)
	if err != nil {
		return err
	}
	pending := &identityFile{Server: a.origin, AccountNumber: phase1.AccountNumber, PendingToken: phase1.PendingToken}
	if err := saveIdentity(a.idPath, pending, false); err != nil {
		return err
	}
	// The counter file exists from the identity's first run on, so no later start mistakes its
	// absence for a lost file (state.go, E_AGENT_STATE_REBUILT)
	a.persistCountersOrWarn()
	if err := a.adoptIdentity(phase1.AccountNumber); err != nil {
		return err
	}
	a.pendingToken = phase1.PendingToken
	logger.Info("identity file written; confirming the account")
	return a.confirm(ctx, phase1.PendingToken)
}

// markConfirmed records that the account exists: the pending token leaves the identity file.
func (a *Agent) markConfirmed() error {
	if a.pendingToken == "" {
		return nil
	}
	if err := confirmIdentityFile(a.idPath); err != nil {
		return err
	}
	a.pendingToken = ""
	logger.Info("account confirmed")
	return nil
}

func (a *Agent) registerPreview(ctx context.Context) (*models.RegisterResponse, error) {
	solution, err := a.proofOfWork(ctx)
	if err != nil {
		return nil, err
	}
	var resp models.RegisterResponse
	status, err := a.public(ctx, http.MethodPost, pathRegister, models.RegisterRequest{Confirm: false, PoW: solution}, &resp)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, powStatusError(status)
	}
	if !resp.Success || resp.Confirmed || !utils.ValidateAccountNumber(resp.AccountNumber) || !validPendingToken(resp.PendingToken) {
		return nil, fail(CodeServerAnswer, nil)
	}
	return &resp, nil
}

func validPendingToken(token string) bool {
	if len(token) == 0 || len(token) > maxPendingTokenChars {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// confirm is phase 2, retried with a fresh proof of work after a passing failure; a 401 means
// an earlier attempt created the account (or the registration expired): login decides.
func (a *Agent) confirm(ctx context.Context, pendingToken string) (err error) {
	defer a.endSessionOnError(&err)
	for attempt := 0; attempt < maxConfirmAttempts; attempt++ {
		status, err := a.confirmOnce(ctx, pendingToken)
		passing := (err != nil && CodeOf(err) == CodeNetwork) || (err == nil && status >= http.StatusInternalServerError)
		switch {
		case passing:
			if err := backoff(ctx, attempt); err != nil {
				return err
			}
		case err != nil:
			return err
		case status == http.StatusCreated:
			if err := a.markConfirmed(); err != nil {
				return err
			}
			if a.session == nil {
				return fail(CodeServerAnswer, nil)
			}
			return a.checkMe(ctx)
		case status == http.StatusUnauthorized:
			return a.login(ctx)
		default:
			return powStatusError(status)
		}
	}
	return fail(CodeServerBusy, nil)
}

func (a *Agent) confirmOnce(ctx context.Context, pendingToken string) (int, error) {
	solution, err := a.proofOfWork(ctx)
	if err != nil {
		return 0, err
	}
	var resp models.RegisterResponse
	status, err := a.public(ctx, http.MethodPost, pathRegister,
		models.RegisterRequest{Confirm: true, PendingToken: pendingToken, PoW: solution}, &resp)
	if err == nil && status == http.StatusCreated && (!resp.Success || !resp.Confirmed || resp.AccountNumber != "") {
		return 0, fail(CodeServerAnswer, nil)
	}
	return status, err
}

// login proves the account with its derived auth key; the AccountNumber never travels. A 401
// for an identity still pending means its registration expired unconfirmed.
func (a *Agent) login(ctx context.Context) (err error) {
	defer a.endSessionOnError(&err)
	a.endSession()
	var resp models.LoginResponse
	status, err := a.public(ctx, http.MethodPost, pathLogin, models.LoginRequest{AuthKey: a.authKey}, &resp)
	if err != nil {
		return err
	}
	switch {
	case status == http.StatusOK && resp.Success && a.session != nil:
		if err := a.markConfirmed(); err != nil {
			return err
		}
		return a.checkMe(ctx)
	case status == http.StatusOK:
		return fail(CodeServerAnswer, nil)
	case status == http.StatusUnauthorized && a.pendingToken != "":
		return fail(CodeIdentityUnconfirmed, nil)
	case status == http.StatusUnauthorized:
		return fail(CodeIdentityUnknown, nil)
	default:
		return statusError(status)
	}
}

// checkMe verifies that the server serves this identity's public key (as the browser does) and
// takes the room and file limits it reports, each within its bounds. Any failure ends the session (fail closed).
func (a *Agent) checkMe(ctx context.Context) (err error) {
	defer a.endSessionOnError(&err)
	var me models.MeResponse
	status, err := a.public(ctx, http.MethodGet, pathMe, nil, &me)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return statusError(status)
	}
	if me.PublicKey != a.publicKey {
		return fail(CodeIdentityMismatch, nil)
	}
	if me.RoomMaxMembers < MinRoomMembers || me.RoomMaxMembers > MaxRoomMembers ||
		me.RoomMaxTTLHours < MinRoomTTLHours || me.RoomMaxTTLHours > MaxRoomTTLHours ||
		me.MessageTTLDays < 1 || me.MessageTTLDays > maxMessageTTLDays ||
		me.FileMaxBytes < minFileMaxBytes || me.FileMaxBytes > maxFileMaxBytes {
		return fail(CodeServerAnswer, nil)
	}
	a.limits = &me
	return nil
}

// proofOfWork fetches a fresh challenge and solves it.
func (a *Agent) proofOfWork(ctx context.Context) (*models.PoWSolution, error) {
	var resp models.PoWChallengeResponse
	status, err := a.public(ctx, http.MethodGet, pathChallenge, nil, &resp)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	if !resp.Success || resp.Challenge == nil {
		return nil, fail(CodeServerAnswer, nil)
	}
	return solve(ctx, resp.Challenge)
}

// powStatusError explains the statuses a request paid with a proof of work can get.
func powStatusError(status int) error {
	if status == http.StatusForbidden || status == http.StatusPreconditionFailed {
		return fail(CodeProofOfWork, nil)
	}
	return statusError(status)
}

// solve brute-forces SHA-256(challenge || nonce || salt) under the issued difficulty, with the
// verifier's own leading-zero rule; bounded by powTimeout and maxPoWNonces.
func solve(ctx context.Context, ch *models.PoWChallenge) (*models.PoWSolution, error) {
	if !pow.IsHexOfLen(ch.Challenge, pow.ChallengeBytes) || !pow.IsHexOfLen(ch.Salt, pow.SaltBytes) || ch.Difficulty < 0 {
		return nil, fail(CodeServerAnswer, nil)
	}
	if ch.Difficulty > maxPoWDifficulty {
		return nil, fail(CodeProofOfWork, nil)
	}
	ctx, cancel := context.WithTimeout(ctx, powTimeout)
	defer cancel()
	input := make([]byte, 0, len(ch.Challenge)+len(strconv.FormatUint(maxPoWNonces, 10))+len(ch.Salt))
	for nonce := uint64(0); nonce < maxPoWNonces; nonce++ {
		if nonce%powContextCheckEvery == 0 && ctx.Err() != nil {
			return nil, fail(CodeProofOfWork, ctx.Err())
		}
		input = append(strconv.AppendUint(append(input[:0], ch.Challenge...), nonce, 10), ch.Salt...)
		sum, err := cryptoengine.SHA256(input)
		if err != nil {
			return nil, fail(CodeInternal, err)
		}
		if pow.HasLeadingZeroBits(sum, ch.Difficulty) {
			return ch.Answer(strconv.FormatUint(nonce, 10)), nil
		}
	}
	return nil, fail(CodeProofOfWork, nil)
}
