package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/utils"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
	jwtLogger       = utils.NewLogger("JWT")
)

// MaxTokenBytes bounds what the JWT parser ever sees; a genuine token is ~250 bytes
const MaxTokenBytes = 1024

// compactSegments is the number of segments of a compact JWS: header, payload, signature
const compactSegments = 3

// segmentSeparator joins the segments of a compact JWS
const segmentSeparator = "."

// pendingSubject marks pending-registration tokens; it can never be a valid user id
const pendingSubject = "pending_registration"

// Claims represents JWT claims with security best practices
// Uses RegisteredClaims.Subject for user UUID (standard "sub" claim)
// SessionEpoch must equal users.session_epoch; logout bumps it to revoke every token
type Claims struct {
	jwt.RegisteredClaims
	SessionEpoch int `json:"sep"`
}

// Session is the verified result of a session token
type Session struct {
	UserUUID     string
	SessionEpoch int
	IssuedAt     time.Time
}

// PendingRegistrationClaims represents JWT claims for pending registration
// Contains the pending ID that references server-side stored AccountNumber
type PendingRegistrationClaims struct {
	jwt.RegisteredClaims
	PendingID string `json:"pending_id"`
	IsPending bool   `json:"is_pending"`
}

// validateSecret ensures JWT secret meets security requirements
func validateSecret(secret string) error {
	if secret == "" {
		return errors.New("JWT_SECRET not configured")
	}
	minLen := config.GetJWTSecretMinLength()
	if minLen <= 0 {
		return errors.New("JWT_SECRET_MIN_LEN not configured")
	}
	if len(secret) < minLen {
		return fmt.Errorf("JWT_SECRET too short (minimum %d characters)", minLen)
	}
	return nil
}

func getJWTBaseConfig() (string, string, string, error) {
	secret := config.GetJWTSecret()
	if err := validateSecret(secret); err != nil {
		return "", "", "", err
	}
	issuer := config.GetJWTIssuer()
	if issuer == "" {
		return "", "", "", errors.New("JWT_ISSUER not configured")
	}
	audience := config.GetJWTAudience()
	if audience == "" {
		return "", "", "", errors.New("JWT_AUDIENCE not configured")
	}
	return secret, issuer, audience, nil
}

// SignToken creates a JWT token for the given user UUID and session epoch
// Security: Uses HS256, includes iss/aud/iat/exp/nbf claims; the subject must be an internal id
func SignToken(userUUID string, sessionEpoch int) (string, error) {
	if !utils.ValidateUUID(userUUID) || sessionEpoch < 0 {
		return "", ErrInvalidToken
	}

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("SignToken: %v", err)
		return "", err
	}

	expiration := config.GetJWTExpiration()
	if expiration <= 0 {
		jwtLogger.Error("SignToken: invalid JWT_EXPIRATION_MINUTES")
		return "", errors.New("JWT_EXPIRATION_MINUTES not configured")
	}
	now := time.Now()

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			Subject:   userUUID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
		},
		SessionEpoch: sessionEpoch,
	}

	// Use HS256 (HMAC-SHA256) - symmetric signing
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		jwtLogger.LogError("SignToken", err)
		return "", err
	}

	return tokenString, nil
}

// SignPendingRegistrationToken creates a short-lived JWT for pending registration
// This token contains the pending ID that references server-side stored AccountNumber
// Security: Short expiration from config, contains is_pending flag
func SignPendingRegistrationToken(pendingID string) (string, error) {

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("SignPendingRegistrationToken: %v", err)
		return "", err
	}

	now := time.Now()
	expiration := config.GetPendingTokenTTL()
	if expiration <= 0 {
		jwtLogger.Error("SignPendingRegistrationToken: invalid PENDING_TOKEN_TTL_SEC")
		return "", errors.New("PENDING_TOKEN_TTL_SEC not configured")
	}

	claims := PendingRegistrationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			Subject:   pendingSubject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			NotBefore: jwt.NewNumericDate(now),
		},
		PendingID: pendingID,
		IsPending: true,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		jwtLogger.LogError("SignPendingRegistrationToken", err)
		return "", err
	}

	return tokenString, nil
}

// VerifyPendingRegistrationToken verifies a pending registration token and returns its
// pending ID and the identity derived in phase 1. Returns an error if the token is not a
// pending registration token or is invalid/expired. The entry stays until the caller
// completes it (CompletePendingRegistration) once the account exists.
func VerifyPendingRegistrationToken(tokenString string) (string, PendingIdentity, error) {
	token, err := parseServerToken("VerifyPendingRegistrationToken", tokenString, &PendingRegistrationClaims{})
	if err != nil {
		return "", PendingIdentity{}, err
	}

	claims, ok := token.Claims.(*PendingRegistrationClaims)
	if !ok || !token.Valid {
		jwtLogger.Warn("VerifyPendingRegistrationToken: invalid claims")
		return "", PendingIdentity{}, ErrInvalidToken
	}

	// Verify this is a pending registration token
	if !claims.IsPending || claims.Subject != pendingSubject {
		jwtLogger.Warn("VerifyPendingRegistrationToken: not a pending registration token")
		return "", PendingIdentity{}, ErrInvalidToken
	}

	if claims.PendingID == "" {
		jwtLogger.Warn("VerifyPendingRegistrationToken: pending ID is empty")
		return "", PendingIdentity{}, ErrInvalidToken
	}

	pending, err := PendingRegistration(claims.PendingID)
	if err != nil {
		jwtLogger.Warn("VerifyPendingRegistrationToken: no pending registration for this token")
		return "", PendingIdentity{}, err
	}
	return claims.PendingID, pending, nil
}

// VerifyToken verifies a JWT token and returns the session it carries
// Security: Validates signing method, issuer, audience, expiration and the subject's exact shape
func VerifyToken(tokenString string) (*Session, error) {
	token, err := parseServerToken("VerifyToken", tokenString, &Claims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		jwtLogger.Warn("VerifyToken: token claims invalid or token not valid")
		return nil, ErrInvalidToken
	}

	// Whitelist: the subject is an internal user id (never a pending-registration token)
	if !utils.ValidateUUID(claims.Subject) || claims.IssuedAt == nil || claims.SessionEpoch < 0 {
		jwtLogger.Warn("VerifyToken: subject, issued-at or epoch claim invalid")
		return nil, ErrInvalidToken
	}

	return &Session{UserUUID: claims.Subject, SessionEpoch: claims.SessionEpoch, IssuedAt: claims.IssuedAt.Time}, nil
}

// wellFormedToken reports whether s has the exact shape of a compact JWS the server signs:
// at most MaxTokenBytes, exactly three non-empty segments of the unpadded base64url alphabet.
// Go's base64 decoders skip CR and LF even in strict mode, so the alphabet is whitelisted
// before anything is decoded; strict decoding (parseServerToken) then refuses non-zero unused
// bits, so exactly one string carries a given signature.
func wellFormedToken(s string) bool {
	if len(s) == 0 || len(s) > MaxTokenBytes {
		return false
	}
	segments := strings.Split(s, segmentSeparator)
	if len(segments) != compactSegments {
		return false
	}
	for _, segment := range segments {
		if !utils.IsBase64URL(segment) {
			return false
		}
	}
	return true
}

// parseServerToken is the one parse path of every token the server verifies (session and
// pending): the shape whitelist, then HS256 under the server's secret, issuer and audience
// with strict base64url decoding and a required expiry. Every refusal is ErrInvalidToken
// (ErrExpiredToken for a genuine but expired token), the same public answer whatever the cause.
func parseServerToken(op, tokenString string, claims jwt.Claims) (*jwt.Token, error) {
	if !wellFormedToken(tokenString) {
		jwtLogger.Warn("%s: malformed token", op)
		return nil, ErrInvalidToken
	}

	secret, issuer, audience, err := getJWTBaseConfig()
	if err != nil {
		jwtLogger.Error("%s: %v", op, err)
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// CRITICAL: Validate signing method to prevent algorithm confusion attacks
		// Only accept HMAC (HS256/HS384/HS512), reject RS256, ES256, none, etc.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			jwtLogger.Warn("%s: unexpected signing method: %v", op, token.Method.Alg())
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), // Explicitly allow only HS256
		jwt.WithIssuer(issuer),       // Validate issuer
		jwt.WithAudience(audience),   // Validate audience
		jwt.WithExpirationRequired(), // Require expiration
		jwt.WithStrictDecoding(),     // Canonical base64url only: no non-zero unused bits
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			jwtLogger.Warn("%s: token expired", op)
			return nil, ErrExpiredToken
		}
		jwtLogger.Warn("%s: invalid token", op)
		return nil, ErrInvalidToken
	}
	return token, nil
}
