package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"elyrn/internal/auth"
	"elyrn/tests/testutil"

	"github.com/golang-jwt/jwt/v5"
)

// signWithServerSecret signs claims exactly as the server would (same secret, issuer,
// audience, algorithm), so only the claim under test differs from a genuine token.
func signWithServerSecret(t testing.TB, claims auth.Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return token
}

// base64URLAlphabet is RFC 4648 section 5's alphabet in index order
const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// signatureMalleations are look-alikes of a genuine token that a lenient decoder reads as the
// same signature: the last signature character with its unused low bit flipped (an HS256
// signature is 32 bytes, so its 43rd character carries two unused bits), and CR/LF inserted
// into the signature (Go's base64 skips them). Each must be refused.
func signatureMalleations(t testing.TB, genuine string) []string {
	t.Helper()
	cut := strings.LastIndex(genuine, ".")
	if cut < 0 || cut == len(genuine)-1 {
		t.Fatalf("token %q has no signature segment", genuine)
	}
	last := len(genuine) - 1
	index := strings.IndexByte(base64URLAlphabet, genuine[last])
	if index < 0 {
		t.Fatalf("token %q ends outside the base64url alphabet", genuine)
	}
	flipped := genuine[:last] + string(base64URLAlphabet[index^1])
	want, err := base64.RawURLEncoding.DecodeString(genuine[cut+1:])
	if err != nil {
		t.Fatalf("genuine signature does not decode: %v", err)
	}
	if got, err := base64.RawURLEncoding.DecodeString(flipped[cut+1:]); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("flipped signature no longer decodes leniently to the same bytes (%v)", err)
	}
	return []string{
		flipped,
		genuine[:last] + "\n" + genuine[last:],
		genuine[:last] + "\r\n" + genuine[last:],
		genuine[:cut+1] + "\n" + genuine[cut+1:],
	}
}

func serverClaims(subject string, epoch int) auth.Claims {
	now := time.Now()
	return auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    os.Getenv("JWT_ISSUER"),
			Audience:  jwt.ClaimStrings{os.Getenv("JWT_AUDIENCE")},
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
		SessionEpoch: epoch,
	}
}

func TestSessionToken_RoundTrip(t *testing.T) {
	setupPendingJWTEnv(t)

	userID := testutil.NewInternalID(t)
	token, err := auth.SignToken(userID, 3)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	session, err := auth.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if session.UserUUID != userID || session.SessionEpoch != 3 {
		t.Fatalf("session = %+v, want subject %s epoch 3", session, userID)
	}
}

// The subject is looked up in the database: only the exact internal-id shape may reach it.
func TestSignToken_RejectsMalformedSubjects(t *testing.T) {
	setupPendingJWTEnv(t)

	for _, subject := range []string{"", "pending_registration", "../../../etc/passwd", "short", testutil.NewInternalID(t) + "x"} {
		if _, err := auth.SignToken(subject, 0); err == nil {
			t.Errorf("SignToken(%q) succeeded", subject)
		}
	}
	if _, err := auth.SignToken(testutil.NewInternalID(t), -1); err == nil {
		t.Error("SignToken accepted a negative session epoch")
	}
}

func TestVerifyToken_RejectsMalformedSubjectEvenWithValidSignature(t *testing.T) {
	setupPendingJWTEnv(t)

	for _, subject := range []string{"short", "' OR 1=1 --", testutil.NewInternalID(t)[:23] + "!"} {
		token := signWithServerSecret(t, serverClaims(subject, 0))
		if _, err := auth.VerifyToken(token); err == nil {
			t.Errorf("VerifyToken accepted subject %q", subject)
		}
	}
}

// A pending-registration token and a session token are never interchangeable.
func TestTokens_PendingAndSessionAreNotInterchangeable(t *testing.T) {
	setupPendingJWTEnv(t)

	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		t.Fatalf("GeneratePendingID: %v", err)
	}
	if err := auth.StorePendingRegistration(pendingID, testutil.NewPendingIdentity(t)); err != nil {
		t.Fatalf("StorePendingRegistration: %v", err)
	}
	pending, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		t.Fatalf("SignPendingRegistrationToken: %v", err)
	}
	if _, err := auth.VerifyToken(pending); err == nil {
		t.Fatal("pending-registration token accepted as a session")
	}

	session, err := auth.SignToken(testutil.NewInternalID(t), 0)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if _, _, err := auth.VerifyPendingRegistrationToken(session); err == nil {
		t.Fatal("session token accepted as a pending registration")
	}
}

// A genuine session token verifies; its signature-malleated look-alikes never do.
func TestVerifyToken_RefusesSignatureMalleation(t *testing.T) {
	setupPendingJWTEnv(t)

	token, err := auth.SignToken(testutil.NewInternalID(t), 0)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if _, err := auth.VerifyToken(token); err != nil {
		t.Fatalf("VerifyToken(genuine): %v", err)
	}
	for _, variant := range signatureMalleations(t, token) {
		if _, err := auth.VerifyToken(variant); !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("VerifyToken(%q) = %v, want ErrInvalidToken", variant, err)
		}
	}
}
