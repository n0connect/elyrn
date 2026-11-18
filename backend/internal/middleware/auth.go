package middleware

import (
	"errors"
	"net/http"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/config"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"
)

// sessionRefreshDivisor: a token past 1/sessionRefreshDivisor of its lifetime is re-issued
const sessionRefreshDivisor = 2

var (
	authMiddlewareLogger = utils.NewLogger("AUTH_MIDDLEWARE")
	userRepository       = store.NewUserRepository()

	// ErrNoSession means the request carries no live, non-revoked session
	ErrNoSession = errors.New("no valid session")
)

// Authenticate is the single session gate (protected routes and logout share it).
// The only credential is the HttpOnly session cookie: no header, no body field, so the
// token is never readable by page script. It must verify and carry the user's current
// session epoch, which every logout bumps.
func Authenticate(r *http.Request) (*models.User, *auth.Session, error) {
	session, err := signedSession(r)
	if err != nil {
		if !errors.Is(err, ErrNoSession) && !errors.Is(err, auth.ErrExpiredToken) {
			authMiddlewareLogger.Warn("invalid session token presented")
		}
		return nil, nil, ErrNoSession
	}
	user, err := userRepository.WithContext(DatabaseContext(r)).FindByUUID(session.UserUUID)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, nil, err
		}
		return nil, nil, ErrNoSession
	}
	if user.SessionEpoch != session.SessionEpoch {
		authMiddlewareLogger.Debug("revoked session presented")
		return nil, nil, ErrNoSession
	}
	return user, session, nil
}

// signedSession is the cookie's token once its signature and expiry verify: ErrNoSession without
// a cookie, VerifyToken's error for a bad token. It reads no database, so whether the session is
// still live (its epoch) is Authenticate's to decide; only StreamRevocationMark uses it alone.
func signedSession(r *http.Request) (*auth.Session, error) {
	token := auth.GetAuthCookie(r)
	if token == "" {
		return nil, ErrNoSession
	}
	return auth.VerifyToken(token)
}

// Reauthenticate runs the session gate again for a request that outlives its database deadline
// (the event stream, on every heartbeat), under a fresh deadline of its own: nil while the
// session is live, ErrNoSession once it is revoked or expired, or the store's failure.
func Reauthenticate(r *http.Request) error {
	ctx, cancel := databaseContext(r)
	defer cancel()
	_, _, err := Authenticate(withDatabaseContext(r, ctx))
	return err
}

// JWTMiddleware admits only requests with a live session and adds the user UUID to the context.
// SECURITY: Sliding session: tokens past half their lifetime are re-issued as a fresh cookie
func JWTMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, session, err := Authenticate(r)
		if err != nil {
			if !errors.Is(err, ErrNoSession) {
				apperr.WriteError(w, "JWTMiddleware: Authenticate", err)
				return
			}
			if auth.GetAuthCookie(r) != "" {
				auth.ClearAuthCookie(w)
			}
			apperr.Write(w, "JWTMiddleware", apperr.NoSession)
			return
		}

		if time.Since(session.IssuedAt) > config.GetJWTExpiration()/sessionRefreshDivisor {
			if fresh, err := auth.SignToken(user.UUID, user.SessionEpoch); err == nil {
				auth.SetAuthCookie(w, fresh)
			} else {
				authMiddlewareLogger.LogError("SignToken (refresh)", err)
			}
		}

		ctx := auth.WithUserUUID(r.Context(), user.UUID)
		next(w, r.WithContext(ctx))
	}
}
