package handlers

import (
	"errors"
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/identity"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/internal/utils"
)

var logoutLogger = utils.NewLogger("LOGOUT")

// LogoutHandler revokes every session of the caller and clears the cookie.
// SECURITY: Bumping the session epoch invalidates all outstanding JWTs (all devices) and
// closes live event streams. Only a live session may do that: a token revoked earlier
// cannot end the sessions created after it. A failed revocation is reported, never hidden: a
// revocation whose streams could not be closed (the stream tag not derived, or the hub lock not
// taken) answers 503 E_STORE_UNAVAILABLE after the epoch bump (kickStreams).
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := admitted(w, r, "LogoutHandler"); !ok {
		return
	}
	w.Header().Set(utils.HeaderCacheControl, utils.CacheNoStore)
	// The cookie goes in every case: absent, expired, revoked or live
	auth.ClearAuthCookie(w)

	user, _, err := middleware.Authenticate(r)
	switch {
	case errors.Is(err, middleware.ErrNoSession):
		// Nothing live to revoke: the browser is logged out once the cookie is gone
	case err != nil:
		apperr.WriteError(w, "LogoutHandler: Authenticate", err)
		return
	default:
		if err := userRepository.WithContext(middleware.DatabaseContext(r)).BumpSessionEpoch(user.UUID); err != nil {
			apperr.WriteError(w, "LogoutHandler: BumpSessionEpoch", err)
			return
		}
		stream, err := identity.StreamTag(user.UUID)
		if err != nil {
			// The epoch is bumped, but the account's streams cannot be named to close them
			apperr.WriteCause(w, "LogoutHandler: StreamTag", apperr.StoreUnavailable, err)
			return
		}
		if !kickStreams(w, "LogoutHandler: Kick", stream) {
			return
		}
		logoutLogger.Debug("LogoutHandler: sessions revoked")
	}

	clearSiteData(w)
	utils.EncodeJSONResponse(w, models.LoginResponse{
		Success: true,
		Message: "Logged out successfully",
	}, http.StatusOK)
}

// kickStreams closes the live event streams of stream (and bumps its revocation generation), or
// answers the registered "temporarily unavailable" (503 E_STORE_UNAVAILABLE) when the hub lock
// could not be taken in time. It runs after the sessions were revoked in the database, so the
// 503 reports a partial revocation: every session is already refused, and a stream the kick
// did not reach ends at its next heartbeat's session check (handlers.sessionHolds).
func kickStreams(w http.ResponseWriter, op, stream string) bool {
	if err := realtime.Default.Kick(stream); err != nil {
		apperr.WriteCause(w, op, apperr.StoreUnavailable, err)
		return false
	}
	return true
}

// clearSiteData asks the browser to drop this origin's cookies and stored data (the identity,
// keys and replay records in IndexedDB) with the answer: belt and braces for a browser whose own
// wipe failed. Only the two answers that end an identity on this device send it: a successful
// logout and a successful account deletion.
func clearSiteData(w http.ResponseWriter) {
	w.Header().Set(utils.HeaderClearSiteData, utils.ClearCookiesAndStorage)
}
