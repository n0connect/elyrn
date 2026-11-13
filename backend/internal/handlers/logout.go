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
// cannot end the sessions created after it. A failed revocation is reported, never hidden.
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
		if stream, err := identity.StreamTag(user.UUID); err == nil {
			realtime.Default.Kick(stream)
		}
		logoutLogger.Debug("LogoutHandler: sessions revoked")
	}

	utils.EncodeJSONResponse(w, models.LoginResponse{
		Success: true,
		Message: "Logged out successfully",
	}, http.StatusOK)
}
