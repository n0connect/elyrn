// Package server wires handlers to routes. Shared by cmd/server and integration tests
// so tests exercise the exact production middleware chains.
package server

import (
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/contract"
	"elyrn/internal/handlers"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

var serverLogger = utils.NewLogger("SERVER")

// guarded is the security chain every route shares: headers -> CORS (exact origins) ->
// same-origin proof for writes -> the input contract's gate (path, method, query, content type,
// body size, JSON shape, every field). The gate runs before the session check, so a malformed
// request costs no database lookup.
func guarded(h http.HandlerFunc) http.HandlerFunc {
	return middleware.SecurityHeadersMiddleware(middleware.CORSMiddleware(
		middleware.SameOriginWritesMiddleware(contract.Gate(h))))
}

// public wraps an unauthenticated endpoint: panic recovery -> the request's one database
// deadline (middleware.RequestDeadline) -> the security chain (guarded).
func public(h http.HandlerFunc) http.HandlerFunc {
	return middleware.Recover(middleware.RequestDeadline(guarded(h)))
}

// protected additionally requires a valid, non-revoked session
func protected(h http.HandlerFunc) http.HandlerFunc {
	return public(middleware.JWTMiddleware(h))
}

// stream is protected without the request deadline on the request itself, for the event
// stream: it lives for minutes and bounds each write itself (handlers.EventsHandler), so a
// request deadline would cut it. Its session and member lookups run under the same detached,
// bounded database context as any request (middleware.StreamDeadline), so a client hanging up
// mid-lookup is never an internal error.
func stream(h http.HandlerFunc) http.HandlerFunc {
	return middleware.Recover(middleware.StreamDeadline(guarded(middleware.JWTMiddleware(h))))
}

// NewMux builds the complete HTTP surface with its middleware chains.
// Using http.NewServeMux() for explicit route registration (rejects unregistered endpoints)
func NewMux() *http.ServeMux {
	mux := http.NewServeMux()
	routes := []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{models.PathPoWChallenge, public(handlers.PoWChallengeHandler)},
		{models.PathRegister, public(handlers.RegisterHandler)},
		{models.PathLogin, public(middleware.RateLimitMiddleware(handlers.LoginHandler))},
		{models.PathLogout, public(handlers.LogoutHandler)},
		{models.PathMe, protected(handlers.MeHandler)},
		{models.PathInvites, protected(handlers.CreateInviteHandler)},
		{models.PathInvitesRedeem, protected(handlers.RedeemInviteHandler)},
		{models.PathRooms, protected(handlers.CreateRoomHandler)},
		{models.PathRoomsJoin, protected(handlers.JoinRoomHandler)},
		{models.PathConversations, protected(handlers.ConversationsHandler)},
		{models.PathConversations + "/", protected(handlers.ConversationsHandler)},
		{models.PathEvents, stream(handlers.EventsHandler)},
		{models.PathHealth, public(handlers.HealthHandler)},
	}
	for _, route := range routes {
		serverLogger.Debug("Registering route: %s", route.pattern)
		mux.HandleFunc(route.pattern, route.handler)
	}

	// Request Path Whitelist: a path outside every registered pattern answers 404 here (the
	// gate answers the same for a path under /conversations/ that no template fits)
	mux.HandleFunc("/", middleware.Recover(func(w http.ResponseWriter, r *http.Request) {
		apperr.Write(w, "NewMux: unknown path", apperr.RouteNotFound)
	}))

	serverLogger.Info("All routes registered successfully")
	return mux
}
