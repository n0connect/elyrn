// Package server wires handlers to routes. Shared by cmd/server and integration tests
// so tests exercise the exact production middleware chains.
package server

import (
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/handlers"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

var serverLogger = utils.NewLogger("SERVER")

// public wraps an unauthenticated endpoint with the base security chain:
// headers -> CORS (exact origins) -> same-origin proof for writes -> content-type whitelist
func public(h http.HandlerFunc) http.HandlerFunc {
	return middleware.SecurityHeadersMiddleware(middleware.CORSMiddleware(
		middleware.SameOriginWritesMiddleware(middleware.ContentTypeMiddleware(h))))
}

// protected additionally requires a valid, non-revoked session
func protected(h http.HandlerFunc) http.HandlerFunc {
	return public(middleware.JWTMiddleware(h))
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
		{models.PathEvents, protected(handlers.EventsHandler)},
	}
	for _, route := range routes {
		serverLogger.Debug("Registering route: %s", route.pattern)
		mux.HandleFunc(route.pattern, route.handler)
	}

	// Request Path Whitelist: Handle unknown paths with 404
	// Only registered paths are allowed, all others return 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apperr.Write(w, "NewMux: unknown path", apperr.RouteNotFound)
	})

	serverLogger.Info("All routes registered successfully")
	return mux
}
