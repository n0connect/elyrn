package handlers

import (
	"context"
	"net/http"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/chat"
	"elyrn/internal/database"
	"elyrn/internal/middleware"
)

// healthTimeout bounds the healthcheck's SELECT 1: well under the compose healthcheck's own
// timeout, so a slow database is reported as 503, not as a hung probe
const healthTimeout = 3 * time.Second

// HealthHandler answers the container healthcheck (docker-compose.yaml): 200 with no body when
// the database answers SELECT 1 within healthTimeout and retention is still cycling, else 503
// with no body (E_HEALTH_UNAVAILABLE in the log). Only a loopback peer gets an answer; any other
// is told the path does not exist, exactly like an unknown path. nginx never forwards it (its
// whitelist proxies /api/ alone).
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := admitted(w, r, "HealthHandler"); !ok {
		return
	}
	if !middleware.IsLoopbackPeer(r) {
		apperr.Write(w, "HealthHandler: not loopback", apperr.RouteNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	if err := database.Ping(ctx); err != nil {
		apperr.Write(w, "HealthHandler: database", apperr.HealthUnavailable)
		return
	}
	if !chat.RetentionAlive() {
		apperr.Write(w, "HealthHandler: retention", apperr.HealthUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
