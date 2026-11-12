package server

import (
	"net/http"

	"elyrn/internal/config"
	"elyrn/internal/utils"
)

// NewHTTPServer is the one http.Server configuration: the port and every timeout and bound from
// the validated configuration (the database's request deadlines follow WriteTimeout, see
// internal/database), net/http's own error lines through the logger, peer addresses removed.
// cmd/server adds its BaseContext; integration tests serve the same configuration.
func NewHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + config.GetBackendPort(),
		Handler:           handler,
		ReadHeaderTimeout: config.GetServerReadHeaderTimeout(),
		ReadTimeout:       config.GetServerReadTimeout(),
		WriteTimeout:      config.GetServerWriteTimeout(),
		IdleTimeout:       config.GetServerIdleTimeout(),
		MaxHeaderBytes:    config.GetServerMaxHeaderBytes(),
		ErrorLog:          utils.NewLogger("HTTP_SERVER").StdLogger(),
	}
}
