package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/database"
	"elyrn/internal/encryption"
	"elyrn/internal/middleware"
	"elyrn/internal/pow"
	"elyrn/internal/server"
	"elyrn/internal/utils"
)

// Shutdown budget. After SIGINT/SIGTERM in-flight requests get shutdownGrace to finish, then
// the background jobs get jobStopDeadline to return. The container's stop_grace_period
// (docker-compose.yaml) must exceed their sum, or Docker kills the process before it has closed
// the database and zeroized its keys; make check-hardening reads both constants from this file.
const (
	shutdownGrace   = 10 * time.Second
	jobStopDeadline = 5 * time.Second
)

var mainLogger = utils.NewLogger("MAIN")

func main() {
	if config.IsProductionMode() {
		mainLogger.Info("Starting elyrn. backend (production)")
	} else {
		mainLogger.Info("Starting elyrn. backend (development)")
	}

	// Every goroutine and request context derives from ctx: a signal, a failed listener or a lost
	// single-instance lock cancels them all; the cause decides the exit status
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, stop := context.WithCancelCause(signalCtx)
	defer stop(nil)

	lock := start(func(f *opcode.Failure) { stop(f) })
	srv := serve(ctx, stop)
	<-ctx.Done()
	mainLogger.Info("Shutdown began")
	shutdown(srv, lock)

	var f *opcode.Failure
	if errors.As(context.Cause(ctx), &f) {
		utils.ExitStartup(f)
	}
	mainLogger.Info("Server stopped; database closed, key material zeroized")
}

// start runs every startup step in order; the first failure exits through utils.ExitStartup.
// The single-instance lock is taken before the schema or any record is touched.
func start(lockLost func(*opcode.Failure)) *database.InstanceLock {
	// Known-answer self-test of the compiled crypto engine before any key or user data is touched
	if err := cryptoengine.SelfTest(); err != nil {
		utils.ExitStartup(opcode.Fail(opcode.SelfTest, "", ""))
	}
	mainLogger.Info("Crypto engine: %s (%s), self-test passed", cryptoengine.EngineName(), cryptoengine.EngineVersion())

	if err := database.ValidateStartupConfig(); err != nil {
		utils.ExitStartup(opcode.As(err, opcode.ConfigInvalid))
	}
	// Parsed now, not at the first request (validation has already refused malformed lists)
	middleware.LoadTrustedProxies()
	middleware.LoadAllowedOrigins()
	if f := database.Connect(); f != nil {
		utils.ExitStartup(f)
	}
	lock, f := database.AcquireInstanceLock(lockLost)
	if f != nil {
		database.Close()
		utils.ExitStartup(f)
	}
	fail := func(f *opcode.Failure) {
		lock.Release()
		database.Close()
		encryption.Close()
		utils.ExitStartup(f)
	}
	if f := database.Migrate(database.DB); f != nil {
		fail(f)
	}
	// Fail closed on keys that cannot open this database (a regenerated .env, a master key
	// dropped too early): starting anyway would answer every account with errors
	background := chat.NewBackgroundService()
	if err := background.VerifyKeys(); err != nil {
		fail(opcode.As(err, opcode.DBUnreachable))
	}
	// The file store's bound is checked against an in-process count: without one every upload
	// is refused (fail closed), so it is taken before the first request
	if err := background.RecountFileParts(); err != nil {
		fail(opcode.As(err, opcode.DBUnreachable))
	}
	return lock
}

// serve starts the supervised background jobs and the HTTP server; a listener that fails
// cancels ctx with E_LISTEN.
func serve(ctx context.Context, stop context.CancelCauseFunc) *http.Server {
	chatService := chat.NewBackgroundService()
	utils.SafeGoSupervised(ctx, "pow-cleanup", pow.RunCleanup)
	utils.SafeGoSupervised(ctx, "pending-cleanup", auth.RunPendingCleanup)
	utils.SafeGoSupervised(ctx, "retention", chatService.RunRetention)
	utils.SafeGoSupervised(ctx, "rewrap", chatService.RunRewrap)

	srv := server.NewHTTPServer(server.NewMux())
	// Long-lived SSE streams end as soon as shutdown begins
	srv.BaseContext = func(net.Listener) context.Context { return ctx }
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			detail := "the listener failed"
			if errors.Is(err, syscall.EADDRINUSE) {
				detail = "the port is in use"
			}
			stop(opcode.Fail(opcode.Listen, config.EnvBackendPort, detail))
		}
	}()
	mainLogger.Info("Server is ready to accept connections")
	return srv
}

// shutdown stops everything in dependency order: requests (shutdownGrace, then any left are cut
// off), the background jobs (jobStopDeadline; their context is already cancelled), the
// database pool, the single-instance lock, and last the master keys, which wait for any
// operation still using them and refuse every later one (encryption.ErrClosing, 503).
func shutdown(srv *http.Server, lock *database.InstanceLock) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		mainLogger.Warn("Requests still running after %s are cut off", shutdownGrace)
		if err := srv.Close(); err != nil {
			mainLogger.LogError("Close", err)
		}
	}
	if !utils.WaitJobs(jobStopDeadline) {
		utils.LogFailure(opcode.Fail(opcode.ShutdownLate, "", ""))
	}
	database.Close()
	lock.Release()
	encryption.Close()
}
