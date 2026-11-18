package handlers

import (
	"errors"
	"io"
	"net/http"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/middleware"
	"elyrn/internal/realtime"
	"elyrn/internal/utils"
)

const (
	// sseWriteTimeout bounds every individual write so a stalled client cannot pin a goroutine
	sseWriteTimeout = 10 * time.Second
	// sseKeepAlive keeps proxies from reaping idle streams, and tells the browser the stream is
	// delivering (frontend chat.js STREAM_SILENCE_LIMIT_MS allows two of them and some slack; one
	// more is sent right after the preamble, for STREAM_FIRST_PROOF_MS). Short, so a page behind a
	// proxy that holds the stream notices within seconds and fetches its updates instead.
	sseKeepAlive = 10 * time.Second
	// sseMaxLifetime forces periodic reconnects; the session itself is checked on every heartbeat
	sseMaxLifetime = 10 * time.Minute
	// sseMaxIterations bounds the event loop (RULES.md §8.1); lifetime normally ends it first
	sseMaxIterations = 100000
	// sseRetryPreamble asks the browser to reconnect after 3000 ms and marks the stream ready
	sseRetryPreamble = "retry: 3000\n: ready\n\n"
	// ssePing is a named event, not a comment: EventSource never shows a comment to the page, so
	// only an event lets the browser see that a proxy is passing the stream through. The data line
	// is required (an event without data is never dispatched) and carries nothing.
	ssePing = "event: ping\ndata: {}\n\n"
)

// formatEvent renders whitelisted event kinds only; payloads are server-generated IDs.
func formatEvent(ev realtime.Event) string {
	switch ev.Kind {
	case realtime.KindMessage:
		return "event: msg\ndata: {\"c\":\"" + ev.ConversationID + "\"}\n\n"
	case realtime.KindConversation:
		return "event: conv\ndata: {}\n\n"
	default:
		return ""
	}
}

var eventsLogger = utils.NewLogger("EVENTS")

// sessionHolds re-checks the stream's session (signature, expiry and epoch) under a fresh
// database deadline, on every heartbeat: a revoked session's stream ends within one heartbeat
// even when no kick reached it (a kick that timed out on the hub lock). A store failure ends the
// stream too (fail closed): the browser reconnects and gets the registered answer there.
func sessionHolds(r *http.Request) bool {
	err := middleware.Reauthenticate(r)
	if err == nil {
		return true
	}
	if errors.Is(err, middleware.ErrNoSession) {
		eventsLogger.Debug("EventsHandler: session no longer live, stream ended")
		return false
	}
	code, ok := apperr.CodeOf(err)
	if !ok {
		code = apperr.Internal
	}
	id, _ := apperr.Describe(code)
	eventsLogger.LogError("EventsHandler: Reauthenticate ("+id+")", err)
	return false
}

// EventsHandler streams content-free change notifications (GET /api/v2/events).
//
// http.Server.ReadTimeout does not end the stream, so nothing here clears the read deadline
// (settled from the pinned Go 1.27.4 source, src/net/http/server.go): conn.readRequest sets the
// whole-request read deadline from ReadTimeout (lines 1035-1036, 1099), but for a request
// without a body conn.serve then calls connReader.startBackgroundRead (line 2150) before the
// handler runs, and startBackgroundRead clears the connection's read deadline
// (SetReadDeadline(time.Time{}), line 737) before its background read. The stream is a GET
// without a body. WriteTimeout does not end it either: every write sets its own deadline
// (sseWriteTimeout).
func EventsHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := admitted(w, r, "EventsHandler"); !ok {
		return
	}
	_, me, ok := resolveMe(w, r)
	if !ok {
		return
	}
	// The generation read before the session check (server.stream): a kick since refuses below
	generation, ok := middleware.StreamGeneration(r, me.StreamTag)
	if !ok {
		apperr.Write(w, "EventsHandler: StreamGeneration", apperr.SessionContextMissing)
		return
	}

	// The stream counts against this network's share as well as the account's (S-04)
	client, err := middleware.ClientKey(r)
	if err != nil {
		apperr.WriteError(w, "EventsHandler: ClientKey", err)
		return
	}
	events, cancel, err := realtime.Default.Subscribe(me.StreamTag, client, generation)
	if err != nil {
		// Every Subscribe failure answers 429, as it always has: a subscriber cap (account,
		// network or hub), a hub lock timeout under contention, or a kick since the generation
		// was read (all mean "retry later"; a revoked session's retry is refused with 401 by the
		// session check itself)
		apperr.Write(w, "EventsHandler", apperr.SubscriberLimit)
		return
	}
	defer cancel()

	rc := http.NewResponseController(w)
	write := func(payload string) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		if _, err := io.WriteString(w, payload); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	w.Header().Set(utils.HeaderContentType, utils.MIMEEventStream)
	w.Header().Set("X-Accel-Buffering", "no") // nginx: do not buffer the stream
	w.WriteHeader(http.StatusOK)
	// The preamble first (the agent waits for its ": ready"), then one heartbeat at once, so a
	// browser sees within its first-proof limit that the stream is being delivered
	if !write(sseRetryPreamble + ssePing) {
		return
	}

	keepAlive := time.NewTicker(sseKeepAlive)
	defer keepAlive.Stop()
	lifetime := time.NewTimer(sseMaxLifetime)
	defer lifetime.Stop()

	for i := 0; i < sseMaxIterations; i++ {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-keepAlive.C:
			if !sessionHolds(r) || !write(ssePing) {
				return
			}
		case ev, open := <-events:
			if !open {
				return // session revoked (Kick) — client reconnect will fail auth
			}
			if payload := formatEvent(ev); payload != "" && !write(payload) {
				return
			}
		}
	}
}
