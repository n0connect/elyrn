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
	// sseKeepAlive keeps proxies from reaping idle streams
	sseKeepAlive = 25 * time.Second
	// sseMaxLifetime forces periodic reconnects, which re-run JWT + session-epoch checks
	sseMaxLifetime = 10 * time.Minute
	// sseMaxIterations bounds the event loop (RULES.md §8.1); lifetime normally ends it first
	sseMaxIterations = 100000
	// sseRetryPreamble asks the browser to reconnect after 3000 ms and marks the stream ready
	sseRetryPreamble = "retry: 3000\n: ready\n\n"
	ssePing          = ": ping\n\n"
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

// EventsHandler streams content-free change notifications (GET /api/v2/events).
func EventsHandler(w http.ResponseWriter, r *http.Request) {
	if _, ok := admitted(w, r, "EventsHandler"); !ok {
		return
	}
	_, me, ok := resolveMe(w, r)
	if !ok {
		return
	}

	// The stream counts against this network's share as well as the account's (S-04)
	client, err := middleware.ClientKey(r)
	if err != nil {
		apperr.WriteError(w, "EventsHandler: ClientKey", err)
		return
	}
	events, cancel, err := realtime.Default.Subscribe(me.StreamTag, client)
	if err != nil {
		// Every Subscribe failure answers 429, as it always has: a subscriber cap (account,
		// network or hub), or a hub lock timeout under contention (all mean "retry later")
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
	if !write(sseRetryPreamble) {
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
			if !write(ssePing) {
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
