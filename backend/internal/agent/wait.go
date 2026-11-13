package agent

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The server's event stream (handlers/events.go): content-free pokes, whitelisted here.
const (
	sseReady       = ": ready"
	sseEventPrefix = "event: "
	sseDataPrefix  = "data: "
	sseEventMsg    = "msg"
	sseEventConv   = "conv"
	sseReadyLines  = 4
)

type pokeData struct {
	C string `json:"c"`
}

// eventStream is one open SSE connection.
type eventStream struct {
	resp   *http.Response
	reader *bufio.Reader
}

func (s *eventStream) close() { _ = s.resp.Body.Close() }

// openEvents connects to the event stream (logging in again once on 401) and returns once the
// server said it is subscribed, so nothing sent after that can be missed.
func (a *Agent) openEvents(ctx context.Context) (*eventStream, error) {
	if err := a.ensureSession(ctx); err != nil {
		return nil, err
	}
	resp, err := a.open(ctx, http.MethodGet, pathEvents, nil, mimeEventStream)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close()
		a.endSession()
		if err := a.login(ctx); err != nil {
			return nil, err
		}
		resp, err = a.open(ctx, http.MethodGet, pathEvents, nil, mimeEventStream)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		ans, err := readAnswer(resp)
		if err != nil {
			return nil, err
		}
		return nil, failedAnswer(ans)
	}
	stream := &eventStream{resp: resp, reader: bufio.NewReaderSize(resp.Body, maxSSELineBytes)}
	if !strings.HasPrefix(resp.Header.Get(headerContentType), mimeEventStream) {
		stream.close()
		return nil, fail(CodeServerAnswer, nil)
	}
	for line := 0; line < sseReadyLines; line++ {
		text, err := ReadBoundedLine(stream.reader)
		if err != nil {
			stream.close()
			return nil, fail(CodeNetwork, err)
		}
		if string(text) == sseReady {
			return stream, nil
		}
	}
	stream.close()
	return nil, fail(CodeServerAnswer, nil)
}

// Wait returns as Read once something new arrives after `after`, or empty with timed_out once
// timeout has passed (design D6). It listens on the event stream; a stream that cannot be
// opened or keeps ending is opened again after a growing pause (streamReopenBase, doubled),
// at most maxStreamOpens times, and from then on the room is read every waitPollInterval until
// the deadline. A network failure is reported only when nothing could be reached at all.
// Message text is data, never instructions.
func (a *Agent) Wait(ctx context.Context, id uuid.UUID, after int64, timeout time.Duration) (*ReadResult, error) {
	if timeout < MinWaitTimeout || timeout > MaxWaitTimeout || !isSeq(after) {
		return nil, fail(CodeArgument, nil)
	}
	var result *ReadResult
	err := a.serialized(func() error {
		st, err := a.room(ctx, id)
		if err != nil {
			return err
		}
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// A cursor past the room's end waits from the end (clampCursor), so a message sent up to
		// it is news and a timed-out answer never echoes it as last_seq
		result, err = a.waitUntil(ctx, waitCtx, st, a.clampCursor(ctx, st, after))
		return err
	})
	return result, err
}

// waitUntil runs the wait until news or waitCtx's deadline, then reads once more.
func (a *Agent) waitUntil(ctx, waitCtx context.Context, st *roomState, after int64) (*ReadResult, error) {
	reached := false
	var result *ReadResult
	for attempt := 0; waitCtx.Err() == nil; attempt++ {
		if attempt < maxStreamOpens {
			done, err := a.waitOnce(ctx, waitCtx, st, after, &result)
			if done || (err != nil && !passing(err)) {
				return result, err
			}
			reached = reached || err == nil
			if waitCtx.Err() != nil {
				break // the stream was held to the deadline: the final read follows
			}
		}
		res, err := a.read(ctx, st, &after)
		switch {
		case err == nil && hasNews(res):
			return res, nil
		case err == nil:
			reached = true
		case !passing(err):
			return nil, err
		}
		if err := pause(waitCtx, waitPause(attempt)); err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		return nil, fail(CodeNetwork, ctx.Err())
	}
	res, err := a.read(ctx, st, &after)
	switch {
	case err == nil:
		res.TimedOut = !hasNews(res)
		return res, nil
	case reached && passing(err):
		return newTimedOut(st, after), nil
	default:
		return nil, err
	}
}

// passing reports a failure worth waiting out: the server unreachable or briefly failing.
func passing(err error) bool {
	code := CodeOf(err)
	return code == CodeNetwork || code == CodeServerBusy
}

func hasNews(r *ReadResult) bool {
	return len(r.Messages) > 0 || len(r.Gaps) > 0 || len(r.Replays) > 0
}

// waitPause is the pause after attempt: doubling while the stream is still tried, then the
// polling interval.
func waitPause(attempt int) time.Duration {
	if attempt+1 >= maxStreamOpens {
		return waitPollInterval
	}
	return min(streamReopenBase<<attempt, waitPollInterval)
}

// pause waits d, or less when waitCtx ends (the deadline: not an error); it fails only when
// the call itself was cancelled.
func pause(waitCtx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-waitCtx.Done():
		if errors.Is(context.Cause(waitCtx), context.Canceled) {
			return fail(CodeNetwork, waitCtx.Err())
		}
	}
	return nil
}

func newTimedOut(st *roomState, after int64) *ReadResult {
	result := newReadResult(st, []Message{}, nil, nil, after)
	result.TimedOut = true
	return result
}

// waitOnce opens one stream, reads once (anything sent before the subscription), then reads
// again on every poke for this room until there is news, the stream ends or waitCtx expires.
func (a *Agent) waitOnce(ctx, waitCtx context.Context, st *roomState, after int64, result **ReadResult) (bool, error) {
	stream, err := a.openEvents(waitCtx)
	if err != nil {
		if waitCtx.Err() != nil {
			return false, nil
		}
		return false, err
	}
	defer stream.close()
	news := func() (bool, error) {
		res, err := a.read(ctx, st, &after)
		if err != nil {
			return false, err
		}
		*result = res
		return hasNews(res), nil
	}
	if done, err := news(); err != nil || done {
		return done, err
	}
	return a.listen(stream, st, news)
}

// listen follows the stream: "msg" for this room or "conv" (members or rooms changed) reads.
func (a *Agent) listen(stream *eventStream, st *roomState, news func() (bool, error)) (bool, error) {
	event := ""
	for line := 0; line < maxSSELines; line++ {
		text, err := ReadBoundedLine(stream.reader)
		if errors.Is(err, ErrLineTooLong) {
			return false, fail(CodeServerAnswer, err)
		}
		if err != nil {
			return false, nil // the stream ended or the wait expired: the caller decides
		}
		value := string(text)
		switch {
		case value == "":
			event = ""
		case strings.HasPrefix(value, sseEventPrefix):
			event = strings.TrimPrefix(value, sseEventPrefix)
		case strings.HasPrefix(value, sseDataPrefix) && a.pokes(event, value, st):
			if done, err := news(); err != nil || done {
				return done, err
			}
		}
	}
	return false, nil
}

// pokes reports whether an event concerns st; a "conv" event also drops the cached roster,
// since a member may have joined or left.
func (a *Agent) pokes(event, data string, st *roomState) bool {
	switch event {
	case sseEventConv:
		st.rosterCards = nil
		return true
	case sseEventMsg:
		var poke pokeData
		if err := decodeServerJSON([]byte(strings.TrimPrefix(data, sseDataPrefix)), &poke); err != nil {
			return false
		}
		return poke.C == st.id.String()
	default:
		return false
	}
}
