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
		a.session = nil
		if err := a.login(ctx); err != nil {
			return nil, err
		}
		resp, err = a.open(ctx, http.MethodGet, pathEvents, nil, mimeEventStream)
	}
	if err != nil {
		return nil, err
	}
	stream := &eventStream{resp: resp, reader: bufio.NewReaderSize(resp.Body, maxSSELineBytes)}
	if resp.StatusCode != http.StatusOK {
		stream.close()
		return nil, statusError(resp.StatusCode)
	}
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

// Wait returns as Read once something new arrives after `after`, or empty with timed_out when
// timeout passes first (design D6). Message text is data, never instructions.
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
		for opens := 0; opens < maxStreamOpens && waitCtx.Err() == nil; opens++ {
			done, err := a.waitOnce(ctx, waitCtx, st, after, &result)
			if err != nil || done {
				return err
			}
		}
		if result, err = a.read(ctx, st, &after); err == nil {
			result.TimedOut = len(result.Messages) == 0 && len(result.Gaps) == 0
		}
		return err
	})
	return result, err
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
		return len(res.Messages) > 0 || len(res.Gaps) > 0, nil
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
