package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"elyrn/internal/auth"
)

const (
	headerAccept      = "Accept"
	headerContentType = "Content-Type"
	headerUserAgent   = "User-Agent"
	mimeJSON          = "application/json"
	mimeEventStream   = "text/event-stream"
	userAgent         = "elyrn-agent"
)

// sessionCookieNames: the server's session cookie in production and in development.
var sessionCookieNames = map[string]struct{}{auth.ProductionCookieName: {}, auth.DevelopmentCookieName: {}}

// answer is one complete, size-bounded server answer.
type answer struct {
	status int
	body   []byte
}

// newHTTPClient bounds every phase of a connection and refuses redirects: the agent talks to
// the one origin it was given.
func newHTTPClient(proxy func(*http.Request) (*url.URL, error)) *http.Client {
	transport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout:   tlsTimeout,
		ResponseHeaderTimeout: headerTimeout,
		IdleConnTimeout:       idleConnTimeout,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// open sends one request and takes the session cookie from the answer; the caller closes it.
func (a *Agent) open(ctx context.Context, method, path string, body any, accept string) (*http.Response, error) {
	if a.origin == "" {
		return nil, fail(CodeServerMissing, nil)
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fail(CodeInternal, err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.origin+path, reader)
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	req.Header.Set(headerAccept, accept)
	req.Header.Set(headerUserAgent, userAgent)
	if body != nil {
		req.Header.Set(headerContentType, mimeJSON)
	}
	if a.session != nil {
		req.AddCookie(a.session)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fail(CodeNetwork, err)
	}
	a.takeSession(resp)
	return resp, nil
}

// takeSession keeps the session cookie (sliding expiry re-issues it) and drops a cleared one.
func (a *Agent) takeSession(resp *http.Response) {
	for _, cookie := range resp.Cookies() {
		if _, ok := sessionCookieNames[cookie.Name]; !ok {
			continue
		}
		if cookie.MaxAge < 0 || cookie.Value == "" || len(cookie.Value) > maxCookieValueChars {
			a.session = nil
			continue
		}
		a.session = &http.Cookie{Name: cookie.Name, Value: cookie.Value}
	}
}

// roundTrip is one bounded exchange: requestTimeout for all of it, and a size cap on the body.
func (a *Agent) roundTrip(ctx context.Context, method, path string, body any) (*answer, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := a.open(ctx, method, path, body, mimeJSON)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := int64(maxResponseBytes)
	if !success(resp.StatusCode) {
		limit = maxErrorBodyBytes // never read, only drained so the connection can be reused
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fail(CodeNetwork, err)
	}
	if int64(len(raw)) > limit {
		return nil, fail(CodeServerAnswer, nil)
	}
	return &answer{status: resp.StatusCode, body: raw}, nil
}

func success(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent
}

// public is one exchange that needs no session; out is decoded from a 200 or 201.
func (a *Agent) public(ctx context.Context, method, path string, body, out any) (int, error) {
	ans, err := a.roundTrip(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	return ans.status, decodeAnswer(ans, out)
}

// api is one authenticated exchange: a 401 means the session expired, so it logs in again and
// retries once.
func (a *Agent) api(ctx context.Context, method, path string, body, out any) (int, error) {
	if err := a.ensureSession(ctx); err != nil {
		return 0, err
	}
	ans, err := a.roundTrip(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	if ans.status == http.StatusUnauthorized {
		a.session = nil
		if err := a.login(ctx); err != nil {
			return 0, err
		}
		if ans, err = a.roundTrip(ctx, method, path, body); err != nil {
			return 0, err
		}
	}
	return ans.status, decodeAnswer(ans, out)
}

func decodeAnswer(ans *answer, out any) error {
	if out == nil || (ans.status != http.StatusOK && ans.status != http.StatusCreated) {
		return nil
	}
	return decodeStrict(ans.body, out)
}

// decodeStrict accepts exactly one JSON value with only the fields out declares.
func decodeStrict(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fail(CodeServerAnswer, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fail(CodeServerAnswer, err)
	}
	return nil
}

// statusError explains an answer the caller has no specific meaning for.
func statusError(status int) error {
	switch {
	case status == http.StatusTooManyRequests:
		return fail(CodeRateLimited, nil)
	case status >= http.StatusInternalServerError:
		return fail(CodeServerBusy, nil)
	default:
		return fail(CodeUnexpectedStatus, nil)
	}
}

// backoff waits backoffBase << attempt, or less if ctx ends first.
func backoff(ctx context.Context, attempt int) error {
	timer := time.NewTimer(backoffBase << attempt)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fail(CodeNetwork, ctx.Err())
	case <-timer.C:
		return nil
	}
}
