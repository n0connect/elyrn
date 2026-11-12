package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"elyrn/internal/auth"
	"elyrn/internal/utils"
)

const (
	headerAccept      = "Accept"
	headerContentType = utils.HeaderContentType
	headerUserAgent   = "User-Agent"
	mimeJSON          = utils.MIMEJSON
	mimeEventStream   = utils.MIMEEventStream
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
		return nil, fail(transportCode(err), err)
	}
	a.takeSession(resp)
	return resp, nil
}

// transportCode tells a failed TLS handshake or certificate (not worth retrying, and a matter
// for the operator) from a server that could not be reached.
func transportCode(err error) Code {
	var verifyErr *tls.CertificateVerificationError
	var authorityErr x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var alertErr tls.AlertError
	var headerErr tls.RecordHeaderError
	if errors.As(err, &verifyErr) || errors.As(err, &authorityErr) || errors.As(err, &hostErr) ||
		errors.As(err, &invalidErr) || errors.As(err, &alertErr) || errors.As(err, &headerErr) {
		return CodeTLS
	}
	return CodeNetwork
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
	return readAnswer(resp)
}

// readAnswer reads a whole answer within its bound. A failure's body is read only for nginx's
// edge code (edgeFailure) and is never shown. An unavailable answer's body is not read at all
// (unavailable): whatever it holds, it reaches the caller as its bare status.
func readAnswer(resp *http.Response) (*answer, error) {
	if unavailable(resp.StatusCode) {
		return &answer{status: resp.StatusCode}, nil
	}
	limit := int64(maxResponseBytes)
	if !success(resp.StatusCode) {
		limit = maxErrorBodyBytes
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

// The ids nginx answers its own /api/ failures with, as JSON {"success":false,"message":…,
// "code":…} (backend/internal/apperr/edge.go EdgeAnswers; that package carries the server's
// store, so the ids are repeated here and edge_test.go compares the two tables). 500, 502 and
// 504 all reach the agent as 503 E_BACKEND_UNAVAILABLE.
const (
	edgeBackendUnavailable = "E_BACKEND_UNAVAILABLE"
	edgeNotFound           = "E_EDGE_NOT_FOUND"
	edgeMethodNotAllowed   = "E_EDGE_METHOD_NOT_ALLOWED"
	edgeBodyTooLarge       = "E_BODY_TOO_LARGE"
	edgeRateLimited        = "E_EDGE_RATE_LIMITED"
)

// edgeAnswer is what the agent makes of one edge id: the status it must come with, and whether
// nginx refused the request itself (route: the backend never saw it, so a status the callers
// give a meaning to, above all 404 "room gone", must not be read from it).
type edgeAnswer struct {
	status int
	route  bool
}

var edgeAnswers = map[string]edgeAnswer{
	edgeBackendUnavailable: {http.StatusServiceUnavailable, false}, // status mapping: CodeServerBusy, a passing failure
	edgeRateLimited:        {http.StatusTooManyRequests, false},    // status mapping: CodeRateLimited
	edgeNotFound:           {http.StatusNotFound, true},
	edgeMethodNotAllowed:   {http.StatusMethodNotAllowed, true},
	edgeBodyTooLarge:       {http.StatusRequestEntityTooLarge, true},
}

// edgeBody is the one field read from a failure's body; the message is never read.
type edgeBody struct {
	Code string `json:"code"`
}

// edgeFailure classifies a failed answer below 500 by nginx's edge code: a refusal at the edge
// is CodeServerRoute, a known id under another status is CodeServerAnswer, and anything else
// (the backend's own text answers, unknown JSON, a body that is not JSON, a rate-limited edge
// answer) is nil: the caller maps the status. A 5xx is always nil (unavailable).
func edgeFailure(ans *answer) error {
	if success(ans.status) || unavailable(ans.status) {
		return nil
	}
	var body edgeBody
	if json.Unmarshal(ans.body, &body) != nil {
		return nil
	}
	edge, known := edgeAnswers[body.Code]
	switch {
	case !known:
		return nil
	case edge.status != ans.status:
		return fail(CodeServerAnswer, nil)
	case edge.route:
		return fail(CodeServerRoute, nil)
	default:
		return nil
	}
}

// failedAnswer explains a failed answer the caller has no specific meaning for.
func failedAnswer(ans *answer) error {
	if err := edgeFailure(ans); err != nil {
		return err
	}
	return statusError(ans.status)
}

func success(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusNoContent
}

// unavailable reports a 5xx: the backend, or a front end in its place, failed or did not answer
// in time. Such an answer is judged by its status alone, never by its body: the body of a
// failing server proves nothing (a backend whose answer was cut off becomes nginx's 502 or 504,
// and an nginx deployed before its error pages stated their status answered those with the 503
// id E_BACKEND_UNAVAILABLE; a proxy in between may send a page of any size). Every caller reads
// a 5xx as a passing failure (statusError: CodeServerBusy; a send or a create: answer lost),
// so the agent says "wait and retry", never "wrong answer".
func unavailable(status int) bool {
	return status >= http.StatusInternalServerError
}

// public is one exchange that needs no session; out is decoded from a 200 or 201.
func (a *Agent) public(ctx context.Context, method, path string, body, out any) (int, error) {
	ans, err := a.roundTrip(ctx, method, path, body)
	if err != nil {
		return 0, err
	}
	return settleAnswer(ans, out)
}

// settleAnswer hands the caller the status of an answer, or the error of an edge refusal
// (edgeFailure) or of a success body that does not decode, in place of a status it could
// misread: a failure never comes with a status. The status is judged first: out is decoded from
// a 200 or 201 only, so no other answer's body ever becomes a success value or an error of its
// shape, and every other status reaches the caller (or edgeFailure) as it was served.
func settleAnswer(ans *answer, out any) (int, error) {
	if err := edgeFailure(ans); err != nil {
		return 0, err
	}
	if err := decodeAnswer(ans, out); err != nil {
		return 0, err
	}
	return ans.status, nil
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
		a.endSession()
		if err := a.login(ctx); err != nil {
			return 0, err
		}
		if ans, err = a.roundTrip(ctx, method, path, body); err != nil {
			return 0, err
		}
	}
	return settleAnswer(ans, out)
}

func decodeAnswer(ans *answer, out any) error {
	if out == nil || (ans.status != http.StatusOK && ans.status != http.StatusCreated) {
		return nil
	}
	return decodeServerJSON(ans.body, out)
}

// decodeServerJSON is the one decoder of server answers and event data: exactly one JSON value,
// every field out declares type-checked by encoding/json (the callers then check lengths and
// ranges). Fields out does not declare are ignored on purpose: a server that adds a response
// field must not break every agent already deployed (forward compatibility). Nothing unknown is
// kept, so nothing unknown is ever trusted or shown.
func decodeServerJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
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
