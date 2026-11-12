package apperr

import (
	"encoding/json"
	"net/http"
)

// sayBodyTooLarge is nginx's answer to a body over a location's bound (the backend's own bound
// is checked by the input contract and answers InvalidRequest)
const sayBodyTooLarge = "Request entity too large"

// EdgeAnswer is a failure nginx answers itself on /api/, without the backend: the backend is
// down or slow, or nginx's whitelist, body bound or rate limit refused the request first. The
// backend never writes these; they are registered here so each id exists in one place and
// cannot collide with a registry or operator id. nginx-api-errors.conf returns Body() verbatim
// (TestEdgeAnswersMatchNginx and make check-hardening compare them).
type EdgeAnswer struct {
	ID       string
	Status   int
	Sentence string
}

// EdgeAnswers lists every nginx-generated /api/ answer. 502 and 504 (no answer, or none in
// time) are answered 503 like the backend's own outage, so a client tells only "unavailable".
var EdgeAnswers = []EdgeAnswer{
	{"E_BACKEND_UNAVAILABLE", http.StatusServiceUnavailable, sayUnavailable},
	{"E_EDGE_NOT_FOUND", http.StatusNotFound, sayRouteNotFound},
	{"E_EDGE_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, sayMethodNotAllowed},
	{"E_BODY_TOO_LARGE", http.StatusRequestEntityTooLarge, sayBodyTooLarge},
	{"E_EDGE_RATE_LIMITED", http.StatusTooManyRequests, sayTooManyRequests},
}

// edgeBody is the wire shape: login's JSON failure shape (shapeJSON) plus the code, so the
// browser's existing mapping by message keeps working and a client can read the id.
type edgeBody struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Body is the exact JSON nginx returns for this answer (no trailing newline).
func (a EdgeAnswer) Body() string {
	raw, err := json.Marshal(edgeBody{Success: false, Message: a.Sentence, Code: a.ID})
	if err != nil {
		// Unreachable: three plain fields always marshal
		panic(err)
	}
	return string(raw)
}
