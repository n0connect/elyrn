package contract

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
	"elyrn/internal/utils"
)

const (
	pathSeparator  = "/"
	querySeparator = "&"
	queryAssign    = "="
)

// segment is one piece of a path template: a literal, or a UUIDv4 parameter and its position.
type segment struct {
	literal  string
	param    bool
	position int
}

// Input is what the gate admitted: the operation, its parsed path parameters, its query values
// and the body that passed every field check. Handlers read it with InputOf.
type Input struct {
	Op     *Op
	params [maxPathParams]uuid.UUID
	query  map[string]int64
	body   []byte
}

// PathID returns the path parameter at position i (PathConversation, PathNote, PathFile), or
// uuid.Nil when the template has none there.
func (in *Input) PathID(i int) uuid.UUID {
	if i < 0 || i >= maxPathParams {
		return uuid.Nil
	}
	return in.params[i]
}

// Query returns an admitted query parameter's value and whether the request carried it.
func (in *Input) Query(name string) (int64, bool) {
	v, ok := in.query[name]
	return v, ok
}

type inputKey struct{}

// InputOf returns what the gate admitted for r; ok is false only when the route was wired
// without the gate.
func InputOf(r *http.Request) (*Input, bool) {
	in, ok := r.Context().Value(inputKey{}).(*Input)
	return in, ok && in != nil
}

// Bind fills dst (the operation's models request type) from the admitted body. Every field was
// checked by name, type and whitelist already, so a failure is a fault between the table and
// the type, never the client's.
func (in *Input) Bind(dst any) error {
	if len(in.body) == 0 {
		return nil
	}
	return json.Unmarshal(in.body, dst)
}

// buildTable splits every template into segments once, at init.
func buildTable(table []Endpoint) []Endpoint {
	for i := range table {
		parts := strings.Split(table[i].Template, pathSeparator)
		table[i].segments = make([]segment, len(parts))
		for j, part := range parts {
			position, isParam := paramPositions[part]
			table[i].segments[j] = segment{literal: part, param: isParam, position: position}
		}
	}
	return table
}

// maxSegments is the deepest template; a longer path matches nothing and is not split further.
var maxSegments = deepestTemplate(endpoints)

func deepestTemplate(table []Endpoint) int {
	deepest := 0
	for _, e := range table {
		deepest = max(deepest, len(e.segments))
	}
	return deepest
}

// match finds the endpoint whose template the path fits and parses its UUID parameters.
func match(path string) (*Endpoint, [maxPathParams]uuid.UUID, bool) {
	var params [maxPathParams]uuid.UUID
	parts := strings.SplitN(path, pathSeparator, maxSegments+1)
	if len(parts) > maxSegments {
		return nil, params, false
	}
	for i := range endpoints {
		// Fresh per template: one that fails half-way leaves no id behind for the next
		var candidate [maxPathParams]uuid.UUID
		if fits(endpoints[i].segments, parts, &candidate) {
			return &endpoints[i], candidate, true
		}
	}
	return nil, params, false
}

// fits compares one template with the path's parts, parsing parameters into params.
func fits(segments []segment, parts []string, params *[maxPathParams]uuid.UUID) bool {
	if len(segments) != len(parts) {
		return false
	}
	for i, seg := range segments {
		if !seg.param {
			if parts[i] != seg.literal {
				return false
			}
			continue
		}
		if !patternUUIDv4.Accepts(parts[i]) {
			return false
		}
		id, err := uuid.Parse(parts[i]) // canonical v4 already: this only converts
		if err != nil {
			return false
		}
		params[seg.position] = id
	}
	return true
}

// opFor returns the operation for method, or nil.
func (e *Endpoint) opFor(method string) *Op {
	for i := range e.Ops {
		if e.Ops[i].Method == method {
			return &e.Ops[i]
		}
	}
	return nil
}

// Gate is the one enforcement point: every route passes it before its handler. It checks, in
// order, the path, the method, the query, the content type, the body's presence and size, the
// JSON shape and every field, and answers the first failure through apperr.
func Gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		in, code, ok := admit(r)
		if !ok {
			apperr.Write(w, "contract.Gate", code)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), inputKey{}, in)))
	}
}

// admit runs every check on r and returns what it admitted or the code that refuses it.
func admit(r *http.Request) (*Input, apperr.Code, bool) {
	// A percent-encoded path is refused: a genuine client never escapes these paths, and the
	// whitelist must see the bytes that were sent
	if r.URL.EscapedPath() != r.URL.Path {
		return nil, apperr.RouteNotFound, false
	}
	endpoint, params, ok := match(r.URL.Path)
	if !ok {
		return nil, apperr.RouteNotFound, false
	}
	op := endpoint.opFor(r.Method)
	if op == nil {
		if r.Method == http.MethodHead && endpoint.BareHead {
			return nil, apperr.HeadNotAllowed, false
		}
		return nil, apperr.MethodNotAllowed, false
	}
	query, ok := parseQuery(r.URL.RawQuery, op)
	if !ok {
		return nil, apperr.InvalidRequest, false
	}
	if code, ok := checkContentType(r, op); !ok {
		return nil, code, false
	}
	body, code, ok := readBody(r, op)
	if !ok {
		return nil, code, false
	}
	return &Input{Op: op, params: params, query: query, body: body}, 0, true
}

// parseQuery admits the raw query: pairs "name=value" separated by "&", each name declared,
// once, at most op.MaxQuery of them, each value matching its pattern and range, and every
// required one present. Values are matched as sent (not percent-decoded): the declared
// alphabets need no escaping.
func parseQuery(raw string, op *Op) (map[string]int64, bool) {
	values, ok := parsePairs(raw, op)
	if !ok {
		return nil, false
	}
	for _, param := range op.Query {
		if _, present := values[param.Name]; param.Required && !present {
			return nil, false
		}
	}
	return values, true
}

// parsePairs reads the pairs of a raw query (none when it is empty).
func parsePairs(raw string, op *Op) (map[string]int64, bool) {
	if raw == "" {
		return nil, true
	}
	pairs := strings.SplitN(raw, querySeparator, op.MaxQuery+1)
	if len(pairs) > op.MaxQuery {
		return nil, false
	}
	values := make(map[string]int64, len(pairs))
	for _, pair := range pairs {
		name, text, found := strings.Cut(pair, queryAssign)
		param := op.queryParam(name)
		if !found || param == nil || !param.Text.Accepts(text) {
			return nil, false
		}
		if _, repeated := values[name]; repeated {
			return nil, false
		}
		v, ok := parseInteger(text)
		if !ok || !param.Int.Accepts(v) {
			return nil, false
		}
		values[name] = v
	}
	return values, true
}

func (op *Op) queryParam(name string) *QueryParam {
	for i := range op.Query {
		if op.Query[i].Name == name {
			return &op.Query[i]
		}
	}
	return nil
}

// bodyPresent: a declared length of zero is the only proof of no body (-1 is "unknown").
func bodyPresent(r *http.Request) bool { return r.ContentLength != 0 }

// checkContentType: a request that carries a body, and every POST or PUT to an operation that
// requires one, must declare exactly application/json. A bodiless operation refuses any body.
func checkContentType(r *http.Request, op *Op) (apperr.Code, bool) {
	writes := r.Method == http.MethodPost || r.Method == http.MethodPut
	bodyRequired := op.Body != nil && !op.Body.Optional
	if !bodyPresent(r) && !(writes && bodyRequired) {
		return 0, true
	}
	if declared := r.Header.Values(utils.HeaderContentType); len(declared) != 1 || declared[0] != utils.MIMEJSON {
		return apperr.UnsupportedMediaType, false
	}
	if op.Body == nil {
		return apperr.InvalidRequest, false
	}
	return 0, true
}

// readBody reads at most the operation's bound and checks the JSON against its fields.
func readBody(r *http.Request, op *Op) ([]byte, apperr.Code, bool) {
	if op.Body == nil {
		return nil, 0, true
	}
	limit := bodyLimit(op.Body)
	if r.ContentLength > int64(limit) {
		return nil, op.Body.Refuse, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, op.Body.Refuse, false
	}
	if len(raw) == 0 && !op.Body.Optional {
		return nil, op.Body.Refuse, false
	}
	if code, ok := checkBody(raw, op.Body); !ok {
		return nil, code, false
	}
	return raw, 0, true
}

// bodyLimit is the operation's own bound, never above MAX_REQUEST_BODY_BYTES.
func bodyLimit(b *Body) int {
	limit := MaxBodyBytes(b)
	if global := config.GetMaxRequestBodyBytes(); global > 0 && global < limit {
		return global
	}
	return limit
}
