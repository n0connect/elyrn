package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
)

// Compact JSON sizes the body bound is derived from
const (
	objectBraces = len("{}")
	stringQuotes = len(`""`)
	keyFraming   = len(`"":`) + len(",") // quotes and colon around a key, the comma after a member
	boolLiteral  = len("false")
	nullLiteral  = len("null")
	// jsonWhitespaceAllowance: room for a trailing newline and a little spacing; encoding/json
	// and JSON.stringify (the agent and the browser) send compact JSON
	jsonWhitespaceAllowance = 64
	// topLevelDepth is the body object itself
	topLevelDepth = 1
)

var errShape = errors.New("contract: body is not the declared JSON shape")

// value is one JSON value the walk admitted, already of its field's declared kind.
type value struct {
	str    string
	number int64
	object map[string]*value
}

// MaxBodyBytes is the largest body the fields can take, written compactly, plus a whitespace
// allowance: every string at its pattern's MaxLen, every integer at its widest literal.
func MaxBodyBytes(b *Body) int {
	return objectBytes(b.Fields) + jsonWhitespaceAllowance
}

func objectBytes(fields []Field) int {
	total := objectBraces
	for _, f := range fields {
		total += len(f.Name) + keyFraming + max(valueBytes(f), nullLiteral)
	}
	return total
}

func valueBytes(f Field) int {
	switch f.Kind {
	case KindString:
		return f.Str.MaxLen + stringQuotes
	case KindInt:
		return maxIntLiteral
	case KindBool:
		return boolLiteral
	default:
		return objectBytes(f.Fields)
	}
}

// checkBody walks the JSON (shape) and then checks every field (whitelist), in table order.
func checkBody(raw []byte, b *Body) (apperr.Code, bool) {
	root, err := walk(raw, b.Fields)
	if err != nil {
		return b.Refuse, false
	}
	return checkFields(b.Fields, root)
}

// walk admits exactly one JSON object holding only declared keys, each once, each of its
// declared kind, nested only where an object is declared, followed by nothing. An empty
// (optional) body and a bare null stand for {}.
func walk(raw []byte, fields []Field) (map[string]*value, error) {
	if len(raw) == 0 {
		return map[string]*value{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, errShape
	}
	root := map[string]*value{}
	switch tok {
	case nil:
	case json.Delim('{'):
		if root, err = walkObject(dec, fields, topLevelDepth); err != nil {
			return nil, err
		}
	default:
		return nil, errShape
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errShape // a second value, or trailing bytes
	}
	return root, nil
}

// walkObject reads the members of an object whose '{' was consumed. The loop is bounded by
// the declared fields: an undeclared or repeated key ends it.
func walkObject(dec *json.Decoder, fields []Field, depth int) (map[string]*value, error) {
	if depth > config.GetMaxJSONDepth() {
		return nil, errShape
	}
	members := make(map[string]*value, len(fields))
	for range len(fields) + 1 {
		tok, err := dec.Token()
		if err != nil {
			return nil, errShape
		}
		if tok == json.Delim('}') {
			return members, nil
		}
		name, isKey := tok.(string)
		field := fieldNamed(fields, name)
		if !isKey || field == nil {
			return nil, errShape
		}
		if _, repeated := members[name]; repeated {
			return nil, errShape
		}
		v, err := walkValue(dec, field, depth)
		if err != nil {
			return nil, err
		}
		members[name] = v // nil for null: absent
	}
	return nil, errShape
}

// walkValue reads one member's value and refuses any kind other than the declared one.
func walkValue(dec *json.Decoder, f *Field, depth int) (*value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, errShape
	}
	switch t := tok.(type) {
	case nil:
		return nil, nil
	case string:
		if f.Kind == KindString {
			return &value{str: t}, nil
		}
	case json.Number:
		if n, ok := parseInteger(t.String()); ok && f.Kind == KindInt {
			return &value{number: n}, nil
		}
	case bool:
		if f.Kind == KindBool {
			return &value{}, nil
		}
	case json.Delim:
		if t == json.Delim('{') && f.Kind == KindObject {
			object, err := walkObject(dec, f.Fields, depth+1)
			return &value{object: object}, err
		}
	}
	return nil, errShape
}

func fieldNamed(fields []Field, name string) *Field {
	for i := range fields {
		if fields[i].Name == name {
			return &fields[i]
		}
	}
	return nil
}

// checkFields checks presence and whitelist of every field, in table order, and returns the
// first failing field's registered answer.
func checkFields(fields []Field, members map[string]*value) (apperr.Code, bool) {
	for i := range fields {
		f := &fields[i]
		v := members[f.Name]
		if v == nil {
			if f.Required {
				return orInvalidRequest(f.Missing), false
			}
			continue
		}
		if code, ok := checkValue(f, v); !ok {
			return code, false
		}
	}
	return 0, true
}

func checkValue(f *Field, v *value) (apperr.Code, bool) {
	switch f.Kind {
	case KindString:
		if !f.Str.Accepts(v.str) {
			return orInvalidRequest(f.Invalid), false
		}
	case KindInt:
		if !f.Int.Accepts(v.number) {
			return orInvalidRequest(f.Invalid), false
		}
	case KindObject:
		return checkFields(f.Fields, v.object)
	}
	return 0, true
}

// orInvalidRequest: a field without its own answer is refused with 400 "Invalid request".
func orInvalidRequest(code apperr.Code) apperr.Code {
	if code == 0 {
		return apperr.InvalidRequest
	}
	return code
}
