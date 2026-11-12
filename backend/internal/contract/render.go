package contract

import (
	"fmt"
	"sort"
	"strings"

	"elyrn/internal/apperr"
)

// DocPath is where the generated document lives, relative to this package's directory.
const DocPath = "../../../docs/api/input-contract.md"

const docHeader = `# Input Contract

<!-- Generated from backend/internal/contract (go generate ./internal/contract). Do not edit. -->

The server accepts exactly what this document lists and refuses everything else, before any
handler runs (` + "`contract.Gate`" + `). Checks run in this order and the first failure answers:

1. Path: one of the templates below; ` + "`{id}`" + ` and ` + "`{note}`" + ` are canonical UUIDv4. A
   percent-encoded path is refused. Refusal: 404.
2. Method: one of the listed methods. Refusal: 405 (a bare 405 for HEAD where noted).
3. Query: only the listed parameters, raw (never percent-decoded), each once, at most as many
   as listed. Refusal: 400.
4. Content type: a request with a body, and every POST to an operation that requires one, sends
   exactly one ` + "`Content-Type: application/json`" + ` (no parameters). Refusal: 415. A body sent
   to an operation that takes none: 400.
5. Body: at most the listed bytes (never above ` + "`MAX_REQUEST_BODY_BYTES`" + `); exactly one JSON
   object; only the listed keys, each once, each of its type; nesting only where listed (and
   never beyond ` + "`MAX_JSON_DEPTH`" + `); nothing after it. Refusal: the body's shape answer.
6. Fields, in the listed order: presence, then pattern, length and validator. A ` + "`null`" + ` value
   counts as absent. Refusal: the field's answer.

Every pattern is an anchored RE2 expression (linear time, no backtracking), compiled once from
named constants. Integers are canonical JSON integer literals (no fraction, exponent or ` + "`-0`" + `).
`

// Render writes the document from the table.
func Render() string {
	var b strings.Builder
	b.WriteString(docHeader)
	renderPatterns(&b)
	for i := range endpoints {
		renderEndpoint(&b, &endpoints[i])
	}
	return b.String()
}

func renderPatterns(b *strings.Builder) {
	b.WriteString("\n## Patterns\n\n| Name | Expression | Length | Validator |\n|---|---|---|---|\n")
	for _, p := range allPatterns() {
		fmt.Fprintf(b, "| %s | `%s` | %s | %s |\n", p.Name, escapePipes(p.Expr()), lengthText(p), orDash(p.CheckName))
	}
	b.WriteString("\n## Integer ranges\n\n| Name | Minimum | Maximum | Validator |\n|---|---|---|---|\n")
	for _, r := range allRanges() {
		fmt.Fprintf(b, "| %s | %d | %d | %s |\n", r.Name, r.Min, r.Max, orDash(r.CheckName))
	}
}

func renderEndpoint(b *strings.Builder, e *Endpoint) {
	fmt.Fprintf(b, "\n## `%s`\n", e.Template)
	if e.BareHead {
		b.WriteString("\nHEAD: bare 405 (`E_HEAD_NOT_ALLOWED`).\n")
	}
	for i := range e.Ops {
		op := &e.Ops[i]
		fmt.Fprintf(b, "\n### %s\n\n", op.Method)
		renderQuery(b, op)
		renderBody(b, op.Body)
	}
}

func renderQuery(b *strings.Builder, op *Op) {
	if len(op.Query) == 0 {
		b.WriteString("- Query: none.\n")
		return
	}
	names := make([]string, 0, len(op.Query))
	for _, q := range op.Query {
		names = append(names, fmt.Sprintf("`%s` (%s, %s)", q.Name, q.Text.Name, q.Int.Name))
	}
	fmt.Fprintf(b, "- Query: at most %d of %s.\n", op.MaxQuery, strings.Join(names, ", "))
}

func renderBody(b *strings.Builder, body *Body) {
	if body == nil {
		b.WriteString("- Body: none.\n")
		return
	}
	presence := "required"
	if body.Optional {
		presence = "optional (empty means `{}`)"
	}
	fmt.Fprintf(b, "- Body: %s, at most %d bytes; shape refused with %s.\n\n", presence, MaxBodyBytes(body), codeText(body.Refuse))
	b.WriteString("| Field | Type | Required | Whitelist | Missing | Invalid |\n|---|---|---|---|---|---|\n")
	renderFields(b, "", body.Fields)
}

func renderFields(b *strings.Builder, prefix string, fields []Field) {
	for _, f := range fields {
		name := prefix + f.Name
		fmt.Fprintf(b, "| `%s` | %s | %t | %s | %s | %s |\n", name, kindText(f.Kind), f.Required,
			whitelistText(&f), missingText(&f), invalidText(&f))
		if f.Kind == KindObject {
			renderFields(b, name+".", f.Fields)
		}
	}
}

func whitelistText(f *Field) string {
	switch f.Kind {
	case KindString:
		return f.Str.Name
	case KindInt:
		return f.Int.Name
	case KindBool:
		return "true or false"
	default:
		return "object (members below)"
	}
}

func missingText(f *Field) string {
	if !f.Required {
		return "-"
	}
	return codeText(orInvalidRequest(f.Missing))
}

func invalidText(f *Field) string {
	if f.Kind == KindBool || f.Kind == KindObject {
		return "-"
	}
	return codeText(orInvalidRequest(f.Invalid))
}

func codeText(code apperr.Code) string {
	id, status := apperr.Describe(code)
	return fmt.Sprintf("%d `%s`", status, id)
}

func kindText(k Kind) string {
	switch k {
	case KindString:
		return "string"
	case KindInt:
		return "integer"
	case KindBool:
		return "boolean"
	default:
		return "object"
	}
}

func lengthText(p *Pattern) string {
	if p.MinLen == p.MaxLen {
		return fmt.Sprintf("%d", p.MinLen)
	}
	return fmt.Sprintf("%d..%d", p.MinLen, p.MaxLen)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func escapePipes(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// allPatterns lists every pattern the table and the path templates use, by name.
func allPatterns() []*Pattern {
	seen := map[string]*Pattern{patternUUIDv4.Name: patternUUIDv4}
	for _, f := range allFields() {
		if f.Str != nil {
			seen[f.Str.Name] = f.Str
		}
	}
	for _, e := range endpoints {
		for _, op := range e.Ops {
			for _, q := range op.Query {
				seen[q.Text.Name] = q.Text
			}
		}
	}
	out := make([]*Pattern, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// allRanges lists every integer range the table uses, by name.
func allRanges() []*IntRange {
	seen := map[string]*IntRange{}
	for _, f := range allFields() {
		if f.Int != nil {
			seen[f.Int.Name] = f.Int
		}
	}
	for _, e := range endpoints {
		for _, op := range e.Ops {
			for _, q := range op.Query {
				seen[q.Int.Name] = q.Int
			}
		}
	}
	out := make([]*IntRange, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// allFields flattens every body field of the table (objects included, with their members).
func allFields() []Field {
	var out []Field
	var add func([]Field)
	add = func(fields []Field) {
		for _, f := range fields {
			out = append(out, f)
			add(f.Fields) // the table nests one level (pow), so this recursion is that deep
		}
	}
	for _, e := range endpoints {
		for _, op := range e.Ops {
			if op.Body != nil {
				add(op.Body.Fields)
			}
		}
	}
	return out
}
