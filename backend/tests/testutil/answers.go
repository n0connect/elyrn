//go:build test
// +build test

package testutil

import (
	"net/http/httptest"
	"sync"

	"elyrn/internal/apperr"
	"elyrn/internal/utils"
)

// answer is what apperr writes on the wire for one code.
type answer struct {
	code        apperr.Code
	status      int
	body        string
	contentType string
}

var (
	answersOnce sync.Once
	answers     []answer
)

// registeredAnswers renders every registered code once (the registry runs from
// apperr.MethodNotAllowed to apperr.Internal, see apperr.TestRegistryComplete).
func registeredAnswers() []answer {
	answersOnce.Do(func() {
		for code := apperr.MethodNotAllowed; code <= apperr.Internal; code++ {
			rec := httptest.NewRecorder()
			apperr.Write(rec, "testutil.registeredAnswers", code)
			answers = append(answers, answer{code: code, status: rec.Code, body: rec.Body.String(),
				contentType: rec.Header().Get(utils.HeaderContentType)})
		}
	})
	return answers
}

func (a answer) matches(rec *httptest.ResponseRecorder) bool {
	return a.status == rec.Code && a.body == rec.Body.String() && a.contentType == rec.Header().Get(utils.HeaderContentType)
}

// RegisteredAnswer reports the first registered code whose answer rec holds exactly (status,
// body and content type): a fuzz target proves with it that every refusal is one the registry
// knows, never a body a handler wrote itself.
func RegisteredAnswer(rec *httptest.ResponseRecorder) (apperr.Code, bool) {
	for _, a := range registeredAnswers() {
		if a.matches(rec) {
			return a.code, true
		}
	}
	return 0, false
}

// IsAnswer reports whether rec holds exactly the answer apperr registers for code.
func IsAnswer(rec *httptest.ResponseRecorder, code apperr.Code) bool {
	for _, a := range registeredAnswers() {
		if a.code == code {
			return a.matches(rec)
		}
	}
	return false
}
