package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/pow"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Fuzz targets over every surface of the agent that parses or judges bytes it does not control:
// the server address, the identity and counter files, the server's answers and event stream,
// the proof-of-work challenge and received text (room pages: fuzz_rooms_test.go). Each asserts
// an invariant, not only the absence of a panic.
// Run one with: go test -tags test -run '^$' -fuzz '^FuzzClassifyServerURL$' -fuzztime 30s ./internal/agent

const (
	// fuzzMaxSolvedDifficulty bounds the challenges FuzzSolveChallenge really solves: harder
	// valid ones only cost time (up to maxPoWDifficulty is the agent's documented work).
	fuzzMaxSolvedDifficulty = 8
	// Statuses FuzzServerAnswer draws from: every three-digit status.
	fuzzMinHTTPStatus  = 100
	fuzzHTTPStatusSpan = 900
	fuzzTestServer     = "https://elyrn.example"
	fuzzValidToken     = "a.b-c_d"
	fuzzRoomID         = "0b6b9a54-3c0e-4f3a-9d6c-2a1f0e5b7c11"
	fuzzSenderKey      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// wantFailure asserts err is a registered failure among allowed whose text is exactly the code
// and its sentence: nothing of the input (a secret, a path, server text) can be in it.
func wantFailure(t *testing.T, err error, allowed ...Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("no failure, want one of %v", allowed)
	}
	code := CodeOf(err)
	if !slices.Contains(allowed, code) {
		t.Fatalf("failure code %s, want one of %v", code, allowed)
	}
	if err.Error() != string(code)+": "+Sentence(code) {
		t.Fatalf("the failure text of %s is not its registered sentence", code)
	}
}

func FuzzClassifyServerURL(f *testing.F) {
	for _, seed := range []string{
		fuzzTestServer, "HTTPS://Elyrn.Example:8443/", "https://elyrn.example:", "http://localhost:8080",
		"http://127.0.0.1", "http://[::1]:", "http://abcdef.onion", "http://example.com", "https://u:p@host",
		"https://host/path", "https://host?q", "https://host#f", "https://host:0", "https://host:065535",
		"https://[fe80::1%25en0]", "https://-bad-.example", "https://exa%6Dple.com", "javascript:alert(1)",
		"https://" + strings.Repeat("a", maxHostLabelChars+1) + ".example", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		origin, kind := ClassifyServerURL(raw)
		if kind == URLRefused {
			if origin != "" {
				t.Fatalf("%q was refused with an origin %q", raw, origin)
			}
			return
		}
		if again, againKind := ClassifyServerURL(origin); again != origin || againKind != kind {
			t.Fatalf("%q: origin %q (kind %d) classifies again as %q (kind %d)", raw, origin, kind, again, againKind)
		}
		u, err := url.Parse(origin)
		if err != nil || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery ||
			u.Fragment != "" || origin != strings.ToLower(origin) || strings.HasSuffix(origin, portSeparator) {
			t.Fatalf("%q gave the non-canonical origin %q", raw, origin)
		}
		host := u.Hostname()
		_, loopback := loopbackHosts[host]
		switch {
		case kind == URLHTTPS && u.Scheme == schemeHTTPS:
		case kind == URLLoopbackHTTP && u.Scheme == schemeHTTP && loopback:
		case kind == URLOnionHTTP && u.Scheme == schemeHTTP && strings.HasSuffix(host, onionSuffix):
		default:
			t.Fatalf("%q: origin %q accepted as kind %d", raw, origin, kind)
		}
	})
}

func FuzzParseIdentity(f *testing.F) {
	number, err := utils.GenerateAccountNumber()
	if err != nil {
		f.Fatalf("GenerateAccountNumber: %v", err)
	}
	for _, fields := range []map[string]string{
		{"server": fuzzTestServer, "account_number": number},
		{"server": fuzzTestServer, "account_number": number, "pending_token": fuzzValidToken},
		{"server": "HTTPS://Elyrn.Example/", "account_number": number},
		{"server": "http://localhost:8080", "account_number": number, "pending_token": "not a token"},
		{"server": "ftp://elyrn.example", "account_number": number},
		{"server": fuzzTestServer, "account_number": number[1:]},
		{"server": fuzzTestServer, "account_number": number, "confirmed": "yes"},
	} {
		raw, err := json.Marshal(fields)
		if err != nil {
			f.Fatalf("marshal: %v", err)
		}
		f.Add(raw)
		f.Add(append(raw, raw...))
	}
	f.Add([]byte("null"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		id, err := parseIdentity(raw)
		if err != nil {
			wantFailure(t, err, CodeIdentityFile)
			return
		}
		if origin, kind := ClassifyServerURL(id.Server); kind == URLRefused || origin != id.Server {
			t.Fatal("a loaded identity carries a server address that is not a canonical origin")
		}
		if !utils.ValidateAccountNumber(id.AccountNumber) || (id.PendingToken != "" && !validPendingToken(id.PendingToken)) {
			t.Fatal("a loaded identity carries a malformed secret")
		}
		saved, err := json.Marshal(id)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		again, err := parseIdentity(saved)
		if err != nil || !reflect.DeepEqual(again, id) {
			t.Fatal("a loaded identity, saved again, does not load identically")
		}
	})
}

func FuzzDecodeCounterRooms(f *testing.F) {
	for _, seed := range []string{
		`{"version":1,"rooms":{}}`,
		`{"version":1,"rooms":null}`,
		`{"version":1,"rooms":{"` + fuzzRoomID + `":{"seq":3,"mine":2,"senders":{"` + fuzzSenderKey + `":1},"expires":1767225600}}}`,
		`{"version":1,"rooms":{"` + fuzzRoomID + `":{"seq":3,"mine":2,"senders":null}}}`,
		`{"version":1,"rooms":{"` + fuzzRoomID + `":{"seq":-1,"mine":0,"senders":{}}}}`,
		`{"version":1,"rooms":{"` + strings.ToUpper(fuzzRoomID) + `":{"seq":1,"mine":0,"senders":{}}}}`,
		`{"version":1,"rooms":{"` + fuzzRoomID + `":{"seq":1,"mine":0,"senders":{"` + fuzzSenderKey[:len(fuzzSenderKey)-1] + `B":1}}}}`,
		`{"version":1,"rooms":{"` + fuzzRoomID + `":null}}`,
		`{"version":2,"rooms":{}}`,
		`{"version":1,"rooms":{},"extra":true}`,
		`{"version":1,"rooms":{}} {}`,
		`{"VERSION":1,"Rooms":{}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		rooms, err := decodeCounterRooms(raw)
		if err != nil {
			wantFailure(t, err, CodeStateFile)
			return
		}
		checkCounterBounds(t, rooms)
		state := &counterState{rooms: rooms}
		saved, err := state.encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		again, err := decodeCounterRooms(saved)
		if err != nil || !reflect.DeepEqual(again, rooms) {
			t.Fatalf("loaded records, saved again, do not load identically (%v)", err)
		}
		// What save keeps stays within the bound and holds no record the agent prunes
		now := time.Now()
		state.pruneExpired(now)
		state.evict(nil)
		checkCounterBounds(t, state.rooms)
		for _, record := range state.rooms {
			if expiredLongAgo(record.Expires, now) {
				t.Fatal("a record of a room long expired survived pruning")
			}
		}
	})
}

// checkCounterBounds asserts the bounds a loaded counter file must respect, independently of
// validRecord: rooms times senders bounded, every number a safe sequence, every key canonical.
func checkCounterBounds(t *testing.T, rooms map[uuid.UUID]*counterRecord) {
	t.Helper()
	if len(rooms) > maxStateRooms {
		t.Fatalf("%d records loaded, the bound is %d", len(rooms), maxStateRooms)
	}
	for id, record := range rooms {
		if id.Version() != 4 || id.Variant() != uuid.RFC4122 {
			t.Fatal("a record under a room id that is not a UUIDv4")
		}
		if record == nil || record.Senders == nil || len(record.Senders) > maxTrackedSenders {
			t.Fatal("a record without senders or above the senders bound")
		}
		for _, n := range []int64{record.Seq, record.Mine, record.Expires} {
			if n < 0 || n > maxSafeSeq {
				t.Fatalf("a record holds %d, outside the safe sequence range", n)
			}
		}
		for key, counter := range record.Senders {
			public, err := base64.RawURLEncoding.Strict().DecodeString(key)
			if err != nil || len(public) != identity.KeySize || senderKey(public) != key || counter < 1 || counter > maxSafeSeq {
				t.Fatal("a sender entry with a non-canonical key or a counter out of range")
			}
		}
	}
}

// FuzzServerAnswer: every status and body the server (or anything in front of it) can send.
// The invariants, for every status and every body:
//   - a 5xx is judged by its status alone: readAnswer and settleAnswer never fail on it, whatever
//     its body (any size, any bytes, any edge id), the status reaches the caller unchanged, and
//     failedAnswer is exactly CodeServerBusy (a database outage behind an nginx that kept 502 or
//     504 must read "wait and retry", never "wrong answer");
//   - no status other than 200 or 201 ever has its body decoded into out: out stays untouched,
//     so a failure's body never becomes a success value, and below 500 the only failures that
//     replace the status are the edge refusals (CodeServerRoute, a known edge id under another
//     status: CodeServerAnswer) and a failure body over maxErrorBodyBytes (CodeServerAnswer);
//   - nginx's own refusals below 500 never reach a caller as the backend's status: above all,
//     never as 404 "room gone".
func FuzzServerAnswer(f *testing.F) {
	for _, seed := range []struct {
		status int
		body   string
	}{
		{http.StatusNotFound, `{"success":false,"message":"x","code":"` + edgeNotFound + `"}`},
		{http.StatusInternalServerError, `{"code":"` + edgeNotFound + `"}`},
		{http.StatusServiceUnavailable, `{"code":"` + edgeBackendUnavailable + `"}`},
		{http.StatusBadGateway, `{"success":false,"message":"Service unavailable","code":"` + edgeBackendUnavailable + `"}`},
		{http.StatusGatewayTimeout, `{"success":true}`},
		{http.StatusServiceUnavailable, "Service unavailable\n"},
		{http.StatusBadGateway, strings.Repeat("x", maxErrorBodyBytes+1)},
		{http.StatusRequestEntityTooLarge, `{"code":"` + edgeBodyTooLarge + `"}`},
		{http.StatusMethodNotAllowed, `{"CODE":"` + edgeMethodNotAllowed + `"}`},
		{http.StatusNotFound, `{"code":"E_NOT_FOUND","message":"room gone"}`},
		{http.StatusUnauthorized, `{"success":true}`},
		{http.StatusOK, `{"success":true}`},
		{http.StatusOK, `{"success":true} {}`},
		{http.StatusCreated, `[`},
		{http.StatusTooManyRequests, ""},
		{http.StatusNotFound, strings.Repeat("x", maxErrorBodyBytes+1)},
	} {
		f.Add(seed.status, []byte(seed.body))
	}
	f.Fuzz(func(t *testing.T, rawStatus int, body []byte) {
		status := fuzzMinHTTPStatus + int(uint(rawStatus)%fuzzHTTPStatusSpan)
		ans, err := readAnswer(&http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body))})
		limit := maxResponseBytes
		if !success(status) {
			limit = maxErrorBodyBytes
		}
		switch {
		case unavailable(status):
			if err != nil || ans.status != status || len(ans.body) != 0 {
				t.Fatalf("a %d answer of %d bytes was judged by its body: %v", status, len(body), err)
			}
		case len(body) > limit:
			wantFailure(t, err, CodeServerAnswer)
			return
		case err != nil || ans.status != status || !bytes.Equal(ans.body, body):
			t.Fatalf("a bounded answer (status %d, %d bytes) was not read as served: %v", status, len(body), err)
		}
		var out struct {
			Success bool `json:"success"`
		}
		got, err := settleAnswer(ans, &out)
		if err != nil {
			wantFailure(t, err, CodeServerRoute, CodeServerAnswer)
			if got != 0 {
				t.Fatal("a refused answer still handed its status to the caller")
			}
		} else if got != status {
			t.Fatalf("status %d handed over as %d", status, got)
		}
		if status != http.StatusOK && status != http.StatusCreated && out.Success {
			t.Fatalf("the body of a %d answer was decoded as a success value", status)
		}
		if unavailable(status) {
			if err != nil {
				t.Fatalf("a %d answer failed as %s instead of reaching the caller as its status", status, CodeOf(err))
			}
			wantFailure(t, failedAnswer(ans), CodeServerBusy)
			return
		}
		var edge edgeBody
		if known, ok := edgeAnswers[edgeCode(body, &edge)]; ok && err == nil && !success(status) && (known.route || known.status != status) {
			t.Fatalf("the edge id %s under status %d was handed to the caller as a status", edge.Code, status)
		}
		if !success(status) {
			wantFailure(t, failedAnswer(ans), CodeServerRoute, CodeServerAnswer, CodeRateLimited, CodeUnexpectedStatus)
		}
	})
}

// edgeCode is the edge id a body carries, "" when it is not JSON.
func edgeCode(body []byte, edge *edgeBody) string {
	if json.Unmarshal(body, edge) != nil {
		return ""
	}
	return edge.Code
}

func FuzzEventStream(f *testing.F) {
	for _, seed := range []string{
		sseReady + "\n\n" + sseEventPrefix + sseEventMsg + "\n" + sseDataPrefix + `{"c":"` + fuzzRoomID + `"}` + "\n\n",
		sseEventPrefix + sseEventMsg + "\r\n" + sseDataPrefix + `{"c":"` + strings.ToUpper(fuzzRoomID) + `"}` + "\r\n",
		sseEventPrefix + sseEventConv + "\n" + sseDataPrefix + "{}\n",
		sseEventPrefix + sseEventMsg + "\n" + sseDataPrefix + `{"c":"` + fuzzRoomID + `"} {}` + "\n",
		sseDataPrefix + `{"c":"` + fuzzRoomID + `"}` + "\n",
		sseEventPrefix + sseEventMsg + "\n" + sseDataPrefix + strings.Repeat("x", maxSSELineBytes) + "\n",
	} {
		f.Add([]byte(seed))
	}
	room := uuid.MustParse(fuzzRoomID)
	f.Fuzz(func(t *testing.T, stream []byte) {
		st := &roomState{id: room, rosterCards: []string{fuzzSenderKey}}
		events := &eventStream{reader: bufio.NewReaderSize(bytes.NewReader(stream), maxSSELineBytes)}
		pokes := 0
		done, err := (&Agent{}).listen(events, st, func() (bool, error) {
			pokes++
			return false, nil
		})
		if done {
			t.Fatal("the stream ended a wait by itself")
		}
		if err != nil {
			wantFailure(t, err, CodeServerAnswer)
		}
		if pokes > bytes.Count(stream, []byte(sseDataPrefix)) {
			t.Fatalf("%d pokes from fewer data lines", pokes)
		}
		conv := bytes.Contains(stream, []byte(sseEventPrefix+sseEventConv))
		if st.rosterCards == nil && !conv {
			t.Fatal("the roster was dropped without a conv event")
		}
		if pokes > 0 && !conv && !bytes.Contains(stream, []byte(sseEventPrefix+sseEventMsg)) {
			t.Fatal("a data line outside a msg or conv event woke the wait")
		}
	})
}

func FuzzSolveChallenge(f *testing.F) {
	challenge := strings.Repeat("0a", pow.ChallengeBytes)
	salt := strings.Repeat("f1", pow.SaltBytes)
	for _, seed := range []struct {
		challenge, salt string
		difficulty      int
	}{
		{challenge, salt, 0}, {challenge, salt, 4}, {challenge, salt, fuzzMaxSolvedDifficulty},
		{challenge, salt, maxPoWDifficulty + 1}, {challenge, salt, -1}, {strings.ToUpper(challenge), salt, 1},
		{challenge[1:], salt, 1}, {challenge, salt + "0", 1}, {"", "", 0},
	} {
		f.Add(seed.challenge, seed.salt, seed.difficulty)
	}
	f.Fuzz(func(t *testing.T, challenge, salt string, difficulty int) {
		valid := pow.IsHexOfLen(challenge, pow.ChallengeBytes) && pow.IsHexOfLen(salt, pow.SaltBytes) && difficulty >= 0
		if valid && difficulty > fuzzMaxSolvedDifficulty && difficulty <= maxPoWDifficulty {
			return // solvable by design, only slow
		}
		ch := &models.PoWChallenge{Challenge: challenge, Salt: salt, Difficulty: difficulty}
		solution, err := solve(context.Background(), ch)
		switch {
		case !valid:
			wantFailure(t, err, CodeServerAnswer)
		case difficulty > maxPoWDifficulty:
			wantFailure(t, err, CodeProofOfWork)
		case err != nil:
			t.Fatalf("a valid challenge of difficulty %d was not solved: %v", difficulty, err)
		default:
			nonce, parseErr := strconv.ParseUint(solution.Solution, 10, 64)
			sum := sha256.Sum256([]byte(challenge + solution.Solution + salt))
			if parseErr != nil || strconv.FormatUint(nonce, 10) != solution.Solution || !pow.HasLeadingZeroBits(sum[:], difficulty) ||
				*solution != *ch.Answer(solution.Solution) {
				t.Fatalf("the solution %+v does not answer the challenge", solution)
			}
		}
	})
}

// messageTrimSamples pins the one message-text trim rule (messageTrimChars, validation.js
// MESSAGE_TRIM_CHARS): each sample at both ends and inside, and what is sent ("" = refused).
// frontend/tests/validation.fuzz.test.mjs holds the same table, row for row.
var messageTrimSamples = []struct{ text, sent string }{
	{"\u0085hi\u0085", ""}, // C1 control: not trimmed, refused
	{"a\u0085b", ""},
	{"\ufeffhi\ufeff", "hi"}, // byte order mark: trimmed
	{"a\ufeffb", "a\ufeffb"},
	{"\u00a0hi\u00a0", "hi"}, // no-break space: trimmed
	{"a\u00a0b", "a\u00a0b"},
	{"\u2028hi\u2028", "hi"}, // line separator: trimmed
	{"a\u2028b", "a\u2028b"},
	{"\u2029hi\u2029", "hi"}, // paragraph separator: trimmed
	{"a\u2029b", "a\u2029b"},
	{"\u200bhi\u200b", "\u200bhi\u200b"}, // zero-width space: content, kept
	{"a\u200bb", "a\u200bb"},
	{"\thi\t", "hi"}, // tab: trimmed, kept inside
	{"a\tb", "a\tb"},
	{"\r\nhi\r\n", "hi"}, // CR/LF: normalized to LF, trimmed, kept inside
	{"a\r\nb", "a\nb"},
	{"a\rb", "a\nb"},
	{"\nhi\r", "hi"},
	{" \t\r\n\u00a0\u2028\u2029\ufeff", ""}, // nothing but trimmed characters: empty, refused
}

func FuzzReceivedText(f *testing.F) {
	for _, sample := range messageTrimSamples {
		sent, err := ValidateMessageText(sample.text)
		if sample.sent == "" {
			if err == nil {
				f.Fatalf("ValidateMessageText(%q) sent %q, want refused", sample.text, sent)
			}
		} else if err != nil || sent != sample.sent {
			f.Fatalf("ValidateMessageText(%q) = %q, %v, want %q", sample.text, sent, err, sample.sent)
		}
		f.Add(sample.text)
	}
	for _, seed := range []string{
		"hello", "  trimmed  ", "a\r\nb\rc", "tab\tand\nnewline", "bell\a", "swap\u202eme", "\u2066iso\u2069",
		"\u0085next line", "\x7f", "\xff\xfe", "", "   ", strings.Repeat("\u00e7", MaxMessageChars),
		strings.Repeat("\u00e7", MaxMessageChars+1), "\ufeffbom", "\u200bzero width",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		shown := neutralize(text)
		if !utf8.ValidString(shown) || strings.IndexFunc(shown, forbiddenRune) >= 0 {
			t.Fatalf("neutralize(%q) = %q still holds a forbidden character", text, shown)
		}
		if utf8.RuneCountInString(shown) != utf8.RuneCountInString(text) || neutralize(shown) != shown {
			t.Fatalf("neutralize(%q) = %q is not a one-for-one, idempotent replacement", text, shown)
		}
		if utf8.ValidString(text) && strings.IndexFunc(text, forbiddenRune) < 0 && shown != text {
			t.Fatalf("neutralize changed the clean text %q", text)
		}
		sent, err := ValidateMessageText(text)
		if err != nil {
			wantFailure(t, err, CodeMessageText)
			return
		}
		n := utf8.RuneCountInString(sent)
		if n < 1 || n > MaxMessageChars || strings.ContainsRune(sent, '\r') || neutralize(sent) != sent ||
			sent != strings.Trim(crlfNormalizer.Replace(text), messageTrimChars) {
			t.Fatalf("ValidateMessageText(%q) accepted %q", text, sent)
		}
		if again, err := ValidateMessageText(sent); err != nil || again != sent {
			t.Fatalf("accepted text %q does not validate to itself (%q, %v)", sent, again, err)
		}
	})
}
