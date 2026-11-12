package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"elyrn/internal/agent"
	"elyrn/internal/utils"
)

// The agent's files on a real disk, through the real agent: the identity lock, the identity
// file's formats, the counter file's policy and the TLS failure code. Nothing here contacts an
// elyrn server: New touches no network, and the TLS test's server is the broken party itself.

const testServer = "https://elyrn.example"

// identityAt writes an identity file the way a released agent did (server and AccountNumber
// only), plus extra fields, in a private directory; it returns the file's path.
func identityAt(t *testing.T, extra map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "elyrn")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	number, err := utils.GenerateAccountNumber()
	if err != nil {
		t.Fatalf("GenerateAccountNumber: %v", err)
	}
	fields := map[string]string{"server": testServer, "account_number": number}
	for k, v := range extra {
		fields[k] = v
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
	return path
}

func open(t *testing.T, path string, readOnly bool) (*agent.Agent, error) {
	t.Helper()
	a, err := agent.New(agent.Config{IdentityPath: path, ReadOnly: readOnly})
	if err == nil {
		t.Cleanup(a.Close)
	}
	return a, err
}

func wantCode(t *testing.T, err error, want agent.Code, what string) {
	t.Helper()
	if agent.CodeOf(err) != want {
		t.Fatalf("%s: %v, want %s", what, err, want)
	}
}

func counterFile(identity string) string {
	return filepath.Join(filepath.Dir(identity), "agent.counters.json")
}

// A second agent on the same identity is refused at once; whoami (read-only) still works
// beside it, and the identity is free again once the first agent closes.
func TestIdentityLock_OneAgentPerIdentity(t *testing.T) {
	path := identityAt(t, nil)
	first, err := open(t, path, false)
	if err != nil {
		t.Fatalf("first agent: %v", err)
	}
	_, err = open(t, path, false)
	wantCode(t, err, agent.CodeIdentityInUse, "a second agent on the same identity")

	reader, err := open(t, path, true)
	if err != nil {
		t.Fatalf("read-only agent beside the first: %v", err)
	}
	if who, err := reader.Whoami(); err != nil || who.Server != testServer {
		t.Fatalf("Whoami beside a running agent = %+v, %v", who, err)
	}
	_, err = reader.Identity(context.Background())
	wantCode(t, err, agent.CodeInternal, "a network call on a read-only agent")

	first.Close()
	first.Close() // idempotent
	_, err = first.Whoami()
	wantCode(t, err, agent.CodeStopped, "a call after Close")
	if _, err := open(t, path, false); err != nil {
		t.Fatalf("the identity stayed locked after Close: %v", err)
	}
}

// The lock is taken before any identity exists, so two first runs cannot both register.
func TestIdentityLock_HeldBeforeTheIdentityExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh", "agent.json")
	first, err := agent.New(agent.Config{Server: testServer, IdentityPath: path})
	if err != nil {
		t.Fatalf("first agent: %v", err)
	}
	t.Cleanup(first.Close)
	_, err = agent.New(agent.Config{Server: testServer, IdentityPath: path})
	wantCode(t, err, agent.CodeIdentityInUse, "a second first run")
}

// A file written by an earlier release (no pending token) is a confirmed identity; a pending
// token must be well formed; an unknown field is refused.
func TestIdentityFile_FormatsThatLoad(t *testing.T) {
	if _, err := open(t, identityAt(t, nil), false); err != nil {
		t.Fatalf("a released identity file: %v", err)
	}
	if _, err := open(t, identityAt(t, map[string]string{"pending_token": "a.b-c_d"}), false); err != nil {
		t.Fatalf("an unconfirmed identity file: %v", err)
	}
	_, err := open(t, identityAt(t, map[string]string{"pending_token": "not a token"}), false)
	wantCode(t, err, agent.CodeIdentityFile, "a malformed pending token")
	_, err = open(t, identityAt(t, map[string]string{"confirmed": "yes"}), false)
	wantCode(t, err, agent.CodeIdentityFile, "an unknown field")
}

// A missing counter file is rebuilt (the agent starts); a present but malformed one, or one of
// another version, fails closed; one open to other users is refused like the identity.
func TestCounterFile_Policy(t *testing.T) {
	path := identityAt(t, nil)
	a, err := open(t, path, false)
	if err != nil {
		t.Fatalf("without a counter file: %v", err)
	}
	a.Close()

	for name, content := range map[string]string{
		"not JSON":         "{",
		"another version":  `{"version":2,"rooms":{}}`,
		"a bad room id":    `{"version":1,"rooms":{"room":{"seq":1,"mine":1,"senders":{}}}}`,
		"a negative seq":   `{"version":1,"rooms":{"6f9619ff-8b86-4d11-b42d-00c04fc964ff":{"seq":-1,"mine":0,"senders":{}}}}`,
		"a bad sender key": `{"version":1,"rooms":{"6f9619ff-8b86-4d11-b42d-00c04fc964ff":{"seq":1,"mine":0,"senders":{"x":1}}}}`,
		"an unknown field": `{"version":1,"rooms":{},"extra":true}`,
		"trailing content": `{"version":1,"rooms":{}} {}`,
	} {
		if err := os.WriteFile(counterFile(path), []byte(content), 0o600); err != nil {
			t.Fatalf("write counter file: %v", err)
		}
		_, err := open(t, path, false)
		wantCode(t, err, agent.CodeStateFile, "a counter file with "+name)
	}

	valid := `{"version":1,"rooms":{"6f9619ff-8b86-4d11-b42d-00c04fc964ff":{"seq":3,"mine":2,"senders":{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA":1}}}}`
	if err := os.WriteFile(counterFile(path), []byte(valid), 0o600); err != nil {
		t.Fatalf("write counter file: %v", err)
	}
	b, err := open(t, path, false)
	if err != nil {
		t.Fatalf("a valid counter file: %v", err)
	}
	b.Close()

	if runtime.GOOS == "windows" {
		return // modes say nothing about access on Windows (permissions_windows.go)
	}
	if err := os.Chmod(counterFile(path), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	_, err = open(t, path, false)
	wantCode(t, err, agent.CodeIdentityPermissions, "a counter file open to other users")
}

// rebuiltWarnings runs fn with the agent's log captured and counts its E_AGENT_STATE_REBUILT
// lines.
func rebuiltWarnings(t *testing.T, fn func()) int {
	t.Helper()
	t.Setenv("LOG_LEVEL", "warn")
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(previous)
	fn()
	return strings.Count(buf.String(), string(agent.CodeStateRebuilt))
}

// startAndClose starts a writable agent on path and closes it.
func startAndClose(t *testing.T, path string) {
	t.Helper()
	a, err := open(t, path, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a.Close()
}

// The counter file is expected beside every identity, so its absence is reported only when it
// really went missing, and once: an identity written by a release without the file logs
// E_AGENT_STATE_REBUILT at its first start, which writes the file (private, valid, empty); the
// next start logs nothing. A file lost later is reported once more and written again.
func TestCounterFile_MissingIsReportedOnceAndWritten(t *testing.T) {
	path := identityAt(t, nil)
	for round := range 2 {
		if got := rebuiltWarnings(t, func() { startAndClose(t, path) }); got != 1 {
			t.Fatalf("round %d: a missing counter file was reported %d times, want once", round, got)
		}
		info, err := os.Stat(counterFile(path))
		if err != nil {
			t.Fatalf("round %d: the start did not write the counter file: %v", round, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("round %d: the counter file has mode %v, want 0600", round, info.Mode().Perm())
		}
		if got := rebuiltWarnings(t, func() { startAndClose(t, path) }); got != 0 {
			t.Fatalf("round %d: a healthy start logged E_AGENT_STATE_REBUILT %d times", round, got)
		}
		if err := os.Remove(counterFile(path)); err != nil {
			t.Fatalf("remove the counter file: %v", err)
		}
	}
}

// A temporary file an interrupted write left behind (it may hold the AccountNumber) is removed
// by the next agent that takes the identity.
func TestTemporaryFiles_SweptAtStart(t *testing.T) {
	path := identityAt(t, nil)
	leftover := filepath.Join(filepath.Dir(path), ".agent-123.json")
	if err := os.WriteFile(leftover, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write leftover: %v", err)
	}
	if _, err := open(t, path, false); err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("the leftover temporary file is still there: %v", err)
	}
}

// A server whose certificate is not trusted fails with the TLS code, not as unreachable.
func TestTLS_UntrustedCertificateHasItsOwnCode(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	path := filepath.Join(t.TempDir(), "tls", "agent.json")
	a, err := agent.New(agent.Config{Server: srv.URL, IdentityPath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	_, err = a.Identity(context.Background())
	wantCode(t, err, agent.CodeTLS, "an untrusted certificate")
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("an identity was written although the server was never reached: %v", statErr)
	}
}
