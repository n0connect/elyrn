//go:build test
// +build test

package testutil

import (
	"bytes"
	"io"
	"log"
	"sync"
	"testing"
)

// LockedLog is a log destination the server's goroutines write while the test reads it.
type LockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *LockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *LockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// RedirectStandardLog sends the standard logger to w until restore is called.
func RedirectStandardLog(w io.Writer) (restore func()) {
	previous := log.Writer()
	log.SetOutput(w)
	return func() { log.SetOutput(previous) }
}

// CaptureLog sends the standard logger to a LockedLog until the test ends.
func CaptureLog(t testing.TB) *LockedLog {
	t.Helper()
	captured := &LockedLog{}
	t.Cleanup(RedirectStandardLog(captured))
	return captured
}
