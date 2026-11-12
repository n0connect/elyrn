package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"elyrn/internal/config"
)

// LogLevel represents the severity of a log message
type LogLevel string

const (
	LogLevelINFO  LogLevel = "INFO"
	LogLevelWARN  LogLevel = "WARN"
	LogLevelERROR LogLevel = "ERROR"
	LogLevelDEBUG LogLevel = "DEBUG"
)

// Logging policy (zero identifiers): log lines describe what happened, never who or
// from where. No IPs, user UUIDs, account numbers, pseudonyms, conversation ids or
// request paths. Per-request traces exist only at DEBUG.

// levelRank orders levels; LOG_LEVEL selects the minimum rank that is emitted.
var levelRank = map[LogLevel]int{LogLevelDEBUG: 0, LogLevelINFO: 1, LogLevelWARN: 2, LogLevelERROR: 3}

// newlineEscaper keeps every entry on one line (RULES.md §12.2: log injection prevention)
var newlineEscaper = strings.NewReplacer("\r", "\\r", "\n", "\\n")

func enabled(level LogLevel) bool {
	minimum, ok := levelRank[LogLevel(strings.ToUpper(config.GetLogLevel()))]
	if !ok {
		minimum = levelRank[LogLevelINFO]
	}
	return levelRank[level] >= minimum
}

// Logger provides structured logging functionality
type Logger struct {
	prefix string
}

// NewLogger creates a new logger with a prefix
func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

// formatMessage formats a log message with timestamp, level, prefix, and message
func (l *Logger) formatMessage(level LogLevel, message string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	formattedMessage := newlineEscaper.Replace(fmt.Sprintf(message, args...))
	return fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, level, l.prefix, formattedMessage)
}

// Info logs an informational message
func (l *Logger) Info(message string, args ...interface{}) {
	if enabled(LogLevelINFO) {
		log.Println(l.formatMessage(LogLevelINFO, message, args...))
	}
}

// Warn logs a warning message, at most LogBurst per message template per LogWindow
func (l *Logger) Warn(message string, args ...interface{}) {
	l.At(LogLevelWARN, message, message, args...)
}

// Error logs an error message, at most LogBurst per message template per LogWindow
func (l *Logger) Error(message string, args ...interface{}) {
	l.At(LogLevelERROR, message, message, args...)
}

// At logs message at level under the flood bound of key (Admit): callers whose template is
// shared by many causes (apperr) pass the cause's id as key.
func (l *Logger) At(level LogLevel, key, message string, args ...interface{}) {
	if l.Admit(level, key) {
		log.Println(l.formatMessage(level, message, args...))
	}
}

// Debug logs a debug message
func (l *Logger) Debug(message string, args ...interface{}) {
	if enabled(LogLevelDEBUG) {
		log.Println(l.formatMessage(LogLevelDEBUG, message, args...))
	}
}

// LogRequest traces an incoming request (DEBUG only; the path is never recorded)
func (l *Logger) LogRequest(method string) {
	l.Debug("Request received: method=%s", method)
}

// LogResponse traces a response (DEBUG only)
func (l *Logger) LogResponse(statusCode int, message string) {
	l.Debug("Response sent: status=%d message=%s", statusCode, message)
}

// LogError logs an error with context and stack trace (RULES.md §6.3)
func (l *Logger) LogError(operation string, err error) {
	l.LogErrorFrom(1, operation, err)
}

// LogErrorFrom is LogError for helpers that log on their caller's behalf: skip counts the
// frames above LogErrorFrom's caller, so the recorded caller is the code that failed.
func (l *Logger) LogErrorFrom(skip int, operation string, err error) {
	if !l.Admit(LogLevelERROR, operation) {
		return
	}
	// Get caller info for stack trace
	_, file, line, ok := runtime.Caller(skip + 1)
	callerInfo := "unknown"
	if ok {
		callerInfo = fmt.Sprintf("%s:%d", file, line)
	}

	// Structured JSON logging (RULES.md §12.2)
	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format("2006-01-02T15:04:05.000Z07:00"),
		"level":     "ERROR",
		"module":    l.prefix,
		"operation": operation,
		"error":     err.Error(),
		"caller":    callerInfo,
	}

	if jsonBytes, err := json.Marshal(logEntry); err == nil {
		log.Println(string(jsonBytes))
	} else {
		// Fallback to text format
		log.Println(l.formatMessage(LogLevelERROR, "Operation failed: operation=%s error=%v caller=%s", operation, err, callerInfo))
	}
}

// peerAddress matches an IP address in any spelling a library may print, with or without a
// port: net/http names the peer in its own error lines ("TLS handshake error from
// 192.0.2.1:4000"). In order: a bracketed IPv6 address (a zone id included), a dotted quad,
// and a bare IPv6 address (at least two colons; a zone id runs to the next blank). None is
// anchored to a word boundary, so an address glued to other text ("x192.0.2.1", "fe80::1%eth0")
// is removed too: over-redacting a library line is harmless, leaking a peer is not.
var peerAddress = regexp.MustCompile(`\[[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*(%[^\]\s]*)?\](:\d+)?` +
	`|\d{1,3}(\.\d{1,3}){3}(:\d+)?` +
	`|[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,7}(%\S+)?`)

// peerRedacted replaces a peer address in a library's log line
const peerRedacted = "[peer]"

// stdWriter turns each line a library writes to a *log.Logger into one of this logger's
// lines, peer addresses removed (zero identifiers).
type stdWriter struct{ l *Logger }

func (w stdWriter) Write(p []byte) (int, error) {
	w.l.Error("%s", scrubPeerAddresses(strings.TrimRight(string(p), "\n")))
	return len(p), nil
}

// scrubPeerAddresses replaces every IP address in a library's log line with peerRedacted.
func scrubPeerAddresses(line string) string {
	return peerAddress.ReplaceAllString(line, peerRedacted)
}

// StdLogger returns a *log.Logger (for a library such as net/http's Server.ErrorLog) whose
// every line goes through this logger at ERROR, with peer addresses removed.
func (l *Logger) StdLogger() *log.Logger {
	return log.New(stdWriter{l: l}, "", 0)
}

// Log flood bound: lines a client can cause for free (refused requests, rate limits, malformed
// proofs of work, invalid tokens) are throttled per key, so a flood cannot write unbounded lines
// to the disk. WARN and ERROR lines are keyed by their message template (or by an explicit key,
// At), LogError by its operation; INFO and DEBUG are not throttled (DEBUG is off in production).
// At most LogBurst lines per key are written per LogWindow; the first line under a key after a
// window in which lines were dropped is preceded by one line that says how many were dropped
// (written when the key is next logged, so a flood that ends is reported by its next line).
const (
	LogBurst  = 20
	LogWindow = time.Minute
	// maxThrottleKeys bounds the table; keys are registered codes, so it is never reached
	maxThrottleKeys = 1024
)

type throttleWindow struct {
	start      time.Time
	written    int
	suppressed int
}

var (
	throttleMu sync.Mutex
	throttles  = make(map[string]*throttleWindow)
)

// admitLine counts one line under key at now: whether it may be written, and how many lines
// were dropped under key in the window that just ended (to be reported once).
func admitLine(key string, now time.Time) (ok bool, dropped int) {
	throttleMu.Lock()
	defer throttleMu.Unlock()
	w, found := throttles[key]
	if !found {
		if len(throttles) >= maxThrottleKeys {
			return false, 0
		}
		w = &throttleWindow{start: now}
		throttles[key] = w
	}
	if now.Sub(w.start) >= LogWindow || now.Before(w.start) {
		dropped = w.suppressed
		*w = throttleWindow{start: now}
	}
	if w.written >= LogBurst {
		w.suppressed++
		return false, dropped
	}
	w.written++
	return true, dropped
}

// Admit reports whether one more line at level under key may be written now (always false when
// level is not logged). When lines under key were dropped in the previous window, it first
// writes one WARN line saying how many.
func (l *Logger) Admit(level LogLevel, key string) bool {
	if !enabled(level) {
		return false
	}
	ok, dropped := admitLine(l.prefix+"/"+key, time.Now())
	if dropped > 0 && enabled(LogLevelWARN) {
		log.Println(l.formatMessage(LogLevelWARN, "%s: suppressed %d lines in the previous %s (flood bound %d per %s)",
			key, dropped, LogWindow, LogBurst, LogWindow))
	}
	return ok
}
