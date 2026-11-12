package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"runtime"
	"strings"
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

// Warn logs a warning message
func (l *Logger) Warn(message string, args ...interface{}) {
	if enabled(LogLevelWARN) {
		log.Println(l.formatMessage(LogLevelWARN, message, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(message string, args ...interface{}) {
	if enabled(LogLevelERROR) {
		log.Println(l.formatMessage(LogLevelERROR, message, args...))
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
	if !enabled(LogLevelERROR) {
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
		l.Error("Operation failed: operation=%s error=%v caller=%s", operation, err, callerInfo)
	}
}

// peerAddress matches an IPv4 or bracketed IPv6 address, with or without a port: net/http
// names the peer in its own error lines ("TLS handshake error from 192.0.2.1:4000")
var peerAddress = regexp.MustCompile(`\[[0-9A-Fa-f:.%]+\](:\d+)?|\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b`)

// peerRedacted replaces a peer address in a library's log line
const peerRedacted = "[peer]"

// stdWriter turns each line a library writes to a *log.Logger into one of this logger's
// lines, peer addresses removed (zero identifiers).
type stdWriter struct{ l *Logger }

func (w stdWriter) Write(p []byte) (int, error) {
	w.l.Error("%s", peerAddress.ReplaceAllString(strings.TrimRight(string(p), "\n"), peerRedacted))
	return len(p), nil
}

// StdLogger returns a *log.Logger (for a library such as net/http's Server.ErrorLog) whose
// every line goes through this logger at ERROR, with peer addresses removed.
func (l *Logger) StdLogger() *log.Logger {
	return log.New(stdWriter{l: l}, "", 0)
}
