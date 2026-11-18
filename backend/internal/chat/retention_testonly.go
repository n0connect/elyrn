//go:build test
// +build test

package chat

// RetentionFinishedForTesting is the liveness reading the healthcheck compares (when the last
// retention cycle finished, as time since the process started), so a test can see which cycles
// count as finished. SECURITY: compiled only with -tags test.
func RetentionFinishedForTesting() int64 {
	return retentionBeat.Load()
}
