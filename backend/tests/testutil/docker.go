//go:build test
// +build test

package testutil

import (
	"os"
	"strings"
)

// IsRunningInDocker checks if tests are running inside a Docker container
// This is useful for determining the correct database host
func IsRunningInDocker() bool {
	// Check for Docker-specific environment variables or files
	// Method 1: Check for .dockerenv file (most reliable)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Method 2: Check for Docker-specific cgroup
	// This is a fallback method
	if cgroup, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if strings.Contains(string(cgroup), "docker") {
			return true
		}
	}

	return false
}

// GetDatabaseHost returns the appropriate database host based on environment
// - If running in Docker: returns "postgres" (Docker service name)
// - If running locally: returns "localhost"
func GetDatabaseHost() string {
	if IsRunningInDocker() {
		return "postgres"
	}
	return "localhost"
}
