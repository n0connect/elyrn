//go:build test
// +build test

package testutil

import "os"

// SetupTestDatabaseEnv sets up database environment variables for tests
// This should be called before StartDatabase in database tests
// Automatically detects Docker environment and uses appropriate host
func SetupTestDatabaseEnv() {
	setDatabaseDefaults(GetDatabaseHost())
}

// setDatabaseDefaults gives every database variable that is still unset the test database's
// value, with the database on host.
func setDatabaseDefaults(host string) {
	if os.Getenv("DB_HOST") == "" {
		os.Setenv("DB_HOST", host)
	}
	if os.Getenv("DB_PORT") == "" {
		os.Setenv("DB_PORT", "5432")
	}
	if os.Getenv("DB_USER") == "" {
		os.Setenv("DB_USER", "postgres")
	}
	if os.Getenv("DB_PASSWORD") == "" {
		os.Setenv("DB_PASSWORD", "postgres")
	}
	if os.Getenv("DB_NAME") == "" {
		os.Setenv("DB_NAME", "noaddx_test")
	}
	if os.Getenv("DB_SSL_MODE") == "" {
		os.Setenv("DB_SSL_MODE", "disable")
	}
}
