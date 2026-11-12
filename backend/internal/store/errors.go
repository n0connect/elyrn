package store

import (
	"errors"

	"elyrn/internal/database"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	// ErrUnavailable wraps every error that means the database itself failed (classified once,
	// in internal/database/errors.go); it answers 503, never 500 or a misleading 401/404.
	ErrUnavailable = database.ErrUnavailable
)
