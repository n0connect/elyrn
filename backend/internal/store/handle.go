package store

import (
	"elyrn/internal/database"

	"gorm.io/gorm"
)

// handle is which database handle a repository uses: database.DB, whose deadlines follow the
// HTTP write timeout, for request paths, or database.BackgroundDB, under the full deadlines, for
// the server's background work (the startup key check, re-wrapping, retention). It is resolved
// at each call: repositories are built before database.Connect sets both.
type handle struct {
	background bool
}

func (h handle) db() *gorm.DB {
	if h.background {
		return database.BackgroundDB
	}
	return database.DB
}

var (
	requestHandle    = handle{}
	backgroundHandle = handle{background: true}
)
