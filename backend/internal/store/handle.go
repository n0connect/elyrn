package store

import (
	"context"

	"elyrn/internal/database"

	"gorm.io/gorm"
)

// handle is which database handle a repository uses: database.DB, whose deadlines follow the
// HTTP write timeout, for request paths, or database.BackgroundDB, under the full deadlines, for
// the server's background work (the startup key check, re-wrapping, retention). It is resolved
// at each call: repositories are built before database.Connect sets both.
//
// A request-path repository bound to a request (WithContext) runs every statement under that
// request's context, so under its one deadline (database.RequestBudget, set by the request
// deadline middleware); unbound, each statement and transaction gets the handle's own defaults.
type handle struct {
	background bool
	ctx        context.Context // nil: not bound to a request
}

func (h handle) db() *gorm.DB {
	base := database.DB
	if h.background {
		base = database.BackgroundDB
	}
	if h.ctx != nil {
		return base.WithContext(h.ctx)
	}
	return base
}

// bound is h bound to ctx (a request's context, carrying its deadline).
func (h handle) bound(ctx context.Context) handle {
	h.ctx = ctx
	return h
}

var (
	requestHandle    = handle{}
	backgroundHandle = handle{background: true}
)
