// Package store wraps a local DuckDB database (github.com/marcboeker/go-duckdb)
// that holds normalized CUR, CloudTrail, and Terraform data for querying by
// the analyzers in internal/analyze.
//
// Scaffolded in Unit 2 (Week 2). The DuckDB-backed implementation lands in
// Unit 3 (Week 3), tagged v0.1.0-ingest. Per docs/raid-log.md (D-03), a
// SQLite fallback via database/sql is the contingency if the DuckDB driver
// proves unstable on the target platforms.
package store

import (
	"context"
	"errors"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

// ErrNotImplemented is returned by stubs until the Week 3 implementation lands.
var ErrNotImplemented = errors.New("store: not implemented until Week 3 (v0.1.0-ingest)")

// Store persists normalized ingest records locally and answers analytical
// queries over them. All implementations must keep data on the local
// filesystem only; no network calls.
type Store interface {
	InsertCURRecords(ctx context.Context, records []cur.Record) error
	InsertCloudTrailEvents(ctx context.Context, events []cloudtrail.Event) error
	InsertTerraformResources(ctx context.Context, resources []tfstate.Resource) error
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
	Close() error
}

// Rows is a minimal row-iteration contract, mirroring database/sql.Rows so a
// future SQLite fallback (docs/raid-log.md, D-03) can satisfy it too.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
}

// Open opens (creating if absent) a local DuckDB database file at path. It
// currently returns a stub that reports ErrNotImplemented on every call.
func Open(_ context.Context, _ string) (Store, error) {
	return nil, ErrNotImplemented
}
