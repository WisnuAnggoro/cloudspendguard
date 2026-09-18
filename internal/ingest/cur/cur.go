// Package cur reads AWS Cost and Usage Report (CUR) 2.0 exports (Parquet or
// CSV) and normalizes each line item into a [Record] the local store can
// ingest.
//
// Scaffolded in Unit 2 (Week 2). The Parquet reader backed by Apache Arrow Go
// (https://pkg.go.dev/github.com/apache/arrow/go/v14) and the golden-file
// tests against bundled sample data land in Unit 3 (Week 3), tagged
// v0.1.0-ingest.
package cur

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubs until the Week 3 implementation lands.
var ErrNotImplemented = errors.New("cur: not implemented until Week 3 (v0.1.0-ingest)")

// Record is a normalized CUR line item, independent of the Parquet/CSV
// source format, ready for insertion into the local DuckDB store.
type Record struct {
	UsageAccountID string
	Service        string // e.g. "AmazonEC2", "AmazonS3"
	ResourceID     string
	UsageType      string
	Region         string
	Tags           map[string]string
	UnblendedCost  float64
	UsageStartDate time.Time
	UsageEndDate   time.Time
}

// Reader reads a CUR export from path and returns normalized records.
// Implementations must accept both Parquet (preferred, CUR 2.0 default) and
// CSV (legacy) inputs, per docs/architecture.md.
type Reader interface {
	Read(ctx context.Context, path string) ([]Record, error)
}

// NewReader returns the default Reader. It currently returns a stub that
// reports ErrNotImplemented; see internal/ingest/cur/cur_test.go (added in
// Week 3) for the golden-file contract it must satisfy.
func NewReader() Reader { return stubReader{} }

type stubReader struct{}

func (stubReader) Read(_ context.Context, _ string) ([]Record, error) {
	return nil, ErrNotImplemented
}
