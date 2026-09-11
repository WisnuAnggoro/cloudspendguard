// Package cloudtrail reads AWS CloudTrail JSON event logs and normalizes
// each entry into an [Event] the local store and security analyzers can
// consume.
//
// Scaffolded in Unit 2 (Week 2). The JSON reader and golden-file tests
// against bundled sample events land in Unit 3 (Week 3), tagged
// v0.1.0-ingest.
package cloudtrail

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by stubs until the Week 3 implementation lands.
var ErrNotImplemented = errors.New("cloudtrail: not implemented until Week 3 (v0.1.0-ingest)")

// Event is a normalized CloudTrail record.
type Event struct {
	EventID    string
	EventName  string // e.g. "PutBucketAcl", "AuthorizeSecurityGroupIngress"
	EventTime  time.Time
	Region     string
	SourceIP   string
	UserARN    string
	ResourceID string
	Raw        map[string]any // full event payload, redacted before any LLM call
}

// Reader reads a CloudTrail JSON export (single file or directory of
// dated shards) and returns normalized events.
type Reader interface {
	Read(ctx context.Context, path string) ([]Event, error)
}

// NewReader returns the default Reader. It currently returns a stub that
// reports ErrNotImplemented.
func NewReader() Reader { return stubReader{} }

type stubReader struct{}

func (stubReader) Read(_ context.Context, _ string) ([]Event, error) {
	return nil, ErrNotImplemented
}
