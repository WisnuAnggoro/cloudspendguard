// Package live collects resource inventory directly from AWS using a read-only
// IAM role, for operators who do not have CUR exports or Terraform state on
// disk. It is module M3b in docs/architecture.md and satisfies the live-mode
// half of FR9 in docs/requirements.md.
//
// Scaffolded in Unit 3 (Week 3). The AWS SDK v2 paginated Describe* and ce:Get*
// calls land alongside the ingestion milestone, tagged v0.1.0-ingest.
package live

import (
	"context"
	"errors"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

// ErrNotImplemented is returned by stubs until the live collector lands.
var ErrNotImplemented = errors.New("live: not implemented until v0.1.0-ingest")

// Options configures the live collector. RoleARN must grant read-only access;
// see docs/iam-policy.json for the least-privilege policy this module assumes.
type Options struct {
	RoleARN string
	Regions []string
}

// Collector enumerates live AWS resources into the same normalized Resource
// shape produced by the Terraform ingester (M3), so downstream analyzers cannot
// tell which ingestion path supplied their input.
type Collector interface {
	Collect(ctx context.Context, opts Options) ([]tfstate.Resource, error)
}

// NewCollector returns the default Collector. It currently returns a stub that
// reports ErrNotImplemented.
func NewCollector() Collector { return stubCollector{} }

type stubCollector struct{}

func (stubCollector) Collect(_ context.Context, _ Options) ([]tfstate.Resource, error) {
	return nil, ErrNotImplemented
}
