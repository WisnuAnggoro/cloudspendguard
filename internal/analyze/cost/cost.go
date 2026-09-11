// Package cost implements cost-waste detectors (idle EBS volumes, unattached
// Elastic IPs, oversized RDS instances, idle NAT gateways, and more) plus the
// anomaly-detection pass (STL decomposition, z-score, and Isolation Forest)
// described in docs/architecture.md.
//
// Scaffolded in Unit 2 (Week 2). Detectors and CI-gated rule tests land in
// Unit 4 (Week 4), alongside the first security detectors.
package cost

import (
	"context"
	"errors"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// ErrNotImplemented is returned by stubs until the Week 4 implementation lands.
var ErrNotImplemented = errors.New("cost: not implemented until Week 4 (v0.2.0-analyze-alpha)")

// Detector inspects normalized cost records and produces cost-waste findings.
type Detector interface {
	// RuleID uniquely identifies the detector, e.g. "COST-EBS-IDLE-001".
	RuleID() string
	Detect(ctx context.Context, records []cur.Record) ([]models.Finding, error)
}

// Registry returns the built-in detector set. It is empty until Week 4;
// analyzers are added here as each rule is implemented and unit-tested.
func Registry() []Detector { return nil }

// Analyze runs every registered detector against records and aggregates the
// resulting findings. It currently returns ErrNotImplemented because
// Registry() has no detectors yet.
func Analyze(ctx context.Context, records []cur.Record) ([]models.Finding, error) {
	detectors := Registry()
	if len(detectors) == 0 {
		return nil, ErrNotImplemented
	}
	var findings []models.Finding
	for _, d := range detectors {
		fs, err := d.Detect(ctx, records)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}
