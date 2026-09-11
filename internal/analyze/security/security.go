// Package security implements the security-misconfiguration rule engine that
// inspects CloudTrail events and Terraform resources, mapping findings to
// CIS AWS Foundations Benchmark, PCI-DSS, and GDPR controls per
// docs/architecture.md.
//
// Scaffolded in Unit 2 (Week 2). Detectors and the CIS/PCI/GDPR control-map
// land in Unit 4 (Week 4), alongside the first cost detectors.
package security

import (
	"context"
	"errors"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// ErrNotImplemented is returned by stubs until the Week 4 implementation lands.
var ErrNotImplemented = errors.New("security: not implemented until Week 4 (v0.2.0-analyze-alpha)")

// Detector inspects normalized events and/or Terraform resources and
// produces security-misconfiguration findings.
type Detector interface {
	// RuleID uniquely identifies the detector, e.g. "SEC-S3-PUBLIC-001".
	RuleID() string
	// ComplianceControls lists the mapped controls, e.g. "CIS-AWS-2.1.5".
	ComplianceControls() []string
	Detect(ctx context.Context, events []cloudtrail.Event, resources []tfstate.Resource) ([]models.Finding, error)
}

// Registry returns the built-in detector set. It is empty until Week 4.
func Registry() []Detector { return nil }

// Analyze runs every registered detector and aggregates the resulting
// findings. It currently returns ErrNotImplemented because Registry() has no
// detectors yet.
func Analyze(ctx context.Context, events []cloudtrail.Event, resources []tfstate.Resource) ([]models.Finding, error) {
	detectors := Registry()
	if len(detectors) == 0 {
		return nil, ErrNotImplemented
	}
	var findings []models.Finding
	for _, d := range detectors {
		fs, err := d.Detect(ctx, events, resources)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}
