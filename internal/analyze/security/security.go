// Package security implements the security-misconfiguration rule engine
// (module M6 in docs/architecture.md). Rules inspect Terraform resources
// (declared configuration) and CloudTrail events (changes made outside
// Terraform) and map every finding to a CIS AWS Foundations Benchmark
// v3.0.0 control.
//
// Unit 4 (Week 4, v0.2.0-analyze-alpha) ships the first two rules:
//
//   - SEC-S3-PUBLIC-001    S3 bucket exposed to the public (CIS 2.1.4)
//   - SEC-IAM-ADMIN-001    IAM policy granting "*:*" (CIS 1.16)
//
// The remaining rules follow in Unit 5.
package security

import (
	"context"
	"sort"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// Input is everything a security detector may inspect.
type Input struct {
	Events    []cloudtrail.Event
	Resources []tfstate.Resource
	// Now stamps DetectedAt; zero means time.Now().
	Now time.Time
}

// Detector inspects normalized events and/or Terraform resources and
// produces security-misconfiguration findings.
type Detector interface {
	// RuleID uniquely identifies the detector, e.g. "SEC-S3-PUBLIC-001".
	RuleID() string
	// ComplianceControls lists the mapped controls, e.g. "CIS-AWS-v3.0.0-2.1.4".
	ComplianceControls() []string
	Detect(ctx context.Context, in Input) ([]models.Finding, error)
}

// Registry returns the built-in detector set in a stable order.
func Registry() []Detector {
	return []Detector{
		PublicS3Bucket{},
		IAMFullAdmin{},
	}
}

// Analyze runs every registered detector and aggregates the findings.
func Analyze(ctx context.Context, in Input) ([]models.Finding, error) {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	var findings []models.Finding
	for _, d := range Registry() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fs, err := d.Detect(ctx, in)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Resource.ResourceID < findings[j].Resource.ResourceID
	})
	return findings, nil
}

// evidence collects de-duplicated reasons per resource while preserving the
// order in which resources were first seen.
type evidence struct {
	order   []string
	reasons map[string][]string
	meta    map[string]map[string]string
}

func newEvidence() *evidence {
	return &evidence{reasons: map[string][]string{}, meta: map[string]map[string]string{}}
}

func (e *evidence) add(id, reason string) {
	if _, ok := e.reasons[id]; !ok {
		e.order = append(e.order, id)
	}
	for _, r := range e.reasons[id] {
		if r == reason {
			return
		}
	}
	e.reasons[id] = append(e.reasons[id], reason)
}

func (e *evidence) set(id, key, value string) {
	if e.meta[id] == nil {
		e.meta[id] = map[string]string{}
	}
	if e.meta[id][key] == "" {
		e.meta[id][key] = value
	}
}
