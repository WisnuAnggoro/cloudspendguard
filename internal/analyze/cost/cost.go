// Package cost implements cost-waste detectors (module M5 in
// docs/architecture.md). Each detector combines CUR line items (what was
// billed) with the Terraform resource inventory (what exists and how it is
// wired) and emits [models.Finding] values carrying a projected monthly saving.
//
// Unit 4 (Week 4, v0.2.0-analyze-alpha) ships the first two rules:
//
//   - COST-EBS-IDLE-001      EBS volume not attached to any instance
//   - COST-EIP-UNATTACHED-001 Elastic IP not associated with any resource
//
// The remaining rules (oversized RDS, idle NAT gateway, and so on) and the
// anomaly-detection pass follow in Unit 5.
package cost

import (
	"context"
	"sort"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// hoursPerMonth is the AWS billing convention (730 h) for monthly estimates.
const hoursPerMonth = 730.0

// Input is everything a cost detector may inspect.
type Input struct {
	CUR       []cur.Record
	Resources []tfstate.Resource
	// Now stamps DetectedAt; zero means time.Now().
	Now time.Time
}

// Detector inspects normalized cost records and resource inventory and
// produces cost-waste findings.
type Detector interface {
	// RuleID uniquely identifies the detector, e.g. "COST-EBS-IDLE-001".
	RuleID() string
	Detect(ctx context.Context, in Input) ([]models.Finding, error)
}

// Registry returns the built-in detector set in a stable order.
func Registry() []Detector {
	return []Detector{
		IdleEBSVolume{},
		UnattachedEIP{},
	}
}

// Analyze runs every registered detector and aggregates the findings,
// ordered by rule and then resource for reproducible output.
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

// observedMonthlyCost projects the billed cost for resource IDs matching any
// of ids onto a 730-hour month, using the covered usage window. It returns
// ok=false when CUR holds no line items for the resource.
func observedMonthlyCost(records []cur.Record, ids ...string) (monthly float64, ok bool) {
	want := map[string]bool{}
	for _, id := range ids {
		if id != "" {
			want[id] = true
		}
	}
	var total float64
	var first, last time.Time
	for _, r := range records {
		if !want[r.ResourceID] {
			continue
		}
		ok = true
		total += r.UnblendedCost
		if first.IsZero() || r.UsageStartDate.Before(first) {
			first = r.UsageStartDate
		}
		if r.UsageEndDate.After(last) {
			last = r.UsageEndDate
		}
	}
	if !ok {
		return 0, false
	}
	hours := last.Sub(first).Hours()
	if hours <= 0 {
		return total, true
	}
	return total / hours * hoursPerMonth, true
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }
