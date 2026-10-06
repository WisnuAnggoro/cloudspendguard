// Package cost implements cost-waste detectors (module M5 in
// docs/architecture.md). Each detector combines CUR line items (what was
// billed) with the Terraform resource inventory (what exists and how it is
// wired) and emits [models.Finding] values carrying a projected monthly saving.
//
// Unit 4 (v0.2.0-analyze-alpha) shipped the first two rules, idle EBS and
// unattached EIP. Unit 5 (v0.3.0-algo) completes the library to 15 rules
// (FR4): the multi-signal anomaly detector in internal/analyze/anomaly, a
// CUR-only idle NAT gateway rule, and eleven declarative rules in rules.go.
package cost

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/anomaly"
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
	ds := []Detector{
		IdleEBSVolume{},
		UnattachedEIP{},
		IdleNATGateway{},
		anomalyDetector{},
	}
	return append(ds, libraryRules()...)
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
	findings = compoundOverlaps(findings, in)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Resource.ResourceID < findings[j].Resource.ResourceID
	})
	return findings, nil
}

// compoundOverlaps stops two rules from claiming the same dollars. When
// several findings target one resource whose monthly cost C is known from
// CUR, they are applied largest first and each later saving is taken from
// what remains: s_i' = s_i * prod_{j<i} (1 - s_j / C). Without this, the
// Multi-AZ and right-sizing rules each claimed 50% of one RDS instance and
// the backlog promised 100% savings on a database that keeps running.
func compoundOverlaps(fs []models.Finding, in Input) []models.Finding {
	byRes := map[string][]int{}
	for i, f := range fs {
		if f.MonthlySavingsUSD > 0 && f.Resource.TerraformAddress != "" {
			byRes[f.Resource.TerraformAddress] = append(byRes[f.Resource.TerraformAddress], i)
		}
	}
	for addr, idx := range byRes {
		if len(idx) < 2 {
			continue
		}
		var ids []string
		for _, r := range in.Resources {
			if r.Address == addr {
				ids = []string{r.Attr("id"), r.Attr("arn"), r.Attr("identifier")}
			}
		}
		monthly, ok := observedMonthlyCost(in.CUR, ids...)
		if !ok || monthly <= 0 {
			continue
		}
		sort.SliceStable(idx, func(a, b int) bool { return fs[idx[a]].MonthlySavingsUSD > fs[idx[b]].MonthlySavingsUSD })
		remaining := 1.0
		for k, i := range idx {
			share := fs[i].MonthlySavingsUSD / monthly
			if k > 0 {
				alone := fs[i].MonthlySavingsUSD
				fs[i].MonthlySavingsUSD = round2(alone * remaining)
				d := fs[i].Description
				if cut := strings.Index(d, " Fixing it saves"); cut >= 0 {
					d = d[:cut]
				}
				fs[i].Description = fmt.Sprintf("%s Fixing it saves USD %.2f/month after %s is applied to the same resource (USD %.2f on its own).",
					d, fs[i].MonthlySavingsUSD, fs[idx[0]].RuleID, alone)
			}
			remaining *= 1 - min(share, 1)
		}
	}
	return fs
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

// anomalyDetector adapts the STL + Isolation Forest pass to Detector.
type anomalyDetector struct{}

func (anomalyDetector) RuleID() string { return anomaly.RuleID }

func (anomalyDetector) Detect(ctx context.Context, in Input) ([]models.Finding, error) {
	return anomaly.Detector{}.Detect(ctx, in.CUR, in.Now)
}
