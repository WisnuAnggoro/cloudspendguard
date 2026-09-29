package cost

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

var day0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// daily returns n daily CUR line items of cost each for resource id.
func daily(id, usage string, cost float64, n int) []cur.Record {
	out := make([]cur.Record, n)
	for i := range out {
		s := day0.AddDate(0, 0, i)
		out[i] = cur.Record{Service: "AmazonEC2", ResourceID: id, UsageType: usage, Region: "eu-west-1", UnblendedCost: cost, UsageStartDate: s, UsageEndDate: s.Add(24 * time.Hour)}
	}
	return out
}

func res(typ, name string, attrs map[string]any) tfstate.Resource {
	return tfstate.Resource{Address: typ + "." + name, Type: typ, Name: name, Attributes: attrs}
}

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Registry() {
		if d.RuleID() == "" || seen[d.RuleID()] {
			t.Fatalf("rule IDs must be unique and non-empty: %q", d.RuleID())
		}
		seen[d.RuleID()] = true
	}
	if len(seen) < 2 {
		t.Fatalf("v0.2.0 ships at least 2 cost rules, got %d", len(seen))
	}
}

func TestIdleEBSVolume(t *testing.T) {
	attached := res("aws_ebs_volume", "data", map[string]any{"id": "vol-att", "size": 100.0, "type": "gp3"})
	attachment := res("aws_volume_attachment", "data", map[string]any{"volume_id": "vol-att"})
	idle := res("aws_ebs_volume", "scratch", map[string]any{"id": "vol-idle", "size": 500.0, "type": "gp3", "availability_zone": "eu-west-1b", "tags": map[string]any{"team": "data", "n": 1.0}})
	noID := res("aws_ebs_volume", "pending", map[string]any{"size": 10.0})

	tests := []struct {
		name        string
		in          Input
		wantIDs     []string
		wantSavings float64
		wantBasis   string
	}{
		{"attached volume is clean", Input{Resources: []tfstate.Resource{attached, attachment}}, nil, 0, ""},
		{"volume without id is skipped", Input{Resources: []tfstate.Resource{noID}}, nil, 0, ""},
		{"idle volume priced from CUR", Input{Resources: []tfstate.Resource{attached, attachment, idle}, CUR: daily("vol-idle", "EBS:VolumeUsage.gp3", 1.3333, 30)}, []string{"vol-idle"}, 40.55, "observed in CUR"},
		{"idle volume estimated without CUR", Input{Resources: []tfstate.Resource{idle}}, []string{"vol-idle"}, 40.0, "estimated"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IdleEBSVolume{}.Detect(context.Background(), tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("want %d findings, got %d: %+v", len(tc.wantIDs), len(got), got)
			}
			for i, f := range got {
				if f.Resource.ResourceID != tc.wantIDs[i] || f.Kind != models.KindCost || f.RuleID != "COST-EBS-IDLE-001" {
					t.Fatalf("unexpected finding %+v", f)
				}
				if math.Abs(f.MonthlySavingsUSD-tc.wantSavings) > 0.01 {
					t.Fatalf("savings = %.2f, want %.2f", f.MonthlySavingsUSD, tc.wantSavings)
				}
				if !strings.Contains(f.Description, tc.wantBasis) {
					t.Fatalf("description %q should mention %q", f.Description, tc.wantBasis)
				}
				if f.Resource.Region != "eu-west-1" || f.Resource.Tags["team"] != "data" || f.SuggestedRemediation == nil {
					t.Fatalf("resource metadata incomplete: %+v", f.Resource)
				}
			}
		})
	}
}

func TestUnattachedEIP(t *testing.T) {
	associated := res("aws_eip", "web", map[string]any{"id": "eipalloc-web", "allocation_id": "eipalloc-web", "association_id": "eipassoc-1", "public_ip": "203.0.113.10"})
	byInstance := res("aws_eip", "inst", map[string]any{"id": "eipalloc-inst", "instance": "i-1"})
	idle := res("aws_eip", "legacy", map[string]any{"id": "eipalloc-idle", "allocation_id": "eipalloc-idle", "association_id": "", "public_ip": "203.0.113.77", "tags": map[string]any{"team": "legacy"}})
	idleNoAlloc := res("aws_eip", "old", map[string]any{"id": "eipalloc-old"})
	blank := res("aws_eip", "blank", map[string]any{})

	tests := []struct {
		name        string
		in          Input
		wantIDs     []string
		wantSavings []float64
		wantSignals []string
	}{
		{"associated addresses are clean", Input{Resources: []tfstate.Resource{associated, byInstance, blank}, CUR: daily("eipalloc-web", "PublicIPv4:InUseAddress", 0.12, 3)}, nil, nil, nil},
		{"terraform only, estimated", Input{Resources: []tfstate.Resource{idleNoAlloc}}, []string{"eipalloc-old"}, []float64{3.65}, []string{"no association"}},
		{"terraform and CUR merged", Input{Resources: []tfstate.Resource{idle}, CUR: daily("eipalloc-idle", "EUW1-PublicIPv4:IdleAddress", 0.12, 30)}, []string{"eipalloc-idle"}, []float64{3.65}, []string{"no association", "billed as EUW1-PublicIPv4:IdleAddress"}},
		{"CUR keyed by public IP", Input{Resources: []tfstate.Resource{idle}, CUR: daily("203.0.113.77", "PublicIPv4:IdleAddress", 0.24, 10)}, []string{"eipalloc-idle"}, []float64{7.30}, []string{"billed as"}},
		{"CUR only, legacy usage type", Input{CUR: daily("eipalloc-cur", "ElasticIP:IdleAddress", 0.12, 5)}, []string{"eipalloc-cur"}, []float64{3.65}, []string{"not managed by Terraform"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UnattachedEIP{}.Detect(context.Background(), tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("want %d findings, got %d: %+v", len(tc.wantIDs), len(got), got)
			}
			for i, f := range got {
				if f.Resource.ResourceID != tc.wantIDs[i] || f.RuleID != "COST-EIP-UNATTACHED-001" {
					t.Fatalf("unexpected finding %+v", f)
				}
				if math.Abs(f.MonthlySavingsUSD-tc.wantSavings[i]) > 0.01 {
					t.Fatalf("savings = %.2f, want %.2f", f.MonthlySavingsUSD, tc.wantSavings[i])
				}
				for _, s := range tc.wantSignals {
					if !strings.Contains(f.Description, s) {
						t.Fatalf("description %q should mention %q", f.Description, s)
					}
				}
			}
		})
	}
}

func TestAnalyze_OrdersAndStamps(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	in := Input{
		Now: now,
		Resources: []tfstate.Resource{
			res("aws_eip", "b", map[string]any{"id": "eipalloc-b"}),
			res("aws_ebs_volume", "z", map[string]any{"id": "vol-z", "size": 1.0}),
			res("aws_ebs_volume", "a", map[string]any{"id": "vol-a", "size": 1.0}),
		},
	}
	got, err := Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, f := range got {
		order = append(order, f.ID)
		if !f.DetectedAt.Equal(now) {
			t.Fatalf("DetectedAt = %v", f.DetectedAt)
		}
	}
	want := "COST-EBS-IDLE-001:vol-a,COST-EBS-IDLE-001:vol-z,COST-EIP-UNATTACHED-001:eipalloc-b"
	if strings.Join(order, ",") != want {
		t.Fatalf("order = %v", order)
	}

	if got, _ := Analyze(context.Background(), Input{}); len(got) != 0 {
		t.Fatal("empty input must produce no findings")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, in); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestObservedMonthlyCost(t *testing.T) {
	if _, ok := observedMonthlyCost(nil, "x"); ok {
		t.Fatal("no records should report ok=false")
	}
	// Zero-length window: return the raw total rather than dividing by zero.
	recs := []cur.Record{{ResourceID: "x", UnblendedCost: 2, UsageStartDate: day0, UsageEndDate: day0}}
	if v, ok := observedMonthlyCost(recs, "x", ""); !ok || v != 2 {
		t.Fatalf("got %v %v", v, ok)
	}
	if availabilityZoneRegion("") != "" || availabilityZoneRegion("eu-west-1") != "eu-west-1" {
		t.Fatal("availabilityZoneRegion edge cases")
	}
}
