package cost

import (
	"context"
	"strings"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// costCase is one black-box test for one rule: an input that must trigger
// it (positive) and the minimally different input that must not (negative).
type costCase struct {
	rule        string
	positive    Input
	negative    Input
	wantSavings float64 // expected MonthlySavingsUSD of the positive finding
	wantAction  models.RemediationAction
}

func costCases() []costCase {
	staging := map[string]any{"env": "staging"}
	prod := map[string]any{"env": "prod"}
	db := func(attrs map[string]any) tfstate.Resource {
		base := map[string]any{"id": "db-1", "identifier": "app", "instance_class": "db.t4g.small", "storage_type": "gp3"}
		for k, v := range attrs {
			base[k] = v
		}
		return res("aws_db_instance", "app", base)
	}
	bucket := res("aws_s3_bucket", "b", map[string]any{"id": "b", "bucket": "b"})
	lb := res("aws_lb", "web", map[string]any{"id": "lb-1", "arn": "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/web/1"})
	return []costCase{
		{"COST-EBS-GP2-001",
			Input{Resources: []tfstate.Resource{res("aws_ebs_volume", "v", map[string]any{"id": "vol-1", "type": "gp2", "size": 100.0})}},
			Input{Resources: []tfstate.Resource{res("aws_ebs_volume", "v", map[string]any{"id": "vol-1", "type": "gp3", "size": 100.0})}},
			2.0, models.ActionModify},
		{"COST-EC2-PREVGEN-001",
			// 30 days at USD 5.328 = USD 162.06/month observed, 10% saved.
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "m4.xlarge"})}, CUR: daily("i-1", "BoxUsage:m4.xlarge", 5.328, 30)},
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "m5.xlarge"})}},
			16.21, models.ActionModify},
		{"COST-EC2-GRAVITON-001",
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "c5.large"})}},
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "c7g.large"})}},
			0, models.ActionInvestigate},
		{"COST-EC2-STOPPED-001",
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "t3.micro", "instance_state": "stopped", "root_block_device": []any{map[string]any{"volume_size": 50.0}}})}},
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "instance_type": "t3.micro", "instance_state": "running"})}},
			4.0, models.ActionDelete},
		{"COST-RDS-NONPROD-SIZE-001",
			Input{Resources: []tfstate.Resource{db(map[string]any{"instance_class": "db.r5.2xlarge", "tags": staging})}},
			Input{Resources: []tfstate.Resource{db(map[string]any{"instance_class": "db.r5.2xlarge", "tags": prod})}},
			0, models.ActionModify},
		{"COST-RDS-NONPROD-MULTIAZ-001",
			Input{Resources: []tfstate.Resource{db(map[string]any{"multi_az": true, "tags": staging})}},
			Input{Resources: []tfstate.Resource{db(map[string]any{"multi_az": true, "tags": prod})}},
			0, models.ActionModify},
		{"COST-RDS-GP2-001",
			Input{Resources: []tfstate.Resource{db(map[string]any{"storage_type": "gp2", "allocated_storage": 100.0})}},
			Input{Resources: []tfstate.Resource{db(nil)}},
			2.3, models.ActionModify},
		{"COST-S3-NO-LIFECYCLE-001",
			Input{Resources: []tfstate.Resource{bucket}},
			Input{Resources: []tfstate.Resource{bucket, res("aws_s3_bucket_lifecycle_configuration", "b", map[string]any{"bucket": "${aws_s3_bucket.b.id}"})}},
			0, models.ActionInvestigate},
		{"COST-LOGS-RETENTION-001",
			Input{Resources: []tfstate.Resource{res("aws_cloudwatch_log_group", "l", map[string]any{"id": "/app", "retention_in_days": 0.0})}},
			Input{Resources: []tfstate.Resource{res("aws_cloudwatch_log_group", "l", map[string]any{"id": "/app", "retention_in_days": 90.0})}},
			1.5, models.ActionModify},
		{"COST-EBS-SNAPSHOT-ORPHAN-001",
			Input{Resources: []tfstate.Resource{res("aws_ebs_snapshot", "s", map[string]any{"id": "snap-1", "volume_id": "vol-gone", "volume_size": 100.0})}},
			Input{Resources: []tfstate.Resource{res("aws_ebs_snapshot", "s", map[string]any{"id": "snap-1", "volume_id": "vol-1"}), res("aws_ebs_volume", "v", map[string]any{"id": "vol-1", "type": "gp3"})}},
			5.0, models.ActionDelete},
		{"COST-ELB-IDLE-001",
			Input{Resources: []tfstate.Resource{lb}},
			Input{Resources: []tfstate.Resource{lb, res("aws_lb_listener", "https", map[string]any{"load_balancer_arn": "${aws_lb.web.arn}"})}},
			16.43, models.ActionDelete},
		{"COST-NAT-IDLE-001",
			Input{CUR: daily("nat-1", "EUW1-NatGateway-Hours", 1.08, 30)},
			Input{CUR: append(daily("nat-1", "EUW1-NatGateway-Hours", 1.08, 30), daily("nat-1", "EUW1-NatGateway-Bytes", 2.25, 30)...)},
			32.85, models.ActionDelete},
	}
}

// TestLibraryRules runs every table-driven rule against its positive and its
// negative input and checks the savings basis.
func TestLibraryRules(t *testing.T) {
	byID := map[string]Detector{}
	for _, d := range Registry() {
		byID[d.RuleID()] = d
	}
	seen := map[string]bool{}
	for _, tc := range costCases() {
		t.Run(tc.rule, func(t *testing.T) {
			d, ok := byID[tc.rule]
			if !ok {
				t.Fatalf("%s is not registered", tc.rule)
			}
			seen[tc.rule] = true
			got, err := d.Detect(context.Background(), tc.positive)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("positive input: want 1 finding, got %d: %+v", len(got), got)
			}
			f := got[0]
			if f.Kind != models.KindCost || f.RuleID != tc.rule || f.SuggestedRemediation == nil || f.Description == "" {
				t.Errorf("finding fields: %+v", f)
			}
			if f.SuggestedRemediation.Action != tc.wantAction {
				t.Errorf("action = %q, want %q", f.SuggestedRemediation.Action, tc.wantAction)
			}
			if diff := f.MonthlySavingsUSD - tc.wantSavings; diff > 0.01 || diff < -0.01 {
				t.Errorf("savings = %.2f, want %.2f (%s)", f.MonthlySavingsUSD, tc.wantSavings, f.Description)
			}
			if neg, _ := d.Detect(context.Background(), tc.negative); len(neg) != 0 {
				t.Fatalf("negative input: want no finding, got %+v", neg)
			}
		})
	}
	for id := range byID {
		if !seen[id] && id != "COST-EBS-IDLE-001" && id != "COST-EIP-UNATTACHED-001" && id != "COST-ANOMALY-001" {
			t.Errorf("rule %s has no positive/negative test case", id)
		}
	}
	if n := len(Registry()); n != 15 {
		t.Errorf("want 15 cost rules, got %d", n)
	}
}

// TestCompoundOverlaps is the regression test for the double-counting bug:
// two rules on one RDS instance each claimed 50% of the same cost.
func TestCompoundOverlaps(t *testing.T) {
	r := res("aws_db_instance", "a", map[string]any{"id": "db-1", "identifier": "a", "arn": "arn:aws:rds:eu-west-1:1:db:a",
		"instance_class": "db.r5.2xlarge", "multi_az": true, "tags": map[string]any{"env": "staging"}})
	in := Input{Resources: []tfstate.Resource{r}, CUR: daily("arn:aws:rds:eu-west-1:1:db:a", "Multi-AZUsage:db.r5.2xlarge", 23.04, 30)}
	fs, err := Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	got := map[string]float64{}
	for _, f := range fs {
		got[f.RuleID] = f.MonthlySavingsUSD
		total += f.MonthlySavingsUSD
	}
	if got["COST-RDS-NONPROD-SIZE-001"] != 350.4 || got["COST-RDS-NONPROD-MULTIAZ-001"] != 175.2 {
		t.Fatalf("want 350.40 then 175.20 (50%% of the remaining half), got %v", got)
	}
	if total >= 700.8 {
		t.Fatalf("combined savings %.2f must stay below the resource's monthly cost 700.80", total)
	}
}

func TestAnomalyAdapter(t *testing.T) {
	recs := daily("i-1", "BoxUsage:m5.large", 2.0, 30)
	spike := daily("i-gpu", "BoxUsage:p3.2xlarge", 73.44, 1)
	spike[0].UsageStartDate = recs[18].UsageStartDate
	spike[0].UsageEndDate = recs[18].UsageEndDate
	for i := range recs {
		recs[i].Tags = map[string]string{"team": "booking"}
	}
	spike[0].Tags = map[string]string{"team": "booking"}
	fs, err := anomalyDetector{}.Detect(context.Background(), Input{CUR: append(recs, spike...)})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "COST-ANOMALY-001" || !strings.Contains(fs[0].Description, "2026-09-19") {
		t.Fatalf("want one anomaly on 2026-09-19, got %+v", fs)
	}
	if fs, _ := (anomalyDetector{}).Detect(context.Background(), Input{CUR: recs}); len(fs) != 0 {
		t.Fatalf("flat spend must not be anomalous: %+v", fs)
	}
	var none []cur.Record
	if fs, _ := (anomalyDetector{}).Detect(context.Background(), Input{CUR: none}); len(fs) != 0 {
		t.Fatal("no data, no finding")
	}
}
