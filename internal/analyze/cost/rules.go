package cost

import (
	"context"
	"fmt"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// List prices (us-east-1 / eu-west-1, on-demand, USD) used only when CUR has
// no line items for a resource. Every finding that relies on them says the
// figure is an estimate.
const (
	gp2PricePerGBMonth      = 0.10
	snapshotPricePerGBMonth = 0.05
	albPerHour              = 0.0225
)

// resourceRule is a declarative cost rule over Terraform resources. Most of
// the Unit 5 rule library is expressed this way, so adding a rule means
// adding one table entry plus one positive and one negative test case.
type resourceRule struct {
	id, title string
	types     []string
	// match returns a human-readable reason when r is wasteful.
	match func(r tfstate.Resource, ix *index) (reason string, ok bool)
	// fraction of the observed monthly cost that the fix saves (0 to 1).
	fraction float64
	// estimate is the monthly saving when CUR has no line items.
	estimate func(r tfstate.Resource) float64
	severity models.Severity
	risk     float64
	blast    float64
	action   models.RemediationAction
	fix      func(r tfstate.Resource) string
}

// RuleID implements Detector.
func (rr resourceRule) RuleID() string { return rr.id }

// Detect implements Detector.
func (rr resourceRule) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	ix := newIndex(in.Resources)
	var out []models.Finding
	for _, r := range ix.ofType(rr.types...) {
		reason, ok := rr.match(r, ix)
		if !ok {
			continue
		}
		id := firstNonEmpty(r.Attr("identifier"), r.Attr("id"), r.Attr("arn"), r.Address)
		savings, observed := observedMonthlyCost(in.CUR, r.Attr("id"), r.Attr("arn"), r.Attr("identifier"))
		basis := ""
		if observed {
			savings *= rr.fraction
			basis = fmt.Sprintf("USD %.2f/month (%.0f%% of the cost observed in CUR)", savings, rr.fraction*100)
		} else {
			savings = 0
			if rr.estimate != nil {
				savings = rr.estimate(r)
			}
			basis = fmt.Sprintf("an estimated USD %.2f/month at list price", savings)
		}
		out = append(out, models.Finding{
			ID:          rr.id + ":" + id,
			Kind:        models.KindCost,
			RuleID:      rr.id,
			Title:       rr.title,
			Description: fmt.Sprintf("%s (%s): %s. Fixing it saves %s.", id, r.Address, reason, basis),
			Resource: models.ResourceRef{
				Provider: "aws", Service: serviceOf(r.Type), ResourceID: id,
				Region: regionOf(r), Tags: stringTags(r.Attributes["tags"]), TerraformAddress: r.Address,
			},
			Severity:             rr.severity,
			MonthlySavingsUSD:    round2(savings),
			RiskReductionScore:   rr.risk,
			BlastRadiusScore:     rr.blast,
			SuggestedRemediation: &models.Remediation{Summary: rr.fix(r), Action: rr.action},
			DetectedAt:           in.Now,
		})
	}
	return out, nil
}

// libraryRules returns the table-driven part of the rule library.
func libraryRules() []Detector {
	return []Detector{
		resourceRule{
			id: "COST-EBS-GP2-001", title: "EBS volume on gp2 instead of gp3", types: []string{"aws_ebs_volume"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "volume type gp2 costs about 20% more than gp3 for the same baseline performance", r.Attr("type") == "gp2"
			},
			fraction: 0.2,
			estimate: func(r tfstate.Resource) float64 { return num(r, "size") * (gp2PricePerGBMonth - gp3PricePerGBMonth) },
			severity: models.SeverityLow, risk: 0, blast: 10, action: models.ActionModify,
			fix: func(r tfstate.Resource) string {
				return "Set type = \"gp3\" on " + r.Address + " (online migration, no detach needed)"
			},
		},
		resourceRule{
			id: "COST-EC2-PREVGEN-001", title: "EC2 instance uses a previous-generation type", types: []string{"aws_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				t := r.Attr("instance_type")
				fam, _, _ := strings.Cut(t, ".")
				return fmt.Sprintf("instance type %s is previous generation; %s is cheaper and faster", t, currentGen[fam]+"."+sizeOf(t)), currentGen[fam] != ""
			},
			fraction: 0.1, severity: models.SeverityLow, risk: 5, blast: 40, action: models.ActionModify,
			fix: func(r tfstate.Resource) string {
				t := r.Attr("instance_type")
				fam, _, _ := strings.Cut(t, ".")
				return fmt.Sprintf("Change instance_type to %s.%s in a maintenance window (requires stop/start)", currentGen[fam], sizeOf(t))
			},
		},
		resourceRule{
			id: "COST-EC2-GRAVITON-001", title: "EC2 instance could run on Graviton (arm64)", types: []string{"aws_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				t := r.Attr("instance_type")
				fam, _, _ := strings.Cut(t, ".")
				return fmt.Sprintf("%s has an arm64 Graviton equivalent (%s.%s) at roughly 20%% lower price", t, graviton[fam], sizeOf(t)), graviton[fam] != ""
			},
			fraction: 0.2, severity: models.SeverityInfo, risk: 0, blast: 60, action: models.ActionInvestigate,
			fix: func(r tfstate.Resource) string {
				return "Rebuild the AMI for arm64 and test the workload before switching " + r.Address + " to Graviton"
			},
		},
		resourceRule{
			id: "COST-EC2-STOPPED-001", title: "Stopped EC2 instance still pays for EBS", types: []string{"aws_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "instance has been left in the stopped state, so its EBS volumes keep billing", r.Attr("instance_state") == "stopped"
			},
			fraction: 1,
			estimate: func(r tfstate.Resource) float64 {
				size := 8.0
				if b, ok := firstBlock(r, "root_block_device"); ok {
					if v, ok := b["volume_size"].(float64); ok {
						size = v
					}
				}
				return size * gp3PricePerGBMonth
			},
			severity: models.SeverityLow, risk: 10, blast: 30, action: models.ActionDelete,
			fix: func(r tfstate.Resource) string {
				return "Create an AMI as a backup, then terminate " + r.Address + " or schedule it with Instance Scheduler"
			},
		},
		resourceRule{
			id: "COST-RDS-NONPROD-SIZE-001", title: "Large RDS instance class in a non-production environment", types: []string{"aws_db_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				class, env := r.Attr("instance_class"), envOf(r)
				return fmt.Sprintf("class %s is oversized for env=%s", class, env), env != "prod" && env != "" && isLargeClass(class)
			},
			fraction: 0.5, severity: models.SeverityMedium, risk: 0, blast: 35, action: models.ActionModify,
			fix: func(r tfstate.Resource) string {
				return "Downsize instance_class on " + r.Address + " one or two sizes (for example db.t4g.medium) and watch CPU and memory for a week"
			},
		},
		resourceRule{
			id: "COST-RDS-NONPROD-MULTIAZ-001", title: "Multi-AZ RDS in a non-production environment", types: []string{"aws_db_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, _ := r.Bool("multi_az")
				env := envOf(r)
				return "multi_az doubles instance cost and is rarely needed outside production (env=" + env + ")", v && env != "prod" && env != ""
			},
			fraction: 0.5, severity: models.SeverityLow, risk: 0, blast: 20, action: models.ActionModify,
			fix: func(r tfstate.Resource) string { return "Set multi_az = false on " + r.Address },
		},
		resourceRule{
			id: "COST-RDS-GP2-001", title: "RDS storage on gp2 instead of gp3", types: []string{"aws_db_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "storage_type gp2 is about 20% more expensive than gp3", r.Attr("storage_type") == "gp2"
			},
			fraction: 0.05,
			estimate: func(r tfstate.Resource) float64 { return num(r, "allocated_storage") * 0.023 },
			severity: models.SeverityInfo, risk: 0, blast: 15, action: models.ActionModify,
			fix: func(r tfstate.Resource) string { return "Set storage_type = \"gp3\" on " + r.Address },
		},
		resourceRule{
			id: "COST-S3-NO-LIFECYCLE-001", title: "S3 bucket has no lifecycle policy", types: []string{"aws_s3_bucket"},
			match: func(r tfstate.Resource, ix *index) (string, bool) {
				if ix.refersTo("aws_s3_bucket_lifecycle_configuration", "bucket", refs(r, "bucket", "id")...) {
					return "", false
				}
				if _, ok := firstBlock(r, "lifecycle_rule"); ok {
					return "", false
				}
				return "no lifecycle configuration, so objects never move to cheaper storage classes or expire", true
			},
			fraction: 0.3, severity: models.SeverityInfo, risk: 5, blast: 25, action: models.ActionInvestigate,
			fix: func(r tfstate.Resource) string {
				return "Add aws_s3_bucket_lifecycle_configuration for " + r.Address + " (Intelligent-Tiering after 30 days, expire noncurrent versions)"
			},
		},
		resourceRule{
			id: "COST-LOGS-RETENTION-001", title: "CloudWatch log group never expires", types: []string{"aws_cloudwatch_log_group"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "retention_in_days is 0 (never expire), so storage grows without bound", num(r, "retention_in_days") == 0
			},
			fraction: 0.5, estimate: func(tfstate.Resource) float64 { return 1.5 },
			severity: models.SeverityInfo, risk: 0, blast: 10, action: models.ActionModify,
			fix: func(r tfstate.Resource) string { return "Set retention_in_days (for example 90) on " + r.Address },
		},
		resourceRule{
			id: "COST-EBS-SNAPSHOT-ORPHAN-001", title: "EBS snapshot of a volume that no longer exists", types: []string{"aws_ebs_snapshot"},
			match: func(r tfstate.Resource, ix *index) (string, bool) {
				vol := r.Attr("volume_id")
				return "source volume " + vol + " is not in the inventory any more", vol != "" && !ix.hasID(vol)
			},
			fraction: 1,
			estimate: func(r tfstate.Resource) float64 { return num(r, "volume_size") * snapshotPricePerGBMonth },
			severity: models.SeverityLow, risk: 5, blast: 20, action: models.ActionDelete,
			fix: func(r tfstate.Resource) string {
				return "Confirm no AMI or restore plan depends on it, then delete " + r.Address
			},
		},
		resourceRule{
			id: "COST-ELB-IDLE-001", title: "Load balancer with no listeners or targets", types: []string{"aws_lb", "aws_alb"},
			match: func(r tfstate.Resource, ix *index) (string, bool) {
				ids := refs(r, "arn", "id")
				if ix.refersTo("aws_lb_listener", "load_balancer_arn", ids...) || ix.refersTo("aws_alb_listener", "load_balancer_arn", ids...) {
					return "", false
				}
				return "no listener references the load balancer, so it serves no traffic", true
			},
			fraction: 1, estimate: func(tfstate.Resource) float64 { return albPerHour * hoursPerMonth },
			severity: models.SeverityLow, risk: 10, blast: 20, action: models.ActionDelete,
			fix: func(r tfstate.Resource) string { return "Check DNS aliases, then remove " + r.Address },
		},
	}
}

// IdleNATGateway flags NAT gateways that bill hours but process almost no
// data. It reads CUR only: Terraform cannot tell whether traffic flows.
type IdleNATGateway struct{}

// RuleID implements Detector.
func (IdleNATGateway) RuleID() string { return "COST-NAT-IDLE-001" }

// idleNATBytesPerMonthGB is the processed-data threshold below which a NAT
// gateway is considered idle. A busy one processes many GB per day.
const idleNATBytesPerMonthGB = 1.0

// Detect implements Detector.
func (d IdleNATGateway) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	type agg struct {
		hours, bytes bool
		bytesCost    float64
		region       string
	}
	byID := map[string]*agg{}
	var order []string
	for _, r := range in.CUR {
		if !strings.HasPrefix(r.ResourceID, "nat-") {
			continue
		}
		a, ok := byID[r.ResourceID]
		if !ok {
			a = &agg{region: r.Region}
			byID[r.ResourceID] = a
			order = append(order, r.ResourceID)
		}
		switch {
		case strings.HasSuffix(r.UsageType, "NatGateway-Hours"):
			a.hours = true
		case strings.HasSuffix(r.UsageType, "NatGateway-Bytes"):
			a.bytes = true
			a.bytesCost += r.UnblendedCost
		}
	}
	ix := newIndex(in.Resources)
	var out []models.Finding
	for _, id := range order {
		a := byID[id]
		// USD 0.045 per GB processed; under ~1 GB in the window is idle.
		if !a.hours || a.bytesCost > idleNATBytesPerMonthGB*0.045 {
			continue
		}
		savings, _ := observedMonthlyCost(in.CUR, id)
		addr := ""
		if r, ok := ix.byID[id]; ok {
			addr = r.Address
		}
		out = append(out, models.Finding{
			ID: d.RuleID() + ":" + id, Kind: models.KindCost, RuleID: d.RuleID(),
			Title:       "Idle NAT gateway",
			Description: fmt.Sprintf("%s bills NAT gateway hours but processed almost no data (USD %.2f data charge in the window). Removing it saves USD %.2f/month observed in CUR.", id, a.bytesCost, savings),
			Resource:    models.ResourceRef{Provider: "aws", Service: "ec2", ResourceID: id, Region: a.region, TerraformAddress: addr},
			Severity:    models.SeverityMedium, MonthlySavingsUSD: round2(savings),
			RiskReductionScore: 5, BlastRadiusScore: 50,
			SuggestedRemediation: &models.Remediation{
				Summary: "Confirm no private subnet route needs outbound internet (check VPC Flow Logs), then delete the NAT gateway or replace it with VPC endpoints",
				Action:  models.ActionDelete,
			},
			DetectedAt: in.Now,
		})
	}
	return out, nil
}

var currentGen = map[string]string{
	"t2": "t3", "m3": "m5", "m4": "m5", "c3": "c5", "c4": "c5", "r3": "r5", "r4": "r5", "i2": "i3", "d2": "d3",
}

var graviton = map[string]string{
	"t3": "t4g", "m5": "m7g", "m6i": "m7g", "c5": "c7g", "c6i": "c7g", "r5": "r7g", "r6i": "r7g",
}

func sizeOf(instanceType string) string {
	_, size, _ := strings.Cut(instanceType, ".")
	return size
}

func isLargeClass(class string) bool {
	parts := strings.Split(class, ".")
	if len(parts) != 3 {
		return false
	}
	size := parts[2]
	return strings.HasSuffix(size, "xlarge") && size != "xlarge" || size == "xlarge" && !strings.HasPrefix(parts[1], "t")
}

func envOf(r tfstate.Resource) string {
	return strings.ToLower(stringTags(r.Attributes["tags"])["env"])
}

func num(r tfstate.Resource, key string) float64 {
	v, _ := r.Attributes[key].(float64)
	return v
}

func firstBlock(r tfstate.Resource, key string) (map[string]any, bool) {
	list, ok := r.Attributes[key].([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	m, ok := list[0].(map[string]any)
	return m, ok
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func serviceOf(tfType string) string {
	switch {
	case strings.HasPrefix(tfType, "aws_db_"):
		return "rds"
	case strings.HasPrefix(tfType, "aws_s3_"):
		return "s3"
	case strings.HasPrefix(tfType, "aws_cloudwatch_"):
		return "logs"
	case strings.HasPrefix(tfType, "aws_lb"), strings.HasPrefix(tfType, "aws_alb"):
		return "elasticloadbalancing"
	}
	return "ec2"
}

func regionOf(r tfstate.Resource) string {
	if v := r.Attr("region"); v != "" {
		return v
	}
	return availabilityZoneRegion(r.Attr("availability_zone"))
}

// index gives detectors cheap lookups across the resource inventory.
type index struct {
	all    []tfstate.Resource
	byType map[string][]tfstate.Resource
	byID   map[string]tfstate.Resource
}

func newIndex(rs []tfstate.Resource) *index {
	ix := &index{all: rs, byType: map[string][]tfstate.Resource{}, byID: map[string]tfstate.Resource{}}
	for _, r := range rs {
		ix.byType[r.Type] = append(ix.byType[r.Type], r)
		if id := r.Attr("id"); id != "" {
			ix.byID[id] = r
		}
	}
	return ix
}

func (ix *index) ofType(types ...string) []tfstate.Resource {
	var out []tfstate.Resource
	for _, t := range types {
		out = append(out, ix.byType[t]...)
	}
	return out
}

func (ix *index) hasID(id string) bool { _, ok := ix.byID[id]; return ok }

// refersTo reports whether any resource of typ has attribute key equal to
// one of the non-empty values.
func (ix *index) refersTo(typ, key string, values ...string) bool {
	for _, r := range ix.byType[typ] {
		for _, v := range values {
			if v != "" && r.Attr(key) == v {
				return true
			}
		}
	}
	return false
}

// refs returns the literal identifiers of target plus the unevaluated HCL
// reference forms ("${aws_lb.web.arn}") the patch verifier sees.
func refs(target tfstate.Resource, keys ...string) []string {
	var out []string
	for _, k := range keys {
		out = append(out, target.Attr(k), "${"+target.Address+"."+k+"}")
	}
	return out
}
