package cost

import (
	"context"
	"fmt"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// gp3PricePerGBMonth is the us-east-1 list price for gp3 storage, used only
// when CUR has no line items for the volume. Other types fall back to it too;
// the finding description says the figure is an estimate.
const gp3PricePerGBMonth = 0.08

// IdleEBSVolume flags aws_ebs_volume resources that no aws_volume_attachment
// references. An unattached volume keeps billing for provisioned storage while
// doing no work, and often holds stale data nobody is monitoring.
type IdleEBSVolume struct{}

// RuleID implements Detector.
func (IdleEBSVolume) RuleID() string { return "COST-EBS-IDLE-001" }

// Detect implements Detector.
func (d IdleEBSVolume) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	attached := map[string]bool{}
	for _, r := range in.Resources {
		if r.Type == "aws_volume_attachment" {
			attached[r.Attr("volume_id")] = true
		}
	}
	var out []models.Finding
	for _, r := range in.Resources {
		if r.Type != "aws_ebs_volume" {
			continue
		}
		id := r.Attr("id")
		if id == "" || attached[id] {
			continue
		}
		savings, observed := observedMonthlyCost(in.CUR, id)
		if !observed {
			size, _ := r.Attributes["size"].(float64)
			savings = size * gp3PricePerGBMonth
		}
		basis := fmt.Sprintf("USD %.2f/month observed in CUR", savings)
		if !observed {
			size, _ := r.Attributes["size"].(float64)
			basis = fmt.Sprintf("an estimated USD %.2f/month (%.0f GiB at USD %.2f/GiB-month)", savings, size, gp3PricePerGBMonth)
		}
		out = append(out, models.Finding{
			ID:     d.RuleID() + ":" + id,
			Kind:   models.KindCost,
			RuleID: d.RuleID(),
			Title:  "Unattached EBS volume",
			Description: fmt.Sprintf("%s (%s, %s) has no aws_volume_attachment and costs %s. Snapshot it if the data is needed, then delete the volume.",
				id, r.Attr("type"), r.Address, basis),
			Resource: models.ResourceRef{
				Provider: "aws", Service: "ec2", ResourceID: id,
				Region: availabilityZoneRegion(r.Attr("availability_zone")),
				Tags:   stringTags(r.Attributes["tags"]),
			},
			Severity:          models.SeverityLow,
			MonthlySavingsUSD: round2(savings),
			// Orphaned volumes often hold unmonitored data, so removal has a
			// small security benefit. Blast radius is low once a snapshot exists.
			RiskReductionScore: 10,
			BlastRadiusScore:   20,
			SuggestedRemediation: &models.Remediation{
				Summary: fmt.Sprintf("aws ec2 create-snapshot --volume-id %s, then remove %s from Terraform", id, r.Address),
			},
			DetectedAt: in.Now,
		})
	}
	return out, nil
}

// availabilityZoneRegion turns "eu-west-1a" into "eu-west-1".
func availabilityZoneRegion(az string) string {
	if n := len(az); n > 0 && az[n-1] >= 'a' && az[n-1] <= 'z' {
		return az[:n-1]
	}
	return az
}

func stringTags(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}
