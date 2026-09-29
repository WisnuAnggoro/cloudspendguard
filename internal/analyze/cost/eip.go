package cost

import (
	"context"
	"fmt"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// publicIPv4PerHour is the AWS charge for every public IPv4 address,
// in use or idle, effective 1 February 2024.
const publicIPv4PerHour = 0.005

// UnattachedEIP flags Elastic IPs that are allocated but not associated with
// an instance or network interface. It uses two signals:
//
//  1. aws_eip in Terraform state with no association_id, instance, or
//     network_interface.
//  2. CUR line items with usage type "*PublicIPv4:IdleAddress" (or the legacy
//     "*ElasticIP:IdleAddress"), which AWS bills only for idle addresses.
//
// Either signal is enough; both are merged per allocation ID.
type UnattachedEIP struct{}

// RuleID implements Detector.
func (UnattachedEIP) RuleID() string { return "COST-EIP-UNATTACHED-001" }

// Detect implements Detector.
func (d UnattachedEIP) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	type candidate struct {
		id, publicIP, address, region string
		tags                          map[string]string
		signals                       []string
	}
	byID := map[string]*candidate{}
	var order []string
	add := func(id string) *candidate {
		if c, ok := byID[id]; ok {
			return c
		}
		c := &candidate{id: id}
		byID[id] = c
		order = append(order, id)
		return c
	}

	for _, r := range in.Resources {
		if r.Type != "aws_eip" {
			continue
		}
		if r.Attr("association_id") != "" || r.Attr("instance") != "" || r.Attr("network_interface") != "" {
			continue
		}
		id := r.Attr("allocation_id")
		if id == "" {
			id = r.Attr("id")
		}
		if id == "" {
			continue
		}
		c := add(id)
		c.publicIP, c.address = r.Attr("public_ip"), r.Address
		c.tags = stringTags(r.Attributes["tags"])
		c.signals = append(c.signals, "no association in Terraform state")
	}

	seen := map[string]bool{}
	for _, rec := range in.CUR {
		if rec.ResourceID == "" || !isIdleIPUsage(rec.UsageType) || seen[rec.ResourceID] {
			continue
		}
		seen[rec.ResourceID] = true
		id := rec.ResourceID
		for _, c := range byID { // CUR may key by public IP rather than allocation ID
			if c.publicIP == rec.ResourceID {
				id = c.id
			}
		}
		c := add(id)
		if c.region == "" {
			c.region = rec.Region
		}
		c.signals = append(c.signals, "billed as "+rec.UsageType)
	}

	var out []models.Finding
	for _, id := range order {
		c := byID[id]
		savings, observed := observedMonthlyCost(in.CUR, c.id, c.publicIP)
		basis := fmt.Sprintf("USD %.2f/month observed in CUR", savings)
		if !observed {
			savings = publicIPv4PerHour * hoursPerMonth
			basis = fmt.Sprintf("an estimated USD %.2f/month (USD %.3f/hour)", savings, publicIPv4PerHour)
		}
		where := c.address
		if where == "" {
			where = "not managed by Terraform"
		}
		out = append(out, models.Finding{
			ID:     d.RuleID() + ":" + c.id,
			Kind:   models.KindCost,
			RuleID: d.RuleID(),
			Title:  "Unattached Elastic IP",
			Description: fmt.Sprintf("%s (%s) is allocated but idle (%s) and costs %s. Check DNS records before releasing it to avoid a dangling record.",
				c.id, where, strings.Join(c.signals, "; "), basis),
			Resource: models.ResourceRef{
				Provider: "aws", Service: "ec2", ResourceID: c.id, Region: c.region, Tags: c.tags,
			},
			Severity:          models.SeverityInfo,
			MonthlySavingsUSD: round2(savings),
			// Releasing an address that DNS still points to enables subdomain
			// takeover, hence a moderate blast radius.
			RiskReductionScore: 5,
			BlastRadiusScore:   25,
			SuggestedRemediation: &models.Remediation{
				Summary: fmt.Sprintf("aws ec2 release-address --allocation-id %s", c.id),
			},
			DetectedAt: in.Now,
		})
	}
	return out, nil
}

func isIdleIPUsage(usageType string) bool {
	return strings.HasSuffix(usageType, "PublicIPv4:IdleAddress") || strings.HasSuffix(usageType, "ElasticIP:IdleAddress")
}
