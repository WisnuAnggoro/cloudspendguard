package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// PublicS3Bucket flags buckets that are, or were made, publicly accessible:
//
//   - aws_s3_bucket_acl with a public canned ACL (public-read, public-read-write)
//   - aws_s3_bucket_public_access_block with any of the four settings false
//   - aws_s3_bucket_policy with an unconditioned Allow for Principal "*"
//   - CloudTrail PutBucketAcl with a public canned ACL or an AllUsers grant
//   - CloudTrail DeleteBucketPublicAccessBlock
//
// Mapped to CIS AWS Foundations Benchmark v3.0.0 control 2.1.4 ("Ensure that
// S3 Buckets are configured with 'Block public access (bucket settings)'").
type PublicS3Bucket struct{}

// RuleID implements Detector.
func (PublicS3Bucket) RuleID() string { return "SEC-S3-PUBLIC-001" }

// ComplianceControls implements Detector.
func (PublicS3Bucket) ComplianceControls() []string { return []string{"CIS-AWS-v3.0.0-2.1.4"} }

var publicACLs = map[string]bool{"public-read": true, "public-read-write": true}

const allUsersURI = "http://acs.amazonaws.com/groups/global/AllUsers"

// Detect implements Detector.
func (d PublicS3Bucket) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	ev := newEvidence()

	for _, r := range in.Resources {
		bucket := r.Attr("bucket")
		switch r.Type {
		case "aws_s3_bucket":
			if bucket != "" {
				ev.set(bucket, "region", r.Attr("region"))
			}
		case "aws_s3_bucket_acl":
			if publicACLs[r.Attr("acl")] {
				ev.add(bucket, fmt.Sprintf("Terraform %s sets acl = %q", r.Address, r.Attr("acl")))
			}
		case "aws_s3_bucket_public_access_block":
			var off []string
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, ok := r.Bool(k); ok && !v {
					off = append(off, k)
				}
			}
			if len(off) > 0 {
				ev.add(bucket, fmt.Sprintf("Terraform %s disables %s", r.Address, strings.Join(off, ", ")))
			}
		case "aws_s3_bucket_policy":
			if policyAllowsPublic(r.Attr("policy")) {
				ev.add(bucket, fmt.Sprintf("Terraform %s allows Principal \"*\" without a Condition", r.Address))
			}
		}
	}

	for _, e := range in.Events {
		rp := e.RequestParameters()
		bucket, _ := rp["bucketName"].(string)
		if bucket == "" {
			continue
		}
		switch e.EventName {
		case "PutBucketAcl":
			if aclEventIsPublic(rp) {
				ev.add(bucket, fmt.Sprintf("CloudTrail %s at %s by %s granted public access", e.EventName, e.EventTime.Format("2006-01-02 15:04Z"), orUnknown(e.UserARN)))
				ev.set(bucket, "region", e.Region)
			}
		case "DeleteBucketPublicAccessBlock":
			ev.add(bucket, fmt.Sprintf("CloudTrail %s at %s by %s removed Block Public Access", e.EventName, e.EventTime.Format("2006-01-02 15:04Z"), orUnknown(e.UserARN)))
			ev.set(bucket, "region", e.Region)
		}
	}

	var out []models.Finding
	for _, bucket := range ev.order {
		out = append(out, models.Finding{
			ID:          d.RuleID() + ":" + bucket,
			Kind:        models.KindSecurity,
			RuleID:      d.RuleID(),
			Title:       "S3 bucket is publicly accessible",
			Description: strings.Join(ev.reasons[bucket], "; ") + ".",
			Resource: models.ResourceRef{
				Provider: "aws", Service: "s3", ResourceID: bucket, Region: ev.meta[bucket]["region"],
			},
			Severity:           models.SeverityCritical,
			RiskReductionScore: 90,
			// Blocking public access breaks any intentionally public website or
			// download endpoint served from the bucket.
			BlastRadiusScore:   30,
			ComplianceControls: d.ComplianceControls(),
			SuggestedRemediation: &models.Remediation{
				Summary: "Set all four aws_s3_bucket_public_access_block arguments to true and remove public ACL grants; serve public content through CloudFront with origin access control.",
			},
			DetectedAt: in.Now,
		})
	}
	return out, nil
}

func aclEventIsPublic(rp map[string]any) bool {
	// Canned ACL arrives as {"x-amz-acl": ["public-read"]}.
	if v, ok := rp["x-amz-acl"].([]any); ok {
		for _, a := range v {
			if s, _ := a.(string); publicACLs[s] {
				return true
			}
		}
	}
	// Explicit grants are nested under AccessControlPolicy; a string search
	// for the AllUsers group URI is robust to CloudTrail's varying shapes.
	b, _ := json.Marshal(rp["AccessControlPolicy"])
	return strings.Contains(string(b), allUsersURI)
}

// policyAllowsPublic reports whether a bucket policy has an Allow statement
// for Principal "*" (or {"AWS": "*"}) with no Condition block.
func policyAllowsPublic(doc string) bool {
	for _, st := range statements(doc) {
		if !strings.EqualFold(asString(st["Effect"]), "Allow") {
			continue
		}
		if _, hasCond := st["Condition"]; hasCond {
			continue
		}
		switch p := st["Principal"].(type) {
		case string:
			if p == "*" {
				return true
			}
		case map[string]any:
			if contains(asStrings(p["AWS"]), "*") {
				return true
			}
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown principal"
	}
	return s
}
