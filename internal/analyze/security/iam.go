package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// IAMFullAdmin flags IAM policy documents that Allow Action "*" on Resource
// "*", from Terraform (aws_iam_policy and inline role, user, or group
// policies) or from CloudTrail calls that create or change a policy.
//
// Mapped to CIS AWS Foundations Benchmark v3.0.0 control 1.16 ("Ensure IAM
// policies that allow full '*:*' administrative privileges are not attached").
type IAMFullAdmin struct{}

// RuleID implements Detector.
func (IAMFullAdmin) RuleID() string { return "SEC-IAM-ADMIN-001" }

// ComplianceControls implements Detector.
func (IAMFullAdmin) ComplianceControls() []string { return []string{"CIS-AWS-v3.0.0-1.16"} }

var iamPolicyTypes = map[string]bool{
	"aws_iam_policy": true, "aws_iam_role_policy": true, "aws_iam_user_policy": true, "aws_iam_group_policy": true,
}

var iamPolicyEvents = map[string]bool{
	"CreatePolicy": true, "CreatePolicyVersion": true, "PutRolePolicy": true, "PutUserPolicy": true, "PutGroupPolicy": true,
}

// Detect implements Detector.
func (d IAMFullAdmin) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	ev := newEvidence()

	for _, r := range in.Resources {
		if !iamPolicyTypes[r.Type] || !grantsFullAdmin(r.Attr("policy")) {
			continue
		}
		id := r.Attr("arn")
		if id == "" {
			id = r.Address
		}
		ev.add(id, fmt.Sprintf("Terraform %s allows Action \"*\" on Resource \"*\"", r.Address))
	}

	for _, e := range in.Events {
		if !iamPolicyEvents[e.EventName] {
			continue
		}
		rp := e.RequestParameters()
		doc := asString(rp["policyDocument"])
		if decoded, err := url.QueryUnescape(doc); err == nil {
			doc = decoded // some CloudTrail producers URL-encode the document
		}
		if !grantsFullAdmin(doc) {
			continue
		}
		target := firstNonEmpty(asString(rp["policyArn"]), asString(rp["roleName"]), asString(rp["userName"]), asString(rp["groupName"]), asString(rp["policyName"]), e.ResourceID)
		ev.add(target, fmt.Sprintf("CloudTrail %s at %s by %s attached a \"*:*\" policy", e.EventName, e.EventTime.Format("2006-01-02 15:04Z"), orUnknown(e.UserARN)))
	}

	var out []models.Finding
	for _, id := range ev.order {
		out = append(out, models.Finding{
			ID:                 d.RuleID() + ":" + id,
			Kind:               models.KindSecurity,
			RuleID:             d.RuleID(),
			Title:              "IAM policy grants full administrative access (*:*)",
			Description:        strings.Join(ev.reasons[id], "; ") + ".",
			Resource:           models.ResourceRef{Provider: "aws", Service: "iam", ResourceID: id},
			Severity:           models.SeverityHigh,
			RiskReductionScore: 85,
			// Narrowing an admin policy can break automation that silently
			// depends on it, so the blast radius is higher than for S3.
			BlastRadiusScore:   60,
			ComplianceControls: d.ComplianceControls(),
			SuggestedRemediation: &models.Remediation{
				Summary: "Replace the wildcard statement with the actions the principal actually uses (IAM Access Analyzer policy generation from CloudTrail helps), and require MFA for any remaining break-glass admin role.",
			},
			DetectedAt: in.Now,
		})
	}
	return out, nil
}

// grantsFullAdmin reports whether a policy JSON document contains an Allow
// statement with Action "*" and Resource "*" (and no NotAction/NotResource).
func grantsFullAdmin(doc string) bool {
	for _, st := range statements(doc) {
		if !strings.EqualFold(asString(st["Effect"]), "Allow") {
			continue
		}
		if contains(asStrings(st["Action"]), "*") && contains(asStrings(st["Resource"]), "*") {
			return true
		}
	}
	return false
}

// statements parses an IAM or bucket policy document and returns its
// statements, accepting both a single object and an array.
func statements(doc string) []map[string]any {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &p); err != nil || len(p.Statement) == 0 {
		return nil
	}
	var many []map[string]any
	if err := json.Unmarshal(p.Statement, &many); err == nil {
		return many
	}
	var one map[string]any
	if err := json.Unmarshal(p.Statement, &one); err == nil {
		return []map[string]any{one}
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return "unknown"
}
