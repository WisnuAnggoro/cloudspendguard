package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// resourceRule is a declarative security rule over Terraform resources,
// optionally backed by CloudTrail evidence of the same misconfiguration
// being made outside Terraform.
type resourceRule struct {
	id, title string
	controls  []string
	types     []string
	// match returns a reason when r violates the control.
	match func(r tfstate.Resource, ix *index) (reason string, ok bool)
	// events maps CloudTrail event names to a function that returns the
	// affected resource ID (and ok=false if the event is benign).
	events   map[string]func(rp map[string]any) (id string, ok bool)
	severity models.Severity
	risk     float64
	blast    float64
	action   models.RemediationAction
	fix      string
}

func (rr resourceRule) RuleID() string               { return rr.id }
func (rr resourceRule) ComplianceControls() []string { return rr.controls }

// Detect implements Detector.
func (rr resourceRule) Detect(_ context.Context, in Input) ([]models.Finding, error) {
	ix := newIndex(in.Resources)
	ev := newEvidence()
	addr := map[string]string{}
	for _, r := range ix.ofType(rr.types...) {
		reason, ok := rr.match(r, ix)
		if !ok {
			continue
		}
		id := resourceID(r)
		ev.add(id, fmt.Sprintf("Terraform %s %s", r.Address, reason))
		ev.set(id, "region", r.Attr("region"))
		addr[id] = r.Address
	}
	for _, e := range in.Events {
		f, ok := rr.events[e.EventName]
		if !ok {
			continue
		}
		id, ok := f(e.RequestParameters())
		if !ok || id == "" {
			continue
		}
		ev.add(id, fmt.Sprintf("CloudTrail %s at %s by %s", e.EventName, e.EventTime.Format("2006-01-02 15:04Z"), orUnknown(e.UserARN)))
		ev.set(id, "region", e.Region)
	}
	var out []models.Finding
	for _, id := range ev.order {
		out = append(out, models.Finding{
			ID: rr.id + ":" + id, Kind: models.KindSecurity, RuleID: rr.id, Title: rr.title,
			Description: strings.Join(ev.reasons[id], "; ") + ".",
			Resource: models.ResourceRef{
				Provider: "aws", Service: serviceOf(rr.types[0]), ResourceID: id,
				Region: ev.meta[id]["region"], TerraformAddress: addr[id],
			},
			Severity: rr.severity, RiskReductionScore: rr.risk, BlastRadiusScore: rr.blast,
			ComplianceControls:   rr.controls,
			SuggestedRemediation: &models.Remediation{Summary: rr.fix, Action: rr.action},
			DetectedAt:           in.Now,
		})
	}
	return out, nil
}

func cis(n string) []string { return []string{"CIS-AWS-v3.0.0-" + n} }

// libraryRules returns the table-driven part of the rule library. Control
// numbers follow the CIS AWS Foundations Benchmark v3.0.0 as mapped in the
// AWS Security Hub CSPM documentation.
func libraryRules() []Detector {
	return []Detector{
		resourceRule{
			id: "SEC-S3-TLS-001", title: "S3 bucket accepts unencrypted (HTTP) requests", controls: cis("2.1.1"), types: []string{"aws_s3_bucket"},
			match: func(r tfstate.Resource, ix *index) (string, bool) {
				for _, p := range ix.byType["aws_s3_bucket_policy"] {
					b := p.Attr("bucket")
					if (b == r.Attr("bucket") || b == "${"+r.Address+".id}" || b == "${"+r.Address+".bucket}") && policyDeniesInsecureTransport(p.Attr("policy")) {
						return "", false
					}
				}
				return "has no bucket policy denying aws:SecureTransport = false", true
			},
			severity: models.SeverityMedium, risk: 40, blast: 15, action: models.ActionModify,
			fix: "Add a Deny statement for all principals when aws:SecureTransport is false to the bucket policy.",
		},
		resourceRule{
			id: "SEC-S3-MFA-DELETE-001", title: "S3 versioning without MFA Delete", controls: cis("2.1.2"), types: []string{"aws_s3_bucket_versioning"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				b, ok := firstBlock(r, "versioning_configuration")
				return "enables versioning without mfa_delete", ok && asString(b["status"]) == "Enabled" && asString(b["mfa_delete"]) != "Enabled"
			},
			severity: models.SeverityLow, risk: 25, blast: 30, action: models.ActionModify,
			fix: "Enable MFA Delete with the root account (it cannot be set through an IAM role) and record it in Terraform.",
		},
		resourceRule{
			id: "SEC-EBS-ENCRYPT-001", title: "EBS volume or account default is unencrypted", controls: cis("2.2.1"), types: []string{"aws_ebs_volume", "aws_ebs_encryption_by_default"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				if r.Type == "aws_ebs_encryption_by_default" {
					v, ok := r.Bool("enabled")
					return "disables EBS encryption by default", ok && !v
				}
				v, ok := r.Bool("encrypted")
				return "sets encrypted = false", ok && !v
			},
			severity: models.SeverityMedium, risk: 50, blast: 45, action: models.ActionModify,
			fix: "Enable EBS encryption by default for the region; existing volumes need a snapshot, an encrypted copy, and a swap.",
		},
		resourceRule{
			id: "SEC-RDS-ENCRYPT-001", title: "RDS instance storage is unencrypted", controls: cis("2.3.1"), types: []string{"aws_db_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, ok := r.Bool("storage_encrypted")
				return "sets storage_encrypted = false", ok && !v
			},
			severity: models.SeverityHigh, risk: 60, blast: 70, action: models.ActionInvestigate,
			fix: "Restore an encrypted copy from a snapshot and cut over; encryption cannot be enabled in place.",
		},
		resourceRule{
			id: "SEC-RDS-PUBLIC-001", title: "RDS instance is publicly accessible", controls: cis("2.3.3"), types: []string{"aws_db_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, _ := r.Bool("publicly_accessible")
				return "sets publicly_accessible = true", v
			},
			events: map[string]func(map[string]any) (string, bool){
				"ModifyDBInstance": func(rp map[string]any) (string, bool) {
					v, _ := rp["publiclyAccessible"].(bool)
					return asString(rp["dBInstanceIdentifier"]), v
				},
			},
			severity: models.SeverityCritical, risk: 85, blast: 35, action: models.ActionModify,
			fix: "Set publicly_accessible = false and reach the database through a bastion, VPN, or RDS Proxy.",
		},
		resourceRule{
			id: "SEC-EFS-ENCRYPT-001", title: "EFS file system is unencrypted", controls: cis("2.4.1"), types: []string{"aws_efs_file_system"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, ok := r.Bool("encrypted")
				return "sets encrypted = false", !ok || !v
			},
			severity: models.SeverityMedium, risk: 50, blast: 60, action: models.ActionInvestigate,
			fix: "Create an encrypted file system and migrate data with AWS DataSync; encryption cannot be enabled in place.",
		},
		resourceRule{
			id: "SEC-CT-MULTIREGION-001", title: "CloudTrail is not multi-region or logging is stopped", controls: cis("3.1"), types: []string{"aws_cloudtrail"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, _ := r.Bool("is_multi_region_trail")
				return "sets is_multi_region_trail = false", !v
			},
			events: map[string]func(map[string]any) (string, bool){
				"StopLogging": func(rp map[string]any) (string, bool) { return asString(rp["name"]), true },
				"DeleteTrail": func(rp map[string]any) (string, bool) { return asString(rp["name"]), true },
			},
			severity: models.SeverityHigh, risk: 70, blast: 10, action: models.ActionModify,
			fix: "Set is_multi_region_trail = true so activity in every region is recorded.",
		},
		resourceRule{
			id: "SEC-CT-VALIDATION-001", title: "CloudTrail log file validation is disabled", controls: cis("3.2"), types: []string{"aws_cloudtrail"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				v, _ := r.Bool("enable_log_file_validation")
				return "sets enable_log_file_validation = false", !v
			},
			severity: models.SeverityMedium, risk: 40, blast: 5, action: models.ActionModify,
			fix: "Set enable_log_file_validation = true so tampering with log files is detectable.",
		},
		resourceRule{
			id: "SEC-CT-KMS-001", title: "CloudTrail logs are not encrypted with a KMS key", controls: cis("3.5"), types: []string{"aws_cloudtrail"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "has no kms_key_id", r.Attr("kms_key_id") == ""
			},
			severity: models.SeverityMedium, risk: 35, blast: 15, action: models.ActionModify,
			fix: "Set kms_key_id to a customer-managed KMS key whose policy allows CloudTrail to encrypt.",
		},
		resourceRule{
			id: "SEC-KMS-ROTATION-001", title: "KMS key rotation is disabled", controls: cis("3.6"), types: []string{"aws_kms_key"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				spec := r.Attr("customer_master_key_spec")
				v, _ := r.Bool("enable_key_rotation")
				return "sets enable_key_rotation = false on a symmetric key", !v && (spec == "" || spec == "SYMMETRIC_DEFAULT")
			},
			events: map[string]func(map[string]any) (string, bool){
				"DisableKeyRotation": func(rp map[string]any) (string, bool) { return asString(rp["keyId"]), true },
			},
			severity: models.SeverityMedium, risk: 35, blast: 5, action: models.ActionModify,
			fix: "Set enable_key_rotation = true.",
		},
		resourceRule{
			id: "SEC-VPC-FLOWLOGS-001", title: "VPC has no flow logs", controls: cis("3.7"), types: []string{"aws_vpc"},
			match: func(r tfstate.Resource, ix *index) (string, bool) {
				return "has no aws_flow_log attached", !ix.refersTo("aws_flow_log", "vpc_id", r, "id")
			},
			events: map[string]func(map[string]any) (string, bool){
				"DeleteFlowLogs": func(rp map[string]any) (string, bool) { return firstNonEmpty(asStrings(rp["flowLogIds"])...), true },
			},
			severity: models.SeverityMedium, risk: 45, blast: 5, action: models.ActionInvestigate,
			fix: "Add an aws_flow_log for the VPC with traffic_type = \"REJECT\" (or ALL) to CloudWatch Logs or S3.",
		},
		resourceRule{
			id: "SEC-NACL-ADMIN-001", title: "Network ACL allows admin ports from the internet", controls: cis("5.1"), types: []string{"aws_network_acl"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				for _, e := range blocks(r, "ingress") {
					if asString(e["action"]) == "allow" && (asString(e["cidr_block"]) == "0.0.0.0/0" || asString(e["ipv6_cidr_block"]) == "::/0") && coversAdminPort(e) {
						return fmt.Sprintf("allows ports %v-%v from the internet", e["from_port"], e["to_port"]), true
					}
				}
				return "", false
			},
			severity: models.SeverityHigh, risk: 60, blast: 40, action: models.ActionModify,
			fix: "Deny ports 22 and 3389 from 0.0.0.0/0 and ::/0 in the network ACL.",
		},
		sgRule("SEC-SG-ADMIN-IPV4-001", "Security group allows SSH or RDP from 0.0.0.0/0", "5.2", "cidr_blocks", "0.0.0.0/0"),
		sgRule("SEC-SG-ADMIN-IPV6-001", "Security group allows SSH or RDP from ::/0", "5.3", "ipv6_cidr_blocks", "::/0"),
		resourceRule{
			id: "SEC-SG-DEFAULT-001", title: "Default security group allows traffic", controls: cis("5.4"), types: []string{"aws_default_security_group"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "has ingress or egress rules", len(blocks(r, "ingress"))+len(blocks(r, "egress")) > 0
			},
			severity: models.SeverityMedium, risk: 40, blast: 50, action: models.ActionModify,
			fix: "Remove every ingress and egress rule from the default security group and use purpose-built groups instead.",
		},
		resourceRule{
			id: "SEC-EC2-IMDSV2-001", title: "EC2 instance allows IMDSv1", controls: cis("5.6"), types: []string{"aws_instance"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				if b, ok := firstBlock(r, "metadata_options"); ok && asString(b["http_tokens"]) == "required" {
					return "", false
				}
				return "does not set metadata_options.http_tokens = \"required\"", true
			},
			severity: models.SeverityHigh, risk: 65, blast: 20, action: models.ActionModify,
			fix: "Set metadata_options { http_tokens = \"required\" } so credentials cannot be stolen through SSRF against IMDSv1.",
		},
		resourceRule{
			id: "SEC-IAM-USER-POLICY-001", title: "IAM policy attached directly to a user", controls: cis("1.15"), types: []string{"aws_iam_user_policy", "aws_iam_user_policy_attachment"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				return "grants permissions directly to user " + r.Attr("user"), true
			},
			events: map[string]func(map[string]any) (string, bool){
				"AttachUserPolicy": func(rp map[string]any) (string, bool) { return asString(rp["userName"]), true },
			},
			severity: models.SeverityLow, risk: 30, blast: 40, action: models.ActionInvestigate,
			fix: "Move the permissions to a group or role and remove the direct user attachment.",
		},
		resourceRule{
			id: "SEC-IAM-PASSWORD-001", title: "IAM password policy is weak", controls: []string{"CIS-AWS-v3.0.0-1.8", "CIS-AWS-v3.0.0-1.9"}, types: []string{"aws_iam_account_password_policy"},
			match: func(r tfstate.Resource, _ *index) (string, bool) {
				var weak []string
				if v, _ := r.Attributes["minimum_password_length"].(float64); v < 14 {
					weak = append(weak, fmt.Sprintf("minimum_password_length = %.0f (want 14 or more)", v))
				}
				if v, _ := r.Attributes["password_reuse_prevention"].(float64); v < 24 {
					weak = append(weak, fmt.Sprintf("password_reuse_prevention = %.0f (want 24)", v))
				}
				return "sets " + strings.Join(weak, " and "), len(weak) > 0
			},
			severity: models.SeverityMedium, risk: 35, blast: 10, action: models.ActionModify,
			fix: "Set minimum_password_length = 14 and password_reuse_prevention = 24.",
		},
	}
}

func sgRule(id, title, control, cidrKey, world string) resourceRule {
	return resourceRule{
		id: id, title: title, controls: cis(control), types: []string{"aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_security_group_rule"},
		match: func(r tfstate.Resource, _ *index) (string, bool) {
			var rules []map[string]any
			switch r.Type {
			case "aws_security_group":
				rules = blocks(r, "ingress")
			case "aws_security_group_rule":
				if r.Attr("type") == "ingress" {
					rules = []map[string]any{r.Attributes}
				}
			default: // aws_vpc_security_group_ingress_rule uses singular cidr_ipv4/cidr_ipv6
				single := "cidr_ipv4"
				if cidrKey == "ipv6_cidr_blocks" {
					single = "cidr_ipv6"
				}
				if asString(r.Attributes[single]) == world {
					rules = []map[string]any{{cidrKey: []any{world}, "from_port": r.Attributes["from_port"], "to_port": r.Attributes["to_port"], "protocol": r.Attributes["ip_protocol"]}}
				}
			}
			for _, rule := range rules {
				if contains(asStrings(rule[cidrKey]), world) && coversAdminPort(rule) {
					return fmt.Sprintf("allows ports %v-%v from %s", rule["from_port"], rule["to_port"], world), true
				}
			}
			return "", false
		},
		events: map[string]func(map[string]any) (string, bool){
			"AuthorizeSecurityGroupIngress": func(rp map[string]any) (string, bool) {
				b := asString(rp["groupId"])
				raw := fmt.Sprint(rp["ipPermissions"])
				return b, strings.Contains(raw, world) && (strings.Contains(raw, "fromPort:22") || strings.Contains(raw, "fromPort:3389"))
			},
		},
		severity: models.SeverityCritical, risk: 80, blast: 30, action: models.ActionModify,
		fix: "Restrict the ingress rule to a corporate CIDR or remove it and use SSM Session Manager.",
	}
}

// coversAdminPort reports whether a rule's port range includes 22 or 3389.
func coversAdminPort(rule map[string]any) bool {
	proto := strings.ToLower(fmt.Sprint(rule["protocol"]))
	from, _ := rule["from_port"].(float64)
	to, _ := rule["to_port"].(float64)
	if proto == "-1" || proto == "all" {
		return true
	}
	if proto != "tcp" && proto != "6" {
		return false
	}
	return (from <= 22 && 22 <= to) || (from <= 3389 && 3389 <= to)
}

// policyDeniesInsecureTransport looks for a Deny statement conditioned on
// aws:SecureTransport = false.
func policyDeniesInsecureTransport(doc string) bool {
	for _, st := range statements(doc) {
		if !strings.EqualFold(asString(st["Effect"]), "Deny") {
			continue
		}
		cond, _ := st["Condition"].(map[string]any)
		b, _ := cond["Bool"].(map[string]any)
		if v := fmt.Sprint(b["aws:SecureTransport"]); strings.EqualFold(v, "false") {
			return true
		}
	}
	return false
}

func blocks(r tfstate.Resource, key string) []map[string]any {
	list, _ := r.Attributes[key].([]any)
	var out []map[string]any
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func firstBlock(r tfstate.Resource, key string) (map[string]any, bool) {
	b := blocks(r, key)
	if len(b) == 0 {
		return nil, false
	}
	return b[0], true
}

func resourceID(r tfstate.Resource) string {
	for _, k := range []string{"bucket", "identifier", "id", "name", "arn"} {
		if v := r.Attr(k); v != "" && !strings.HasPrefix(v, "${") {
			return v
		}
	}
	return r.Address
}

func serviceOf(tfType string) string {
	switch {
	case strings.HasPrefix(tfType, "aws_s3_"):
		return "s3"
	case strings.HasPrefix(tfType, "aws_db_"):
		return "rds"
	case strings.HasPrefix(tfType, "aws_efs_"):
		return "efs"
	case strings.HasPrefix(tfType, "aws_cloudtrail"):
		return "cloudtrail"
	case strings.HasPrefix(tfType, "aws_kms_"):
		return "kms"
	case strings.HasPrefix(tfType, "aws_iam_"):
		return "iam"
	}
	return "ec2"
}

type index struct {
	byType map[string][]tfstate.Resource
}

func newIndex(rs []tfstate.Resource) *index {
	ix := &index{byType: map[string][]tfstate.Resource{}}
	for _, r := range rs {
		ix.byType[r.Type] = append(ix.byType[r.Type], r)
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

// refersTo reports whether a resource of typ points at target through key,
// either by literal ID (Terraform state) or by an unevaluated reference such
// as "${aws_vpc.main.id}" (HCL source, as seen by the patch verifier).
func (ix *index) refersTo(typ, key string, target tfstate.Resource, targetKeys ...string) bool {
	want := map[string]bool{}
	for _, k := range targetKeys {
		if v := target.Attr(k); v != "" {
			want[v] = true
		}
		want["${"+target.Address+"."+k+"}"] = true
	}
	for _, r := range ix.byType[typ] {
		if want[r.Attr(key)] {
			return true
		}
	}
	return false
}
