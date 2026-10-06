package security

import (
	"context"
	"strings"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

func ingress(port float64, key, cidr string) map[string]any {
	return map[string]any{"from_port": port, "to_port": port, "protocol": "tcp", key: []any{cidr}}
}

// ruleCase is one black-box test for one rule: an input that must trigger
// it (positive) and the minimally different input that must not (negative).
type ruleCase struct {
	rule     string
	control  string
	positive Input
	negative Input
}

func ruleCases() []ruleCase {
	tlsDeny := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	bucket := res("aws_s3_bucket", "b", map[string]any{"id": "b", "bucket": "b"})
	trail := func(multi, valid bool, kms string) tfstate.Resource {
		return res("aws_cloudtrail", "t", map[string]any{"id": "t", "name": "t", "is_multi_region_trail": multi, "enable_log_file_validation": valid, "kms_key_id": kms})
	}
	vpc := res("aws_vpc", "v", map[string]any{"id": "vpc-1"})
	return []ruleCase{
		{"SEC-S3-TLS-001", "2.1.1",
			Input{Resources: []tfstate.Resource{bucket}},
			Input{Resources: []tfstate.Resource{bucket, res("aws_s3_bucket_policy", "b", map[string]any{"bucket": "${aws_s3_bucket.b.id}", "policy": tlsDeny})}}},
		{"SEC-S3-MFA-DELETE-001", "2.1.2",
			Input{Resources: []tfstate.Resource{res("aws_s3_bucket_versioning", "b", map[string]any{"bucket": "b", "versioning_configuration": []any{map[string]any{"status": "Enabled"}}})}},
			Input{Resources: []tfstate.Resource{res("aws_s3_bucket_versioning", "b", map[string]any{"bucket": "b", "versioning_configuration": []any{map[string]any{"status": "Enabled", "mfa_delete": "Enabled"}}})}}},
		{"SEC-EBS-ENCRYPT-001", "2.2.1",
			Input{Resources: []tfstate.Resource{res("aws_ebs_encryption_by_default", "d", map[string]any{"id": "x", "enabled": false})}},
			Input{Resources: []tfstate.Resource{res("aws_ebs_volume", "v", map[string]any{"id": "vol-1", "encrypted": true})}}},
		{"SEC-RDS-ENCRYPT-001", "2.3.1",
			Input{Resources: []tfstate.Resource{res("aws_db_instance", "d", map[string]any{"identifier": "d", "storage_encrypted": false})}},
			Input{Resources: []tfstate.Resource{res("aws_db_instance", "d", map[string]any{"identifier": "d", "storage_encrypted": true})}}},
		{"SEC-RDS-PUBLIC-001", "2.3.3",
			Input{Events: []cloudtrail.Event{event("ModifyDBInstance", map[string]any{"dBInstanceIdentifier": "d", "publiclyAccessible": true})}},
			Input{Events: []cloudtrail.Event{event("ModifyDBInstance", map[string]any{"dBInstanceIdentifier": "d", "publiclyAccessible": false})}}},
		{"SEC-EFS-ENCRYPT-001", "2.4.1",
			Input{Resources: []tfstate.Resource{res("aws_efs_file_system", "f", map[string]any{"id": "fs-1"})}},
			Input{Resources: []tfstate.Resource{res("aws_efs_file_system", "f", map[string]any{"id": "fs-1", "encrypted": true})}}},
		{"SEC-CT-MULTIREGION-001", "3.1",
			Input{Resources: []tfstate.Resource{trail(true, true, "k")}, Events: []cloudtrail.Event{event("StopLogging", map[string]any{"name": "t"})}},
			Input{Resources: []tfstate.Resource{trail(true, true, "k")}}},
		{"SEC-CT-VALIDATION-001", "3.2",
			Input{Resources: []tfstate.Resource{trail(true, false, "k")}},
			Input{Resources: []tfstate.Resource{trail(true, true, "k")}}},
		{"SEC-CT-KMS-001", "3.5",
			Input{Resources: []tfstate.Resource{trail(true, true, "")}},
			Input{Resources: []tfstate.Resource{trail(true, true, "arn:aws:kms:eu-west-1:111122223333:key/1")}}},
		{"SEC-KMS-ROTATION-001", "3.6",
			Input{Events: []cloudtrail.Event{event("DisableKeyRotation", map[string]any{"keyId": "k-1"})}},
			// Rotation does not apply to asymmetric keys.
			Input{Resources: []tfstate.Resource{res("aws_kms_key", "k", map[string]any{"id": "k-1", "customer_master_key_spec": "RSA_2048"})}}},
		{"SEC-VPC-FLOWLOGS-001", "3.7",
			Input{Resources: []tfstate.Resource{vpc}},
			Input{Resources: []tfstate.Resource{vpc, res("aws_flow_log", "f", map[string]any{"vpc_id": "${aws_vpc.v.id}"})}}},
		{"SEC-NACL-ADMIN-001", "5.1",
			Input{Resources: []tfstate.Resource{res("aws_network_acl", "n", map[string]any{"id": "acl-1", "ingress": []any{map[string]any{"action": "allow", "cidr_block": "0.0.0.0/0", "protocol": "-1", "from_port": 0.0, "to_port": 0.0}}})}},
			Input{Resources: []tfstate.Resource{res("aws_network_acl", "n", map[string]any{"id": "acl-1", "ingress": []any{map[string]any{"action": "deny", "cidr_block": "0.0.0.0/0", "protocol": "-1"}}})}}},
		{"SEC-SG-ADMIN-IPV4-001", "5.2",
			Input{Resources: []tfstate.Resource{res("aws_security_group_rule", "r", map[string]any{"id": "sgr-1", "type": "ingress", "from_port": 3389.0, "to_port": 3389.0, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}})}},
			Input{Resources: []tfstate.Resource{res("aws_security_group", "s", map[string]any{"id": "sg-1", "ingress": []any{ingress(443, "cidr_blocks", "0.0.0.0/0"), ingress(22, "cidr_blocks", "10.0.0.0/8")}})}}},
		{"SEC-SG-ADMIN-IPV6-001", "5.3",
			Input{Resources: []tfstate.Resource{res("aws_vpc_security_group_ingress_rule", "r", map[string]any{"id": "sgr-2", "cidr_ipv6": "::/0", "from_port": 22.0, "to_port": 22.0, "ip_protocol": "tcp"})}},
			Input{Resources: []tfstate.Resource{res("aws_vpc_security_group_ingress_rule", "r", map[string]any{"id": "sgr-2", "cidr_ipv6": "::/0", "from_port": 443.0, "to_port": 443.0, "ip_protocol": "tcp"})}}},
		{"SEC-SG-DEFAULT-001", "5.4",
			Input{Resources: []tfstate.Resource{res("aws_default_security_group", "d", map[string]any{"id": "sg-d", "egress": []any{map[string]any{"protocol": "-1"}}})}},
			Input{Resources: []tfstate.Resource{res("aws_default_security_group", "d", map[string]any{"id": "sg-d"})}}},
		{"SEC-EC2-IMDSV2-001", "5.6",
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1"})}},
			Input{Resources: []tfstate.Resource{res("aws_instance", "i", map[string]any{"id": "i-1", "metadata_options": []any{map[string]any{"http_tokens": "required"}}})}}},
		{"SEC-IAM-USER-POLICY-001", "1.15",
			Input{Events: []cloudtrail.Event{event("AttachUserPolicy", map[string]any{"userName": "alice"})}},
			Input{Resources: []tfstate.Resource{res("aws_iam_role_policy", "p", map[string]any{"role": "r"})}}},
		{"SEC-IAM-PASSWORD-001", "1.8",
			Input{Resources: []tfstate.Resource{res("aws_iam_account_password_policy", "p", map[string]any{"minimum_password_length": 8.0, "password_reuse_prevention": 24.0})}},
			Input{Resources: []tfstate.Resource{res("aws_iam_account_password_policy", "p", map[string]any{"minimum_password_length": 14.0, "password_reuse_prevention": 24.0})}}},
	}
}

// TestLibraryRules runs every declarative rule against its positive and its
// negative input, checking the CIS control mapping and the finding fields
// the prioritizer and the remediation engine rely on.
func TestLibraryRules(t *testing.T) {
	byID := map[string]Detector{}
	for _, d := range Registry() {
		byID[d.RuleID()] = d
	}
	seen := map[string]bool{}
	for _, tc := range ruleCases() {
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
			if f.Kind != models.KindSecurity || f.RuleID != tc.rule || !strings.HasPrefix(f.ID, tc.rule+":") {
				t.Errorf("identity fields: %+v", f)
			}
			if !strings.Contains(strings.Join(f.ComplianceControls, ","), "CIS-AWS-v3.0.0-"+tc.control) {
				t.Errorf("controls %v must include CIS %s", f.ComplianceControls, tc.control)
			}
			if f.RiskReductionScore <= 0 || f.SuggestedRemediation == nil || f.SuggestedRemediation.Action == "" || f.Description == "" {
				t.Errorf("finding must carry risk, an action, and a description: %+v", f)
			}
			if neg, _ := d.Detect(context.Background(), tc.negative); len(neg) != 0 {
				t.Fatalf("negative input: want no finding, got %+v", neg)
			}
		})
	}
	// Every registered rule needs a test, here or in security_test.go.
	for id := range byID {
		if !seen[id] && id != "SEC-S3-PUBLIC-001" && id != "SEC-IAM-ADMIN-001" {
			t.Errorf("rule %s has no positive/negative test case", id)
		}
	}
	if n := len(Registry()); n != 20 {
		t.Errorf("want 20 security rules, got %d", n)
	}
}

func TestTerraformAndCloudTrailEvidenceMerge(t *testing.T) {
	in := Input{
		Resources: []tfstate.Resource{res("aws_kms_key", "k", map[string]any{"id": "k-1", "enable_key_rotation": false, "region": "eu-west-1"})},
		Events:    []cloudtrail.Event{event("DisableKeyRotation", map[string]any{"keyId": "k-1"})},
	}
	fs, err := Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	var f *models.Finding
	for i := range fs {
		if fs[i].RuleID == "SEC-KMS-ROTATION-001" {
			f = &fs[i]
		}
	}
	if f == nil || !strings.Contains(f.Description, "Terraform aws_kms_key.k") || !strings.Contains(f.Description, "CloudTrail DisableKeyRotation") {
		t.Fatalf("both evidence sources must be merged into one finding: %+v", f)
	}
	if f.Resource.TerraformAddress != "aws_kms_key.k" || f.Resource.Region != "eu-west-1" {
		t.Fatalf("resource ref: %+v", f.Resource)
	}
}

func TestCoversAdminPort(t *testing.T) {
	tests := []struct {
		rule map[string]any
		want bool
	}{
		{map[string]any{"protocol": "tcp", "from_port": 0.0, "to_port": 65535.0}, true},
		{map[string]any{"protocol": "6", "from_port": 3389.0, "to_port": 3389.0}, true},
		{map[string]any{"protocol": "all"}, true},
		{map[string]any{"protocol": "udp", "from_port": 22.0, "to_port": 22.0}, false},
		{map[string]any{"protocol": "tcp", "from_port": 23.0, "to_port": 3388.0}, false},
	}
	for _, tc := range tests {
		if got := coversAdminPort(tc.rule); got != tc.want {
			t.Errorf("coversAdminPort(%v) = %v", tc.rule, got)
		}
	}
}
