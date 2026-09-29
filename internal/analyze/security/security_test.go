package security

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

var t0 = time.Date(2026, 9, 9, 14, 41, 0, 0, time.UTC)

func res(typ, name string, attrs map[string]any) tfstate.Resource {
	return tfstate.Resource{Address: typ + "." + name, Type: typ, Name: name, Attributes: attrs}
}

func event(name string, rp map[string]any) cloudtrail.Event {
	return cloudtrail.Event{EventID: name, EventName: name, EventTime: t0, Region: "eu-west-1", UserARN: "arn:aws:iam::1:user/bob",
		Raw: map[string]any{"requestParameters": rp}}
}

func TestRegistry_EveryRuleMapsToCIS(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Registry() {
		if seen[d.RuleID()] {
			t.Fatalf("duplicate rule %s", d.RuleID())
		}
		seen[d.RuleID()] = true
		if len(d.ComplianceControls()) == 0 || !strings.HasPrefix(d.ComplianceControls()[0], "CIS-AWS-") {
			t.Fatalf("%s must map to a CIS control (FR5)", d.RuleID())
		}
	}
	if len(seen) < 2 {
		t.Fatalf("v0.2.0 ships at least 2 security rules, got %d", len(seen))
	}
}

func TestPublicS3Bucket(t *testing.T) {
	bucket := res("aws_s3_bucket", "b", map[string]any{"bucket": "b1", "region": "eu-west-1"})
	tests := []struct {
		name     string
		in       Input
		want     []string
		mentions string
	}{
		{"private bucket is clean", Input{Resources: []tfstate.Resource{bucket,
			res("aws_s3_bucket_acl", "b", map[string]any{"bucket": "b1", "acl": "private"}),
			res("aws_s3_bucket_public_access_block", "b", map[string]any{"bucket": "b1", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}),
			res("aws_s3_bucket_policy", "b", map[string]any{"bucket": "b1", "policy": `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`}),
		}}, nil, ""},
		{"public canned ACL", Input{Resources: []tfstate.Resource{bucket, res("aws_s3_bucket_acl", "b", map[string]any{"bucket": "b1", "acl": "public-read"})}}, []string{"b1"}, `acl = "public-read"`},
		{"block public access disabled", Input{Resources: []tfstate.Resource{res("aws_s3_bucket_public_access_block", "b", map[string]any{"bucket": "b1", "block_public_acls": false, "block_public_policy": true})}}, []string{"b1"}, "disables block_public_acls"},
		{"policy with Principal *", Input{Resources: []tfstate.Resource{res("aws_s3_bucket_policy", "b", map[string]any{"bucket": "b1", "policy": `{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}}`})}}, []string{"b1"}, `Principal "*"`},
		{"policy with AWS: *", Input{Resources: []tfstate.Resource{res("aws_s3_bucket_policy", "b", map[string]any{"bucket": "b1", "policy": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:*","Resource":"*"}]}`})}}, []string{"b1"}, `Principal "*"`},
		{"deny policy is clean", Input{Resources: []tfstate.Resource{res("aws_s3_bucket_policy", "b", map[string]any{"bucket": "b1", "policy": `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`})}}, nil, ""},
		{"CloudTrail canned public ACL", Input{Events: []cloudtrail.Event{event("PutBucketAcl", map[string]any{"bucketName": "b2", "x-amz-acl": []any{"public-read-write"}})}}, []string{"b2"}, "CloudTrail PutBucketAcl"},
		{"CloudTrail AllUsers grant", Input{Events: []cloudtrail.Event{event("PutBucketAcl", map[string]any{"bucketName": "b2", "AccessControlPolicy": map[string]any{"AccessControlList": map[string]any{"Grant": []any{map[string]any{"Grantee": map[string]any{"URI": allUsersURI}, "Permission": "READ"}}}}})}}, []string{"b2"}, "granted public access"},
		{"CloudTrail private ACL is clean", Input{Events: []cloudtrail.Event{event("PutBucketAcl", map[string]any{"bucketName": "b2", "x-amz-acl": []any{"private"}}), event("GetObject", nil)}}, nil, ""},
		{"CloudTrail BPA removal", Input{Events: []cloudtrail.Event{event("DeleteBucketPublicAccessBlock", map[string]any{"bucketName": "b3"})}}, []string{"b3"}, "removed Block Public Access"},
		{"evidence merged per bucket", Input{
			Resources: []tfstate.Resource{bucket, res("aws_s3_bucket_acl", "b", map[string]any{"bucket": "b1", "acl": "public-read"})},
			Events:    []cloudtrail.Event{event("PutBucketAcl", map[string]any{"bucketName": "b1", "x-amz-acl": []any{"public-read"}}), event("PutBucketAcl", map[string]any{"bucketName": "b1", "x-amz-acl": []any{"public-read"}})},
		}, []string{"b1"}, "; CloudTrail"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PublicS3Bucket{}.Detect(context.Background(), tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("want %v, got %+v", tc.want, got)
			}
			for i, f := range got {
				if f.Resource.ResourceID != tc.want[i] || f.Severity != models.SeverityCritical || f.ComplianceControls[0] != "CIS-AWS-v3.0.0-2.1.4" {
					t.Fatalf("unexpected finding %+v", f)
				}
				if !strings.Contains(f.Description, tc.mentions) {
					t.Fatalf("description %q should mention %q", f.Description, tc.mentions)
				}
				if strings.Count(f.Description, "CloudTrail PutBucketAcl") > 1 {
					t.Fatalf("duplicate evidence not collapsed: %q", f.Description)
				}
			}
		})
	}
}

func TestIAMFullAdmin(t *testing.T) {
	admin := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	tests := []struct {
		name string
		in   Input
		want []string
	}{
		{"managed policy *:*", Input{Resources: []tfstate.Resource{res("aws_iam_policy", "a", map[string]any{"arn": "arn:aws:iam::1:policy/a", "policy": admin})}}, []string{"arn:aws:iam::1:policy/a"}},
		{"inline role policy, list form, no arn", Input{Resources: []tfstate.Resource{res("aws_iam_role_policy", "r", map[string]any{"policy": `{"Statement":{"Effect":"Allow","Action":["s3:GetObject","*"],"Resource":["*"]}}`})}}, []string{"aws_iam_role_policy.r"}},
		{"scoped policy is clean", Input{Resources: []tfstate.Resource{res("aws_iam_policy", "s", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`})}}, nil},
		{"wildcard action on one resource is clean", Input{Resources: []tfstate.Resource{res("aws_iam_policy", "s", map[string]any{"policy": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}]}`})}}, nil},
		{"deny *:* is clean", Input{Resources: []tfstate.Resource{res("aws_iam_policy", "d", map[string]any{"policy": `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`})}}, nil},
		{"non-policy resource ignored", Input{Resources: []tfstate.Resource{res("aws_s3_bucket", "b", map[string]any{"policy": admin})}}, nil},
		{"malformed policy ignored", Input{Resources: []tfstate.Resource{res("aws_iam_policy", "m", map[string]any{"policy": "{"}), res("aws_iam_policy", "e", map[string]any{"policy": `{"Statement": 5}`}), res("aws_iam_policy", "n", map[string]any{})}}, nil},
		{"CloudTrail PutRolePolicy", Input{Events: []cloudtrail.Event{event("PutRolePolicy", map[string]any{"roleName": "ci", "policyDocument": admin})}}, []string{"ci"}},
		{"CloudTrail URL-encoded CreatePolicyVersion", Input{Events: []cloudtrail.Event{event("CreatePolicyVersion", map[string]any{"policyArn": "arn:aws:iam::1:policy/x", "policyDocument": url.QueryEscape(admin)})}}, []string{"arn:aws:iam::1:policy/x"}},
		{"CloudTrail scoped CreatePolicy is clean", Input{Events: []cloudtrail.Event{event("CreatePolicy", map[string]any{"policyName": "ro", "policyDocument": `{"Statement":[{"Effect":"Allow","Action":"ce:Get*","Resource":"*"}]}`}), event("ListUsers", nil)}}, nil},
		{"CloudTrail without target", Input{Events: []cloudtrail.Event{event("PutUserPolicy", map[string]any{"policyDocument": admin})}}, []string{"unknown"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IAMFullAdmin{}.Detect(context.Background(), tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("want %v, got %+v", tc.want, got)
			}
			for i, f := range got {
				if f.Resource.ResourceID != tc.want[i] || f.Kind != models.KindSecurity || f.ComplianceControls[0] != "CIS-AWS-v3.0.0-1.16" {
					t.Fatalf("unexpected finding %+v", f)
				}
			}
		})
	}
}

func TestAnalyze(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	in := Input{Now: now, Resources: []tfstate.Resource{
		res("aws_iam_policy", "a", map[string]any{"arn": "p", "policy": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}),
		res("aws_s3_bucket_acl", "b", map[string]any{"bucket": "b", "acl": "public-read"}),
	}}
	got, err := Analyze(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RuleID != "SEC-IAM-ADMIN-001" || got[1].RuleID != "SEC-S3-PUBLIC-001" || !got[0].DetectedAt.Equal(now) {
		t.Fatalf("unexpected: %+v", got)
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
