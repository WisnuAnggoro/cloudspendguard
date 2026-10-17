//go:build acceptance

// Acceptance test for the live mode path (v0.9.0-rc1): a LocalStack
// container plays the AWS account, and the full CLI runs against it. This
// test needs Docker and is excluded from the default build; run it with
//
//	make acceptance
//
// (go test -tags=acceptance ./cmd/csg). It exercises what the operator sees:
// csg run --live inventories S3 through the read-only API path, the
// analyzers flag the public bucket, and the report is written. What the test
// proves end to end: live collection, normalization, SEC-S3-PUBLIC-001, and
// the quiet public bucket staying quiet.
package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/testcontainers/testcontainers-go"
	ls "github.com/testcontainers/testcontainers-go/modules/localstack"
)

const localstackImage = "localstack/localstack:2026.10.0"

// acceptancePrivateBucketLifecycle is also used by the SDK wire-format
// regression test below. A rule must contain Filter or the legacy Prefix;
// an explicit empty prefix selects all objects without using the legacy field.
func acceptancePrivateBucketLifecycle() *s3types.BucketLifecycleConfiguration {
	return &s3types.BucketLifecycleConfiguration{
		Rules: []s3types.LifecycleRule{{
			ID:          aws.String("tier-down"),
			Filter:      &s3types.LifecycleRuleFilter{Prefix: aws.String("")},
			Status:      s3types.ExpirationStatusEnabled,
			Transitions: []s3types.Transition{{Days: aws.Int32(30), StorageClass: s3types.TransitionStorageClassIntelligentTiering}},
		}},
	}
}

// dockerAvailable reports whether the Docker provider is healthy, so the
// test fails with a clear message instead of skipping.
func dockerAvailable(ctx context.Context) error {
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		return err
	}
	return provider.Health(ctx)
}

// awsConfigForTest builds the SDK config the seeding client uses.
func awsConfigForTest(t *testing.T, endpoint string) aws.Config {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test", SecretAccessKey: "test"}, nil
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAcceptance_LiveModeLocalStack(t *testing.T) {
	// Unified LocalStack images require authentication. Never include the
	// token in failure messages or command-line arguments.
	token := strings.TrimSpace(os.Getenv("LOCALSTACK_AUTH_TOKEN"))
	if token == "" {
		t.Fatal("LOCALSTACK_AUTH_TOKEN is required for the pinned LocalStack image; see docs/ci-troubleshooting.md")
	}
	// The acceptance test must fail loudly when Docker is unavailable: a
	// skipped acceptance run must never look like a passing one.
	ctx := context.Background()
	if err := dockerAvailable(ctx); err != nil {
		t.Fatalf("acceptance test needs a working Docker daemon: %v", err)
	}

	lsC, err := ls.Run(ctx, localstackImage,
		testcontainers.WithEnv(map[string]string{"LOCALSTACK_AUTH_TOKEN": token}),
	)
	if err != nil {
		t.Fatalf("start LocalStack %s: %v", localstackImage, err)
	}
	t.Cleanup(func() { _ = lsC.Terminate(ctx) })

	endpoint, err := lsC.PortEndpoint(ctx, "4566", "http")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_ENDPOINT_URL", endpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-1")

	// Seed the fake account: one bucket fully open to the public, one locked
	// down. Only the open one may be flagged.
	seed := s3.NewFromConfig(awsConfigForTest(t, endpoint), func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	if _, err := seed.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("csg-acceptance-public")}); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String("csg-acceptance-public"),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(false),
			BlockPublicPolicy:     aws.Bool(false),
			IgnorePublicAcls:      aws.Bool(false),
			RestrictPublicBuckets: aws.Bool(false),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("csg-acceptance-private")}); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: aws.String("csg-acceptance-private"),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	}); err != nil {
		t.Fatal(err)
	}
	// The locked-down bucket also denies HTTP, so the TLS rule is satisfied
	// and the bucket stays completely quiet.
	tlsDeny := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::csg-acceptance-private/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	if _, err := seed.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String("csg-acceptance-private"),
		Policy: aws.String(tlsDeny),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String("csg-acceptance-private"),
		LifecycleConfiguration: acceptancePrivateBucketLifecycle(),
	}); err != nil {
		t.Fatal(err)
	}

	// Run the real CLI. The report path proves the whole pipeline ran, not
	// just the collector.
	reportPath := filepath.Join(t.TempDir(), "acceptance.md")
	var out bytes.Buffer
	if err := cmdRun(ctx, []string{"--live", "--report", reportPath}, &out); err != nil {
		t.Fatalf("csg run --live: %v\n%s", err, out.String())
	}

	stdout := out.String()
	if !strings.Contains(stdout, "SEC-S3-PUBLIC-001") {
		t.Errorf("the public bucket was not flagged:\n%s", stdout)
	}
	if !strings.Contains(stdout, "csg-acceptance-public") {
		t.Errorf("the finding does not name the public bucket:\n%s", stdout)
	}
	if strings.Contains(stdout, "csg-acceptance-private") {
		t.Errorf("the locked-down bucket must not be flagged:\n%s", stdout)
	}

	report, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "SEC-S3-PUBLIC-001") {
		t.Errorf("the report file lacks the public bucket finding")
	}
}

// TestAcceptanceLifecycleRequestSchema validates the actual SDK request body
// without a Docker daemon or LocalStack token. It catches omitted filters in
// the same fixture used to seed LocalStack, not a separate example request.
func TestAcceptanceLifecycleRequestSchema(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/csg-acceptance-private" || !r.URL.Query().Has("lifecycle") {
			t.Errorf("unexpected lifecycle request: %s %s", r.Method, r.URL)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var config struct {
			XMLName xml.Name `xml:"LifecycleConfiguration"`
			Rules   []struct {
				ID     string `xml:"ID"`
				Status string `xml:"Status"`
				Filter *struct {
					Prefix *string `xml:"Prefix"`
				} `xml:"Filter"`
				Transitions []struct {
					Days         int    `xml:"Days"`
					StorageClass string `xml:"StorageClass"`
				} `xml:"Transition"`
			} `xml:"Rule"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&config); err != nil {
			t.Errorf("decode lifecycle XML: %v", err)
			http.Error(w, "invalid XML", http.StatusBadRequest)
			return
		}
		if len(config.Rules) != 1 {
			t.Errorf("want one lifecycle rule, got %d", len(config.Rules))
			http.Error(w, "invalid rule count", http.StatusBadRequest)
			return
		}
		rule := config.Rules[0]
		if rule.ID != "tier-down" || rule.Status != "Enabled" ||
			rule.Filter == nil || rule.Filter.Prefix == nil || *rule.Filter.Prefix != "" {
			t.Errorf("expected enabled tier-down rule with an explicit empty-prefix filter: %+v", rule)
			http.Error(w, "missing or invalid lifecycle filter", http.StatusBadRequest)
			return
		}
		if len(rule.Transitions) != 1 || rule.Transitions[0].Days != 30 ||
			rule.Transitions[0].StorageClass != "INTELLIGENT_TIERING" {
			t.Errorf("unexpected lifecycle transitions: %+v", rule.Transitions)
			http.Error(w, "invalid transition", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	seed := s3.NewFromConfig(awsConfigForTest(t, srv.URL), func(o *s3.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
		o.UsePathStyle = true
	})
	_, err := seed.PutBucketLifecycleConfiguration(context.Background(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String("csg-acceptance-private"),
		LifecycleConfiguration: acceptancePrivateBucketLifecycle(),
	})
	if err != nil {
		t.Fatalf("send lifecycle fixture through SDK: %v", err)
	}
}
