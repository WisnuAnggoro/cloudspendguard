package main

// Docker-free system test for live mode (v0.9.0-rc1): the CLI runs against a
// fake S3 API served over HTTP, so the whole pipeline (live collection,
// analysis, prioritization, reporting) is verified without Docker. The
// LocalStack acceptance test (build tag `acceptance`) covers the same path
// against a real emulator.
import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_LiveModeStandalone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(fakeS3Handler))
	t.Cleanup(srv.Close)

	t.Setenv("AWS_ENDPOINT_URL", srv.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-1")

	reportPath := filepath.Join(t.TempDir(), "live.md")
	var out bytes.Buffer
	if err := cmdRun(context.Background(), []string{"--live", "--report", reportPath, "--quiet"}, &out); err != nil {
		t.Fatalf("csg run --live: %v\n%s", err, out.String())
	}

	rep, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(rep)
	if !strings.Contains(got, "SEC-S3-PUBLIC-001") {
		t.Errorf("the public bucket was not flagged:\n%s", got)
	}
	if !strings.Contains(got, "csg-live-public") {
		t.Errorf("the finding does not name the public bucket:\n%s", got)
	}
	if strings.Contains(got, "csg-live-private") {
		t.Errorf("the locked-down bucket must not be flagged:\n%s", got)
	}
}

// fakeS3Handler serves a two-bucket account: one public, one locked down.
func fakeS3Handler(w http.ResponseWriter, r *http.Request) {
	bucket := ""
	if p := r.URL.Path; len(p) > 1 {
		bucket = p[1:]
	}
	switch {
	case r.Method == "GET" && bucket == "" && !r.URL.Query().Has("location"):
		w.Write([]byte(`<?xml version="1.0"?>
<ListAllMyBucketsResult>
  <Buckets>
    <Bucket><Name>csg-live-public</Name></Bucket>
    <Bucket><Name>csg-live-private</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))
	case r.URL.Query().Has("location"):
		w.Write([]byte(`<?xml version="1.0"?><LocationConstraint>eu-west-1</LocationConstraint>`))
	case r.URL.Query().Has("lifecycle"):
		if bucket == "csg-live-private" {
			w.Write([]byte(`<?xml version="1.0"?>
<LifecycleConfiguration>
  <Rule><ID>tier-down</ID><Status>Enabled</Status><Transition><Days>30</Days><StorageClass>INTELLIGENT_TIERING</StorageClass></Transition></Rule>
</LifecycleConfiguration>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchLifecycleConfiguration</Code><Message>none</Message></Error>`)
		}
	case r.URL.Query().Has("policy"):
		if bucket == "csg-live-private" {
			w.Write([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::csg-live-private/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<Error><Code>NoSuchBucketPolicy</Code><Message>none</Message></Error>`)
		}
	case r.URL.Query().Has("publicAccessBlock"):
		if bucket == "csg-live-public" {
			w.Write([]byte(`<?xml version="1.0"?>
<PublicAccessBlockConfiguration>
  <BlockPublicAcls>false</BlockPublicAcls>
  <BlockPublicPolicy>false</BlockPublicPolicy>
  <IgnorePublicAcls>false</IgnorePublicAcls>
  <RestrictPublicBuckets>false</RestrictPublicBuckets>
</PublicAccessBlockConfiguration>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>none</Message></Error>`))
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}
