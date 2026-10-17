package live

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

// fakeS3 serves canned S3 XML so the collector is tested against the real
// SDK client without any AWS account or emulator. The LocalStack acceptance
// test (acceptance build tag) covers the wire path end to end.
type fakeS3 struct {
	status int
}

func (f fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bucket := ""
	if p := r.URL.Path; len(p) > 1 {
		bucket = p[1:]
	}
	switch {
	case r.Method == "GET" && bucket == "" && r.URL.Query().Get("location") == "":
		// ListBuckets
		w.Write([]byte(`<?xml version="1.0"?>
<ListAllMyBucketsResult>
  <Buckets>
    <Bucket><Name>reports</Name></Bucket>
    <Bucket><Name>legacy</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))
	case r.URL.Query().Has("location"):
		if bucket == "reports" {
			w.Write([]byte(`<?xml version="1.0"?><LocationConstraint>eu-west-1</LocationConstraint>`))
		} else {
			w.Write([]byte(`<?xml version="1.0"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`))
		}
	case r.URL.Query().Has("policy"):
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchBucketPolicy</Code><Message>none</Message></Error>`)
	case r.URL.Query().Has("lifecycle"):
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchLifecycleConfiguration</Code><Message>none</Message></Error>`)
	case r.URL.Query().Has("publicAccessBlock"):
		if bucket == "reports" {
			w.Write([]byte(`<?xml version="1.0"?>
<PublicAccessBlockConfiguration>
  <BlockPublicAcls>false</BlockPublicAcls>
  <BlockPublicPolicy>false</BlockPublicPolicy>
  <IgnorePublicAcls>false</IgnorePublicAcls>
  <RestrictPublicBuckets>false</RestrictPublicBuckets>
</PublicAccessBlockConfiguration>`))
		} else if f.status == http.StatusForbidden {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>none</Message></Error>`))
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func collectAgainst(t *testing.T, h http.Handler) ([]tfstate.Resource, error) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewCollector(Options{EndpointURL: srv.URL, AccessKeyID: "test", SecretAccessKey: "test"})
	return c.Collect(context.Background())
}

func TestCollect_MapsBucketsAndPublicAccessPosture(t *testing.T) {
	res, err := collectAgainst(t, fakeS3{})
	if err != nil {
		t.Fatal(err)
	}
	var buckets, pabs int
	for _, r := range res {
		switch r.Type {
		case "aws_s3_bucket":
			buckets++
			if r.Attr("bucket") == "" || r.Attr("region") == "" {
				t.Errorf("bucket %s lacks name or region: %+v", r.Address, r.Attributes)
			}
		case "aws_s3_bucket_public_access_block":
			pabs++
			if v, ok := r.Bool("block_public_acls"); !ok || v {
				t.Errorf("public access block not mapped verbatim: %+v", r.Attributes)
			}
		}
	}
	if buckets != 2 {
		t.Errorf("want 2 buckets, got %d", buckets)
	}
	if pabs != 1 {
		t.Errorf("only the configured bucket should yield a public access block, got %d", pabs)
	}
	// The empty LocationConstraint of legacy buckets defaults to us-east-1.
	for _, r := range res {
		if r.Type == "aws_s3_bucket" && r.Attr("bucket") == "legacy" && r.Attr("region") != "us-east-1" {
			t.Errorf("legacy bucket region: %q", r.Attr("region"))
		}
	}
}

func TestCollect_NoSuchConfigurationIsNotExposure(t *testing.T) {
	res, err := collectAgainst(t, fakeS3{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Type == "aws_s3_bucket_public_access_block" && r.Attr("bucket") == "legacy" {
			t.Errorf("a bucket with no configuration must not be reported as evidence")
		}
	}
}

// A permission failure must fail the whole collection loudly: a partial list
// must never masquerade as a healthy inventory.
func TestCollect_PublicAccessBlockDeniedFailsLoud(t *testing.T) {
	// reports succeeds, legacy is denied: the collection must error.
	_, err := collectAgainst(t, fakeS3{status: http.StatusForbidden})
	if err == nil {
		t.Fatal("access denied on one bucket must fail the collection")
	}
}

func TestCollect_ListBucketsDeniedFailsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`)
	}))
	t.Cleanup(srv.Close)
	c := NewCollector(Options{EndpointURL: srv.URL, AccessKeyID: "test", SecretAccessKey: "test"})
	if _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("access denied on ListBuckets must fail the collection")
	}
}
