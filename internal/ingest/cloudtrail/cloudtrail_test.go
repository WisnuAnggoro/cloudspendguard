package cloudtrail

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixture = "../../../testdata/sample-events.json"

func TestRead_Golden(t *testing.T) {
	evs, err := NewReader().Read(context.Background(), fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 8 {
		t.Fatalf("want 8 events, got %d", len(evs))
	}
	acl := evs[3]
	if acl.EventName != "PutBucketAcl" || acl.EventSource != "s3.amazonaws.com" || acl.Region != "eu-west-1" ||
		acl.SourceIP != "198.51.100.77" || acl.UserARN != "arn:aws:iam::111122223333:user/bob" ||
		acl.ResourceID != "tui-demo-booking-exports" ||
		!acl.EventTime.Equal(time.Date(2026, 9, 9, 14, 41, 30, 0, time.UTC)) {
		t.Fatalf("unexpected PutBucketAcl event: %+v", acl)
	}
	if acl.RequestParameters()["bucketName"] != "tui-demo-booking-exports" {
		t.Fatal("RequestParameters not exposed")
	}
	if evs[0].RequestParameters() != nil {
		t.Fatal("null requestParameters should yield nil")
	}
	if got := evs[5].ResourceID; got != "legacy-ci-deployer" {
		t.Fatalf("PutRolePolicy resource = %q", got)
	}
}

func TestRead_GzipDirectoryAndResourcesArray(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{"ignored": {"x": 1}, "Records": [{"eventID": "e1", "eventName": "GetObject", "eventTime": "2026-09-01T00:00:00Z",
		"resources": [{"ARN": "arn:aws:s3:::bucket/key", "type": "AWS::S3::Object"}], "requestParameters": {"bucketName": "bucket"}}]}`)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(body)
	_ = gz.Close()
	if err := os.MkdirAll(filepath.Join(dir, "2026", "09"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "2026", "09", "shard.json.gz"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("skip"), 0o600); err != nil {
		t.Fatal(err)
	}
	evs, err := NewReader().Read(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].ResourceID != "arn:aws:s3:::bucket/key" {
		t.Fatalf("unexpected: %+v", evs)
	}
}

func TestRead_Errors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"no records key":  `{"foo": []}`,
		"not an object":   `[1,2]`,
		"records not arr": `{"Records": {}}`,
		"missing eventID": `{"Records": [{"eventName": "X"}]}`,
		"bad time":        `{"Records": [{"eventID": "a", "eventTime": "soon"}]}`,
		"truncated":       `{"Records": [{"eventID": "a"`,
		"bad record":      `{"Records": [1]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name+".json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewReader().Read(context.Background(), p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := NewReader().Read(context.Background(), filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error for missing path")
	}
	bad := filepath.Join(dir, "bad.json.gz")
	_ = os.WriteFile(bad, []byte("nope"), 0o600)
	if _, err := NewReader().Read(context.Background(), bad); err == nil {
		t.Fatal("expected gzip error")
	}
}

func TestRead_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewReader().Read(ctx, fixture); err == nil {
		t.Fatal("expected cancellation error")
	}
}
