package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const testdata = "../../testdata"

func csg(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

// TestEndToEnd is the Unit 4 demo script as a test: ingest the three sample
// sources, query the store, and check the prioritized backlog.
func TestEndToEnd(t *testing.T) {
	db := filepath.Join(t.TempDir(), "csg.db")
	steps := [][]string{
		{"ingest", "cur", "--db", db, filepath.Join(testdata, "sample-cur.parquet")},
		{"ingest", "cur", filepath.Join(testdata, "sample-cur.csv"), "--db", db},
		{"ingest", "cloudtrail", "--db", db, filepath.Join(testdata, "sample-events.json")},
		{"ingest", "tfstate", "--db", db, filepath.Join(testdata, "terraform.tfstate")},
	}
	for _, s := range steps {
		if code, _, stderr := csg(t, s...); code != 0 {
			t.Fatalf("%v: exit %d: %s", s, code, stderr)
		}
	}
	// The CSV is the same data as the Parquet file, so it must add nothing.
	if _, out, _ := csg(t, "query", "--db", db, "SELECT COUNT(*) AS n FROM cur"); !strings.Contains(out, "300") {
		t.Fatalf("expected 300 CUR rows after duplicate ingest, got:\n%s", out)
	}
	code, out, stderr := csg(t, "query", "--db", db, "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC")
	if code != 0 || !strings.Contains(out, "AmazonEC2") || !strings.Contains(out, "156.72") || !strings.Contains(out, "(4 rows)") {
		t.Fatalf("query: exit %d\n%s\n%s", code, out, stderr)
	}
	if code, _, _ := csg(t, "query", "--db", db, "DELETE FROM cur"); code != 1 {
		t.Fatal("write queries must fail")
	}

	code, out, stderr = csg(t, "analyze", "--db", db)
	if code != 0 {
		t.Fatalf("analyze: %d %s", code, stderr)
	}
	for _, want := range []string{"COST-EBS-IDLE-001", "COST-EIP-UNATTACHED-001", "SEC-S3-PUBLIC-001", "SEC-IAM-ADMIN-001", "5 findings", "vol-0a1b2c3d4e5f60099", "legacy-ci-deployer"} {
		if !strings.Contains(out, want) {
			t.Fatalf("analyze output missing %q:\n%s", want, out)
		}
	}

	code, out, _ = csg(t, "analyze", "--db", db, "--profile", "security", "--format", "json")
	if code != 0 {
		t.Fatal("analyze json failed")
	}
	var doc struct {
		Profile  string
		Findings []struct {
			RuleID string `json:"rule_id"`
		}
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Profile != "security" || len(doc.Findings) != 5 || doc.Findings[0].RuleID != "SEC-S3-PUBLIC-001" {
		t.Fatalf("security profile should rank the public bucket first: %+v", doc)
	}
}

func TestUsageAndErrors(t *testing.T) {
	db := filepath.Join(t.TempDir(), "none.db")
	cases := []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"help"}, 0},
		{[]string{"version"}, 0},
		{[]string{"bogus"}, 2},
		{[]string{"report"}, 2},
		{[]string{"ingest"}, 2},
		{[]string{"ingest", "cur"}, 2},
		{[]string{"ingest", "cur", "--nope"}, 2},
		{[]string{"ingest", "s3", "--db", db, "x"}, 2},
		{[]string{"ingest", "cur", "--db", db, "missing.parquet"}, 1},
		{[]string{"ingest", "cloudtrail", "--db", db, "missing.json"}, 1},
		{[]string{"ingest", "tfstate", "--db", db, "missing.tfstate"}, 1},
		{[]string{"query"}, 2},
		{[]string{"query", "--db", filepath.Join(t.TempDir(), "absent.db"), "SELECT 1"}, 1},
		{[]string{"analyze", "--profile", "nope"}, 2},
		{[]string{"analyze", "--format", "xml"}, 2},
		{[]string{"analyze", "extra"}, 2},
		{[]string{"analyze", "--db", filepath.Join(t.TempDir(), "absent.db")}, 1},
	}
	for _, tc := range cases {
		if code, _, _ := csg(t, tc.args...); code != tc.code {
			t.Errorf("%v: exit %d, want %d", tc.args, code, tc.code)
		}
	}
}

func TestAnalyze_EmptyStore(t *testing.T) {
	db := filepath.Join(t.TempDir(), "csg.db")
	if code, _, _ := csg(t, "query", "--db", db, "SELECT 1"); code != 1 {
		t.Fatal("query before ingest should fail")
	}
	// Ingesting a state file with no AWS problems yields an empty backlog.
	if code, _, e := csg(t, "ingest", "tfstate", "--db", db, filepath.Join(testdata, "terraform.tfstate")); code != 0 {
		t.Fatal(e)
	}
	t.Setenv("CSG_DB", db)
	if defaultDB() != db {
		t.Fatal("CSG_DB not honoured")
	}
	code, out, _ := csg(t, "analyze")
	if code != 0 || !strings.Contains(out, "0 CUR line items") {
		t.Fatalf("analyze on tfstate only: %d\n%s", code, out)
	}
}
