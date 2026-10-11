package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
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
	if _, out, _ := csg(t, "query", "--db", db, "SELECT COUNT(*) AS n FROM cur"); !strings.Contains(out, "392") {
		t.Fatalf("expected 392 CUR rows after duplicate ingest, got:\n%s", out)
	}
	code, out, stderr := csg(t, "query", "--db", db, "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC")
	if code != 0 || !strings.Contains(out, "AmazonEC2") || !strings.Contains(out, "463.44") || !strings.Contains(out, "(5 rows)") {
		t.Fatalf("query: exit %d\n%s\n%s", code, out, stderr)
	}
	if code, _, _ := csg(t, "query", "--db", db, "DELETE FROM cur"); code != 1 {
		t.Fatal("write queries must fail")
	}

	code, out, stderr = csg(t, "analyze", "--db", db)
	if code != 0 {
		t.Fatalf("analyze: %d %s", code, stderr)
	}
	for _, want := range []string{"COST-EBS-IDLE-001", "COST-EIP-UNATTACHED-001", "SEC-S3-PUBLIC-001", "SEC-IAM-ADMIN-001", "COST-ANOMALY-001", "SEC-EC2-IMDSV2-001", "CIS 5.6", "23 findings", "USD 785.55/month", "vol-0a1b2c3d4e5f60099", "legacy-ci-deployer"} {
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
	if doc.Profile != "security" || len(doc.Findings) != 23 || doc.Findings[0].RuleID != "SEC-S3-PUBLIC-001" {
		t.Fatalf("security profile should rank the public bucket first: %+v", doc)
	}

	// Custom weights: pure savings ranks the oversized staging database first.
	code, out, _ = csg(t, "analyze", "--db", db, "--weights", "1,0,0", "--top", "2")
	if code != 0 || !strings.Contains(out, `Profile "custom"`) || !strings.Contains(out, "1  1.000  1.00/0.00/0.35  cost") || !strings.Contains(out, "top 2 of 23") {
		t.Fatalf("custom weights:\n%s", out)
	}

	// Anomalies: only the GPU spike is flagged; the seasonal Lambda series is not.
	code, out, _ = csg(t, "anomalies", "--db", db)
	if code != 0 || !strings.Contains(out, "09-19,09-20") || strings.Count(out, "09-") != 2 {
		t.Fatalf("anomalies:\n%s", out)
	}
	code, out, _ = csg(t, "anomalies", "--db", db, "--series", "AmazonEC2/booking")
	if code != 0 || strings.Count(out, "ANOMALY") != 2 {
		t.Fatalf("anomaly series:\n%s", out)
	}

	// Remediation from a recorded local-model fixture: verified, never applied.
	code, out, stderr = csg(t, "remediate", "SEC-EC2-IMDSV2-001:i-0a1b2c3d4e5f60042", "--db", db,
		"--llm-provider", "replay", "--fixture", filepath.Join(testdata, "llm", "imdsv2-injection-tag.json"))
	if code != 0 || !strings.Contains(out, "approved by verifier") || !strings.Contains(out, `+    http_tokens                 = "required"`) || !strings.Contains(out, "guardrail: 1 untrusted value") {
		t.Fatalf("remediate: exit %d\n%s\n%s", code, out, stderr)
	}
	code, out, _ = csg(t, "remediate", "SEC-SG-ADMIN-IPV4-001:sg-0a1b2c3d4e5f60022", "--db", db,
		"--llm-provider", "replay", "--fixture", filepath.Join(testdata, "llm", "sg-ssh-retry-exhausted.json"))
	if code != 0 || !strings.Contains(out, "No verified patch") || strings.Count(out, "rejected") != 3 {
		t.Fatalf("remediate fallback:\n%s", out)
	}
	if code, _, _ := csg(t, "remediate", "COST-EBS-IDLE-001:vol-0a1b2c3d4e5f60099", "--db", db, "--llm-provider", "replay", "--fixture", filepath.Join(testdata, "llm", "rds-public.json")); code != 1 {
		t.Fatal("delete-type findings are not eligible for patches")
	}
	if code, _, _ := csg(t, "remediate", "NOPE", "--db", db, "--llm-provider", "replay", "--fixture", filepath.Join(testdata, "llm", "rds-public.json")); code != 1 {
		t.Fatal("unknown finding must fail")
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
		{[]string{"report", "--db", filepath.Join(t.TempDir(), "absent.db")}, 1},
		{[]string{"report", "--format", "pdf"}, 2},
		{[]string{"report", "extra"}, 2},
		{[]string{"run"}, 2},
		{[]string{"run", "--sample", "--input", "x"}, 2},
		{[]string{"run", "--sample", "--profile", "nope"}, 2},
		{[]string{"run", "--sample", "--report", "out.txt"}, 2},
		{[]string{"run", "--sample", "--report", "out.html", "--format", "pdf"}, 2},
		{[]string{"run", "--sample", "extra"}, 2},
		{[]string{"run", "--input", filepath.Join(t.TempDir(), "absent")}, 1},
		{[]string{"run", "--input", t.TempDir()}, 1},
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
		{[]string{"analyze", "--weights", "1,2"}, 2},
		{[]string{"analyze", "--weights", "-1,0,0"}, 2},
		{[]string{"anomalies", "extra"}, 2},
		{[]string{"anomalies", "--db", filepath.Join(t.TempDir(), "absent.db")}, 1},
		{[]string{"remediate"}, 2},
		{[]string{"remediate", "X", "--llm-provider", "openai"}, 2},
		{[]string{"remediate", "X", "--llm-provider", "bard"}, 2},
		{[]string{"remediate", "X", "--llm-provider", "replay"}, 2},
		{[]string{"remediate", "X", "--llm-provider", "replay", "--fixture", "missing.json"}, 1},
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

// TestRun_SampleToEveryFormat is the Unit 6 integration test: one command
// goes from the bundled sample account to a report in all four formats.
func TestRun_SampleToEveryFormat(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		file string
		want []string
	}{
		{"out.html", []string{"<!DOCTYPE html>", "SEC-S3-PUBLIC-001", "bundled sample account", "legacy-ci-deployer"}},
		{"out.md", []string{"# CloudSpendGuard Report", "COST-EBS-IDLE-001", "## Cost anomalies", "AmazonEC2/booking"}},
		{"out.json", []string{`"schema_version": "1"`, `"findings"`, `"rule_id": "SEC-EC2-IMDSV2-001"`}},
		{"out.sarif", []string{`"version": "2.1.0"`, `"ruleId": "SEC-S3-PUBLIC-001"`, `"level": "error"`}},
	} {
		path := filepath.Join(dir, tc.file)
		code, out, stderr := csg(t, "run", "--sample", "--report", path, "--quiet")
		if code != 0 || !strings.Contains(out, "Wrote") {
			t.Fatalf("%s: exit %d: %s%s", tc.file, code, out, stderr)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range tc.want {
			if !strings.Contains(string(b), w) {
				t.Errorf("%s missing %q", tc.file, w)
			}
		}
	}
	// The table output is unchanged from `csg analyze`, and --stats adds timings.
	code, out, _ := csg(t, "run", "--sample", "--stats", "--top", "3")
	if code != 0 || !strings.Contains(out, "top 3 of 23") || !strings.Contains(out, "throughput") || !strings.Contains(out, "total") {
		t.Fatalf("run --stats:\n%s", out)
	}
}

func TestRun_InputDirectoryAndReportFromStore(t *testing.T) {
	// testdata/ holds a CUR export, CloudTrail events, and Terraform state side
	// by side; sub-directories (recorded model answers) must be ignored.
	code, out, stderr := csg(t, "run", "--input", testdata, "--db", filepath.Join(t.TempDir(), "kept.db"), "--weights", "0.6,0.3,0.1")
	if code != 0 || !strings.Contains(out, `Profile "custom"`) || !strings.Contains(out, "23 findings") {
		t.Fatalf("run --input: exit %d\n%s\n%s", code, out, stderr)
	}

	// `csg report` reads the store that `csg ingest` filled.
	db := filepath.Join(t.TempDir(), "csg.db")
	for _, s := range [][]string{
		{"ingest", "cur", "--db", db, filepath.Join(testdata, "sample-cur.csv")},
		{"ingest", "cloudtrail", "--db", db, filepath.Join(testdata, "sample-events.json")},
		{"ingest", "tfstate", "--db", db, filepath.Join(testdata, "terraform.tfstate")},
	} {
		if code, _, e := csg(t, s...); code != 0 {
			t.Fatalf("%v: %s", s, e)
		}
	}
	code, out, _ = csg(t, "report", "--db", db, "--top", "2")
	if code != 0 || !strings.Contains(out, "# CloudSpendGuard Report") || strings.Count(out, "\n### ") != 2 {
		t.Fatalf("report to stdout:\n%s", out)
	}
	path := filepath.Join(t.TempDir(), "nested", "csg.sarif")
	code, out, _ = csg(t, "report", "--db", db, "--out", path, "--sarif-uri", "terraform/main.tf")
	if code != 0 || !strings.Contains(out, "Wrote sarif report with 23 finding(s)") {
		t.Fatalf("report --out: %s", out)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "terraform/main.tf") {
		t.Error("--sarif-uri ignored")
	}
}

func TestDiscoverInputs(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.parquet", "b.CSV", "c.csv.gz", "d.json", "e.json.gz", "f.tfstate", "main.tf", "README.md", "labels.json"} {
		body := []byte(nil)
		switch n {
		case "d.json":
			body = []byte(`{"Records": []}`)
		case "labels.json":
			body = []byte(`{"labels": []}`) // JSON, but not CloudTrail: must be skipped
		}
		if err := os.WriteFile(filepath.Join(dir, n), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "ignored.csv"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := discoverInputs(dir)
	if err != nil || len(in.cur) != 3 || len(in.cloudtrail) != 2 || len(in.terraform) != 2 {
		t.Fatalf("discoverInputs = %+v, %v", in, err)
	}
	if _, err := discoverInputs(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory must fail")
	}
}
