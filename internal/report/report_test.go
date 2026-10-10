package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// fixture builds a small, fully populated report without touching the store.
func fixture() Report {
	mk := func(rank int, kind models.FindingKind, rule, id, title string, sev models.Severity, usd, risk, blast float64) prioritize.Ranked {
		return prioritize.Ranked{
			Finding: models.Finding{
				ID: rule + ":" + id, Kind: kind, RuleID: rule, Title: title, Description: "Terraform " + id + " is wrong.",
				Resource: models.ResourceRef{Provider: "aws", Service: "s3", ResourceID: id, TerraformAddress: "aws_x." + id},
				Severity: sev, MonthlySavingsUSD: usd, RiskReductionScore: risk, BlastRadiusScore: blast,
				ComplianceControls:   []string{"CIS-AWS-v3.0.0-2.1.4"},
				SuggestedRemediation: &models.Remediation{Summary: "Fix it.", Action: models.ActionModify},
			},
			Rank: rank, Score: 0.9 - float64(rank)/10, Savings: 0.5, Risk: risk / 100, Blast: blast / 100,
		}
	}
	return Report{
		Version: "0.6.0-beta", GeneratedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC),
		Profile: "devops", Weights: prioritize.Profiles["devops"],
		Inputs: Inputs{CUR: 392, Events: 8, Terraform: 22},
		Findings: []prioritize.Ranked{
			mk(1, models.KindSecurity, "SEC-S3-PUBLIC-001", "bucket-a", "S3 bucket is publicly accessible", models.SeverityCritical, 0, 90, 30),
			mk(2, models.KindCost, "COST-EBS-IDLE-001", "vol-1", "Idle EBS volume", "", 40.55, 0, 10),
			mk(3, models.KindSecurity, "SEC-S3-PUBLIC-001", "bucket-b", "S3 bucket is publicly accessible", models.SeverityMedium, 0, 40, 30),
		},
		Anomalies: []Anomaly{{Series: "AmazonEC2/booking", Days: []string{"2026-09-19", "2026-09-20"}}},
	}
}

func render(t *testing.T, f Format, r Report) string {
	t.Helper()
	rd, err := NewRenderer(f)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := rd.Render(&b, r); err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	return b.String()
}

func TestFormats(t *testing.T) {
	if _, err := NewRenderer("yaml"); !errors.Is(err, ErrUnknownFormat) {
		t.Fatalf("want ErrUnknownFormat, got %v", err)
	}
	for in, want := range map[string]Format{"md": FormatMarkdown, "Markdown": FormatMarkdown, "HTML": FormatHTML, "htm": FormatHTML, "json": FormatJSON, "sarif": FormatSARIF} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ParseFormat("pdf"); !errors.Is(err, ErrUnknownFormat) {
		t.Error("pdf must be rejected")
	}
	for path, want := range map[string]Format{"a/out.HTML": FormatHTML, "r.md": FormatMarkdown, "x.json": FormatJSON, "x.sarif": FormatSARIF, "x.sarif.json": FormatSARIF} {
		if got, ok := FormatForPath(path); !ok || got != want {
			t.Errorf("FormatForPath(%q) = %q, %v; want %q", path, got, ok, want)
		}
	}
	if _, ok := FormatForPath("out.txt"); ok {
		t.Error("unknown extension must not guess")
	}
}

func TestSummaryHelpers(t *testing.T) {
	r := fixture()
	if got := r.TotalSavings(); got != 40.55 {
		t.Errorf("TotalSavings = %v", got)
	}
	if c, s := r.Counts(); c != 1 || s != 2 {
		t.Errorf("Counts = %d, %d", c, s)
	}
	sc := r.SeverityCounts()
	if len(sc) != 2 || sc[0].Severity != models.SeverityCritical || sc[1].Severity != models.SeverityMedium {
		t.Errorf("SeverityCounts = %+v", sc)
	}
}

func TestMarkdown(t *testing.T) {
	out := render(t, FormatMarkdown, fixture())
	for _, want := range []string{"# CloudSpendGuard Report", "Findings: 3 (2 security, 1 cost)", "USD 40.55 per month",
		"| 1 | 0.800 |", "`SEC-S3-PUBLIC-001`", "CIS 2.1.4", "## Cost anomalies", "2026-09-19, 2026-09-20", "never applies a change"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\u2014") {
		t.Error("report must not contain em dashes")
	}
	empty := render(t, FormatMarkdown, Report{Version: "x", Profile: "devops"})
	if !strings.Contains(empty, "No findings.") || strings.Contains(empty, "## Prioritized backlog") {
		t.Errorf("empty report:\n%s", empty)
	}
}

func TestJSON(t *testing.T) {
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Profile       string `json:"profile"`
		Findings      []struct {
			Rank   int    `json:"rank"`
			RuleID string `json:"rule_id"`
		} `json:"findings"`
		Summary struct {
			Findings int     `json:"findings"`
			Security int     `json:"security_findings"`
			Cost     int     `json:"cost_findings"`
			Savings  float64 `json:"projected_savings_usd_per_month"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(render(t, FormatJSON, fixture())), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != SchemaVersion || doc.Profile != "devops" || len(doc.Findings) != 3 || doc.Findings[0].Rank != 1 ||
		doc.Summary.Findings != 3 || doc.Summary.Security != 2 || doc.Summary.Cost != 1 || doc.Summary.Savings != 40.55 {
		t.Errorf("unexpected JSON: %+v", doc)
	}
	// An empty backlog must be an empty array, not null, for schema validators.
	if out := render(t, FormatJSON, Report{}); !strings.Contains(out, `"findings": []`) {
		t.Errorf("empty findings must be []:\n%s", out)
	}
}

func TestSARIF(t *testing.T) {
	out := render(t, FormatSARIF, fixture())
	var log struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }    `json:"artifactLocation"`
						Region           struct{ StartLine int } `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-2.1.0") || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "CloudSpendGuard" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 3 {
		t.Fatalf("want 2 rules and 3 results, got %d and %d", len(run.Tool.Driver.Rules), len(run.Results))
	}
	wantLevels := []string{"error", "note", "warning"} // critical, cost (no severity), medium
	for i, res := range run.Results {
		if res.Level != wantLevels[i] {
			t.Errorf("result %d level = %s, want %s", i, res.Level, wantLevels[i])
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d ruleIndex does not point at rule %s", i, res.RuleID)
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "infrastructure.tf" || loc.Region.StartLine != 1 {
			t.Errorf("result %d location = %+v", i, loc)
		}
		if res.PartialFingerprints["csgFindingId/v1"] == "" {
			t.Errorf("result %d has no fingerprint", i)
		}
	}
	r := fixture()
	r.ArtifactURI = "terraform/main.tf"
	if !strings.Contains(render(t, FormatSARIF, r), `"uri": "terraform/main.tf"`) {
		t.Error("ArtifactURI not honoured")
	}
	if out := render(t, FormatSARIF, Report{}); !strings.Contains(out, `"results": []`) {
		t.Errorf("empty results must be []:\n%s", out)
	}
}

// TestHTMLEscapesUntrustedText matters because titles, resource IDs, and tag
// values come from the scanned account, which may be attacker-influenced.
func TestHTMLEscapesUntrustedText(t *testing.T) {
	r := fixture()
	r.Findings[0].Resource.ResourceID = `<script>alert(1)</script>`
	r.Findings[0].Description = `"><img src=x onerror=alert(2)>`
	out := render(t, FormatHTML, r)
	for _, bad := range []string{"<script>alert(1)", "<img src=x"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped %q in HTML", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped form not found")
	}
}

func TestHTMLContentAndPrivacy(t *testing.T) {
	out := render(t, FormatHTML, fixture())
	for _, want := range []string{"<!DOCTYPE html>", `lang="en"`, "Prioritized backlog", "Remediation cards", "$40.55", "CIS 2.1.4", "AmazonEC2/booking", "width:50%"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	// NFR2: no external requests, no scripts.
	for _, bad := range []string{"<script", "http://", "src=\"http", "<link"} {
		if strings.Contains(strings.ReplaceAll(out, "https://", ""), bad) {
			t.Errorf("HTML must be self-contained, found %q", bad)
		}
	}
	if !strings.Contains(render(t, FormatHTML, Report{Version: "x"}), "No findings.") {
		t.Error("empty HTML report")
	}
	if strings.Contains(out, "\u2014") {
		t.Error("report must not contain em dashes")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRenderPropagatesWriteErrors(t *testing.T) {
	for _, f := range []Format{FormatMarkdown, FormatHTML, FormatJSON, FormatSARIF} {
		rd, _ := NewRenderer(f)
		if err := rd.Render(failWriter{}, fixture()); err == nil {
			t.Errorf("%s: write error swallowed", f)
		}
	}
}
