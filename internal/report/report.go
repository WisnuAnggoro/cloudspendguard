// Package report renders a prioritized backlog of findings as Markdown,
// HTML, JSON, or SARIF 2.1.0 (for GitHub and GitLab code scanning).
//
// Module M10 in docs/architecture.md. Scaffolded in Unit 2 and implemented in
// Unit 6 (Week 6), tagged v0.6.0-beta. Every renderer is a pure function of a
// [Report] value, so the same input always produces byte-identical output
// except for the timestamp the caller puts in the Report.
package report

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// Format is an output report format.
type Format string

// Supported report formats.
const (
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif" // https://docs.oasis-open.org/sarif/sarif/v2.1.0/
)

// ErrUnknownFormat is returned for a format name that is not supported.
var ErrUnknownFormat = errors.New("report: unknown format")

// Inputs counts the records that fed the analysis.
type Inputs struct {
	CUR        int  `json:"cur_line_items"`
	Events     int  `json:"cloudtrail_events"`
	Terraform  int  `json:"terraform_resources"`
	SampleData bool `json:"sample_data,omitempty"`
}

// Anomaly lists the days one billing series was flagged on.
type Anomaly struct {
	Series string   `json:"series"`
	Days   []string `json:"days"`
}

// Report is everything a renderer needs. It is plain data so it can be
// built in tests without touching the store or the analyzers.
type Report struct {
	Version     string              `json:"version"`
	GeneratedAt time.Time           `json:"generated_at"`
	Profile     string              `json:"profile"`
	Weights     prioritize.Weights  `json:"weights"`
	Inputs      Inputs              `json:"inputs"`
	Findings    []prioritize.Ranked `json:"findings"`
	Anomalies   []Anomaly           `json:"anomalies,omitempty"`

	// ArtifactURI is the file SARIF results point at. Terraform state has no
	// source line numbers, so every result is anchored to this one path.
	ArtifactURI string `json:"-"`
}

// SchemaVersion is the version of the JSON report layout.
const SchemaVersion = "1"

// TotalSavings is the projected monthly saving across all findings, in USD.
func (r Report) TotalSavings() float64 {
	var sum float64
	for _, f := range r.Findings {
		sum += f.MonthlySavingsUSD
	}
	return sum
}

// Counts returns the number of cost and security findings.
func (r Report) Counts() (cost, security int) {
	for _, f := range r.Findings {
		if f.Kind == models.KindSecurity {
			security++
		} else {
			cost++
		}
	}
	return cost, security
}

// SeverityCounts returns findings per severity, highest first, skipping
// severities with no findings. Cost findings carry no severity and are not counted.
func (r Report) SeverityCounts() []SeverityCount {
	n := map[models.Severity]int{}
	for _, f := range r.Findings {
		if f.Severity != "" {
			n[f.Severity]++
		}
	}
	var out []SeverityCount
	for _, s := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		if n[s] > 0 {
			out = append(out, SeverityCount{s, n[s]})
		}
	}
	return out
}

// SeverityCount pairs a severity with its number of findings.
type SeverityCount struct {
	Severity models.Severity
	Count    int
}

// Renderer writes a Report to w in one Format.
type Renderer interface {
	Render(w io.Writer, r Report) error
}

// ParseFormat accepts a format name or common alias (md, htm, sarif).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "markdown", "md":
		return FormatMarkdown, nil
	case "html", "htm":
		return FormatHTML, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	}
	return "", fmt.Errorf("%w %q (want markdown, html, json, or sarif)", ErrUnknownFormat, s)
}

// FormatForPath guesses the format from a file extension, so
// `--report out.html` needs no separate --format flag.
func FormatForPath(path string) (Format, bool) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".html"), strings.HasSuffix(lower, ".htm"):
		return FormatHTML, true
	case strings.HasSuffix(lower, ".md"):
		return FormatMarkdown, true
	case strings.HasSuffix(lower, ".sarif"), strings.HasSuffix(lower, ".sarif.json"):
		return FormatSARIF, true
	case strings.HasSuffix(lower, ".json"):
		return FormatJSON, true
	}
	return "", false
}

// NewRenderer returns the Renderer for format.
func NewRenderer(format Format) (Renderer, error) {
	switch format {
	case FormatMarkdown:
		return markdownRenderer{}, nil
	case FormatHTML:
		return htmlRenderer{}, nil
	case FormatJSON:
		return jsonRenderer{}, nil
	case FormatSARIF:
		return sarifRenderer{}, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownFormat, string(format))
}

// controls shortens "CIS-AWS-v3.0.0-5.6" to "CIS 5.6" for display.
func controls(f models.Finding) string {
	if len(f.ComplianceControls) == 0 {
		return "-"
	}
	out := make([]string, len(f.ComplianceControls))
	for i, c := range f.ComplianceControls {
		out[i] = strings.ReplaceAll(c, "CIS-AWS-v3.0.0-", "CIS ")
	}
	return strings.Join(out, ", ")
}
