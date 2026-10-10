package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
)

//go:embed report.html.tmpl
var htmlTemplateSource string

type htmlRenderer struct{}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct":      func(v float64) string { return fmt.Sprintf("%.0f", v*100) },
	"money":    func(v float64) string { return fmt.Sprintf("%.2f", v) },
	"score":    func(v float64) string { return fmt.Sprintf("%.3f", v) },
	"controls": func(f prioritize.Ranked) string { return controls(f.Finding) },
	"dash":     dash,
	"title":    title,
	"join":     strings.Join,
	"sev": func(s string) string {
		if s == "" {
			return "cost"
		}
		return s
	},
}).Parse(htmlTemplateSource))

// Render writes one self-contained HTML file: inline CSS, no JavaScript, and
// no external requests, so it can be emailed or opened offline. All values
// are escaped by html/template, which matters because resource names and tag
// values come from the account being scanned and are untrusted.
func (htmlRenderer) Render(w io.Writer, r Report) error {
	cost, sec := r.Counts()
	return htmlTemplate.Execute(w, struct {
		Report
		Cost, Security int
		Savings        float64
		Severities     []SeverityCount
		Generated      string
	}{r, cost, sec, r.TotalSavings(), r.SeverityCounts(), r.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC")})
}
