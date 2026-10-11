package report

import (
	"fmt"
	"io"
	"strings"
)

type markdownRenderer struct{}

// Render writes a Markdown report: a summary, the ranked table, and one
// section per finding with its evidence and suggested fix.
func (markdownRenderer) Render(w io.Writer, r Report) error {
	var b strings.Builder
	cost, sec := r.Counts()
	b.WriteString("# CloudSpendGuard Report\n\n")
	fmt.Fprintf(&b, "Generated %s by csg %s.\n\n", r.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"), r.Version)
	fmt.Fprintf(&b, "Input: %d CUR line items, %d CloudTrail events, %d Terraform resources.\n\n", r.Inputs.CUR, r.Inputs.Events, r.Inputs.Terraform)
	fmt.Fprintf(&b, "Profile `%s`: score = %.2f x savings + %.2f x risk - %.2f x blast radius (each normalized 0 to 1).\n\n", r.Profile, r.Weights.Alpha, r.Weights.Beta, r.Weights.Gamma)

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- Findings: %d (%d security, %d cost)\n", len(r.Findings), sec, cost)
	fmt.Fprintf(&b, "- Projected savings: USD %.2f per month\n", r.TotalSavings())
	for _, s := range r.SeverityCounts() {
		fmt.Fprintf(&b, "- %s: %d\n", title(string(s.Severity)), s.Count)
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		b.WriteString("No findings.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	b.WriteString("## Prioritized backlog\n\n")
	b.WriteString("| # | Score | S / R / B | Kind | Severity | Rule | Resource | Savings per month | Controls |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %d | %.3f | %.2f / %.2f / %.2f | %s | %s | `%s` | `%s` | USD %.2f | %s |\n",
			f.Rank, f.Score, f.Savings, f.Risk, f.Blast, f.Kind, dash(string(f.Severity)), f.RuleID, f.Resource.ResourceID, f.MonthlySavingsUSD, controls(f.Finding))
	}

	if len(r.Anomalies) > 0 {
		b.WriteString("\n## Cost anomalies\n\n")
		for _, a := range r.Anomalies {
			fmt.Fprintf(&b, "- `%s`: %s\n", a.Series, strings.Join(a.Days, ", "))
		}
	}

	b.WriteString("\n## Findings\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n### %d. %s\n\n", f.Rank, f.Title)
		fmt.Fprintf(&b, "- Resource: `%s`", f.Resource.ResourceID)
		if f.Resource.TerraformAddress != "" {
			fmt.Fprintf(&b, " (`%s`)", f.Resource.TerraformAddress)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "- Rule: `%s`; controls: %s\n", f.RuleID, controls(f.Finding))
		fmt.Fprintf(&b, "- Evidence: %s\n", f.Description)
		if rem := f.SuggestedRemediation; rem != nil {
			fmt.Fprintf(&b, "- Fix (%s): %s\n", dash(string(rem.Action)), rem.Summary)
		}
	}
	b.WriteString("\nCloudSpendGuard never applies a change. Patches from `csg remediate` are shown for review only.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
