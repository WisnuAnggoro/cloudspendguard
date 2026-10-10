package report

import (
	"encoding/json"
	"io"

	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
)

type jsonRenderer struct{}

// jsonDoc is the stable machine-readable layout. schema_version changes only
// when a field is removed or renamed.
type jsonDoc struct {
	SchemaVersion string `json:"schema_version"`
	Report
	Summary struct {
		Findings        int     `json:"findings"`
		Security        int     `json:"security_findings"`
		Cost            int     `json:"cost_findings"`
		SavingsPerMonth float64 `json:"projected_savings_usd_per_month"`
	} `json:"summary"`
}

// Render writes indented JSON.
func (jsonRenderer) Render(w io.Writer, r Report) error {
	var d jsonDoc
	d.SchemaVersion = SchemaVersion
	d.Report = r
	if d.Findings == nil {
		d.Findings = []prioritize.Ranked{}
	}
	d.Summary.Findings = len(r.Findings)
	d.Summary.Cost, d.Summary.Security = r.Counts()
	d.Summary.SavingsPerMonth = r.TotalSavings()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(d)
}
