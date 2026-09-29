package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/cost"
	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
	"github.com/wisnuanggoro/cloudspendguard/internal/store"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

func defaultDB() string {
	if v := os.Getenv("CSG_DB"); v != "" {
		return v
	}
	return ".csg/csg.db"
}

// parseInterspersed lets flags appear before or after positional arguments,
// so both `csg ingest cur --db x f.parquet` and `csg ingest cur f.parquet --db x` work.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func cmdIngest(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return usageError("ingest: want a source: cur, cloudtrail, or tfstate")
	}
	source := args[0]
	fs := flag.NewFlagSet("ingest "+source, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	paths, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return usageError(err.Error())
	}
	if len(paths) == 0 {
		return usageError("ingest " + source + ": want at least one path")
	}

	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()

	began := time.Now()
	var read, written int
	for _, p := range paths {
		var r, w int
		switch source {
		case "cur":
			recs, err := cur.NewReader().Read(ctx, p)
			if err != nil {
				return err
			}
			r = len(recs)
			if w, err = st.InsertCURRecords(ctx, recs); err != nil {
				return err
			}
		case "cloudtrail":
			evs, err := cloudtrail.NewReader().Read(ctx, p)
			if err != nil {
				return err
			}
			r = len(evs)
			if w, err = st.InsertCloudTrailEvents(ctx, evs); err != nil {
				return err
			}
		case "tfstate", "terraform":
			res, err := tfstate.NewParser().Parse(ctx, p)
			if err != nil {
				return err
			}
			r = len(res)
			if w, err = st.InsertTerraformResources(ctx, res); err != nil {
				return err
			}
		default:
			return usageError("ingest: unknown source " + source + " (want cur, cloudtrail, or tfstate)")
		}
		read += r
		written += w
	}
	fmt.Fprintf(out, "ingested %d %s records from %d path(s) into %s (%d new, %d already present) in %s\n",
		read, source, len(paths), *db, written, read-written, time.Since(began).Round(time.Millisecond))
	return nil
}

func cmdQuery(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return usageError(err.Error())
	}
	if len(rest) != 1 {
		return usageError(`query: want exactly one quoted SQL statement, e.g. csg query "SELECT COUNT(*) FROM cur"`)
	}
	if _, err := os.Stat(*db); err != nil {
		return fmt.Errorf("query: no database at %s; run `csg ingest` first", *db)
	}
	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()

	rows, err := st.Query(ctx, rest[0])
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(cols, "\t"))
	n := 0
	for rows.Next() {
		vals := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		cells := make([]string, len(cols))
		for i, v := range vals {
			if v.Valid {
				cells[i] = v.String
			} else {
				cells[i] = "NULL"
			}
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "(%d row%s)\n", n, plural(n))
	return nil
}

func cmdAnalyze(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	profile := fs.String("profile", "devops", "weighting profile")
	format := fs.String("format", "table", "table or json")
	if rest, err := parseInterspersed(fs, args); err != nil {
		return usageError(err.Error())
	} else if len(rest) > 0 {
		return usageError("analyze: unexpected argument " + rest[0])
	}
	w, ok := prioritize.Profiles[*profile]
	if !ok {
		return usageError("analyze: unknown profile " + *profile + " (want devops, finops, security, or cxo)")
	}
	if *format != "table" && *format != "json" {
		return usageError("analyze: unknown format " + *format + " (want table or json)")
	}
	if _, err := os.Stat(*db); err != nil {
		return fmt.Errorf("analyze: no database at %s; run `csg ingest` first", *db)
	}
	st, err := store.Open(ctx, *db)
	if err != nil {
		return err
	}
	defer st.Close()

	curRecs, err := st.LoadCURRecords(ctx)
	if err != nil {
		return err
	}
	events, err := st.LoadCloudTrailEvents(ctx)
	if err != nil {
		return err
	}
	resources, err := st.LoadTerraformResources(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	costFindings, err := cost.Analyze(ctx, cost.Input{CUR: curRecs, Resources: resources, Now: now})
	if err != nil {
		return err
	}
	secFindings, err := security.Analyze(ctx, security.Input{Events: events, Resources: resources, Now: now})
	if err != nil {
		return err
	}
	findings := prioritize.Prioritize(append(costFindings, secFindings...), w)

	if *format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Profile  string             `json:"profile"`
			Weights  prioritize.Weights `json:"weights"`
			Findings []models.Finding   `json:"findings"`
		}{*profile, w, findings})
	}
	return printBacklog(out, *profile, w, findings, len(curRecs), len(events), len(resources))
}

func printBacklog(out io.Writer, profile string, w prioritize.Weights, fs []models.Finding, nCUR, nEvents, nRes int) error {
	fmt.Fprintf(out, "Input: %d CUR line items, %d CloudTrail events, %d Terraform resources\n", nCUR, nEvents, nRes)
	fmt.Fprintf(out, "Profile %q: score = %.1f x savings + %.1f x risk - %.1f x blast radius (each normalized 0 to 1)\n\n",
		profile, w.Alpha, w.Beta, w.Gamma)
	if len(fs) == 0 {
		fmt.Fprintln(out, "No findings.")
		return nil
	}
	var maxSavings, total float64
	for _, f := range fs {
		if f.MonthlySavingsUSD > maxSavings {
			maxSavings = f.MonthlySavingsUSD
		}
		total += f.MonthlySavingsUSD
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tSCORE\tKIND\tSEVERITY\tRULE\tRESOURCE\tSAVINGS/MO\tRISK\tBLAST\tCONTROLS")
	for i, f := range fs {
		controls := strings.Join(f.ComplianceControls, ",")
		if controls == "" {
			controls = "-"
		}
		fmt.Fprintf(tw, "%d\t%.2f\t%s\t%s\t%s\t%s\tUSD %.2f\t%.0f\t%.0f\t%s\n",
			i+1, prioritize.Score(f, maxSavings, w), f.Kind, f.Severity, f.RuleID, f.Resource.ResourceID,
			f.MonthlySavingsUSD, f.RiskReductionScore, f.BlastRadiusScore, controls)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d finding%s, USD %.2f/month projected savings\n\n", len(fs), plural(len(fs)), total)

	byKind := map[models.FindingKind]int{}
	for _, f := range fs {
		byKind[f.Kind]++
	}
	kinds := make([]string, 0, len(byKind))
	for k, n := range byKind {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(kinds)
	fmt.Fprintf(out, "Details (%s):\n", strings.Join(kinds, ", "))
	for i, f := range fs {
		fmt.Fprintf(out, "  %d. %s: %s\n     %s\n", i+1, f.Title, f.Resource.ResourceID, f.Description)
		if f.SuggestedRemediation != nil {
			fmt.Fprintf(out, "     Fix: %s\n", f.SuggestedRemediation.Summary)
		}
	}
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
