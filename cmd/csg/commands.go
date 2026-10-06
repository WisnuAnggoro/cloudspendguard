package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/anomaly"
	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/cost"
	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/internal/llm"
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

// loadAll reads every table from the store.
func loadAll(ctx context.Context, db string) ([]cur.Record, []cloudtrail.Event, []tfstate.Resource, error) {
	if _, err := os.Stat(db); err != nil {
		return nil, nil, nil, fmt.Errorf("no database at %s; run `csg ingest` first", db)
	}
	st, err := store.Open(ctx, db)
	if err != nil {
		return nil, nil, nil, err
	}
	defer st.Close()
	curRecs, err := st.LoadCURRecords(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	events, err := st.LoadCloudTrailEvents(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	resources, err := st.LoadTerraformResources(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return curRecs, events, resources, nil
}

// findAll runs every cost and security rule over the loaded inputs.
func findAll(ctx context.Context, curRecs []cur.Record, events []cloudtrail.Event, resources []tfstate.Resource, now time.Time) ([]models.Finding, error) {
	costFindings, err := cost.Analyze(ctx, cost.Input{CUR: curRecs, Resources: resources, Now: now})
	if err != nil {
		return nil, err
	}
	secFindings, err := security.Analyze(ctx, security.Input{Events: events, Resources: resources, Now: now})
	if err != nil {
		return nil, err
	}
	return append(costFindings, secFindings...), nil
}

func resolveWeights(profile, weights string) (prioritize.Weights, string, error) {
	if weights != "" {
		w, err := prioritize.ParseWeights(weights)
		if err != nil {
			return w, "", usageError("analyze: " + err.Error())
		}
		return w, "custom", nil
	}
	w, ok := prioritize.Profiles[profile]
	if !ok {
		return w, "", usageError("analyze: unknown profile " + profile + " (want devops, finops, security, or cxo)")
	}
	return w, profile, nil
}

func cmdAnalyze(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	profile := fs.String("profile", "devops", "weighting profile")
	weights := fs.String("weights", "", "explicit alpha,beta,gamma (overrides --profile)")
	format := fs.String("format", "table", "table or json")
	top := fs.Int("top", 0, "show only the first N items (0 = all)")
	if rest, err := parseInterspersed(fs, args); err != nil {
		return usageError(err.Error())
	} else if len(rest) > 0 {
		return usageError("analyze: unexpected argument " + rest[0])
	}
	w, name, err := resolveWeights(*profile, *weights)
	if err != nil {
		return err
	}
	if *format != "table" && *format != "json" {
		return usageError("analyze: unknown format " + *format + " (want table or json)")
	}
	curRecs, events, resources, err := loadAll(ctx, *db)
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}
	findings, err := findAll(ctx, curRecs, events, resources, time.Now().UTC())
	if err != nil {
		return err
	}
	ranked := prioritize.Rank(findings, w)
	if *top > 0 && *top < len(ranked) {
		ranked = ranked[:*top]
	}

	if *format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Profile  string              `json:"profile"`
			Weights  prioritize.Weights  `json:"weights"`
			Findings []prioritize.Ranked `json:"findings"`
		}{name, w, ranked})
	}
	return printBacklog(out, name, w, ranked, len(findings), len(curRecs), len(events), len(resources))
}

func printBacklog(out io.Writer, profile string, w prioritize.Weights, rs []prioritize.Ranked, total, nCUR, nEvents, nRes int) error {
	fmt.Fprintf(out, "Input: %d CUR line items, %d CloudTrail events, %d Terraform resources\n", nCUR, nEvents, nRes)
	fmt.Fprintf(out, "Profile %q: score = %.2f x savings + %.2f x risk - %.2f x blast radius (each normalized 0 to 1)\n\n",
		profile, w.Alpha, w.Beta, w.Gamma)
	if len(rs) == 0 {
		fmt.Fprintln(out, "No findings.")
		return nil
	}
	var sum float64
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tSCORE\t(S/R/B)\tKIND\tSEVERITY\tRULE\tRESOURCE\tSAVINGS/MO\tCONTROLS")
	for _, r := range rs {
		controls := strings.Join(r.ComplianceControls, ",")
		if controls == "" {
			controls = "-"
		}
		controls = strings.ReplaceAll(controls, "CIS-AWS-v3.0.0-", "CIS ")
		fmt.Fprintf(tw, "%d\t%.3f\t%.2f/%.2f/%.2f\t%s\t%s\t%s\t%s\tUSD %.2f\t%s\n",
			r.Rank, r.Score, r.Savings, r.Risk, r.Blast, r.Kind, r.Severity, r.RuleID, short(r.Resource.ResourceID, 40),
			r.MonthlySavingsUSD, controls)
		sum += r.MonthlySavingsUSD
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	shown := ""
	if len(rs) < total {
		shown = fmt.Sprintf(" (top %d of %d)", len(rs), total)
	}
	fmt.Fprintf(out, "\n%d finding%s%s, USD %.2f/month projected savings\n\n", len(rs), plural(len(rs)), shown, sum)

	byKind := map[models.FindingKind]int{}
	for _, r := range rs {
		byKind[r.Kind]++
	}
	kinds := make([]string, 0, len(byKind))
	for k, n := range byKind {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(kinds)
	fmt.Fprintf(out, "Details (%s):\n", strings.Join(kinds, ", "))
	for _, r := range rs {
		fmt.Fprintf(out, "  %d. %s: %s\n     %s\n", r.Rank, r.Title, r.Resource.ResourceID, r.Description)
		if rem := r.SuggestedRemediation; rem != nil {
			patch := ""
			if llm.Eligible(r.Finding) {
				patch = " [patchable: csg remediate " + r.ID + "]"
			}
			fmt.Fprintf(out, "     Fix (%s): %s%s\n", orDash(string(rem.Action)), rem.Summary, patch)
		}
	}
	return nil
}

func cmdAnomalies(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("anomalies", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	series := fs.String("series", "", "print every day of one series, e.g. AmazonEC2/booking")
	if rest, err := parseInterspersed(fs, args); err != nil {
		return usageError(err.Error())
	} else if len(rest) > 0 {
		return usageError("anomalies: unexpected argument " + rest[0])
	}
	curRecs, _, _, err := loadAll(ctx, *db)
	if err != nil {
		return fmt.Errorf("anomalies: %w", err)
	}
	all := anomaly.BuildSeries(curRecs)
	fmt.Fprintf(out, "STL (period 7, robust) + modified z-score (>= 3.5) + Isolation Forest (score >= 0.60); both must agree\n\n")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if *series == "" {
		fmt.Fprintln(tw, "SERIES\tDAYS\tTOTAL USD\tMAX |z|\tMAX IFOREST\tANOMALOUS DAYS")
		for i := range all {
			s := &all[i]
			if err := anomaly.Score(s, anomaly.Config{}); err != nil {
				fmt.Fprintf(tw, "%s\t%d\t-\t-\t-\ttoo short\n", s.Key, len(s.Points))
				continue
			}
			var total, maxZ, maxF float64
			var days []string
			for _, p := range s.Points {
				total += p.Observed
				if p.Z > maxZ {
					maxZ = p.Z
				}
				if p.ForestScore > maxF {
					maxF = p.ForestScore
				}
				if p.Anomalous {
					days = append(days, p.Day.Format("01-02"))
				}
			}
			fmt.Fprintf(tw, "%s\t%d\t%.2f\t%.1f\t%.2f\t%s\n", s.Key, len(s.Points), total, maxZ, maxF, orDash(strings.Join(days, ",")))
		}
		return tw.Flush()
	}
	for i := range all {
		s := &all[i]
		if s.Key != *series {
			continue
		}
		if err := anomaly.Score(s, anomaly.Config{}); err != nil {
			return fmt.Errorf("anomalies: %s: %w", s.Key, err)
		}
		fmt.Fprintln(tw, "DAY\tOBSERVED\tTREND\tSEASONAL\tRESIDUAL\tZ\tIFOREST\tFLAG")
		for _, p := range s.Points {
			flag := ""
			if p.Anomalous {
				flag = "ANOMALY"
			}
			fmt.Fprintf(tw, "%s\t%.2f\t%.2f\t%+.2f\t%+.2f\t%.1f\t%.2f\t%s\n", p.Day.Format("2006-01-02 Mon"), p.Observed, p.Trend, p.Seasonal, p.Residual, p.Z, p.ForestScore, flag)
		}
		return tw.Flush()
	}
	return fmt.Errorf("anomalies: no series %q", *series)
}

func cmdRemediate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("remediate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	provider := fs.String("llm-provider", "ollama", "ollama (default, local), openai (opt-in), or replay")
	model := fs.String("model", "", "model name (default llama3.1:8b for ollama, gpt-4o-mini for openai)")
	baseURL := fs.String("llm-url", "", "backend base URL (default $OLLAMA_HOST or http://127.0.0.1:11434)")
	fixture := fs.String("fixture", "", "recorded fixture for --llm-provider replay")
	record := fs.String("record", "", "save the model's responses as a fixture at this path")
	allowRemote := fs.Bool("allow-remote", false, "permit a non-local provider (data is redacted first)")
	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return usageError(err.Error())
	}
	if len(rest) != 1 {
		return usageError("remediate: want exactly one finding ID (see `csg analyze`)")
	}
	cfg := llm.Config{Provider: llm.Provider(*provider), Model: *model, BaseURL: *baseURL, AllowRemote: *allowRemote}
	if cfg.Provider == llm.ProviderReplay {
		if *fixture == "" {
			return usageError("remediate: --llm-provider replay needs --fixture")
		}
		b, _, err := llm.LoadFixture(*fixture)
		if err != nil {
			return err
		}
		cfg.Backend = b
	}
	engine, err := llm.New(cfg)
	if err != nil {
		if errors.Is(err, llm.ErrRemoteNotAllowed) || errors.Is(err, llm.ErrUnknownProvider) {
			return usageError("remediate: " + err.Error())
		}
		return err
	}
	var recorder *llm.RecordingBackend
	if *record != "" {
		inner := cfg.Backend
		if inner == nil {
			inner = llm.OllamaBackend{BaseURL: firstNonEmpty(*baseURL, os.Getenv("OLLAMA_HOST"), "http://127.0.0.1:11434"), Model: firstNonEmpty(*model, "llama3.1:8b")}
		}
		recorder = &llm.RecordingBackend{Inner: inner}
		cfg.Backend = recorder
		if engine, err = llm.New(cfg); err != nil {
			return err
		}
	}

	curRecs, events, resources, err := loadAll(ctx, *db)
	if err != nil {
		return fmt.Errorf("remediate: %w", err)
	}
	findings, err := findAll(ctx, curRecs, events, resources, time.Now().UTC())
	if err != nil {
		return err
	}
	var target *models.Finding
	for i := range findings {
		if findings[i].ID == rest[0] {
			target = &findings[i]
		}
	}
	if target == nil {
		return fmt.Errorf("remediate: no finding %q (run `csg analyze` for IDs)", rest[0])
	}
	fmt.Fprintf(out, "Finding:  %s\nRule:     %s %s\nResource: %s\nBackend:  %s\n\n", target.Title, target.RuleID,
		strings.Join(target.ComplianceControls, ","), target.Resource.TerraformAddress, *provider)
	rem, err := engine.GenerateAndVerify(ctx, *target, resources)
	if err != nil {
		return err
	}
	if recorder != nil {
		if err := recorder.Save(*record, target.ID, time.Now()); err != nil {
			return err
		}
		fmt.Fprintf(out, "recorded %d response(s) to %s\n", len(recorder.Responses), *record)
	}
	for _, m := range rem.VerifierMessages {
		fmt.Fprintf(out, "  - %s\n", m)
	}
	if !rem.VerifierPassed {
		fmt.Fprintf(out, "\nNo verified patch. Manual fix: %s\n", rem.Summary)
		return nil
	}
	fmt.Fprintf(out, "\nVerified patch after %d attempt(s). Review it, then apply it yourself; csg never applies changes.\n\n%s", rem.Attempts, rem.TerraformPatch)
	return nil
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
