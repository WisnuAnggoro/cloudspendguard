package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/anomaly"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cloudtrail"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/internal/prioritize"
	"github.com/wisnuanggoro/cloudspendguard/internal/report"
	"github.com/wisnuanggoro/cloudspendguard/internal/sample"
	"github.com/wisnuanggoro/cloudspendguard/internal/store"
)

// inputs are the files `csg run` found in an input directory.
type inputs struct {
	cur, cloudtrail, terraform []string
}

func (in inputs) empty() bool { return len(in.cur)+len(in.cloudtrail)+len(in.terraform) == 0 }

// discoverInputs sorts the top-level files of dir into the three sources by
// name: .parquet, .csv, and .csv.gz are CUR exports; .json files that start
// with a "Records" array, and all .json.gz files, are CloudTrail logs; .tfstate files are Terraform state, and a directory that
// holds *.tf files is read as Terraform configuration. Sub-directories are
// ignored so fixtures and recorded model answers next to the data are never
// mistaken for input.
func discoverInputs(dir string) (inputs, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return inputs{}, err
	}
	var in inputs
	hasTF := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		p := filepath.Join(dir, e.Name())
		switch {
		case strings.HasSuffix(name, ".parquet"), strings.HasSuffix(name, ".csv"), strings.HasSuffix(name, ".csv.gz"):
			in.cur = append(in.cur, p)
		case strings.HasSuffix(name, ".tfstate"):
			in.terraform = append(in.terraform, p)
		case strings.HasSuffix(name, ".json.gz"):
			in.cloudtrail = append(in.cloudtrail, p)
		case strings.HasSuffix(name, ".json"):
			if looksLikeCloudTrail(p) {
				in.cloudtrail = append(in.cloudtrail, p)
			}
		case strings.HasSuffix(name, ".tf"):
			hasTF = true
		}
	}
	if hasTF {
		in.terraform = append(in.terraform, dir)
	}
	return in, nil
}

// looksLikeCloudTrail reports whether a .json file starts like a CloudTrail
// log, a top-level object with a "Records" array. Other JSON files that sit
// next to the data (label files, configuration) are skipped, not parsed.
func looksLikeCloudTrail(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 4096)
	n, _ := f.Read(head)
	return strings.Contains(string(head[:n]), `"Records"`)
}

type stage struct {
	name string
	took time.Duration
}

func cmdRun(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	input := fs.String("input", "", "directory with CUR, CloudTrail, and Terraform files")
	useSample := fs.Bool("sample", false, "analyze the bundled sample account (no files, no AWS credentials)")
	reportPath := fs.String("report", "", "write a report to this path (format from the extension, or --format)")
	format := fs.String("format", "", "report format: html, markdown, json, or sarif")
	profile := fs.String("profile", "devops", "weighting profile")
	weights := fs.String("weights", "", "explicit alpha,beta,gamma (overrides --profile)")
	top := fs.Int("top", 0, "show only the first N backlog items (0 = all)")
	db := fs.String("db", "", "keep the local database at this path (default: temporary, deleted after the run)")
	stats := fs.Bool("stats", false, "print stage timings and memory use")
	quiet := fs.Bool("quiet", false, "do not print the backlog table")
	sarifURI := fs.String("sarif-uri", "", "file path SARIF results point at (default infrastructure.tf)")
	if rest, err := parseInterspersed(fs, args); err != nil {
		return usageError(err.Error())
	} else if len(rest) > 0 {
		return usageError("run: unexpected argument " + rest[0])
	}
	if *useSample == (*input != "") {
		return usageError("run: pass exactly one of --sample or --input <dir>")
	}
	w, name, err := resolveWeights(*profile, *weights)
	if err != nil {
		return usageError(strings.Replace(err.Error(), "analyze:", "run:", 1))
	}
	var rf report.Format
	if *reportPath != "" {
		switch {
		case *format != "":
			if rf, err = report.ParseFormat(*format); err != nil {
				return usageError("run: " + err.Error())
			}
		default:
			f, ok := report.FormatForPath(*reportPath)
			if !ok {
				return usageError("run: cannot tell the report format from " + *reportPath + "; add --format")
			}
			rf = f
		}
	}

	var stages []stage
	mark := func(n string, since time.Time) { stages = append(stages, stage{n, time.Since(since)}) }
	began := time.Now()

	dir := *input
	tmp, err := os.MkdirTemp("", "csg-run-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if *useSample {
		dir = filepath.Join(tmp, "sample-account")
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		if err := sample.WriteTo(dir); err != nil {
			return err
		}
	}
	found, err := discoverInputs(dir)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if found.empty() {
		return fmt.Errorf("run: no CUR, CloudTrail, or Terraform files in %s", dir)
	}

	// With --db the data goes through the persistent store, so it can be
	// queried later. Without it the billing data stays in memory: events and
	// Terraform resources are tiny, but a CUR export can hold millions of
	// rows, and the SQLite round trip was 95% of the run time at one million
	// line items (see docs/evaluation.md). store.DedupeCUR returns exactly
	// what the round trip would, which a test proves.
	persist := *db != ""
	dbPath := *db
	if !persist {
		dbPath = filepath.Join(tmp, "csg.db")
	}
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		return err
	}
	closeStore := func(e error) error {
		if cerr := st.Close(); e == nil {
			e = cerr
		}
		return e
	}

	t0 := time.Now()
	var memCUR []cur.Record
	for _, p := range found.cur {
		recs, err := cur.NewReader().Read(ctx, p)
		if err != nil {
			return closeStore(err)
		}
		if persist {
			if _, err := st.InsertCURRecords(ctx, recs); err != nil {
				return closeStore(err)
			}
		} else {
			memCUR = append(memCUR, recs...)
		}
	}
	for _, p := range found.cloudtrail {
		evs, err := cloudtrail.NewReader().Read(ctx, p)
		if err != nil {
			return closeStore(err)
		}
		if _, err := st.InsertCloudTrailEvents(ctx, evs); err != nil {
			return closeStore(err)
		}
	}
	for _, p := range found.terraform {
		res, err := tfstate.NewParser().Parse(ctx, p)
		if err != nil {
			return closeStore(err)
		}
		if _, err := st.InsertTerraformResources(ctx, res); err != nil {
			return closeStore(err)
		}
	}
	mark("ingest", t0)

	t0 = time.Now()
	curRecs := store.DedupeCUR(memCUR)
	var events []cloudtrail.Event
	var resources []tfstate.Resource
	if persist {
		if curRecs, err = st.LoadCURRecords(ctx); err != nil {
			return closeStore(err)
		}
	}
	if events, err = st.LoadCloudTrailEvents(ctx); err != nil {
		return closeStore(err)
	}
	if resources, err = st.LoadTerraformResources(ctx); err != nil {
		return closeStore(err)
	}
	mark("load", t0)

	err = runPipeline(ctx, out, pipelineArgs{
		curRecs: curRecs, events: events, resources: resources,
		w: w, profile: name, top: *top, quiet: *quiet, stats: *stats,
		reportPath: *reportPath, format: rf, sarifURI: *sarifURI, sample: *useSample,
		nCUR: len(curRecs), nEv: len(events), nTF: len(resources), stages: &stages, began: began,
	})
	return closeStore(err)
}

type pipelineArgs struct {
	curRecs        []cur.Record
	events         []cloudtrail.Event
	resources      []tfstate.Resource
	w              prioritize.Weights
	profile        string
	top            int
	quiet, stats   bool
	reportPath     string
	format         report.Format
	sarifURI       string
	sample         bool
	nCUR, nEv, nTF int
	stages         *[]stage
	began          time.Time
}

func runPipeline(ctx context.Context, out io.Writer, a pipelineArgs) error {
	t0 := time.Now()
	findings, err := findAll(ctx, a.curRecs, a.events, a.resources, time.Now().UTC())
	if err != nil {
		return err
	}
	*a.stages = append(*a.stages, stage{"analyze", time.Since(t0)})

	t0 = time.Now()
	ranked := prioritize.Rank(findings, a.w)
	total := len(ranked)
	if a.top > 0 && a.top < len(ranked) {
		ranked = ranked[:a.top]
	}
	*a.stages = append(*a.stages, stage{"prioritize", time.Since(t0)})
	t0 = time.Now()
	anoms := anomalies(a.curRecs)
	*a.stages = append(*a.stages, stage{"anomaly-list", time.Since(t0)})

	if !a.quiet {
		if err := printBacklog(out, a.profile, a.w, ranked, total, a.nCUR, a.nEv, a.nTF); err != nil {
			return err
		}
	}
	if a.reportPath != "" {
		t0 = time.Now()
		rep := report.Report{
			Version: version, GeneratedAt: time.Now().UTC(), Profile: a.profile, Weights: a.w,
			Inputs:   report.Inputs{CUR: a.nCUR, Events: a.nEv, Terraform: a.nTF, SampleData: a.sample},
			Findings: ranked, Anomalies: anoms, ArtifactURI: a.sarifURI,
		}
		if err := writeReport(a.reportPath, a.format, rep); err != nil {
			return err
		}
		*a.stages = append(*a.stages, stage{"report", time.Since(t0)})
		fmt.Fprintf(out, "\nWrote %s report to %s\n", a.format, a.reportPath)
	}
	if a.stats {
		printStats(out, *a.stages, time.Since(a.began), a.nCUR, a.nEv, a.nTF)
	}
	return nil
}

// anomalies returns the billing series with at least one flagged day.
func anomalies(recs []cur.Record) []report.Anomaly {
	var out []report.Anomaly
	all := anomaly.BuildSeries(recs)
	for i := range all {
		s := &all[i]
		if err := anomaly.Score(s, anomaly.Config{}); err != nil {
			continue // series too short to decompose
		}
		var days []string
		for _, p := range s.Points {
			if p.Anomalous {
				days = append(days, p.Day.Format("2006-01-02"))
			}
		}
		if len(days) > 0 {
			out = append(out, report.Anomaly{Series: s.Key, Days: days})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Series < out[j].Series })
	return out
}

func writeReport(path string, format report.Format, rep report.Report) error {
	r, err := report.NewRenderer(format)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	renderErr := r.Render(f, rep)
	closeErr := f.Close()
	return errors.Join(renderErr, closeErr)
}

func printStats(out io.Writer, stages []stage, total time.Duration, nCUR, nEv, nTF int) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(out, "\nStats: %d CUR line items, %d CloudTrail events, %d Terraform resources\n", nCUR, nEv, nTF)
	for _, s := range stages {
		fmt.Fprintf(out, "  %-11s %10s\n", s.name, s.took.Round(time.Microsecond))
	}
	fmt.Fprintf(out, "  %-11s %10s\n", "total", total.Round(time.Microsecond))
	if total > 0 && nCUR > 0 {
		fmt.Fprintf(out, "  throughput  %10.0f CUR line items per second (end to end)\n", float64(nCUR)/total.Seconds())
	}
	fmt.Fprintf(out, "  memory      %7.1f MiB obtained from the OS, %.1f MiB allocated in total, %d GC cycles\n",
		float64(m.Sys)/(1<<20), float64(m.TotalAlloc)/(1<<20), m.NumGC)
	if rss, ok := peakRSS(); ok {
		fmt.Fprintf(out, "  peak RSS    %7.1f MiB\n", float64(rss)/(1<<20))
	}
}

// cmdReport renders a report from an existing local database.
func cmdReport(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	db := fs.String("db", defaultDB(), "local database file")
	format := fs.String("format", "", "html, markdown, json, or sarif (default: from --out, else markdown)")
	outPath := fs.String("out", "", "write to this file instead of standard output")
	profile := fs.String("profile", "devops", "weighting profile")
	weights := fs.String("weights", "", "explicit alpha,beta,gamma (overrides --profile)")
	top := fs.Int("top", 0, "include only the first N backlog items (0 = all)")
	sarifURI := fs.String("sarif-uri", "", "file path SARIF results point at (default infrastructure.tf)")
	if rest, err := parseInterspersed(fs, args); err != nil {
		return usageError(err.Error())
	} else if len(rest) > 0 {
		return usageError("report: unexpected argument " + rest[0])
	}
	w, name, err := resolveWeights(*profile, *weights)
	if err != nil {
		return usageError(strings.Replace(err.Error(), "analyze:", "report:", 1))
	}
	rf := report.FormatMarkdown
	switch {
	case *format != "":
		if rf, err = report.ParseFormat(*format); err != nil {
			return usageError("report: " + err.Error())
		}
	case *outPath != "":
		if f, ok := report.FormatForPath(*outPath); ok {
			rf = f
		}
	}
	curRecs, events, resources, err := loadAll(ctx, *db)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}
	findings, err := findAll(ctx, curRecs, events, resources, time.Now().UTC())
	if err != nil {
		return err
	}
	ranked := prioritize.Rank(findings, w)
	if *top > 0 && *top < len(ranked) {
		ranked = ranked[:*top]
	}
	rep := report.Report{
		Version: version, GeneratedAt: time.Now().UTC(), Profile: name, Weights: w,
		Inputs:   report.Inputs{CUR: len(curRecs), Events: len(events), Terraform: len(resources)},
		Findings: ranked, Anomalies: anomalies(curRecs), ArtifactURI: *sarifURI,
	}
	if *outPath == "" {
		r, err := report.NewRenderer(rf)
		if err != nil {
			return err
		}
		return r.Render(out, rep)
	}
	if err := writeReport(*outPath, rf, rep); err != nil {
		return err
	}
	fmt.Fprintf(out, "Wrote %s report with %d finding(s) to %s\n", rf, len(ranked), *outPath)
	return nil
}
