// Command evalscore computes precision, recall, and F1 for CloudSpendGuard,
// tfsec, and Checkov on the labeled Terraform fixtures in testdata/eval.
//
// Ground truth is labels.json: each entry says that one resource has one
// defect category. A tool finding is a true positive when it reports the same
// (resource, category) pair, a false positive when it reports a pair that is
// not labeled, and every labeled pair a tool misses is a false negative.
// Findings from rules that mapping.json does not list are out of scope.
//
// Usage:
//
//	go run ./tools/evalscore -dir testdata/eval -tfsec tfsec.json -checkov checkov.json
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
)

type pair struct{ addr, cat string }

type mapping struct {
	Categories map[string]string `json:"categories"`
	CSG        map[string]string `json:"csg"`
	Tfsec      map[string]string `json:"tfsec"`
	Checkov    map[string]string `json:"checkov"`
	Aliases    map[string]string `json:"aliases"`
}

type score struct{ tp, fp, fn int }

func (s score) precision() float64 { return ratio(s.tp, s.tp+s.fp) }
func (s score) recall() float64    { return ratio(s.tp, s.tp+s.fn) }
func (s score) f1() float64 {
	p, r := s.precision(), s.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(b, v))
}

// baseAddress trims attribute suffixes, so "aws_db_instance.b.publicly_accessible" becomes "aws_db_instance.b".
func baseAddress(a string, m mapping) string {
	if v, ok := m.Aliases[a]; ok {
		return v
	}
	parts := strings.Split(a, ".")
	if len(parts) > 2 && parts[0] != "data" {
		a = strings.Join(parts[:2], ".")
	}
	if v, ok := m.Aliases[a]; ok {
		return v
	}
	return a
}

func csgPredictions(dir string, m mapping) (map[pair]bool, time.Duration) {
	began := time.Now()
	ctx := context.Background()
	res, err := tfstate.NewParser().Parse(ctx, dir)
	must(err)
	findings, err := security.Analyze(ctx, security.Input{Resources: res, Now: time.Now().UTC()})
	must(err)
	out := map[pair]bool{}
	for _, f := range findings {
		cat, ok := m.CSG[f.RuleID]
		if !ok || f.Resource.TerraformAddress == "" {
			continue
		}
		out[pair{f.Resource.TerraformAddress, cat}] = true
	}
	return out, time.Since(began)
}

func tfsecPredictions(path string, m mapping) map[pair]bool {
	var doc struct {
		Results []struct {
			RuleID   string `json:"rule_id"`
			Resource string `json:"resource"`
		} `json:"results"`
	}
	readJSON(path, &doc)
	out := map[pair]bool{}
	for _, r := range doc.Results {
		if cat, ok := m.Tfsec[r.RuleID]; ok {
			out[pair{baseAddress(r.Resource, m), cat}] = true
		}
	}
	return out
}

func checkovPredictions(path string, m mapping) map[pair]bool {
	var doc struct {
		Results struct {
			Failed []struct {
				CheckID  string `json:"check_id"`
				Resource string `json:"resource"`
			} `json:"failed_checks"`
		} `json:"results"`
	}
	b, err := os.ReadFile(path)
	must(err)
	// Checkov emits one object, or an array of objects when several frameworks run.
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		var docs []struct {
			Results struct {
				Failed []struct {
					CheckID  string `json:"check_id"`
					Resource string `json:"resource"`
				} `json:"failed_checks"`
			} `json:"results"`
		}
		must(json.Unmarshal(b, &docs))
		if len(docs) > 0 {
			doc.Results = docs[0].Results
		}
	} else {
		must(json.Unmarshal(b, &doc))
	}
	out := map[pair]bool{}
	for _, r := range doc.Results.Failed {
		if cat, ok := m.Checkov[r.CheckID]; ok {
			out[pair{baseAddress(r.Resource, m), cat}] = true
		}
	}
	return out
}

func compare(truth, pred map[pair]bool, byCat map[string]*score) score {
	var total score
	bump := func(cat string, f func(*score)) {
		if byCat[cat] == nil {
			byCat[cat] = &score{}
		}
		f(byCat[cat])
	}
	for p := range pred {
		if truth[p] {
			total.tp++
			bump(p.cat, func(s *score) { s.tp++ })
		} else {
			total.fp++
			bump(p.cat, func(s *score) { s.fp++ })
		}
	}
	for p := range truth {
		if !pred[p] {
			total.fn++
			bump(p.cat, func(s *score) { s.fn++ })
		}
	}
	return total
}

func main() {
	dir := flag.String("dir", "testdata/eval", "directory with *.tf fixtures, labels.json, and mapping.json")
	tfsecPath := flag.String("tfsec", "", "tfsec JSON output (optional)")
	checkovPath := flag.String("checkov", "", "checkov JSON output (optional)")
	csvOut := flag.String("csv", "", "write per-category results to this CSV file")
	flag.Parse()

	var m mapping
	readJSON(*dir+"/mapping.json", &m)
	var lab struct {
		Labels []struct {
			Address  string `json:"address"`
			Category string `json:"category"`
		} `json:"labels"`
	}
	readJSON(*dir+"/labels.json", &lab)
	truth := map[pair]bool{}
	for _, l := range lab.Labels {
		truth[pair{l.Address, l.Category}] = true
	}

	type toolRun struct {
		name string
		pred map[pair]bool
	}
	csgPred, took := csgPredictions(*dir, m)
	runs := []toolRun{{"CloudSpendGuard", csgPred}}
	if *tfsecPath != "" {
		runs = append(runs, toolRun{"tfsec", tfsecPredictions(*tfsecPath, m)})
	}
	if *checkovPath != "" {
		runs = append(runs, toolRun{"Checkov", checkovPredictions(*checkovPath, m)})
	}

	fmt.Printf("Labeled defects: %d across %d categories. CloudSpendGuard parse and analyze: %s\n\n", len(truth), len(m.Categories), took.Round(time.Millisecond))
	fmt.Printf("%-16s %4s %4s %4s %9s %7s %6s\n", "TOOL", "TP", "FP", "FN", "PRECISION", "RECALL", "F1")
	cats := make([]string, 0, len(m.Categories))
	for c := range m.Categories {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	per := map[string]map[string]*score{}
	var w *csv.Writer
	if *csvOut != "" {
		f, err := os.Create(*csvOut)
		must(err)
		defer f.Close()
		w = csv.NewWriter(f)
		must(w.Write([]string{"tool", "category", "tp", "fp", "fn", "precision", "recall", "f1"}))
	}
	for _, r := range runs {
		byCat := map[string]*score{}
		t := compare(truth, r.pred, byCat)
		per[r.name] = byCat
		fmt.Printf("%-16s %4d %4d %4d %9.3f %7.3f %6.3f\n", r.name, t.tp, t.fp, t.fn, t.precision(), t.recall(), t.f1())
		if w != nil {
			must(w.Write([]string{r.name, "ALL", fmt.Sprint(t.tp), fmt.Sprint(t.fp), fmt.Sprint(t.fn), fmt.Sprintf("%.3f", t.precision()), fmt.Sprintf("%.3f", t.recall()), fmt.Sprintf("%.3f", t.f1())}))
		}
	}
	fmt.Printf("\nPer category (TP/FP/FN):\n%-16s", "CATEGORY")
	for _, r := range runs {
		fmt.Printf(" %-16s", r.name)
	}
	fmt.Println()
	for _, c := range cats {
		fmt.Printf("%-16s", c)
		for _, r := range runs {
			s := per[r.name][c]
			if s == nil {
				s = &score{}
			}
			fmt.Printf(" %-16s", fmt.Sprintf("%d/%d/%d", s.tp, s.fp, s.fn))
			if w != nil {
				must(w.Write([]string{r.name, c, fmt.Sprint(s.tp), fmt.Sprint(s.fp), fmt.Sprint(s.fn), fmt.Sprintf("%.3f", s.precision()), fmt.Sprintf("%.3f", s.recall()), fmt.Sprintf("%.3f", s.f1())}))
			}
		}
		fmt.Println()
	}
	if w != nil {
		w.Flush()
	}

	// List every disagreement so each number can be traced to a resource.
	fmt.Println("\nDisagreements with the labels:")
	for _, r := range runs {
		var lines []string
		for p := range r.pred {
			if !truth[p] {
				lines = append(lines, fmt.Sprintf("  %-16s FALSE POSITIVE %-12s %s", r.name, p.cat, p.addr))
			}
		}
		for p := range truth {
			if !r.pred[p] {
				lines = append(lines, fmt.Sprintf("  %-16s MISSED         %-12s %s", r.name, p.cat, p.addr))
			}
		}
		sort.Strings(lines)
		for _, l := range lines {
			fmt.Println(l)
		}
	}
}
