package anomaly

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

var day0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// weekly returns n days of base + weekday seasonality + small noise, with
// spikes added on the given days.
func weekly(n int, base, amp float64, spikes map[int]float64, seed uint64) []float64 {
	rng := rand.New(rand.NewPCG(seed, 1))
	y := make([]float64, n)
	for i := range y {
		season := 0.0
		if wd := day0.AddDate(0, 0, i).Weekday(); wd == time.Saturday || wd == time.Sunday {
			season = -amp
		}
		y[i] = base + season + (rng.Float64()-0.5)*0.1*amp + spikes[i]
	}
	return y
}

func TestSTL_RecoversComponents(t *testing.T) {
	// Pure trend + pure seasonality, no noise: the residual must be ~0 and
	// the seasonal component must repeat with period 7.
	n := 42
	y := make([]float64, n)
	for i := range y {
		y[i] = 10 + 0.1*float64(i) + 3*math.Sin(2*math.Pi*float64(i)/7)
	}
	dec, err := STL(y, STLConfig{Period: 7})
	if err != nil {
		t.Fatal(err)
	}
	for i := range y {
		if got := dec.Trend[i] + dec.Seasonal[i] + dec.Residual[i]; math.Abs(got-y[i]) > 1e-9 {
			t.Fatalf("components must sum to y at %d: %v vs %v", i, got, y[i])
		}
	}
	for i := 7; i < n-7; i++ {
		if math.Abs(dec.Residual[i]) > 0.35 {
			t.Fatalf("residual[%d] = %.3f, want close to 0", i, dec.Residual[i])
		}
		if math.Abs(dec.Seasonal[i]-dec.Seasonal[i-7]) > 0.35 {
			t.Fatalf("seasonal component not periodic at %d", i)
		}
	}
	if dec.Trend[n-8] <= dec.Trend[7] {
		t.Fatal("trend should be increasing")
	}
}

func TestSTL_TooShort(t *testing.T) {
	if _, err := STL(make([]float64, 14), STLConfig{Period: 7}); !errors.Is(err, ErrSeriesTooShort) {
		t.Fatalf("want ErrSeriesTooShort, got %v", err)
	}
}

func TestSTL_RobustKeepsSpikeInResidual(t *testing.T) {
	y := weekly(30, 20, 6, map[int]float64{18: 60}, 1)
	robust, _ := STL(y, STLConfig{Period: 7, RobustnessIter: 5})
	plain, _ := STL(y, STLConfig{Period: 7})
	if robust.Residual[18] <= plain.Residual[18] {
		t.Fatalf("robust fit should leave more of the spike in the residual: robust %.2f, plain %.2f", robust.Residual[18], plain.Residual[18])
	}
	if robust.Residual[18] < 45 {
		t.Fatalf("robust residual at spike = %.2f, want most of the 60 spike", robust.Residual[18])
	}
}

func TestRobustZ(t *testing.T) {
	tests := []struct {
		name    string
		in      []float64
		wantMax int // index of the largest score, -1 for all-zero
	}{
		{"normal MAD", []float64{1, 2, 3, 2, 1, 2, 30}, 6},
		{"flat series falls back to mean absolute deviation", []float64{0, 0, 0, 0, 0, 0, 9}, 6},
		{"constant series scores zero", []float64{4, 4, 4, 4}, -1},
		// Regression test: residuals of a flat series are floating-point
		// noise. Before MinScaleUSD they scored z = 9.7 on an ordinary day.
		{"floating-point noise is not an outlier", []float64{1e-9, -2e-9, 3e-9, 0, 1e-9, -1e-9, 2e-8}, -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			z := RobustZ(tc.in)
			best, bestI := 0.0, -1
			for i, v := range z {
				if v > best && v >= 1 {
					best, bestI = v, i
				}
			}
			if bestI != tc.wantMax {
				t.Fatalf("argmax = %d (z = %v), want %d", bestI, z, tc.wantMax)
			}
			if tc.wantMax >= 0 && best < 3.5 {
				t.Fatalf("outlier z = %.2f, want >= 3.5", best)
			}
		})
	}
}

func TestIsolationForest_SeparatesOutlier(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 7))
	var data [][]float64
	for i := 0; i < 200; i++ {
		data = append(data, []float64{rng.NormFloat64(), rng.NormFloat64()})
	}
	data = append(data, []float64{8, 8})
	f := Fit(data, ForestConfig{Seed: 42})
	outlier, inlier := f.Score([]float64{8, 8}), f.Score([]float64{0, 0})
	if outlier < 0.65 || inlier > 0.5 || outlier <= inlier {
		t.Fatalf("outlier score %.3f, inlier score %.3f", outlier, inlier)
	}
	// Same seed, same forest: results must be reproducible (NFR3 tests rely on it).
	if again := Fit(data, ForestConfig{Seed: 42}).Score([]float64{8, 8}); again != outlier {
		t.Fatalf("non-deterministic forest: %v vs %v", again, outlier)
	}
	var empty *Forest
	if empty.Score([]float64{1}) != 0 {
		t.Fatal("nil forest scores 0")
	}
	if avgPathLength(1) != 0 || avgPathLength(2) != 1 {
		t.Fatal("c(n) base cases")
	}
	// Identical points cannot be split; the tree must terminate anyway.
	same := Fit([][]float64{{1, 1}, {1, 1}, {1, 1}}, ForestConfig{Trees: 3, Seed: 1})
	if s := same.Score([]float64{1, 1}); s <= 0 || s > 1 {
		t.Fatalf("score out of range: %v", s)
	}
}

func records(service, team string, y []float64) []cur.Record {
	var out []cur.Record
	for i, v := range y {
		s := day0.AddDate(0, 0, i)
		out = append(out, cur.Record{Service: service, Region: "eu-west-1", Tags: map[string]string{"team": team}, UnblendedCost: v, UsageStartDate: s, UsageEndDate: s.Add(24 * time.Hour)})
	}
	return out
}

func TestDetector(t *testing.T) {
	ctx := context.Background()
	quiet := weekly(30, 40, 8, nil, 3)
	spiky := weekly(30, 40, 8, map[int]float64{18: 90, 19: 70}, 4)
	tiny := weekly(30, 0.05, 0.01, map[int]float64{10: 0.5}, 5)

	tests := []struct {
		name      string
		recs      []cur.Record
		wantIDs   []string
		minExcess float64
	}{
		{"weekly seasonality alone is not an anomaly", records("AmazonEC2", "booking", quiet), nil, 0},
		{"two-day spike is one episode", records("AmazonEC2", "booking", spiky), []string{RuleID + ":AmazonEC2/booking:2026-09-19"}, 140},
		{"financially trivial spike is ignored", records("AmazonS3", "data", tiny), nil, 0},
		{"series too short is skipped", records("AmazonRDS", "x", quiet[:10]), nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detector{}.Detect(ctx, tc.recs, day0)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("want %d findings, got %d: %+v", len(tc.wantIDs), len(got), got)
			}
			for i, f := range got {
				if f.ID != tc.wantIDs[i] || f.Kind != models.KindCost || f.SuggestedRemediation.Action != models.ActionInvestigate {
					t.Fatalf("unexpected finding %+v", f)
				}
				if f.MonthlySavingsUSD < tc.minExcess || !strings.Contains(f.Description, "2026-09-19 to 2026-09-20") {
					t.Fatalf("excess %.2f, description %q", f.MonthlySavingsUSD, f.Description)
				}
				if f.Severity != models.SeverityHigh || f.Resource.Tags["team"] != "booking" {
					t.Fatalf("severity %s tags %v", f.Severity, f.Resource.Tags)
				}
			}
		})
	}

	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (Detector{}).Detect(cctx, records("AmazonEC2", "booking", spiky), day0); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if (Detector{}).RuleID() != RuleID {
		t.Fatal("rule id")
	}
}

func TestBuildSeries_FillsGapsAndGroupsUntagged(t *testing.T) {
	recs := []cur.Record{
		{Service: "AmazonEC2", UnblendedCost: 1, UsageStartDate: day0},
		{Service: "AmazonEC2", UnblendedCost: 2, UsageStartDate: day0.Add(3 * time.Hour)},
		{Service: "AmazonEC2", UnblendedCost: 5, UsageStartDate: day0.AddDate(0, 0, 2)},
		{Service: "AmazonEC2", UnblendedCost: 9}, // no usage date: ignored
	}
	s := BuildSeries(recs)
	if len(s) != 1 || s[0].Key != "AmazonEC2/untagged" || len(s[0].Points) != 3 {
		t.Fatalf("unexpected series %+v", s)
	}
	if s[0].Points[0].Observed != 3 || s[0].Points[1].Observed != 0 || s[0].Points[2].Observed != 5 {
		t.Fatalf("daily totals wrong: %+v", s[0].Points)
	}
	f := finding(s[0], []Point{{Day: day0, Observed: 10, Expected: 4, Z: 5, ForestScore: 0.7}}, day0)
	if f.Resource.Tags != nil || f.Severity != models.SeverityMedium || strings.Contains(f.Description, " to ") {
		t.Fatalf("single-day untagged finding: %+v", f)
	}
}

func TestHelpers(t *testing.T) {
	if mean(nil) != 0 || median(nil) != 0 || median([]float64{1, 3}) != 2 {
		t.Fatal("mean/median edge cases")
	}
	if movingAverage([]float64{1}, 3) != nil {
		t.Fatal("moving average shorter than window")
	}
	if loess(nil, nil, nil, 3, 0) != 0 {
		t.Fatal("empty loess")
	}
	scale(nil)
	rows := [][]float64{{1, 5}, {1, 7}}
	scale(rows)
	if rows[0][0] != 0 || rows[1][1] != 1 {
		t.Fatalf("scale: %v", rows)
	}
	w := robustnessWeights([]float64{1, 1, 1, 5}, []float64{1, 1, 1, 1}, make([]float64, 4))
	if w[0] != 1 || w[3] != 0 {
		t.Fatalf("flat-series robustness weights: %v", w)
	}
	cfg := STLConfig{Period: 1, SeasonalSpan: 8, RobustnessIter: -1}.withDefaults()
	if cfg.Period != 7 || cfg.SeasonalSpan != 9 || cfg.RobustnessIter != 0 || cfg.TrendSpan%2 == 0 {
		t.Fatalf("defaults: %+v", cfg)
	}
}
