package prioritize

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

func ids(rs []Ranked) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}
	return strings.Join(out, ",")
}

// TestRank is the table-driven black-box specification of M7: given a batch
// of findings and a weight profile, the expected order is stated up front.
func TestRank(t *testing.T) {
	cheapRisky := models.Finding{ID: "a", MonthlySavingsUSD: 10, RiskReductionScore: 90, BlastRadiusScore: 10}
	bigSaving := models.Finding{ID: "b", MonthlySavingsUSD: 500, RiskReductionScore: 30, BlastRadiusScore: 10}
	safe := models.Finding{ID: "safe", MonthlySavingsUSD: 100, RiskReductionScore: 50, BlastRadiusScore: 0}
	risky := models.Finding{ID: "risky", MonthlySavingsUSD: 100, RiskReductionScore: 50, BlastRadiusScore: 100}

	tests := []struct {
		name     string
		findings []models.Finding
		weights  Weights
		want     string
	}{
		{"finops profile prefers big savings", []models.Finding{cheapRisky, bigSaving}, Profiles["finops"], "b,a"},
		{"security profile prefers risk reduction", []models.Finding{cheapRisky, bigSaving}, Profiles["security"], "a,b"},
		{"high blast radius is penalized", []models.Finding{risky, safe}, Profiles["devops"], "safe,risky"},
		{"gamma = 0 ignores blast radius, tie broken by ID", []models.Finding{safe, risky}, Weights{Alpha: 1, Beta: 1}, "risky,safe"},
		{"pure cost weights rank by savings", []models.Finding{cheapRisky, safe, bigSaving}, Weights{Alpha: 1}, "b,safe,a"},
		{"pure risk weights rank by risk", []models.Finding{bigSaving, safe, cheapRisky}, Weights{Beta: 1}, "a,safe,b"},
		{"empty batch", nil, Profiles["cxo"], ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Rank(tc.findings, tc.weights)
			if ids(got) != tc.want {
				t.Fatalf("order = %s, want %s", ids(got), tc.want)
			}
			for i, r := range got {
				if r.Rank != i+1 {
					t.Fatalf("rank numbering broken: %+v", r)
				}
				if i > 0 && got[i-1].Score < r.Score {
					t.Fatalf("not sorted by score: %v then %v", got[i-1].Score, r.Score)
				}
			}
		})
	}
}

// TestRank_SeverityBreaksTies covers the deterministic tie-break that the
// golden-file tests for the CLI depend on.
func TestRank_SeverityBreaksTies(t *testing.T) {
	fs := []models.Finding{
		{ID: "z-low", Severity: models.SeverityLow, RiskReductionScore: 50},
		{ID: "y-critical", Severity: models.SeverityCritical, RiskReductionScore: 50},
		{ID: "x-low", Severity: models.SeverityLow, RiskReductionScore: 50},
	}
	if got := ids(Rank(fs, Profiles["devops"])); got != "y-critical,x-low,z-low" {
		t.Fatalf("order = %s", got)
	}
}

// TestNormalize_LogScaleKeepsSmallSavingsVisible is a white-box test of the
// normalization choice. With linear max-normalization a USD 5,000 anomaly
// would push a USD 40 saving down to 0.008; on the log scale it keeps 0.44.
func TestNormalize_LogScaleKeepsSmallSavingsVisible(t *testing.T) {
	s, r, b := Normalize(models.Finding{MonthlySavingsUSD: 40, RiskReductionScore: 150, BlastRadiusScore: -5}, 5000)
	if math.Abs(s-math.Log1p(40)/math.Log1p(5000)) > 1e-12 || s < 0.4 {
		t.Fatalf("savings component = %.4f", s)
	}
	if r != 1 || b != 0 {
		t.Fatalf("risk and blast must be clamped to [0,1]: %v %v", r, b)
	}
	if s, _, _ := Normalize(models.Finding{MonthlySavingsUSD: 40}, 0); s != 0 {
		t.Fatal("zero max savings must not divide by zero")
	}
	if s, _, _ := Normalize(models.Finding{MonthlySavingsUSD: 5000}, 5000); s != 1 {
		t.Fatal("largest saving normalizes to 1")
	}
	if clamp01(math.NaN()) != 0 {
		t.Fatal("NaN clamps to 0")
	}
}

func TestScore_MatchesFormula(t *testing.T) {
	f := models.Finding{MonthlySavingsUSD: 99, RiskReductionScore: 40, BlastRadiusScore: 20}
	w := Weights{Alpha: 0.5, Beta: 0.3, Gamma: 0.2}
	want := 0.5*math.Log1p(99)/math.Log1p(99) + 0.3*0.4 - 0.2*0.2
	if got := Score(f, 99, w); math.Abs(got-want) > 1e-12 {
		t.Fatalf("score = %v, want %v", got, want)
	}
}

func TestPrioritize_SortsInPlace(t *testing.T) {
	fs := []models.Finding{{ID: "low", RiskReductionScore: 10}, {ID: "high", RiskReductionScore: 90}}
	Prioritize(fs, Profiles["security"])
	if fs[0].ID != "high" {
		t.Fatalf("got %q first", fs[0].ID)
	}
}

func TestParseWeights(t *testing.T) {
	tests := []struct {
		in      string
		want    Weights
		wantErr bool
	}{
		{"0.6,0.3,0.1", Weights{0.6, 0.3, 0.1}, false},
		{" 1 , 0 , 0 ", Weights{1, 0, 0}, false},
		{"0.5,0.5", Weights{}, true},
		{"a,b,c", Weights{}, true},
		{"-1,0.5,0", Weights{}, true},
		{"0,0,1", Weights{}, true},
		{"NaN,1,0", Weights{}, true},
	}
	for _, tc := range tests {
		got, err := ParseWeights(tc.in)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%q: err = %v, wantErr %v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Fatalf("%q: got %+v", tc.in, got)
		}
	}
	if err := (Weights{Alpha: math.Inf(1), Beta: 1}).Validate(); !errors.Is(err, ErrInvalidWeights) {
		t.Fatal("infinite weight must be rejected")
	}
	for name, w := range Profiles {
		if err := w.Validate(); err != nil {
			t.Fatalf("profile %s invalid: %v", name, err)
		}
	}
}
