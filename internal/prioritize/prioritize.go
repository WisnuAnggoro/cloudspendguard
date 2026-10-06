// Package prioritize implements the joint cost-x-risk prioritization algorithm
// (module M7) that is the core research contribution of CloudSpendGuard.
//
//	S(f) = alpha * savings(f) + beta * risk(f) - gamma * blast(f)
//
// Each component is normalized to [0, 1] before weighting:
//
//   - savings(f) = ln(1 + USD_f) / ln(1 + max USD in the batch). The log
//     scale keeps one large saving (a cost anomaly, say) from compressing
//     every other saving to nearly zero, which a linear max-normalization
//     does and which hands the ranking to risk alone.
//   - risk(f)    = RiskReductionScore / 100
//   - blast(f)   = BlastRadiusScore / 100
//
// Weights are tunable per stakeholder profile (devops, finops, security, cxo)
// or with explicit coefficients. Every ranked item carries its component
// subscores so the ranking can be audited rather than trusted (RAID R-08).
package prioritize

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// Weights parameterize the joint scoring function.
type Weights struct {
	Alpha float64 `json:"alpha"` // cost weight
	Beta  float64 `json:"beta"`  // risk-reduction weight
	Gamma float64 `json:"gamma"` // blast-radius penalty
}

// Profiles are convenience presets.
var Profiles = map[string]Weights{
	"devops":   {Alpha: 0.4, Beta: 0.5, Gamma: 0.3},
	"finops":   {Alpha: 0.7, Beta: 0.2, Gamma: 0.2},
	"security": {Alpha: 0.2, Beta: 0.7, Gamma: 0.3},
	"cxo":      {Alpha: 0.5, Beta: 0.5, Gamma: 0.4},
}

// ErrInvalidWeights is returned for negative, non-finite, or all-zero weights.
var ErrInvalidWeights = errors.New("prioritize: weights must be finite, non-negative, and alpha + beta > 0")

// Validate rejects weights that would make the ranking meaningless.
func (w Weights) Validate() error {
	for _, v := range []float64{w.Alpha, w.Beta, w.Gamma} {
		if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return ErrInvalidWeights
		}
	}
	if w.Alpha+w.Beta == 0 {
		return ErrInvalidWeights
	}
	return nil
}

// ParseWeights reads "alpha,beta,gamma", for example "0.6,0.3,0.1".
func ParseWeights(s string) (Weights, error) {
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return Weights{}, fmt.Errorf("prioritize: want alpha,beta,gamma, got %q", s)
	}
	var v [3]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return Weights{}, fmt.Errorf("prioritize: %q: %w", p, err)
		}
		v[i] = f
	}
	w := Weights{Alpha: v[0], Beta: v[1], Gamma: v[2]}
	return w, w.Validate()
}

// Ranked is one backlog item with its score broken down into components.
type Ranked struct {
	models.Finding
	Rank    int     `json:"rank"`
	Score   float64 `json:"score"`
	Savings float64 `json:"savings_component"` // normalized, before alpha
	Risk    float64 `json:"risk_component"`    // normalized, before beta
	Blast   float64 `json:"blast_component"`   // normalized, before gamma
}

// Normalize maps a finding's raw fields to [0, 1] components.
func Normalize(f models.Finding, maxSavings float64) (savings, risk, blast float64) {
	if maxSavings > 0 && f.MonthlySavingsUSD > 0 {
		savings = math.Log1p(f.MonthlySavingsUSD) / math.Log1p(maxSavings)
	}
	return clamp01(savings), clamp01(f.RiskReductionScore / 100), clamp01(f.BlastRadiusScore / 100)
}

// Score computes the joint score for a single finding, given the largest
// saving in the batch (for normalization).
func Score(f models.Finding, maxSavings float64, w Weights) float64 {
	s, r, b := Normalize(f, maxSavings)
	return w.Alpha*s + w.Beta*r - w.Gamma*b
}

// Rank scores every finding and returns them in descending score order.
// Ties are broken by severity (higher first) and then by finding ID, so the
// output is fully deterministic for golden-file tests and diffable reports.
func Rank(findings []models.Finding, w Weights) []Ranked {
	var maxSavings float64
	for _, f := range findings {
		if f.MonthlySavingsUSD > maxSavings {
			maxSavings = f.MonthlySavingsUSD
		}
	}
	out := make([]Ranked, len(findings))
	for i, f := range findings {
		s, r, b := Normalize(f, maxSavings)
		out[i] = Ranked{Finding: f, Score: w.Alpha*s + w.Beta*r - w.Gamma*b, Savings: s, Risk: r, Blast: b}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if d := out[i].Score - out[j].Score; math.Abs(d) > 1e-12 {
			return d > 0
		}
		if a, b := severityRank[out[i].Severity], severityRank[out[j].Severity]; a != b {
			return a > b
		}
		return out[i].ID < out[j].ID
	})
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// Prioritize sorts findings in place by their joint score, descending, and
// returns the slice for convenience.
func Prioritize(findings []models.Finding, w Weights) []models.Finding {
	for i, r := range Rank(findings, w) {
		findings[i] = r.Finding
	}
	return findings
}

var severityRank = map[models.Severity]int{
	models.SeverityInfo: 1, models.SeverityLow: 2, models.SeverityMedium: 3, models.SeverityHigh: 4, models.SeverityCritical: 5,
}

func clamp01(v float64) float64 {
	switch {
	case v < 0 || math.IsNaN(v):
		return 0
	case v > 1:
		return 1
	}
	return v
}
