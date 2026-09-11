// Package prioritize implements the joint cost-x-risk prioritization algorithm
// that is the core research contribution of CloudSpendGuard.
//
// Score(f) = alpha * normalizedSavings(f)
//          + beta  * normalizedRisk(f)
//          - gamma * normalizedBlastRadius(f)
//
// Weights are tunable per stakeholder profile (devops, finops, security, cxo).
package prioritize

import (
	"sort"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// Weights parameterize the joint scoring function.
type Weights struct {
	Alpha float64 // cost weight
	Beta  float64 // risk-reduction weight
	Gamma float64 // blast-radius penalty
}

// Profiles are convenience presets.
var Profiles = map[string]Weights{
	"devops":   {Alpha: 0.4, Beta: 0.5, Gamma: 0.3},
	"finops":   {Alpha: 0.7, Beta: 0.2, Gamma: 0.2},
	"security": {Alpha: 0.2, Beta: 0.7, Gamma: 0.3},
	"cxo":      {Alpha: 0.5, Beta: 0.5, Gamma: 0.4},
}

// Score computes the joint score for a single finding, given the max observed
// savings across the batch (for normalization).
func Score(f models.Finding, maxSavings float64, w Weights) float64 {
	var savings float64
	if maxSavings > 0 {
		savings = f.MonthlySavingsUSD / maxSavings
	}
	risk := f.RiskReductionScore / 100.0
	blast := f.BlastRadiusScore / 100.0
	return w.Alpha*savings + w.Beta*risk - w.Gamma*blast
}

// Prioritize sorts findings in-place by their joint score, descending.
// Returns the slice for convenience.
func Prioritize(findings []models.Finding, w Weights) []models.Finding {
	var maxSavings float64
	for _, f := range findings {
		if f.MonthlySavingsUSD > maxSavings {
			maxSavings = f.MonthlySavingsUSD
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return Score(findings[i], maxSavings, w) > Score(findings[j], maxSavings, w)
	})
	return findings
}
