package prioritize

import (
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

func TestPrioritize_FinOpsProfilePrefersSavings(t *testing.T) {
	findings := []models.Finding{
		{ID: "a", MonthlySavingsUSD: 10, RiskReductionScore: 90, BlastRadiusScore: 10},
		{ID: "b", MonthlySavingsUSD: 500, RiskReductionScore: 30, BlastRadiusScore: 10},
	}
	got := Prioritize(findings, Profiles["finops"])
	if got[0].ID != "b" {
		t.Fatalf("finops profile should prioritize big savings; got %q first", got[0].ID)
	}
}

func TestPrioritize_SecurityProfilePrefersRisk(t *testing.T) {
	findings := []models.Finding{
		{ID: "a", MonthlySavingsUSD: 10, RiskReductionScore: 90, BlastRadiusScore: 10},
		{ID: "b", MonthlySavingsUSD: 500, RiskReductionScore: 30, BlastRadiusScore: 10},
	}
	got := Prioritize(findings, Profiles["security"])
	if got[0].ID != "a" {
		t.Fatalf("security profile should prioritize high risk-reduction; got %q first", got[0].ID)
	}
}

func TestPrioritize_HighBlastRadiusIsPenalized(t *testing.T) {
	findings := []models.Finding{
		{ID: "safe", MonthlySavingsUSD: 100, RiskReductionScore: 50, BlastRadiusScore: 0},
		{ID: "risky", MonthlySavingsUSD: 100, RiskReductionScore: 50, BlastRadiusScore: 100},
	}
	got := Prioritize(findings, Profiles["devops"])
	if got[0].ID != "safe" {
		t.Fatalf("high blast radius should be penalized; got %q first", got[0].ID)
	}
}
