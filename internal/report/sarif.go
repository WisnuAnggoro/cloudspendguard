package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

type sarifRenderer struct{}

// The structs below are the subset of SARIF 2.1.0 that GitHub code scanning
// reads (https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning).

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	Help             *sarifText     `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// level maps a severity to a SARIF result level. Cost findings have no
// severity and are reported as notes so they never fail a code-scanning gate.
func level(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	}
	return "note"
}

// Render writes a SARIF 2.1.0 log with one rule per distinct rule ID and one
// result per finding, in backlog order.
func (sarifRenderer) Render(w io.Writer, r Report) error {
	uri := r.ArtifactURI
	if uri == "" {
		uri = "infrastructure.tf"
	}
	ruleIndex := map[string]int{}
	var ids []string
	byRule := map[string]models.Finding{}
	for _, f := range r.Findings {
		if _, ok := byRule[f.RuleID]; !ok {
			byRule[f.RuleID] = f.Finding
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for i, id := range ids {
		f := byRule[id]
		ruleIndex[id] = i
		props := map[string]any{"kind": string(f.Kind), "tags": append([]string{string(f.Kind)}, f.ComplianceControls...)}
		rule := sarifRule{ID: id, Name: id, ShortDescription: sarifText{Text: f.Title}, Properties: props}
		if f.SuggestedRemediation != nil {
			rule.Help = &sarifText{Text: f.SuggestedRemediation.Summary}
		}
		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		name := f.Resource.TerraformAddress
		if name == "" {
			name = f.Resource.ResourceID
		}
		results = append(results, sarifResult{
			RuleID: f.RuleID, RuleIndex: ruleIndex[f.RuleID], Level: level(f.Severity),
			Message: sarifText{Text: f.Title + ": " + f.Resource.ResourceID + ". " + f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}, Region: sarifRegion{StartLine: 1}},
				LogicalLocations: []sarifLogical{{Name: name, FullyQualifiedName: f.Resource.Service + "/" + f.Resource.ResourceID, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{"csgFindingId/v1": f.ID},
			Properties: map[string]any{
				"rank": f.Rank, "score": round3(f.Score), "kind": string(f.Kind),
				"monthlySavingsUsd": f.MonthlySavingsUSD, "complianceControls": f.ComplianceControls,
			},
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "CloudSpendGuard", Version: r.Version, InformationURI: "https://github.com/wisnuanggoro/cloudspendguard", Rules: rules}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func round3(v float64) float64 { return float64(int(v*1000+0.5*sign(v))) / 1000 }

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}
