// Package models contains the public data types shared across CloudSpendGuard packages.
package models

import "time"

// Severity of a security finding.
type Severity string

// Severity levels, lowest to highest.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// FindingKind distinguishes cost-waste findings from security-posture findings.
type FindingKind string

// Finding kinds.
const (
	KindCost     FindingKind = "cost"
	KindSecurity FindingKind = "security"
)

// Finding is a single actionable item surfaced by an analyzer.
type Finding struct {
	ID                   string       `json:"id"`
	Kind                 FindingKind  `json:"kind"`
	RuleID               string       `json:"rule_id"`
	Title                string       `json:"title"`
	Description          string       `json:"description"`
	Resource             ResourceRef  `json:"resource"`
	Severity             Severity     `json:"severity,omitempty"`
	MonthlySavingsUSD    float64      `json:"monthly_savings_usd,omitempty"`
	RiskReductionScore   float64      `json:"risk_reduction_score,omitempty"` // 0-100
	BlastRadiusScore     float64      `json:"blast_radius_score,omitempty"`   // 0-100 (higher = riskier to change)
	ComplianceControls   []string     `json:"compliance_controls,omitempty"`  // e.g. "CIS-AWS-2.1.5", "PCI-DSS-2.2"
	SuggestedRemediation *Remediation `json:"suggested_remediation,omitempty"`
	DetectedAt           time.Time    `json:"detected_at"`
}

// ResourceRef identifies a cloud resource.
type ResourceRef struct {
	Provider   string            `json:"provider"` // "aws"
	Service    string            `json:"service"`  // "ec2", "s3", "rds"
	ResourceID string            `json:"resource_id"`
	Region     string            `json:"region,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	// TerraformAddress is the resource address in Terraform state, e.g.
	// "aws_instance.legacy_reporting". Empty when the resource is not managed
	// by Terraform (for example, evidence that comes only from CloudTrail).
	TerraformAddress string `json:"terraform_address,omitempty"`
}

// RemediationAction says what kind of change resolves a finding. Only
// ActionModify findings are eligible for an LLM-generated Terraform patch:
// deletions and investigations are left to a human by design.
type RemediationAction string

// Remediation actions.
const (
	ActionModify      RemediationAction = "modify"      // change arguments of one resource
	ActionDelete      RemediationAction = "delete"      // remove the resource
	ActionInvestigate RemediationAction = "investigate" // human analysis first (e.g. a cost anomaly)
)

// Remediation is a proposed fix, optionally including an LLM-generated Terraform patch.
type Remediation struct {
	Summary          string            `json:"summary"`
	Action           RemediationAction `json:"action,omitempty"`
	TerraformPatch   string            `json:"terraform_patch,omitempty"` // unified diff
	VerifierPassed   bool              `json:"verifier_passed"`
	VerifierMessages []string          `json:"verifier_messages,omitempty"`
	// Attempts is how many generate-then-verify rounds were used (0 when no
	// patch was requested).
	Attempts int `json:"attempts,omitempty"`
}
