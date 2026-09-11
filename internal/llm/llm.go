// Package llm provides LLM-assisted remediation-patch generation with a
// generate-then-verify safety loop. Ollama is the default, local backend;
// OpenAI/Anthropic are opt-in only and require explicit user consent per the
// data-privacy mitigation in the Unit 2 assignment's ethics matrix (Table 1).
//
// Scaffolded in Unit 2 (Week 2). The client, sanitizer, prompt-injection
// guardrails, and adversarial test suite land in Unit 5 (Week 5), tagged
// v0.3.0-algo.
package llm

import (
	"context"
	"errors"

	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// ErrNotImplemented is returned by stubs until the Week 5 implementation lands.
var ErrNotImplemented = errors.New("llm: not implemented until Week 5 (v0.3.0-algo)")

// Provider identifies which backend generated a remediation.
type Provider string

const (
	// ProviderOllama is the default, local-only backend. No data leaves the machine.
	ProviderOllama Provider = "ollama"
	// ProviderOpenAI is opt-in only; requires --llm-provider=openai and triggers
	// the sanitizer/redaction pass before any request leaves the machine.
	ProviderOpenAI Provider = "openai"
	// ProviderAnthropic is opt-in only, same guardrails as ProviderOpenAI.
	ProviderAnthropic Provider = "anthropic"
)

// Config selects the backend and safety options for the remediation engine.
type Config struct {
	Provider      Provider
	Model         string
	RedactPII     bool // forced true for any non-local provider
	MaxMonthlyUSD float64
}

// Engine generates a remediation for a finding and verifies it by re-running
// the relevant analyzer against the patched configuration before returning
// it to the caller.
type Engine interface {
	GenerateAndVerify(ctx context.Context, f models.Finding) (*models.Remediation, error)
}

// New returns the default Engine for cfg. It currently returns a stub that
// reports ErrNotImplemented.
func New(cfg Config) Engine { return stubEngine{cfg: cfg} }

type stubEngine struct{ cfg Config }

func (stubEngine) GenerateAndVerify(_ context.Context, _ models.Finding) (*models.Remediation, error) {
	return nil, ErrNotImplemented
}
