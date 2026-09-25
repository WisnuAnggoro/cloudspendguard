// Package verify is module M9 in docs/architecture.md: the independent gate that
// decides whether a candidate Terraform patch produced by the remediation engine
// (M8, internal/llm) may be shown to a human at all.
//
// This package is deliberately separate from internal/llm. Language models can
// repair vulnerable code but also introduce new defects (Pearce et al., 2023,
// https://arxiv.org/abs/2112.02125), so the component that generates a patch is
// never permitted to approve its own output. Verify re-parses the patched HCL and
// re-runs the same rule set used by internal/analyze/security, rejecting any
// patch that introduces a finding. It satisfies FR7 and mitigates R-07 in
// docs/raid-log.md.
//
// Scaffolded in Unit 3 (Week 3). The re-scan loop lands with v0.6.0-beta.
package verify

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by stubs until the verify loop lands.
var ErrNotImplemented = errors.New("verify: not implemented until v0.6.0-beta")

// MaxRetries bounds how many times the remediation engine may be asked to
// regenerate a patch before the finding is reported without one.
const MaxRetries = 3

// Result is the verdict on a candidate patch.
type Result struct {
	Approved bool
	// NewFindingIDs lists findings that did not exist before the patch was
	// applied. A non-empty slice always means Approved is false.
	NewFindingIDs []string
	// ResolvedOriginal reports whether the finding the patch was generated for
	// is no longer detected after the patch is applied.
	ResolvedOriginal bool
	Messages         []string
}

// Verifier checks a candidate patch against the original configuration.
type Verifier interface {
	Verify(ctx context.Context, originalHCL, patchDiff, findingID string) (Result, error)
}

// NewVerifier returns the default Verifier. It currently returns a stub that
// reports ErrNotImplemented.
func NewVerifier() Verifier { return stubVerifier{} }

type stubVerifier struct{}

func (stubVerifier) Verify(_ context.Context, _, _, _ string) (Result, error) {
	return Result{}, ErrNotImplemented
}
