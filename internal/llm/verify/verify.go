// Package verify is module M9 in docs/architecture.md: the independent gate that
// decides whether a candidate Terraform patch produced by the remediation engine
// (M8, internal/llm) may be shown to a human at all.
//
// This package is deliberately separate from internal/llm. Language models can
// repair vulnerable code but also introduce new defects (Pearce et al., 2023,
// https://arxiv.org/abs/2112.02125), so the component that generates a patch is
// never permitted to approve its own output. Verify re-parses the patched HCL and
// re-runs the same cost and security rule sets used by internal/analyze,
// rejecting any patch that leaves the original finding in place or introduces a
// new security finding. It satisfies FR7 and mitigates R-07 and R-09 in
// docs/raid-log.md.
//
// Implemented in Unit 5 (v0.3.0-algo).
package verify

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/cost"
	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// MaxRetries bounds how many times the remediation engine may be asked to
// regenerate a patch before the finding is reported without one.
const MaxRetries = 3

// forbiddenNested are block types that execute code or open connections
// when Terraform applies the plan. A remediation never needs them.
var forbiddenNested = map[string]bool{"provisioner": true, "connection": true}

// Request is everything the verifier needs to judge one candidate patch.
type Request struct {
	Finding    models.Finding
	Original   tfstate.Resource   // the resource the finding points at
	Inventory  []tfstate.Resource // every resource, including Original
	PatchedHCL string             // the model's candidate, placeholders restored
}

// Result is the verdict on a candidate patch.
type Result struct {
	Approved bool
	// NewFindingIDs lists security findings that did not exist before the
	// patch. A non-empty slice always means Approved is false.
	NewFindingIDs []string
	// ResolvedOriginal reports whether the finding the patch was generated for
	// is no longer detected after the patch is applied.
	ResolvedOriginal bool
	// Diff is a unified diff of the resource block, set when Approved.
	Diff     string
	Messages []string
}

// Verifier checks a candidate patch against the original configuration.
type Verifier interface {
	Verify(ctx context.Context, req Request) (Result, error)
}

// NewVerifier returns the default rule-engine Verifier.
func NewVerifier() Verifier { return ruleVerifier{} }

type ruleVerifier struct{}

func (ruleVerifier) Verify(ctx context.Context, req Request) (Result, error) {
	var res Result
	reject := func(format string, args ...any) (Result, error) {
		res.Messages = append(res.Messages, fmt.Sprintf(format, args...))
		res.Approved = false
		return res, nil
	}

	// 1. Re-parse: the candidate must be valid HCL.
	hf, err := tfstate.ParseHCL([]byte(req.PatchedHCL), "patch.tf")
	if err != nil {
		return reject("patch is not valid HCL: %v", err)
	}
	// 2. Scope: exactly one resource block, the same one, nothing else.
	if len(hf.OtherBlocks) > 0 {
		return reject("patch adds non-resource blocks (%s); only the target resource may change", strings.Join(hf.OtherBlocks, ", "))
	}
	if len(hf.Resources) != 1 {
		return reject("patch must contain exactly one resource block, found %d", len(hf.Resources))
	}
	patched := hf.Resources[0]
	if patched.Type != req.Original.Type || patched.Name != req.Original.Name {
		return reject("patch targets %s.%s, want %s.%s", patched.Type, patched.Name, req.Original.Type, req.Original.Name)
	}
	if bad := forbiddenBlocks(patched.Attributes); len(bad) > 0 {
		return reject("patch adds forbidden nested blocks: %s", strings.Join(bad, ", "))
	}
	if exprs := expressions(patched.Attributes, ""); len(exprs) > 0 {
		return reject("patch introduces expressions that cannot be checked statically: %s", strings.Join(exprs, ", "))
	}
	if dropped := droppedArguments(req.Original.Attributes, patched.Attributes); len(dropped) > 0 {
		return reject("patch removes arguments unrelated to the finding: %s; keep them unchanged", strings.Join(dropped, ", "))
	}
	if bad := invalidValues(patched.Attributes, ""); len(bad) > 0 {
		return reject("patch contains invalid values: %s", strings.Join(bad, ", "))
	}
	// Carry provider-computed identifiers over so cross-references still match.
	patched.Address = req.Original.Address
	patched.Provider = req.Original.Provider
	for k := range tfstate.ComputedAttributes {
		if v, ok := req.Original.Attributes[k]; ok {
			patched.Attributes[k] = v
		}
	}

	// 3. Re-scan: run the full rule engine before and after.
	before, err := scan(ctx, req.Inventory)
	if err != nil {
		return Result{}, err
	}
	after, err := scan(ctx, replace(req.Inventory, patched))
	if err != nil {
		return Result{}, err
	}
	_, res.ResolvedOriginal = after[req.Finding.ID]
	res.ResolvedOriginal = !res.ResolvedOriginal
	for id, f := range after {
		if _, existed := before[id]; existed {
			continue
		}
		if f.Kind == models.KindSecurity {
			res.NewFindingIDs = append(res.NewFindingIDs, id)
		} else {
			res.Messages = append(res.Messages, "note: patch surfaces a new cost suggestion "+id)
		}
	}
	sort.Strings(res.NewFindingIDs)
	if len(res.NewFindingIDs) > 0 {
		return reject("patch introduces new security findings: %s", strings.Join(res.NewFindingIDs, ", "))
	}
	if !res.ResolvedOriginal {
		return reject("patch does not resolve %s", req.Finding.ID)
	}

	orig := tfstate.RenderHCL(req.Original)
	next := tfstate.RenderHCL(patched)
	res.Diff = UnifiedDiff(fileFor(req.Original), string(orig), string(next))
	res.Approved = true
	res.Messages = append(res.Messages, fmt.Sprintf("re-parsed HCL and re-ran %d cost and %d security rules: %s resolved, no new security findings",
		len(cost.Registry()), len(security.Registry()), req.Finding.RuleID))
	return res, nil
}

func scan(ctx context.Context, inv []tfstate.Resource) (map[string]models.Finding, error) {
	cf, err := cost.Analyze(ctx, cost.Input{Resources: inv})
	if err != nil {
		return nil, err
	}
	sf, err := security.Analyze(ctx, security.Input{Resources: inv})
	if err != nil {
		return nil, err
	}
	out := map[string]models.Finding{}
	for _, f := range append(cf, sf...) {
		out[f.ID] = f
	}
	return out, nil
}

func replace(inv []tfstate.Resource, r tfstate.Resource) []tfstate.Resource {
	out := make([]tfstate.Resource, 0, len(inv))
	found := false
	for _, x := range inv {
		if x.Address == r.Address {
			out = append(out, r)
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		out = append(out, r)
	}
	return out
}

func forbiddenBlocks(attrs map[string]any) []string {
	var bad []string
	for k, v := range attrs {
		if forbiddenNested[k] {
			bad = append(bad, k)
		}
		if list, ok := v.([]any); ok {
			for _, e := range list {
				if m, ok := e.(map[string]any); ok {
					bad = append(bad, forbiddenBlocks(m)...)
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// expressions lists attributes whose value could not be evaluated without
// variables, functions, or references (kept as "${...}" by ParseHCL).
func expressions(v any, path string) []string {
	var out []string
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "${") {
			out = append(out, path+" = "+t)
		}
	case []any:
		for i, e := range t {
			out = append(out, expressions(e, fmt.Sprintf("%s[%d]", path, i))...)
		}
	case map[string]any:
		for k, e := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			out = append(out, expressions(e, p)...)
		}
	}
	sort.Strings(out)
	return out
}

// droppedArguments lists top-level arguments and nested blocks that the
// original sets but the patch omits. Unit 5 finding: a terse but "correct"
// IMDSv2 patch dropped subnet_id, availability_zone, and an encrypted
// root_block_device; the rules saw nothing wrong, yet on apply Terraform
// would have replaced the instance in a different subnet. Fixes change
// values (for example a CIDR list), they do not delete arguments.
func droppedArguments(orig, patched map[string]any) []string {
	var out []string
	for k, v := range orig {
		if tfstate.ComputedAttributes[k] || v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if _, ok := patched[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// placeholderToken matches sanitizer-style tokens such as [[ACCOUNT_ID_1]].
// Real placeholders are restored before verification, so any token still
// present was invented by the model.
var placeholderToken = regexp.MustCompile(`\[\[[A-Z0-9_]+\]\]`)

// invalidValues finds values the rules would read as "not open" even though
// Terraform would reject them or a human must still fill them in. Unit 5
// finding: a recorded model answer replaced 0.0.0.0/0 with the made-up token
// "[[CORPORATE_CIDR]]"; the SG rule saw no open CIDR and the first verifier
// approved a patch that would never apply.
func invalidValues(v any, path string) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			out = append(out, invalidValues(t[k], p)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, invalidValues(e, path)...)
		}
	case string:
		if tok := placeholderToken.FindString(t); tok != "" {
			out = append(out, fmt.Sprintf("%s = %q is an unresolved placeholder, use a concrete value", path, tok))
		} else if strings.HasSuffix(path, "cidr_blocks") || strings.HasSuffix(path, "cidr_block") {
			if _, _, err := net.ParseCIDR(t); err != nil {
				out = append(out, fmt.Sprintf("%s = %q is not a valid CIDR", path, t))
			}
		}
	}
	return out
}

func fileFor(r tfstate.Resource) string {
	return strings.ReplaceAll(r.Address, ".", "_") + ".tf"
}
