package llm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// maxUntrustedLen caps any single untrusted string sent to a model. Real tag
// values are limited to 256 characters by AWS; anything longer is suspicious.
const maxUntrustedLen = 256

// injectionPatterns are phrases that try to turn data into instructions
// (OWASP LLM01, indirect prompt injection via resource names and tags;
// Greshake et al., 2023). Matching is case-insensitive.
var injectionPatterns = regexp.MustCompile(`(?i)(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|system)|` +
	`system\s*prompt|you\s+are\s+now|new\s+instructions?|developer\s+mode|jailbreak|` +
	`do\s+not\s+follow|act\s+as\s|<\s*/?\s*(system|untrusted|instructions?)\b|` +
	"```|" + `\bassistant\s*:|\buser\s*:|\bsystem\s*:|` +
	`provisioner|local-exec|remote-exec|curl\s+|wget\s+|base64\s+-d|` +
	`(add|grant|attach|give)\s+.{0,80}(admin|\*:\*|full\s+access)|AdministratorAccess|PowerUserAccess`)

// Identifier patterns redacted before any non-local model call (NFR2,
// GDPR Art. 32 data minimization). Order matters: ARNs contain account IDs.
var redactPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"ARN", regexp.MustCompile(`arn:aws[a-zA-Z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"',}\]]+`)},
	{"ACCESS_KEY", regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)},
	{"EMAIL", regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)},
	{"ACCOUNT_ID", regexp.MustCompile(`\b\d{12}\b`)},
	{"IP", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
}

// cidrPassthrough keeps network ranges that are policy, not identity, so the
// model can still reason about "0.0.0.0/0".
var cidrPassthrough = map[string]bool{"0.0.0.0": true, "127.0.0.1": true}

// Sanitizer replaces untrusted or identifying strings with stable
// placeholders before a prompt is built, and restores them in the model's
// answer. Placeholders are plain tokens such as [[ACCOUNT_ID_1]], which HCL
// accepts inside string literals, so a patch round-trips intact.
type Sanitizer struct {
	redact    bool
	forward   map[string]string // original -> placeholder
	reverse   map[string]string // placeholder -> original
	counts    map[string]int
	Neutered  []string // original untrusted strings that looked like instructions
	Redacted  int
	Truncated int
	Withheld  int // every untrusted value replaced by a placeholder
}

// NewSanitizer returns a Sanitizer. redact enables identifier redaction,
// which is forced on for any provider that is not local.
func NewSanitizer(redact bool) *Sanitizer {
	return &Sanitizer{redact: redact, forward: map[string]string{}, reverse: map[string]string{}, counts: map[string]int{}}
}

func (s *Sanitizer) placeholder(kind, original string) string {
	if p, ok := s.forward[original]; ok {
		return p
	}
	s.counts[kind]++
	p := fmt.Sprintf("[[%s_%d]]", kind, s.counts[kind])
	s.forward[original] = p
	s.reverse[p] = original
	return p
}

func (s *Sanitizer) withhold(v string) string {
	if _, seen := s.forward[v]; !seen {
		s.Withheld++
	}
	return s.placeholder("UNTRUSTED_TEXT", v)
}

// Untrusted sanitizes one attacker-influenced string (a tag value, a
// resource name, a description). Control characters are removed, overlong
// values are replaced, and anything that reads like an instruction is
// replaced wholesale with an opaque placeholder: the model never sees it.
func (s *Sanitizer) Untrusted(v string) string {
	clean := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != ' ' {
			return -1
		}
		return r
	}, v)
	if len(clean) > maxUntrustedLen {
		s.Truncated++
		return s.withhold(v)
	}
	if injectionPatterns.MatchString(clean) {
		s.Neutered = append(s.Neutered, v)
		return s.withhold(v)
	}
	if clean != v {
		return s.withhold(v)
	}
	return s.Identifiers(clean)
}

// Identifiers redacts ARNs, access keys, e-mail addresses, account IDs, and
// IP addresses when redaction is enabled.
func (s *Sanitizer) Identifiers(v string) string {
	if !s.redact {
		return v
	}
	for _, p := range redactPatterns {
		v = p.re.ReplaceAllStringFunc(v, func(m string) string {
			if p.kind == "IP" && cidrPassthrough[m] {
				return m
			}
			if strings.HasPrefix(m, "[[") {
				return m
			}
			s.Redacted++
			return s.placeholder(p.kind, m)
		})
	}
	return v
}

// Attributes returns a sanitized deep copy of Terraform attributes. Tags,
// names, and descriptions are treated as untrusted; every other string is
// passed through identifier redaction only.
func (s *Sanitizer) Attributes(attrs map[string]any) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[k] = s.value(k, v, untrustedKey(k))
	}
	return out
}

func untrustedKey(k string) bool {
	switch k {
	case "tags", "tags_all", "name", "description", "comment", "user_data", "name_prefix":
		return true
	}
	return false
}

func (s *Sanitizer) value(key string, v any, untrusted bool) any {
	switch t := v.(type) {
	case string:
		if untrusted {
			return s.Untrusted(t)
		}
		return s.Identifiers(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = s.value(key, e, untrusted)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // stable placeholder numbering
		for _, k := range keys {
			out[k] = s.value(k, t[k], untrusted || untrustedKey(k))
		}
		return out
	}
	return v
}

// Restore puts the original strings back into the model's answer.
func (s *Sanitizer) Restore(text string) string {
	if len(s.reverse) == 0 {
		return text
	}
	keys := make([]string, 0, len(s.reverse))
	for p := range s.reverse {
		keys = append(keys, p)
	}
	// Longest first so [[IP_10]] is not clobbered by [[IP_1]].
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	pairs := make([]string, 0, 2*len(keys))
	for _, p := range keys {
		pairs = append(pairs, p, escapeHCL(s.reverse[p]))
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

// escapeHCL makes an original value safe to put back inside a quoted HCL
// string, so restored text cannot break out of the literal.
func escapeHCL(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "${", "$${", "%{", "%%{")
	v = r.Replace(v)
	// Other control characters (NUL, BEL, ...) are written as \uNNNN escapes;
	// raw, they would corrupt the restored file.
	var sb strings.Builder
	for _, c := range v {
		if unicode.IsControl(c) {
			fmt.Fprintf(&sb, `\u%04x`, c)
			continue
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
