package verify

import (
	"fmt"
	"strings"
)

// UnifiedDiff returns a unified diff (3 lines of context) between two texts,
// or "" when they are identical. Inputs are small (one resource block), so a
// plain longest-common-subsequence table is fast enough and easy to audit.
func UnifiedDiff(name, a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		text string
		ai   int // line number in a (1-based) for ' ' and '-'
		bi   int // line number in b (1-based) for ' ' and '+'
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, op{' ', x[i], i + 1, j + 1})
			i++
			j++
		// Prefer deletions on ties so a changed line reads "-old" then "+new",
		// the order reviewers and `patch` expect. (Unit 5 test finding: the
		// first version emitted "+new" before "-old".)
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', x[i], i + 1, j})
			i++
		default:
			ops = append(ops, op{'+', y[j], i, j + 1})
			j++
		}
	}
	const ctx = 3
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- a/%s\n+++ b/%s\n", name, name)
	for k := 0; k < len(ops); {
		if ops[k].kind == ' ' {
			k++
			continue
		}
		start := max(k-ctx, 0)
		end := k
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*ctx {
				end = min(end+ctx, len(ops))
				break
			}
			end = run
		}
		aStart, bStart, aLen, bLen := 0, 0, 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				if aLen == 0 {
					aStart = o.ai
				}
				aLen++
			}
			if o.kind != '-' {
				if bLen == 0 {
					bStart = o.bi
				}
				bLen++
			}
		}
		if aLen == 0 {
			aStart = ops[start].ai
		}
		if bLen == 0 {
			bStart = ops[start].bi
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, o := range ops[start:end] {
			sb.WriteByte(o.kind)
			sb.WriteString(o.text)
			sb.WriteByte('\n')
		}
		k = end
	}
	return sb.String()
}

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
