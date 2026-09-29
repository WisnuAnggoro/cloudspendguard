# CloudSpendGuard — RAID Log

A single register tracking **Risks, Assumptions, Issues, and Dependencies** for the CloudSpendGuard capstone project (MSIT 5910). Reviewed every Wednesday alongside the Gantt milestones.

## Legend

- **Type** — `R` (Risk, potential), `A` (Assumption, unverified), `I` (Issue, already occurred), `D` (Dependency, needed from outside)
- **Impact** — `Low` / `Medium` / `High` (effect on schedule, quality, or scope)
- **Likelihood** — `Low` / `Medium` / `High` (only meaningful for Risks)
- **Status** — `Open` / `Mitigating` / `Resolved` / `Closed` / `Escalated`
- **Owner** — always `WA` (Wisnu Anggoro) for this solo project

## How I use this log

1. Every Wednesday I re-read every open entry.
2. If a **Risk** materializes, I move it from `R` to `I` (Issue) and act on it.
3. New entries appended at the bottom; retired entries stay in the log with `Resolved` or `Closed` status for traceability.
4. Referenced in the final report's *Limitations* section.

---

## Risks

| ID | Type | Description | Impact | Likelihood | Mitigation | Status | Last reviewed |
|---|---|---|---|---|---|---|---|
| R-01 | R | AWS Cost and Usage Report (CUR) schema evolves during the project, breaking the Parquet parser | High | Low | Pin implementation to CUR 2.0 schema documented at [AWS CUR docs](https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html); subscribe to AWS release notes; add schema-version assertion in ingest tests | Open | 2026-09-06 |
| R-02 | R | LLM API pricing changes or free-tier revocation before Week 5 | Medium | Medium | Default to local Ollama; treat OpenAI/Anthropic as opt-in only; cap monthly LLM budget at USD 15 | Open | 2026-09-06 |
| R-03 | R | Human-evaluation survey attracts fewer than 5 respondents in Week 6 | Medium | Medium | Begin recruitment in Week 4 via LinkedIn + peer network; prepare a fallback of 2 heuristic reviewers if respondent count under 5 | Open | 2026-09-06 |
| R-04 | R | Prompt-injection guardrails have false-positive rate that blocks legitimate remediation suggestions | Medium | Medium | Maintain adversarial test suite of 30 payloads with expected outcomes; measure both true-positive and false-positive rates in Week 5 | Open | 2026-09-06 |
| R-05 | R | Scope creep from adding Azure or GCP support after early positive feedback | High | Medium | Documented scope boundary in Unit 2 assignment; refuse scope changes after Week 3; log rejected scope requests as "future work" in report | Open | 2026-09-06 |
| R-06 | R | Personal illness or work travel disrupts a peak week (3, 5, or 6) | High | Low | Front-load work: aim to complete each unit's engineering deliverable by Monday, leaving Tue/Wed as buffer | Open | 2026-09-06 |
| R-07 | R | Hallucinated Terraform patches from LLM introduce new security findings not caught by verifier | High | Medium | Generate-then-verify loop: re-scan every patch; reject patches that fail verification; log rejection rate as a metric | Mitigating | 2026-09-19 |
| R-08 | R | Weight coefficients in the M7 scoring function are effectively unfalsifiable, making the ranking a hidden value judgment | Medium | High | Weights configurable per stakeholder profile; active coefficients and component subscores printed in every report; savings reported as a range rather than a point estimate | Mitigating | 2026-09-19 |
| R-09 | R | Resource tags and Terraform comments are attacker-influenced text flowing into an LLM prompt (indirect prompt injection, OWASP LLM01) | High | Medium | Untrusted data confined to a delimited prompt block; output contract restricted to a diff against one named resource; adversarial payload suite in `internal/llm` tests | Mitigating | 2026-09-19 |
| R-10 | R | Comparative evaluation lacks a defensible baseline because no existing tool produces a joint cost-and-risk ranking | Medium | Medium | Baseline against the union of a cost tool and a CSPM tool run separately; document the composition method in the evaluation chapter | Open | 2026-09-19 |

## Assumptions

| ID | Type | Description | Impact if false | Validation plan | Status | Last reviewed |
|---|---|---|---|---|---|---|
| A-01 | A | 5 or more peer engineers will be available for the qualitative usability study in Week 6 | Medium (Unit 6 qualitative metric weakened) | Send recruitment message in Week 4; get soft commitments before Week 5 | Open | 2026-09-06 |
| A-02 | A | Public CUR sample data and tfsec/KICS fixtures provide sufficient labeled ground truth for a ≥ 85% precision evaluation | High (Unit 6 quantitative metric weakened) | Manually label 100 sample records in Week 3; extend synthetically if needed | Open | 2026-09-06 |
| A-03 | A | Local Ollama on M3 Pro can serve Llama 3.1 8B (or comparable) with latency under 3 seconds per remediation suggestion | Medium (fallback to cloud LLM increases cost and privacy risk) | Benchmark Ollama in Week 3; document p50/p95 latency | Open | 2026-09-06 |
| A-04 | A | GitHub Actions free tier (2,000 minutes/month on private repos) is sufficient for the CI matrix across the 8 weeks | Low (fallback: make repo public earlier) | Monitor Actions minute usage each week from Week 2 onwards | Open | 2026-09-06 |
| A-05 | A | UoPeople instructor accepts a Master's-grade capstone framed around an open-source Go CLI (not a web app) | High (would require full pivot) | Confirm implicitly via approval of Unit 1 discussion and Unit 2 proposal | Open | 2026-09-06 |

## Issues

| ID | Type | Description | Impact | Resolution | Status | Last reviewed |
|---|---|---|---|---|---|---|
| I-01 | I | The DuckDB Go driver needs cgo, which breaks NFR4 (static `CGO_ENABLED=0` binary for macOS, Linux, and Windows) and the Windows leg of the CI matrix | Medium (NFR1 performance headroom smaller than planned) | Took the D-03 fallback: `internal/store` now uses pure-Go SQLite behind the unchanged `Store` interface. Re-evaluate DuckDB in Unit 6 against the NFR1 benchmark; swap only if SQLite misses the 60-second target | Resolved | 2026-09-25 |
| I-02 | I | Week 3 ingest milestone (`v0.1.0-ingest`) slipped: M1 to M4 were still stubs at the start of Week 4 | Medium (Week 4 demo depended on ingest and query) | Delivered M1 to M4 together with the Week 4 analyzers in one milestone; CHANGELOG records both tags so the history stays honest | Resolved | 2026-09-25 |

## Dependencies

| ID | Type | Description | Impact if unavailable | Mitigation / alternative | Status | Last reviewed |
|---|---|---|---|---|---|---|
| D-01 | D | Go 1.23+ installed on local dev machine | Blocks all engineering | Already installed and verified | Closed | 2026-09-06 |
| D-02 | D | Pure-Go Parquet library for CUR ingestion. Planned: [Apache Arrow Go v14+](https://pkg.go.dev/github.com/apache/arrow/go/v14). Used: [parquet-go](https://github.com/parquet-go/parquet-go), which is lighter and maps rows straight onto Go structs | Blocks CUR ingestion | CSV ingestion path (CUR 1.0 and 2.0 headers) implemented alongside Parquet | Closed | 2026-09-25 |
| D-03 | D | [DuckDB Go driver](https://github.com/marcboeker/go-duckdb) for local time-series store | Blocks Store module | Fallback taken: pure-Go SQLite ([modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite)) via `database/sql`. See I-01 | Closed | 2026-09-25 |
| D-04 | D | Ollama runtime installed locally with a suitable model | Blocks default LLM path | Optional OpenAI/Anthropic fallback (opt-in, budgeted) | Open | 2026-09-06 |
| D-05 | D | Access to public sample datasets ([flaws.cloud](http://flaws.cloud/), [tfsec fixtures](https://github.com/aquasecurity/tfsec), [KICS fixtures](https://github.com/Checkmarx/kics)) | Blocks evaluation | All datasets are publicly hosted and archived; snapshot into `testdata/` in Week 3 to guard against upstream removal | Open | 2026-09-06 |
| D-06 | D | UoPeople Brightspace access for weekly submissions | Blocks academic delivery | Submit early; keep offline copies of every submission | Open | 2026-09-06 |
| D-07 | D | GitHub account and free CI minutes for the private repo | Blocks CI/CD evidence | Fallback to running CI locally via `make ci`; screenshots serve as evidence | Open | 2026-09-06 |

---

## Change log

| Date | Change |
|---|---|
| 2026-09-06 | Initial RAID log created for Unit 1 discussion submission |
| 2026-09-19 | Unit 3 design review: added R-08 (prioritizer weight transparency), R-09 (indirect prompt injection), R-10 (evaluation baseline). Moved R-07 to `Mitigating` now that M9 is specified as a package separate from M8 in `docs/architecture.md`. |
| 2026-09-25 | Unit 4 implementation review: added I-01 (DuckDB replaced by pure-Go SQLite to keep NFR4) and I-02 (Week 3 ingest slip, recovered in Week 4); closed D-02 (parquet-go chosen over Arrow) and D-03 (fallback taken). |

## References

Association for Project Management. (n.d.). *RAID log*. https://www.apm.org.uk/resources/find-a-resource/raid-log/

Oguz, A. (2025). *Project management* (2nd ed.), Ch. 1.6 (Project Management Knowledge Areas). MSL Academic Endeavors. https://pressbooks.ulib.csuohio.edu/projectmanagement2ndedition/

Project Management Institute. (n.d.). *Risk register*. https://www.pmi.org/learning/library/risk-register-9520
