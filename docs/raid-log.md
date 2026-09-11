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
| R-07 | R | Hallucinated Terraform patches from LLM introduce new security findings not caught by verifier | High | Medium | Generate-then-verify loop: re-scan every patch; reject patches that fail verification; log rejection rate as a metric | Open | 2026-09-06 |

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
| I-01 | I | *(No open issues at project start. Issues are added here as they materialize, typically converted from Risks.)* | — | — | — | 2026-09-06 |

## Dependencies

| ID | Type | Description | Impact if unavailable | Mitigation / alternative | Status | Last reviewed |
|---|---|---|---|---|---|---|
| D-01 | D | Go 1.23+ installed on local dev machine | Blocks all engineering | Already installed and verified | Closed | 2026-09-06 |
| D-02 | D | [Apache Arrow Go v14+](https://pkg.go.dev/github.com/apache/arrow/go/v14) for Parquet ingestion | Blocks CUR ingestion | Fallback CSV ingestion path; pure-Go CSV parser as backup | Open | 2026-09-06 |
| D-03 | D | [DuckDB Go driver](https://github.com/marcboeker/go-duckdb) for local time-series store | Blocks Store module | Fallback to SQLite via `database/sql`; slower but functional | Open | 2026-09-06 |
| D-04 | D | Ollama runtime installed locally with a suitable model | Blocks default LLM path | Optional OpenAI/Anthropic fallback (opt-in, budgeted) | Open | 2026-09-06 |
| D-05 | D | Access to public sample datasets ([flaws.cloud](http://flaws.cloud/), [tfsec fixtures](https://github.com/aquasecurity/tfsec), [KICS fixtures](https://github.com/Checkmarx/kics)) | Blocks evaluation | All datasets are publicly hosted and archived; snapshot into `testdata/` in Week 3 to guard against upstream removal | Open | 2026-09-06 |
| D-06 | D | UoPeople Brightspace access for weekly submissions | Blocks academic delivery | Submit early; keep offline copies of every submission | Open | 2026-09-06 |
| D-07 | D | GitHub account and free CI minutes for the private repo | Blocks CI/CD evidence | Fallback to running CI locally via `make ci`; screenshots serve as evidence | Open | 2026-09-06 |

---

## Change log

| Date | Change |
|---|---|
| 2026-09-06 | Initial RAID log created for Unit 1 discussion submission |

## References

Association for Project Management. (n.d.). *RAID log*. https://www.apm.org.uk/resources/find-a-resource/raid-log/

Oguz, A. (2025). *Project management* (2nd ed.), Ch. 1.6 (Project Management Knowledge Areas). MSL Academic Endeavors. https://pressbooks.ulib.csuohio.edu/projectmanagement2ndedition/

Project Management Institute. (n.d.). *Risk register*. https://www.pmi.org/learning/library/risk-register-9520
