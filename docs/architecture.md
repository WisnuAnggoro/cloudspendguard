# CloudSpendGuard: Architecture

Authoritative design document for the CloudSpendGuard capstone (MSIT 5910). Last revised in Unit 3
alongside `docs/requirements.md`. The narrative version submitted for Unit 3 lives at
`../../capstone-plan/Unit3-Doc1-Architecture-and-Version-Control.md`, and the full technical report at
`../../capstone-plan/Unit3-Doc2-Technical-Report.md`.

## Architectural style

CloudSpendGuard is a **layered pipeline**: data flows in one direction from external sources to a
rendered report, with a single cross-cutting orchestration module. The layered pattern suits stages
that are sequential and testable in isolation, while the pipeline pattern suits transformation-heavy
workloads where each stage consumes the previous stage's output ([Walker, 2022](https://www.redhat.com/en/blog/14-software-architecture-patterns)).
Microservices were rejected: their deployment and network complexity only pays off at organizational
scale, and this tool must run entirely on one laptop with no server to operate.

Rendered diagram: [`design/architecture_diagram.py`](design/architecture_diagram.py) generates
`architecture.png`. The diagram is regenerated from version-controlled code rather than pasted in as
an opaque image.

```bash
python3 docs/design/architecture_diagram.py   # writes architecture.png
```

## Layers

| Layer | Contents |
|---|---|
| L0 Data sources | AWS CUR, CloudTrail, Terraform state and HCL, live read-only AWS APIs |
| L1 Ingestion | M1, M2, M3, M3b |
| L2 Normalization and storage | M4 |
| L3 Analysis | M5, M6 |
| L4 Prioritization | M7 |
| L5 Remediation | M8, M9 |
| L6 Presentation | M10 |
| Cross-cutting | M11 orchestration |

## Module-wise functional specification

| Module | Package | Input | Output | Methodology |
|---|---|---|---|---|
| M1 CUR Ingester | `internal/ingest/cur` | Path to CUR Parquet or CSV file | `[]CostRecord` | Columnar Parquet read via pure-Go parquet-go (CUR 2.0 names) and CSV read accepting CUR 1.0 and 2.0 headers; batched reads to bound memory |
| M2 CloudTrail Ingester | `internal/ingest/cloudtrail` | Path to CloudTrail JSON files | `[]AuditEvent` | Streaming JSON decoder; event-name and principal extraction |
| M3 Terraform Ingester | `internal/ingest/tfstate` | `terraform.tfstate`, `*.tf` files | `[]Resource` | State-file unmarshalling plus HCL abstract syntax tree walk |
| M3b Live Collector | `internal/ingest/live` | Read-only IAM role ARN | `[]Resource` | AWS SDK v2 paginated `Describe*` and `ce:Get*` calls |
| M4 Normalizer and Store | `internal/store` | Heterogeneous records from M1 to M3b | Canonical relational schema | Type coercion, tag flattening, persistence into embedded pure-Go SQLite (DuckDB deferred, see RAID I-01) |
| M5 Cost Analyzer | `internal/analyze/cost` | Cost records plus resource inventory | `[]Finding{savings, confidence}` | 15+ rule-based waste detectors; STL decomposition with z-score and Isolation Forest for anomalies |
| M6 Security Analyzer | `internal/analyze/security` | Resources plus audit events | `[]Finding{severity, control_id}` | 20+ AST rules mapped to CIS AWS Foundations Benchmark, PCI-DSS, GDPR |
| M7 Joint Prioritizer | `internal/prioritize` | Unified `[]Finding` | Ranked remediation backlog | Min-max normalization then weighted scoring, `S(r) = a*savings + b*risk_reduction - c*blast_radius` |
| M8 LLM Remediation Engine | `internal/llm` | Ranked finding plus rule context | Candidate Terraform patch as a diff | Redaction of ARNs, account identifiers, IP addresses; hardened system prompt; local Ollama by default |
| M9 Verifier | `internal/llm/verify` | Candidate patch | Approved patch or rejection reason | Re-parse of patched HCL and full re-execution of M6 rules; rejection on any new finding |
| M10 Reporter | `internal/report` | Approved backlog plus verified patches | Markdown, HTML, JSON, SARIF | Template rendering; SARIF 2.1.0 serialization for code-scanning platforms |
| M11 CLI Orchestrator | `cmd/csg` | Command-line arguments and configuration | Exit code plus structured logs | Command parsing, weight-profile loading, pipeline sequencing |

Each module is a single Go package with one exported entry point, so its input and output contract is
testable in isolation. This follows the guidance that subsystem requirements be decomposed so each
subsystem's contribution is individually verifiable ([Summers, 2020](https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers), Ch. 4.4).

### Why M8 and M9 are separate packages

Large language models can repair vulnerable code but also introduce new defects
([Pearce et al., 2023](https://arxiv.org/abs/2112.02125)), so the generating component is never
permitted to approve its own output. M9 is an independent gate that re-runs the same rule engine used
in M6, meaning a hallucinated patch is caught by the identical logic that found the original problem.
M9 retries at most three times, then reports the finding without a patch. No patch is ever applied
automatically.

## Data flow

```
CUR + CloudTrail + tfstate + live APIs     (L0/L1: M1, M2, M3, M3b)
         |
         v
     Store, SQLite (pure Go)               (L2: M4)
         |
         v
  Cost + Security analyzers  ->  Findings  (L3: M5, M6)
         |
         v
      Prioritizer  ->  ranked backlog      (L4: M7)
         |
         v
  LLM remediation engine  ->  patches      (L5: M8)
         |
         v
     Verifier, re-scan  ->  approved       (L5: M9)
         |
         v
       Reporter                            (L6: M10)
```

## Non-functional constraints

See `docs/requirements.md` for the numbered, testable form. In summary:

- Single static Go binary for macOS, Linux, and Windows (NFR4)
- Under 60s to analyze 1 GB CUR plus 100 MB CloudTrail on an M-series MacBook (NFR1)
- Zero outbound network calls unless the operator passes `--llm-provider=openai` (NFR2)
- 90% or higher unit-test coverage on M5 through M9 (NFR3)
- Useful output within five minutes of installation (NFR5)

## References

Letaw, L. (2024). *Handbook of software engineering methods*. Oregon State University. https://open.oregonstate.education/setextbook/

Pearce, H., Tan, B., Ahmad, B., Karri, R., & Dolan-Gavitt, B. (2023). Examining zero-shot vulnerability repair with large language models. https://arxiv.org/abs/2112.02125

Summers, B. L. (2020). *Effective methods for software engineering*. Auerbach Publications. https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers

Walker, V. (2022, March 16). *14 software architecture design patterns to know*. Red Hat. https://www.redhat.com/en/blog/14-software-architecture-patterns
