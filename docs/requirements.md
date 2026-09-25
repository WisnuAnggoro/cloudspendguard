# CloudSpendGuard: Requirements Specification

Created in Unit 3 (MSIT 5910). Companion to [`architecture.md`](architecture.md). Every requirement is
written so a single automated test can decide whether it passes, following the principle that a good
requirement is unambiguous, testable, and free of implementation detail
([Letaw, 2024](https://open.oregonstate.education/setextbook/), Ch. 3.3, 3.6).

## Functional requirements

| ID | Requirement | Module | Verification |
|---|---|---|---|
| FR1 | Ingest AWS CUR data in Parquet or CSV format | M1 | `internal/ingest/cur` tests over fixture files of both formats |
| FR2 | Ingest CloudTrail JSON events from a local path or an S3 prefix | M2 | `internal/ingest/cloudtrail` tests; S3 path exercised with a stubbed client |
| FR3 | Parse Terraform state and HCL configuration files | M3 | `internal/ingest/tfstate` tests over `testdata/` state and `.tf` files |
| FR4 | Detect at least 15 cost-waste patterns, including idle EBS volumes, unattached Elastic IPs, oversized RDS instances, and idle NAT gateways | M5 | Detector registry length assertion plus one positive and one negative fixture per detector |
| FR5 | Detect at least 20 security misconfigurations, each mapped to a named CIS AWS Foundations Benchmark control | M6 | Rule registry length assertion; every rule must carry a non-empty `control_id` |
| FR6 | Produce a single prioritized backlog in which every item carries both a projected monthly saving and a risk-reduction score | M7 | Golden-file test asserting both fields are populated on every backlog row |
| FR7 | Generate Terraform remediation patches and reject any that fails verification | M8, M9 | Adversarial suite: patches that introduce a finding must be rejected |
| FR8 | Emit reports in Markdown, HTML, JSON, and SARIF | M10 | Schema validation of JSON output; SARIF 2.1.0 validated against the official schema |
| FR9 | Operate in local-file mode with no AWS credentials, and in live mode using a read-only IAM role | M3b, M11 | End-to-end test with the credential environment cleared |

## Non-functional requirements

| ID | Category | Requirement | Design consequence |
|---|---|---|---|
| NFR1 | Performance | Analyze 1 GB of CUR data and 100 MB of CloudTrail data in under 60 seconds on an Apple M-series laptop | Columnar Parquet reads and an embedded analytical database instead of row-oriented parsing |
| NFR2 | Privacy | No cloud data leaves the machine unless the operator explicitly passes `--llm-provider=openai` | Redaction sanitizer placed inside M8 rather than at the network edge, so the default path has no egress at all |
| NFR3 | Reliability | 90% or higher unit-test coverage on M5 through M9 | Every module exposes a pure-function entry point with no hidden global state |
| NFR4 | Portability | A single static binary for macOS, Linux, and Windows | No dependency requiring a system package manager |
| NFR5 | Usability | Useful output within five minutes of installation | Sample fixtures ship inside the binary (`csg run --sample`) |

Non-functional requirements frequently constrain architecture more tightly than functional ones
([Letaw, 2024](https://open.oregonstate.education/setextbook/), Ch. 3.5), which is why each row above
records its design consequence rather than the requirement alone. The distinction between what the
system does and how well it must do it matters because omitting the latter yields a system that is
nominally complete yet operationally unusable
([Summers, 2020](https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers), Ch. 4.1).

## Traceability

| NFR | Enforced by | Evidence |
|---|---|---|
| NFR1 | M1 streaming reads, M4 DuckDB | Benchmark in CI, recorded per release tag |
| NFR2 | M8 sanitizer, default Ollama backend | Network-isolation test asserting zero outbound connections without the flag |
| NFR3 | Pure-function module entry points | `make cover` gate in `.github/workflows/ci.yml` |
| NFR4 | `CGO_ENABLED=0` static build | Cross-compilation matrix in CI |
| NFR5 | Embedded sample fixtures | `make run-sample` smoke test |

## References

Letaw, L. (2024). *Handbook of software engineering methods*. Oregon State University. https://open.oregonstate.education/setextbook/

Summers, B. L. (2020). *Effective methods for software engineering*. Auerbach Publications. https://www.taylorfrancis.com/books/mono/10.1201/9781003025665/effective-methods-software-engineering-boyd-summers
