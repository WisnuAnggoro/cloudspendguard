# CloudSpendGuard

> Unified FinOps + Cloud Security Posture CLI for AWS. Local-first. Written in Go.

**Status:** Unit 4 (Week 4), `v0.2.0-analyze-alpha`. Ingestion (CUR Parquet and CSV, CloudTrail JSON, Terraform state), the local SQL store, `csg query`, and the first four rules (two cost, two security) feed the joint prioritizer through `csg analyze`. CI runs lint, a race-enabled test matrix on Linux, macOS, and Windows, a 90% coverage gate, static cross-compilation, `govulncheck`, and an end-to-end smoke test. See [`CHANGELOG.md`](CHANGELOG.md), the [demo runbook](docs/demo.md), and [`docs/gantt.mmd`](docs/gantt.mmd) for the remaining schedule.

CloudSpendGuard produces a **single prioritized backlog** of remediation actions where each item shows both its **projected monthly savings** and **security-risk reduction**, so DevOps, FinOps, and Security teams stop working from three different dashboards.

## Why

- Enterprises waste 27–47% of cloud spend on idle/oversized resources ([Harness 2025](https://www.prnewswire.com/news-releases/44-5-billion-in-infrastructure-cloud-waste-projected-for-2025-due-to-finops-and-developer-disconnect-finds-finops-in-focus-report-from-harness-302385580.html)).
- Cloud-misconfiguration breaches average USD 4.88M ([IBM 2024](https://www.ibm.com/reports/data-breach)).
- FinOps and Security teams use separate tools with conflicting recommendations. CloudSpendGuard unifies them.

## Features (target v1.0.0)

- Ingest AWS Cost & Usage Reports (Parquet/CSV), CloudTrail JSON, and Terraform state
- 15+ cost-waste detectors (idle EBS, unattached EIPs, oversized RDS, idle NAT GW, …)
- 20+ security-misconfiguration detectors mapped to CIS AWS Benchmarks, PCI-DSS, GDPR
- Joint cost × risk prioritization with configurable weights per stakeholder profile
- LLM-assisted Terraform patch generation with **generate-then-verify** safety loop
- Local by default (Ollama); opt-in cloud LLM (OpenAI/Anthropic) with PII redaction
- Output as Markdown, HTML, JSON, or SARIF (for GitHub/GitLab code-scanning)

## Quickstart

```bash
make build && export PATH="$PWD/bin:$PATH"

# Ingest the bundled sample account (no AWS credentials needed)
csg ingest cur        ./testdata/sample-cur.parquet
csg ingest cloudtrail ./testdata/sample-events.json
csg ingest tfstate    ./testdata/terraform.tfstate

# Ask the local store anything (read-only SQL)
csg query "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC"

# One prioritized backlog of cost and security findings
csg analyze --profile devops
```

Or run everything at once with `make demo`. Data lives in `.csg/csg.db` (override with `--db` or `$CSG_DB`).

### Rules in v0.2.0

| Rule | Kind | Signal | Control |
|---|---|---|---|
| `COST-EBS-IDLE-001` | cost | `aws_ebs_volume` with no `aws_volume_attachment`, priced from CUR | - |
| `COST-EIP-UNATTACHED-001` | cost | `aws_eip` without association, or CUR `PublicIPv4:IdleAddress` | - |
| `SEC-S3-PUBLIC-001` | security | public ACL, disabled Block Public Access, `Principal "*"` policy, or matching CloudTrail calls | CIS AWS v3.0.0 2.1.4 |
| `SEC-IAM-ADMIN-001` | security | policy allowing `Action "*"` on `Resource "*"` in Terraform or CloudTrail | CIS AWS v3.0.0 1.16 |

### Planned CLI (later units)

```bash
csg run --sample --report ./out.html                 # Unit 6
csg report --format sarif --out ./csg.sarif          # Unit 6
```

## Local development

```bash
git clone https://github.com/wisnuanggoro/cloudspendguard
cd cloudspendguard
make build        # static binary (CGO_ENABLED=0)
make test         # race detector, all packages
make cover-gate   # 90% coverage gate on analyzers and algorithms
make lint         # go vet + golangci-lint v2
make ci           # everything GitHub Actions runs, locally
```

## Security & privacy

- Read-only AWS access only. See [`docs/iam-policy.json`](docs/iam-policy.json).
- No cloud data leaves your machine unless you explicitly pass `--llm-provider=openai`.
- PII/ARN redaction pass before any external LLM call.
- Prompt-injection guardrails and adversarial test suite.

## Roadmap

See the [8-week Gantt chart](docs/gantt.mmd), [architecture doc](docs/architecture.md), and [requirements spec](docs/requirements.md) for the module-by-module delivery plan (`v0.1.0-ingest` through `v1.0.0`). This project is a Master's capstone; contributions welcome after v1.0.0.

## License

MIT © 2026 Wisnu Anggoro
