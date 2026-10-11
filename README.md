# CloudSpendGuard

> Unified FinOps + Cloud Security Posture CLI for AWS. Local-first. Written in Go.

**Status:** Unit 6 (Week 6), `v0.6.0-beta`. One command, `csg run`, now goes from exports to an HTML, Markdown, JSON, or SARIF report, and the detection experiment against tfsec and Checkov is in [`docs/evaluation.md`](docs/evaluation.md). The core is unchanged from `v0.3.0-algo`: the full rule library (15 cost rules and 20 security rules mapped to CIS AWS Foundations v3.0.0), an STL plus Isolation Forest cost-anomaly detector, the joint prioritizer with per-component scores, and LLM-assisted Terraform remediation behind an independent verifier (`csg remediate`). Ollama is the default backend, so nothing leaves the machine. Core packages have 97% statement coverage against a 90% gate. See [`CHANGELOG.md`](CHANGELOG.md), the [demo runbook](docs/demo.md), and [`docs/gantt.mmd`](docs/gantt.mmd) for the remaining schedule.

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
csg analyze --weights 0.6,0.3,0.1 --top 10      # explicit alpha, beta, gamma

# Cost anomalies (STL + robust z-score + Isolation Forest)
csg anomalies
csg anomalies --series AmazonEC2/booking

# A verified Terraform patch for one finding (local Ollama by default)
ollama pull qwen2.5-coder:1.5b
csg remediate SEC-EC2-IMDSV2-001:i-0a1b2c3d4e5f60042 --model qwen2.5-coder:1.5b

# The same, replayed from a recorded fixture (no model needed)
csg remediate SEC-EC2-IMDSV2-001:i-0a1b2c3d4e5f60042 \
  --llm-provider replay --fixture testdata/llm/imdsv2-injection-tag.json
```

`csg remediate` never applies a change. It prints a unified diff only after
the verifier has re-parsed the patch and re-run every rule on it.

Or run everything at once with `make demo`. Data lives in `.csg/csg.db` (override with `--db` or `$CSG_DB`).

### Rules in v0.3.0

Cost (15): `COST-EBS-IDLE-001`, `COST-EIP-UNATTACHED-001`, `COST-NAT-IDLE-001`,
`COST-ANOMALY-001`, `COST-EBS-GP2-001`, `COST-EC2-PREVGEN-001`,
`COST-EC2-GRAVITON-001`, `COST-EC2-STOPPED-001`, `COST-RDS-NONPROD-SIZE-001`,
`COST-RDS-NONPROD-MULTIAZ-001`, `COST-RDS-GP2-001`, `COST-S3-NO-LIFECYCLE-001`,
`COST-LOGS-RETENTION-001`, `COST-EBS-SNAPSHOT-ORPHAN-001`, `COST-ELB-IDLE-001`.
Savings come from CUR when the resource is billed, otherwise from list prices.

Security (20), CIS AWS Foundations Benchmark v3.0.0:

| Rule | CIS | Rule | CIS |
|---|---|---|---|
| `SEC-IAM-PASSWORD-001` | 1.8, 1.9 | `SEC-CT-MULTIREGION-001` | 3.1 |
| `SEC-IAM-USER-POLICY-001` | 1.15 | `SEC-CT-VALIDATION-001` | 3.2 |
| `SEC-IAM-ADMIN-001` | 1.16 | `SEC-CT-KMS-001` | 3.5 |
| `SEC-S3-TLS-001` | 2.1.1 | `SEC-KMS-ROTATION-001` | 3.6 |
| `SEC-S3-MFA-DELETE-001` | 2.1.2 | `SEC-VPC-FLOWLOGS-001` | 3.7 |
| `SEC-S3-PUBLIC-001` | 2.1.4 | `SEC-NACL-ADMIN-001` | 5.1 |
| `SEC-EBS-ENCRYPT-001` | 2.2.1 | `SEC-SG-ADMIN-IPV4-001` | 5.2 |
| `SEC-RDS-ENCRYPT-001` | 2.3.1 | `SEC-SG-ADMIN-IPV6-001` | 5.3 |
| `SEC-RDS-PUBLIC-001` | 2.3.3 | `SEC-SG-DEFAULT-001` | 5.4 |
| `SEC-EFS-ENCRYPT-001` | 2.4.1 | `SEC-EC2-IMDSV2-001` | 5.6 |

Rules combine Terraform state (or `*.tf` files) with CloudTrail evidence of
the same change made outside Terraform.

### One command, one report (v0.6.0)

```bash
csg run --sample --report ./out.html                       # bundled sample, no AWS credentials
csg run --input ./my-account --profile security --report ./report.html --stats
csg run --input ./my-account --report ./csg.sarif --sarif-uri infra/main.tf
csg report --db .csg/csg.db --format sarif --out ./csg.sarif   # re-render a stored backlog
```

An example report is committed at [`docs/sample-report.html`](docs/sample-report.html). Run it in Docker:

```bash
make docker-run      # writes ./out/report.html
```

Install, environment variables, Docker, and the scheduled AWS deployment: [`docs/install.md`](docs/install.md).

## Local development

```bash
git clone https://github.com/wisnuanggoro/cloudspendguard
cd cloudspendguard
make build        # static binary (CGO_ENABLED=0)
make test         # race detector, all packages
make cover-gate   # 90% coverage gate on analyzers and algorithms
make golden       # rewrite LLM golden diffs after an intended change
make lint         # go vet + golangci-lint v2
make ci           # everything GitHub Actions runs, locally
make bench        # NFR1 timings on synthetic CUR files
make eval         # precision and recall against tfsec and Checkov
```

## Security & privacy

- Read-only AWS access only. See [`docs/iam-policy.json`](docs/iam-policy.json).
- No cloud data leaves your machine unless you explicitly pass `--llm-provider=openai`.
- Remote LLMs need both `--llm-provider=openai` and `--allow-remote`; ARNs, account IDs, IPs, e-mails, and access keys are redacted first.
- Prompt-injection guardrails: instruction-like tag and name values never reach the model, and the data block is fenced with a random nonce. Adversarial tests cover 12 injection payloads and 9 malicious model answers.
- Every patch is re-parsed and re-scanned by an independent verifier and is never applied automatically.

## Roadmap

See the [8-week Gantt chart](docs/gantt.mmd), [architecture doc](docs/architecture.md), and [requirements spec](docs/requirements.md) for the module-by-module delivery plan (`v0.1.0-ingest` through `v1.0.0`). This project is a Master's capstone; contributions welcome after v1.0.0.

## License

MIT © 2026 Wisnu Anggoro
