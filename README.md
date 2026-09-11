# CloudSpendGuard

> Unified FinOps + Cloud Security Posture CLI for AWS. Local-first. Written in Go.

**Status:** early scaffold — MSIT 5910 Capstone Project.

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

## Quickstart (planned CLI)

```bash
# Install (once released)
go install github.com/wisnuanggoro/cloudspendguard/cmd/csg@latest

# Try it against bundled sample data
csg run --sample --report ./out.html

# Real usage
csg ingest cur   ./cur/2026-01/*.parquet
csg ingest cloudtrail ./cloudtrail/2026-01/*.json
csg analyze --terraform ./infra --profile devops
csg report --format html --out ./out.html
```

## Local development

```bash
git clone https://github.com/wisnuanggoro/cloudspendguard
cd cloudspendguard
make build
make test
make run-sample
```

## Security & privacy

- Read-only AWS access only. See [`docs/iam-policy.json`](docs/iam-policy.json).
- No cloud data leaves your machine unless you explicitly pass `--llm-provider=openai`.
- PII/ARN redaction pass before any external LLM call.
- Prompt-injection guardrails and adversarial test suite.

## Roadmap

See [`docs/roadmap.md`](docs/roadmap.md). This project is a Master's capstone; contributions welcome after v1.0.0.

## License

MIT © 2026 Wisnu Anggoro
