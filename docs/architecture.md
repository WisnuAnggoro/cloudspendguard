# CloudSpendGuard — Architecture

See the full Master's-grade specification at `../../capstone-plan/CloudSpendGuard-Project-Spec.md`
in the parent workspace, or the version committed to the report.

## Modules

| Module | Path | Responsibility |
|---|---|---|
| Ingest — CUR | `internal/ingest/cur` | Read AWS CUR Parquet/CSV, normalize into DuckDB rows |
| Ingest — CloudTrail | `internal/ingest/cloudtrail` | Read CloudTrail JSON events |
| Ingest — Terraform | `internal/ingest/tfstate` | Parse `terraform.tfstate` + HCL files |
| Store | `internal/store` | DuckDB wrapper; time-series queries |
| Analyze — Cost | `internal/analyze/cost` | Waste detectors + STL/z-score/Isolation Forest anomaly detection |
| Analyze — Security | `internal/analyze/security` | HCL rule engine + CIS/PCI/NIST mapping |
| Prioritize | `internal/prioritize` | Joint cost × risk scoring (core research contribution) |
| LLM | `internal/llm` | Ollama/OpenAI clients; sanitizer; prompt-injection guardrails; verify loop |
| Report | `internal/report` | Markdown / HTML / JSON / SARIF renderers |
| CLI | `cmd/csg` | Cobra-style command surface |

## Data flow

```
CUR + CloudTrail + tfstate
         │
         ▼
       Store (DuckDB)
         │
         ▼
  Cost + Security analyzers  →  Findings
         │
         ▼
      Prioritizer  →  ranked backlog
         │
         ▼
  LLM remediation engine  →  Terraform patches
         │
         ▼
     Verifier (re-scan)  →  approved patches
         │
         ▼
       Reporter
```

## Non-functional constraints

- Single static Go binary
- < 60s to analyze 1 GB CUR + 100 MB CloudTrail on M-series MacBook
- Zero outbound network calls unless the user opts into a cloud LLM
