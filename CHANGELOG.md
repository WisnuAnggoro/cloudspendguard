# Changelog

All notable changes to CloudSpendGuard. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/) with the milestone tags defined in
[`docs/version-control.md`](docs/version-control.md).

## [0.6.0-beta], Unit 6 (Week 6)

Integration, reporting, evaluation, and deployment. Tag `v0.6.0-beta` on the merge commit into `main`.

### Added

- `csg run (--sample | --input <dir>)`: ingest, analyze, prioritize, and report in one command, with `--profile`,
  `--weights`, `--top`, `--format`, `--report`, `--db`, `--sarif-uri`, `--quiet`, and `--stats` (stage timings,
  throughput, peak memory).
- `csg report`: re-render the stored backlog as Markdown, HTML, JSON, or SARIF 2.1.0 (M10).
- Self-contained HTML report (no scripts, no external requests) with score bars and remediation cards; the
  bundled example is `docs/sample-report.html`.
- `internal/sample`: the sample account embedded in the binary, so `--sample` works anywhere.
- Evaluation harness: `testdata/eval` (34 labeled defects), `tools/evalscore`, `scripts/eval.sh`,
  `tools/benchgen`, `scripts/bench.sh`, `scripts/validate_sarif.py`, and the survey kit in `docs/survey`.
- `Dockerfile` (multi-stage, distroless, non-root), `.dockerignore`, `deploy/aws/scheduled-scan.yaml`,
  `docs/install.md`, `docs/evaluation.md`.
- CI: smoke run of all four formats with SARIF schema validation, Docker build and GHCR push on version tags,
  manual SARIF upload to code scanning.
- Make targets `sample-report`, `bench`, `eval`, `docker`, `docker-run`.

### Changed

- `csg run` keeps CUR rows in memory unless `--db` is set (`store.DedupeCUR`): 1,000,000 rows in 7.1 s, was 41 s.
- Core coverage gate now includes `internal/report`.

### Fixed

- SARIF validator now loads certifi's certificate bundle in addition to the configured/default
  trust roots, avoiding missing-CA failures on macOS while retaining TLS verification.
  Dependency installation uses `python3 -m pip` to match the executing interpreter.
- IMDSv2 rule treated `http_endpoint = "disabled"` as non-compliant (false positive found by the evaluation).

### Known limits

- Terraform variables and data sources are not resolved. Memory grows with CUR rows (NFR1 partly met).
  No Lambda handler; scheduled Fargate task instead.

## [0.3.0-algo], Unit 5 (Week 5)

Core logic milestone: the full rule library, the cost-anomaly detector, the
joint prioritizer (M7), and the LLM remediation engine with its verifier
(M8 and M9). Tag `v0.3.0-algo` on the merge commit into `main`.

### Added

- M5 cost-anomaly detector `internal/analyze/anomaly` (`COST-ANOMALY-001`):
  robust STL decomposition (Cleveland et al., 1990) per service and team,
  modified z-score on residuals (Iglewicz and Hoaglin, 1993), and a seeded
  Isolation Forest (Liu et al., 2008). A day is anomalous only when both
  signals agree and the excess is material (at least USD 1 and 20% of the
  expected spend). New command `csg anomalies [--series <key>]`.
- M5 cost rules, now 15: `EBS-GP2`, `EC2-PREVGEN`, `EC2-GRAVITON`,
  `EC2-STOPPED`, `RDS-NONPROD-SIZE`, `RDS-NONPROD-MULTIAZ`, `RDS-GP2`,
  `S3-NO-LIFECYCLE`, `LOGS-RETENTION`, `EBS-SNAPSHOT-ORPHAN`, `ELB-IDLE`,
  `NAT-IDLE` (CUR only), and `ANOMALY`, in a declarative rule table.
- M6 security rules, now 20, each mapped to a CIS AWS Foundations v3.0.0
  control: 1.8/1.9, 1.15, 1.16, 2.1.1, 2.1.2, 2.1.4, 2.2.1, 2.3.1, 2.3.3,
  2.4.1, 3.1, 3.2, 3.5, 3.6, 3.7, 5.1, 5.2, 5.3, 5.4, 5.6.
- M3 HCL support: `ParseHCL` reads `*.tf` directories (`csg ingest tfstate
  <dir>`), and `RenderHCL` turns a state resource back into canonical HCL.
- M7 `prioritize.Rank` returns rank, score, and the normalized savings, risk,
  and blast components; `csg analyze --weights a,b,g` and `--top n`.
- M8 `internal/llm`: generate-then-verify loop with at most 3 attempts.
  Ollama is the default and local; OpenAI-compatible APIs need
  `--allow-remote` and always redact ARNs, account IDs, IPs, e-mails, and
  access keys. Untrusted tag and name values that look like instructions are
  withheld behind placeholders and restored after generation. The data block
  is fenced with a random nonce. `csg remediate <finding-id>` with
  `--llm-provider ollama|openai|replay`, `--fixture`, and `--record`.
- M9 `internal/llm/verify`: re-parses the candidate HCL, rejects extra
  blocks, provisioners, expressions, dropped arguments, invented
  placeholders, and invalid CIDRs, then re-runs all 35 rules and rejects any
  patch that leaves the finding open or adds a security finding. Produces a
  unified diff. Patches are never applied.
- Tests: positive and negative case for every rule, 12 prompt-injection
  payloads, 9 malicious model answers, httptest mocks for both backends,
  golden-file tests over 5 fixtures recorded from a local
  `qwen2.5-coder:1.5b` model (`make golden`), and a detection-quality
  experiment on 400 synthetic series (precision 0.997, recall 0.910).
- Sample data: a two-day GPU spike, a seasonal Lambda series, an oversized
  Multi-AZ staging database, a legacy instance whose `owner` tag carries a
  prompt-injection payload, and resources for the new CIS rules.

### Changed

- Prioritizer normalizes savings with `log1p` instead of dividing by the
  maximum, so one large anomaly no longer flattens every other saving.
- Overlapping cost findings on one resource are compounded instead of
  summed (RDS right-sizing plus Multi-AZ claimed 100% of the bill before).
- `Finding.Resource.TerraformAddress` and `Remediation.Action`
  (`modify`, `delete`, `investigate`) added; only `modify` findings with a
  Terraform address are eligible for LLM patches.

### Fixed

- Unified diff printed `+new` before `-old`.
- Flat billing series produced z-scores in the millions from floating-point
  noise; dispersion is now floored at one cent.
- Security: `golang.org/x/text` v0.11.0 to v0.39.0 (GO-2026-5970, infinite
  loop on invalid input, reachable through HCL parsing) and
  `github.com/klauspost/compress` v1.17.9 to v1.18.7 (GO-2026-5841). The fix
  requires Go 1.25, so the minimum Go version is now 1.25 and CI builds on
  Go 1.26 with golangci-lint v2.14.0.
- Golden-file tests failed on Windows because Git converted fixtures to CRLF;
  `.gitattributes` now keeps them byte-identical and the comparison ignores CRLF.

### Not yet

- `csg report` and `csg run` (Unit 6), Docker image and SARIF upload on tag
  (Units 6 and 8).

## [0.2.0-analyze-alpha], Unit 4 (Week 4)

This milestone also delivers the Week 3 ingest scope, which slipped
(RAID I-02). Tag both on the same commit so the version history matches the
plan: `v0.1.0-ingest` for M1 to M4 and `v0.2.0-analyze-alpha` for M5 and M6.

### Added

- M1 `internal/ingest/cur`: CUR reader for Parquet (CUR 2.0 column names) and
  CSV or CSV.gz (CUR 1.0 and 2.0 headers), single file or directory; user tag
  prefixes (`user:` and `user_`) normalized.
- M2 `internal/ingest/cloudtrail`: streaming reader for CloudTrail
  `{"Records": [...]}` logs, `.json` and `.json.gz`, file or directory.
- M3 `internal/ingest/tfstate`: Terraform state v4 parser (managed resources,
  modules, `count` and `for_each` index keys). HCL parsing follows in Unit 5.
- M4 `internal/store`: embedded pure-Go SQLite store with tables `cur`,
  `cloudtrail_events`, and `tf_resources`; idempotent re-ingest; read-only
  query path enforced twice (statement prefix check and SQLite `query_only`).
- M5 cost rules: `COST-EBS-IDLE-001` (unattached EBS volume) and
  `COST-EIP-UNATTACHED-001` (idle Elastic IP), priced from CUR when billed,
  otherwise estimated from list prices.
- M6 security rules: `SEC-S3-PUBLIC-001` (CIS AWS Foundations v3.0.0 2.1.4)
  and `SEC-IAM-ADMIN-001` (CIS 1.16), each combining Terraform state with
  CloudTrail evidence of out-of-band changes.
- CLI: `csg ingest cur|cloudtrail|tfstate`, `csg query "<SQL>"`, and
  `csg analyze [--profile] [--format table|json]`, which prints the M7
  prioritized backlog together with the active weights (RAID R-08).
- Synthetic fixtures in `testdata/` and their generator `tools/gensample`.
- CI: golangci-lint v2, `go mod tidy` check, race-enabled test matrix on
  Linux, macOS, and Windows, Codecov upload, 90% coverage gate on analyzers and
  core algorithms (NFR3), static cross-compilation for five targets (NFR4),
  `govulncheck`, and an end-to-end smoke run (`make demo`).
- Makefile targets: `build-all`, `cover`, `cover-gate`, `sample-data`, `demo`,
  and `ci` (local fallback for RAID D-07).

### Changed

- Store engine: DuckDB replaced by pure-Go SQLite to keep the binary static
  (RAID I-01, D-03). The `Store` interface is unchanged apart from row counts
  returned by inserts, `Load*` methods, and `Rows.Columns`.
- Parquet library: parquet-go instead of Apache Arrow Go (RAID D-02).
- `cost.Analyze` and `security.Analyze` take an `Input` struct so detectors
  can join billing data with resource inventory.
- CIS control IDs now carry the benchmark version (`CIS-AWS-v3.0.0-...`).

### Not yet

- `csg report` and `csg run` (Unit 6), Docker image and SARIF upload on tag
  (Units 6 and 8), and the remaining 13 cost and 18 security rules (Unit 5).

## [0.0.1-scaffold], Units 1 to 3

- Repository scaffold, package stubs, architecture, requirements, and RAID log.
