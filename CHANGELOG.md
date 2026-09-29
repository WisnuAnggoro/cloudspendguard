# Changelog

All notable changes to CloudSpendGuard. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/) with the milestone tags defined in
[`docs/version-control.md`](docs/version-control.md).

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
