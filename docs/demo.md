# Unit 4 System Demonstration Runbook

Commands for the Unit 4 identity verification and system demonstration
video. Every command runs offline against the synthetic fixtures in
`testdata/` (one fictional account, `111122223333`, for September 2026). No
AWS credentials are needed.

## Before recording

```bash
make clean && make build        # static binary in ./bin/csg
rm -rf .csg                     # start from an empty local store
export PATH="$PWD/bin:$PATH"
csg version                     # csg 0.2.0-analyze-alpha (or the git tag)
```

Increase the terminal font size and widen the window to about 180 columns so
the backlog table does not wrap.

## Core functionality 1: ingest three sources into one local store

```bash
csg ingest cur ./testdata/sample-cur.parquet
csg ingest cloudtrail ./testdata/sample-events.json
csg ingest tfstate ./testdata/terraform.tfstate
```

Expected: 300 CUR line items, 8 CloudTrail events, 15 Terraform resources.
To show idempotency, ingest the CSV copy of the same billing data:

```bash
csg ingest cur ./testdata/sample-cur.csv    # 0 new, 300 already present
```

## Core functionality 2: query the store with SQL

```bash
csg query "SELECT service, SUM(cost) FROM cur GROUP BY 1"
csg query "SELECT service, ROUND(SUM(cost), 2) AS cost FROM cur GROUP BY 1 ORDER BY 2 DESC"
csg query "SELECT event_time, event_name, user_arn FROM cloudtrail_events ORDER BY event_time"
csg query "DELETE FROM cur"                 # rejected: the query path is read-only
```

Expected totals: AmazonEC2 156.72, AmazonRDS 48.96, AmazonS3 14.10,
AWSCloudTrail 1.50 (USD, September 2026).

## Core functionality 3: prioritized cost and security backlog

```bash
csg analyze                         # devops profile
csg analyze --profile security      # public bucket moves to the top
csg analyze --format json | head -40
```

Expected: five findings, USD 44.20 per month projected savings.

| Rule | Resource | Why it fires |
|---|---|---|
| COST-EBS-IDLE-001 | vol-0a1b2c3d4e5f60099 | 500 GiB gp3 volume with no attachment, USD 40.55/month in CUR |
| SEC-S3-PUBLIC-001 | tui-demo-booking-exports | public-read ACL, Block Public Access disabled, and bob's CloudTrail calls |
| SEC-IAM-ADMIN-001 | break-glass-admin policy | Terraform policy with Action and Resource `*` |
| SEC-IAM-ADMIN-001 | legacy-ci-deployer | `*:*` inline policy added through CloudTrail, outside Terraform |
| COST-EIP-UNATTACHED-001 | eipalloc-0a1b2c3d4e5f60077 | no association and billed as `PublicIPv4:IdleAddress` |

The clean resources (attached volume, associated IP, private log bucket,
scoped IAM policies) are negative controls: they must not appear.

## Development environment and CI

```bash
make test         # race detector, all packages
make cover-gate   # 90% gate on analyzers and core algorithms (NFR3)
make lint         # go vet and golangci-lint v2
make build-all    # static binaries for five OS and architecture targets
```

Then show `.github/workflows/ci.yml` and a green run in the GitHub Actions tab.

## One command

`make demo` runs the build, the three ingests, the SQL query, and `analyze`
against a throwaway database in `tmp/`. CI runs the same target as its smoke
test.

## Unit 6: one command to a report

```bash
./bin/csg run --sample --report tmp/report.html --stats --top 5
./bin/csg report --db tmp/demo.db --format sarif --out tmp/demo.sarif
python3 scripts/validate_sarif.py tmp/demo.sarif       # expect: valid against SARIF 2.1.0
make eval                                               # needs tfsec and Checkov on PATH
make bench                                              # 10k, 100k, 1M CUR line items
```
