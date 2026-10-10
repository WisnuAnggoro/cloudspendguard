# CloudSpendGuard: Install, Configure, and Deploy

Written for Unit 6 (v0.6.0-beta). Every command here was run against this repository; the Docker and AWS
commands are marked where they could not be run in the author's test environment.

## 1. Choose a deployment method

| Method | Use when | Needs | Notes |
|---|---|---|---|
| Local binary (default) | One engineer, one laptop, data must stay on the machine | Nothing at run time | Static binary, no cgo, no AWS credentials for local-file mode |
| Docker image | Reproducible runs, CI jobs, a server without a Go toolchain | Docker 24 or newer | Distroless, non-root, about 20 MB |
| Scheduled AWS task | A report every morning without anyone running a command | AWS account, ECS, S3 | `deploy/aws/scheduled-scan.yaml`, read-only IAM |
| AWS Lambda | Not supported in v0.6.0 | | `csg` is a command, not a Lambda handler, and runs can exceed 15 minutes (see section 7) |

The recommended method is the local binary, with the Docker image for automation. Section 7 explains why.

## 2. System prerequisites

| Item | Requirement | Why |
|---|---|---|
| Operating system | macOS 12+, Linux (glibc or musl), or Windows 10+ | Prebuilt binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64 |
| Go toolchain | 1.25 or newer (CI uses 1.26) | Only to build from source; 1.25 is the floor because of the `golang.org/x/text` fix GO-2026-5970 |
| Git | 2.30 or newer | Clone the repository |
| make | GNU make 3.81 or newer | Wrapper for build, test, and demo targets |
| Docker | 24 or newer | Optional, for the container image |
| Ollama | 0.3 or newer | Optional, only for `csg remediate` with a local model |
| tfsec, Checkov | v1.28.14 and 3.3.26 | Optional, only for `make eval` |
| Disk | 50 MB for the binary and cache; roughly 100 MB per million CUR line items for the report data | |
| Memory | About 1.8 GB of RAM per million CUR line items (measured, see `docs/evaluation.md`) | The whole export is held in memory |

Runtime library dependencies: none. The binary is built with `CGO_ENABLED=0`, so it needs no C library, no
SQLite, and no DuckDB install.

## 3. Environment variables and settings

| Variable or flag | Default | Effect |
|---|---|---|
| `CSG_DB` or `--db <path>` | `.csg/csg.db` | Local SQLite store used by `ingest`, `query`, `analyze`, `report`. For `csg run` the store is temporary unless `--db` is given |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Where `csg remediate` finds the local model |
| `OPENAI_API_KEY` | unset | Used only with `--llm-provider openai --allow-remote`; never needed for the default path |
| `--profile devops\|finops\|security\|cxo` | `devops` | Weights for the score `S = a*savings + b*risk - c*blast` |
| `--weights a,b,g` | unset | Explicit weights, overrides `--profile` |
| `--top <n>` | all | Keep only the first n backlog items |
| `--sarif-uri <path>` | `infrastructure.tf` | File that SARIF results point at; set it to the real Terraform path when uploading to GitHub |
| `--stats` | off | Print stage timings, throughput, and peak memory |

No setting is read from a file. Everything is a flag or one of the variables above, so a run is fully described
by its command line. AWS credentials are not used by any command in v0.6.0: input is read from local files.

## 4. Install and set up

### 4.1 Build from source

```bash
git clone https://github.com/wisnuanggoro/cloudspendguard
cd cloudspendguard
git checkout v0.6.0-beta          # or stay on main
make build                        # static binary at ./bin/csg
export PATH="$PWD/bin:$PATH"
csg version                       # csg v0.6.0-beta
```

### 4.2 Check the installation (no AWS account needed)

```bash
make test                         # unit tests with the race detector
make cover-gate                   # 90% coverage gate on analyzers, prioritizer, LLM engine, reporter
csg run --sample --report ./out.html
```

The last command prints the prioritized backlog and writes `out.html`. Expected: 23 findings, USD 785.55 per
month projected savings, and a file of about 32 KB.

### 4.3 Analyze your own data

```bash
# A directory with a CUR export (.parquet or .csv), CloudTrail logs (.json), and terraform.tfstate or *.tf files
csg run --input ./my-account --profile security --report ./report.html
csg run --input ./my-account --report ./csg.sarif --sarif-uri infra/main.tf
```

`csg run` reads the top level of the directory: `.parquet`, `.csv`, `.csv.gz` are CUR; `.json` files that begin
with a `"Records"` array and all `.json.gz` files are CloudTrail; `.tfstate` is Terraform state; a directory with
`*.tf` files is read as configuration. Sub-directories are ignored.

To keep a queryable store:

```bash
csg run --input ./my-account --db ./.csg/csg.db --quiet
csg query "SELECT service, ROUND(SUM(cost), 2) FROM cur GROUP BY 1 ORDER BY 2 DESC"
csg report --format markdown --top 20 > backlog.md
```

## 5. Build and release commands

```bash
make build                        # one binary for this machine
make build-all                    # five static binaries in ./dist
make lint                         # go vet + golangci-lint v2
make ci                           # lint, test, cover-gate, build-all, demo: what GitHub Actions runs
make sample-report                # regenerate docs/sample-report.html

# Release (see docs/version-control.md)
git switch main && git merge --no-ff develop -m "release: v0.6.0-beta"
git tag -a v0.6.0-beta -m "v0.6.0-beta: integration, reports, evaluation, deployment"
git push origin main v0.6.0-beta
gh release create v0.6.0-beta --title "v0.6.0-beta: Integrated pipeline, reports, and deployment" \
  --notes-file docs/releases/v0.6.0-beta.md --prerelease dist/*
```

## 6. Docker

```bash
docker build -t csg:0.6.0-beta --build-arg VERSION=0.6.0-beta .
docker run --rm csg:0.6.0-beta version
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" \
  csg:0.6.0-beta run --sample --report /out/report.html
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/my-account:/data:ro" -v "$PWD/out:/out" \
  csg:0.6.0-beta run --input /data --report /out/report.html --quiet
```

The image is distroless with a non-root user, so it has no shell and nothing to patch except the binary. It sets
`CSG_DB=/tmp/csg.db`. On version tags, GitHub Actions pushes it to `ghcr.io/wisnuanggoro/cloudspendguard`.
These commands were written for, but not run in, the author's evaluation sandbox, which had no Docker daemon;
the CI `docker` job is the first place they execute.

## 7. Scheduled AWS deployment

```bash
aws cloudformation validate-template --template-body file://deploy/aws/scheduled-scan.yaml
aws cloudformation deploy --stack-name csg-scheduled-scan \
  --template-file deploy/aws/scheduled-scan.yaml --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    ImageUri=ghcr.io/wisnuanggoro/cloudspendguard:0.6.0-beta \
    InputBucket=my-finops-exports InputPrefix=csg-input/ \
    SubnetIds=subnet-aaa,subnet-bbb SecurityGroupId=sg-ccc \
    Profile=devops
```

The template creates a private encrypted report bucket, a Fargate task that copies the input prefix, runs
`csg run`, and publishes `report.html` and `report.sarif`, and an EventBridge rule that starts it every day at
05:00 UTC. The task role can list and read the input prefix and write to the report bucket; nothing else. It
passes `cfn-lint` 1.57; it was not deployed to a real account for this unit.

Why not Lambda? `csg` is a command-line program, so a Lambda deployment would need a separate handler that
speaks the Lambda runtime API. A CUR export can also take longer than the 15-minute limit at scale, and a
local LLM cannot run inside a function. The plan listed Lambda as optional, so v0.6.0 documents the decision
instead of shipping an untested handler (RAID entry D-08).

## 8. Rollback and upgrade

- Local binary: keep the previous `csg` file; the store schema has not changed since v0.2.0, so `.csg/csg.db`
  works with both versions.
- Docker: pin an exact tag (`0.6.0-beta`), never `latest`; roll back by redeploying the previous tag.
- CloudFormation: `aws cloudformation deploy` with the previous `ImageUri`, or delete the stack. The report
  bucket has `DeletionPolicy: Retain`, so reports survive a rollback.
