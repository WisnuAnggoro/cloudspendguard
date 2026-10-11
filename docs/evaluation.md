# Evaluation of CloudSpendGuard v0.6.0-beta

Unit 6 evaluation: detection quality against tfsec and Checkov, performance at four sizes, and the human
evaluation protocol. Everything below can be reproduced with `make eval`, `make bench`, and the survey files.
Numbers are from one machine (2 vCPU x86_64 Linux VM, 8 GB RAM, Go 1.26.1); re-run on your own hardware before
quoting them as your own.

## 1. Detection experiment

Question: when a Terraform configuration contains known misconfigurations, how many does each tool report, and
how many of its reports are wrong?

Method.
- Corpus: `testdata/eval/*.tf`, 10 files, 60 parsed resources and blocks, written for this experiment. Each file
  mixes insecure and secure variants of the same resource.
- Ground truth: `testdata/eval/labels.json`, 34 defects in 13 categories, each mapped to a CIS AWS Foundations
  v3.0.0 control (S3 public access, security groups open to the world on admin ports, unencrypted EBS, RDS and EFS,
  public RDS, IMDSv2, IAM admin wildcards, KMS rotation, CloudTrail validation, KMS, multi-region, VPC flow logs).
  A resource with no label is a negative: a tool report on it is a false positive.
- Tools: CloudSpendGuard v0.6.0-beta (20 security rules), tfsec v1.28.14, Checkov 3.3.26 (Terraform framework).
- Matching: `testdata/eval/mapping.json` maps each tool's rule ids to the 13 categories, so a report counts when
  the category and the resource both match. `tools/evalscore` computes true positives (TP), false positives (FP),
  false negatives (FN), precision = TP / (TP + FP), recall = TP / (TP + FN), and F1.

Results (`go run ./tools/evalscore`):

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| CloudSpendGuard | 32 | 0 | 2 | 1.000 | 0.941 | 0.970 |
| tfsec | 32 | 4 | 2 | 0.889 | 0.941 | 0.914 |
| Checkov | 34 | 0 | 0 | 1.000 | 1.000 | 1.000 |

Where the tools disagree with the labels:

| Tool | Result | Category | Resource | Cause |
|---|---|---|---|---|
| CloudSpendGuard | missed | EBS-ENCRYPT | `aws_ebs_volume.param` | `encrypted = var.encrypt_volumes`; variables are not resolved |
| CloudSpendGuard | missed | IAM-ADMIN | `aws_iam_policy.admin_via_data` | policy built with `data.aws_iam_policy_document`, which is not evaluated |
| tfsec | false positive | IAM-ADMIN | `aws_iam_policy.s3_wild` | flags `s3:*` as an admin wildcard |
| tfsec | false positive | SG-ADMIN | `https_world`, `web_world`, `high_ports_world` | fires on any public ingress, not only admin ports |
| tfsec | missed | IAM-ADMIN | `aws_iam_role_policy.admin_list` | `Action` given as a list |
| tfsec | missed | SG-ADMIN | `aws_vpc_security_group_ingress_rule.ssh_rule_world` | standalone ingress-rule resource |

Evaluation found a real bug. Before the fix CloudSpendGuard reported `aws_instance.no_imds`, an instance with
`http_endpoint = "disabled"`, as lacking IMDSv2 (1 FP, precision 0.970). Disabling the endpoint is compliant, so
the rule was corrected and a regression test added (`TestIMDSDisabledIsCompliant`).

Honest reading.
- Checkov is the best detector here. CloudSpendGuard does not beat it on detection and does not claim to. The
  product value is the joint ranking of cost and risk, verified remediation, and local-first operation.
- Threats to validity: the author wrote both the fixtures and the labels; the corpus is small (34 defects); the
  IMDS fix was made after seeing the false positive, so the 1.000 precision is tuned on this data. A fair test
  needs fixtures written by someone else, for example the public tfsec and Checkov test suites.
- Infracost was dropped from the precision and recall comparison. It estimates cost from Terraform and produces
  no findings to score, and its cloud pricing needs an API key. This deviates from the 8-week plan.

Latency on the same fixtures (median of 5 wall-clock runs, `scripts/eval.sh`): CloudSpendGuard 0.021 s (two
commands, ingest then analyze), tfsec 0.733 s, Checkov 2.733 s. The gap mostly reflects start-up cost of a
Python and a larger Go program, and CloudSpendGuard has fewer rules, so this is not a like-for-like speed claim.

## 2. Performance (NFR1)

NFR1 asks for a 1 GB CUR export in under 60 seconds. `tools/benchgen` writes deterministic synthetic Parquet CUR
files (90 days per resource). `scripts/bench.sh` runs `csg run --input <dir> --stats --quiet` 3 times per size
and reports the median (full table in `docs/bench-results.md`):

| CUR line items | Parquet size (MB) | Total (s) | Ingest (s) | Analyze (s) | Throughput (items/s) | Peak RSS (MB) |
|---:|---:|---:|---:|---:|---:|---:|
| 392 (bundled sample) | 0.04 | 0.02 | 0.002 | 0.007 | about 19,000 | 18.5 |
| 10,000 | 1 | 0.911 | 0.030 | 0.441 | 10,976 | 35.9 |
| 100,000 | 12 | 1.711 | 0.316 | 0.631 | 58,440 | 180.6 |
| 1,000,000 | 122 | 7.113 | 3.118 | 1.169 | 140,588 | 1,800.7 |

A separate 3,000,000-row run (367 MB Parquet) took 23.3 s and 4.8 GB peak RSS.

A finding changed the design. The first version sent every row through the SQLite store: 1,000,000 rows took
about 41 s (median of 3, still the `--db` path today) and the ingest stage was most of it. `csg run` now keeps the CUR rows in
memory unless `--db` is given, and `store.DedupeCUR` returns exactly what the database round trip returns (a
test proves it). Result: 40.9 s to 7.1 s, a 5.8 times speed-up, with about the same memory.

Is NFR1 met? Partly, and the answer needs care.
- Time: extrapolating linearly (about 7 s per 122 MB), a 1 GB Parquet export is about 60 s on this 2-vCPU VM.
  This is an extrapolation, not a measurement; the VM could not hold a run that large.
- Memory: it is not met. The reader loads every row, and peak RSS is about 1.8 KB per line item, so 1 GB of
  Parquet (roughly 8 million rows) would need about 13 GB. A laptop cannot run it.
- Fix for the next release: aggregate per service, team, and day while streaming row groups, and keep only the
  daily series the anomaly detector needs. That turns memory from proportional to the rows into proportional to
  the distinct series times days.
- The 10,000-row run has a fixed cost of about 0.4 s in the anomaly detector (forest training), which
  dominates small inputs.

## 3. Test quality

`go test ./...` at this tag: 92 test functions and 117 subtests, all passing. Coverage of the core gate
(`internal/analyze`, `internal/prioritize`, `internal/llm`, `internal/report`) is 96.9% against a 90% gate;
whole-module coverage is 85.0%. SARIF output validates against the official OASIS 2.1.0 schema with 0 errors
(`scripts/validate_sarif.py`), on the sample account (23 results) and the evaluation fixtures (46 results).

## 4. Human evaluation (qualitative metric)

Protocol: `docs/survey/instrument.md`; cards: `docs/survey/cards-top20.md`; summary script:
`scripts/survey_summary.py`. Status at this tag: instrument ready, responses not yet collected. No survey
numbers are reported in this repository until real respondents have answered. RAID R-03 keeps the fallback of
two heuristic reviewers.

## 5. Limits that remain

- CloudSpendGuard does not resolve Terraform variables or evaluate data sources (2 of the 34 defects).
- The ranking weights are a judgment, not a measured optimum (RAID R-08).
- The R-12 comparison of `qwen2.5-coder:1.5b` with `llama3.1:8b` was not run in this unit.
- The Docker image and the CloudFormation stack were not deployed in the test environment; the template passes
  `cfn-lint` and the CI job builds the image.
