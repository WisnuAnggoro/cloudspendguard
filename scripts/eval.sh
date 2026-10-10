#!/usr/bin/env bash
# Unit 6 detection experiment: CloudSpendGuard vs tfsec vs Checkov on the
# labeled Terraform fixtures in testdata/eval. Needs tfsec and checkov on PATH
# (see docs/evaluation.md). Writes tool outputs to tmp/eval/ and per-category
# results to tmp/eval/results.csv.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p tmp/eval
make -s build >/dev/null

echo "== versions"
tfsec --version 2>/dev/null | head -1 || echo "tfsec not installed"
checkov --version 2>/dev/null | head -1 || echo "checkov not installed"
bin/csg version

wall() { # wall <label> <command...>: median of 5 runs, in seconds
  local label=$1; shift; local t=()
  for _ in 1 2 3 4 5; do
    local s=$(date +%s.%N); "$@" >/dev/null 2>&1 || true; local e=$(date +%s.%N)
    t+=("$(echo "$e - $s" | bc -l)")
  done
  printf '%s\n' "${t[@]}" | sort -n | awk -v l="$label" '{a[NR]=$1} END {printf "%-16s median wall time %.3f s over 5 runs\n", l, a[3]}'
}

echo "== latency on the labeled fixtures"
rm -f tmp/eval/lat.db*
wall "CloudSpendGuard" bash -c 'rm -f tmp/eval/lat.db*; bin/csg ingest tfstate --db tmp/eval/lat.db testdata/eval && bin/csg analyze --db tmp/eval/lat.db'
command -v tfsec >/dev/null && wall "tfsec" tfsec testdata/eval --no-colour --soft-fail
command -v checkov >/dev/null && wall "Checkov" checkov -d testdata/eval --framework terraform --quiet --compact

echo "== tool outputs"
command -v tfsec >/dev/null && tfsec testdata/eval --format json --no-colour --soft-fail > tmp/eval/tfsec.json 2>/dev/null
command -v checkov >/dev/null && checkov -d testdata/eval --framework terraform --output json --quiet --compact > tmp/eval/checkov.json 2>/dev/null || true

echo "== scores"
args=()
[ -s tmp/eval/tfsec.json ] && args+=(-tfsec tmp/eval/tfsec.json)
[ -s tmp/eval/checkov.json ] && args+=(-checkov tmp/eval/checkov.json)
go run ./tools/evalscore -dir testdata/eval -csv tmp/eval/results.csv "${args[@]}"
