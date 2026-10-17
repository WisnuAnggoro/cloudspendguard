#!/usr/bin/env bash
# Unit 6 detection experiment: CloudSpendGuard vs tfsec vs Checkov on the
# labeled Terraform fixtures in testdata/eval. Needs Go and Python 3;
# tfsec and checkov on PATH enable the comparison (see docs/evaluation.md).
# Compatible with Bash 3.2. Writes tool outputs to tmp/eval/ and per-category
# results to tmp/eval/results.csv.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p tmp/eval
# Never score scanner output left over from a previous run.
rm -f tmp/eval/tfsec.json tmp/eval/checkov.json tmp/eval/results.csv
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: Python 3 is required for portable timing" >&2
  exit 1
fi
make -s build >/dev/null

echo "== versions"
tfsec --version 2>/dev/null | head -1 || echo "tfsec not installed"
checkov --version 2>/dev/null | head -1 || echo "checkov not installed"
bin/csg version
if ! command -v tfsec >/dev/null 2>&1 || ! command -v checkov >/dev/null 2>&1; then
  echo "NOTE: comparison is incomplete; missing scanners will be skipped."
  echo "Install both tfsec and Checkov for the three-tool comparison."
fi

wall() { # wall <label> <command...>: median of 5 runs, in seconds
  local label=$1
  shift
  python3 - "$label" "$@" <<'PY'
import statistics
import subprocess
import sys
import time

label = sys.argv[1]
command = sys.argv[2:]
times = []
for _ in range(5):
    started = time.perf_counter()
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    times.append(time.perf_counter() - started)
    # Checkov uses exit status 1 when its scan finds failed checks.
    if result.returncode != 0 and not (label == "Checkov" and result.returncode == 1):
        print(f"{label} timing command failed (exit {result.returncode}): {result.stderr}", file=sys.stderr)
        sys.exit(1)
print(f"{label:<16} median wall time {statistics.median(times):.3f} s over 5 runs")
PY
}

echo "== latency on the labeled fixtures"
rm -f tmp/eval/lat.db*
wall "CloudSpendGuard" bash -c 'rm -f tmp/eval/lat.db*; bin/csg ingest tfstate --db tmp/eval/lat.db testdata/eval && bin/csg analyze --db tmp/eval/lat.db'
if command -v tfsec >/dev/null 2>&1; then
  wall "tfsec" tfsec testdata/eval --no-colour --soft-fail
fi
if command -v checkov >/dev/null 2>&1; then
  wall "Checkov" checkov -d testdata/eval --framework terraform --quiet --compact
fi

echo "== tool outputs"
if command -v tfsec >/dev/null 2>&1; then
  tfsec testdata/eval --format json --no-colour --soft-fail > tmp/eval/tfsec.json
fi
if command -v checkov >/dev/null 2>&1; then
  if checkov -d testdata/eval --framework terraform --output json --quiet --compact > tmp/eval/checkov.json; then
    :
  else
    status=$?
    if [ "$status" -ne 1 ]; then
      echo "error: Checkov failed (exit $status)" >&2
      exit "$status"
    fi
  fi
fi

echo "== scores"
# Positional arguments avoid Bash 3.2's empty-array error with set -u.
set -- -dir testdata/eval -csv tmp/eval/results.csv
if [ -s tmp/eval/tfsec.json ]; then
  set -- "$@" -tfsec tmp/eval/tfsec.json
fi
if [ -s tmp/eval/checkov.json ]; then
  set -- "$@" -checkov tmp/eval/checkov.json
fi
go run ./tools/evalscore "$@"
