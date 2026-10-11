#!/usr/bin/env bash
# Unit 6 performance measurement (NFR1): end-to-end `csg run` on synthetic CUR
# exports of growing size. Prints a Markdown table; save it with
#   scripts/bench.sh | tee docs/bench-results.md
#
# Usage: scripts/bench.sh [rows...]   (default: 10000 100000 1000000)
#        RUNS=5 scripts/bench.sh 1000000
set -euo pipefail
cd "$(dirname "$0")/.."

SIZES=("$@")
[ ${#SIZES[@]} -eq 0 ] && SIZES=(10000 100000 1000000)
RUNS="${RUNS:-3}"

make -s build >/dev/null
go build -o tmp/benchgen ./tools/benchgen

echo "Host: $(uname -sm), $(getconf _NPROCESSORS_ONLN) logical CPUs, $(go version | cut -d' ' -f3)"
echo "Runs per size: $RUNS (median reported)"
echo
echo "| CUR line items | Parquet size (MB) | Total (s) | Ingest (s) | Analyze (s) | Throughput (items/s) | Peak RSS (MB) |"
echo "|---:|---:|---:|---:|---:|---:|---:|"

median() { sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
secs() { # "1.5s" "320ms" "450µs" "1m5.2s" -> seconds
  awk -v v="$1" 'BEGIN {
    t = 0
    if (match(v, /[0-9.]+m[^s]/)) { split(v, p, "m"); t += p[1] * 60; v = p[2] }
    if (v ~ /ms$/) { sub(/ms/, "", v); t += v / 1000 }
    else if (v ~ /µs$/) { sub(/µs/, "", v); t += v / 1000000 }
    else { sub(/s/, "", v); t += v }
    printf "%.3f", t }'
}

for n in "${SIZES[@]}"; do
  dir="tmp/bench-$n"
  [ -f "$dir/bench-cur.parquet" ] || tmp/benchgen -rows "$n" -out "$dir" >/dev/null
  mb=$(( $(wc -c < "$dir/bench-cur.parquet") / 1000000 ))
  : > tmp/.tot; : > tmp/.ing; : > tmp/.ana; : > tmp/.thr; : > tmp/.rss
  for _ in $(seq "$RUNS"); do
    out=$(bin/csg run --input "$dir" --stats --quiet)
    secs "$(echo "$out" | awk '$1=="total"{print $2}')" >> tmp/.tot; echo >> tmp/.tot
    secs "$(echo "$out" | awk '$1=="ingest"{print $2}')" >> tmp/.ing; echo >> tmp/.ing
    secs "$(echo "$out" | awk '$1=="analyze"{print $2}')" >> tmp/.ana; echo >> tmp/.ana
    echo "$out" | awk '$1=="throughput"{print $2}' >> tmp/.thr
    echo "$out" | awk '$1=="peak"{print $3}' >> tmp/.rss
  done
  printf "| %'d | %s | %s | %s | %s | %s | %s |\n" "$n" "$mb" \
    "$(grep -v '^$' tmp/.tot | median)" "$(grep -v '^$' tmp/.ing | median)" "$(grep -v '^$' tmp/.ana | median)" \
    "$(median < tmp/.thr)" "$(median < tmp/.rss)"
done
rm -f tmp/.tot tmp/.ing tmp/.ana tmp/.thr tmp/.rss
