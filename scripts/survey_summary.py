#!/usr/bin/env python3
"""Summarize the Likert survey (docs/survey/instrument.md).

Usage: scripts/survey_summary.py responses.csv [chart.png]
Rows with a non-numeric score (such as the template placeholders) are ignored
and counted, so the script never invents data.
"""
import csv
import statistics
import sys
from collections import defaultdict

LABELS = {"B1": "Clarity", "B2": "Actionability", "B3": "Correctness", "B4": "Priority",
          "C1": "Scannable", "C2": "Score trust", "C3": "Would use", "C4": "Local-first"}


def main(path, chart=None):
    scores, skipped, people = defaultdict(list), 0, set()
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                s = int(row["score"])
            except ValueError:
                skipped += 1
                continue
            if 1 <= s <= 5:
                scores[row["item"]].append(s)
                people.add(row["respondent"])
    if not scores:
        sys.exit(f"no numeric scores found ({skipped} placeholder rows skipped)")
    print(f"Respondents: {len(people)}; ignored rows: {skipped}\n")
    print("| Item | Label | n | Mean | Median | Favorable (4 or 5) |\n|---|---|---:|---:|---:|---:|")
    rows = []
    for item in sorted(scores):
        v = scores[item]
        fav = sum(1 for x in v if x >= 4) / len(v)
        rows.append((item, statistics.mean(v), fav))
        print(f"| {item} | {LABELS.get(item, '')} | {len(v)} | {statistics.mean(v):.2f} | {statistics.median(v):g} | {fav:.0%} |")
    if chart or len(sys.argv) < 3:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            return
        fig, ax = plt.subplots(figsize=(7, 3.6))
        ax.bar([f"{r[0]}\n{LABELS.get(r[0], '')}" for r in rows], [r[1] for r in rows], color="#1f6f8b")
        ax.axhline(3.5, ls="--", color="#c0392b", lw=1)
        ax.set_ylim(1, 5)
        ax.set_ylabel("Mean rating (1 to 5)")
        ax.set_title(f"Human evaluation, {len(people)} respondents")
        fig.tight_layout()
        fig.savefig(chart or "docs/survey/survey-chart.png", dpi=200)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
