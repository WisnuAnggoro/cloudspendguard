"""Generate an illustrative survey CSV and summary figure matching the example table.

These are simulated values, not observations or a Google Form export.
The allocation of scores to example respondent IDs is arbitrary.

Run from the repository root:
    python3 scripts/generate_example_survey.py
Needs:
    python3 -m pip install matplotlib

Writes docs/survey/simulated-responses.csv and docs/survey/fig08-survey-summary.png.
"""
import csv
from pathlib import Path
import random
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

REPO = Path(__file__).resolve().parents[1]
SURVEY = REPO / "docs" / "survey"
DATA = [
    ("B1", "Clarity", {3: 8, 4: 22, 5: 20}, 4.24, 0.84),
    ("B2", "Actionability", {3: 11, 4: 26, 5: 13}, 4.04, 0.78),
    ("B3", "Correctness", {3: 14, 4: 29, 5: 7}, 3.86, 0.72),
    ("B4", "Priority order", {3: 17, 4: 30, 5: 3}, 3.72, 0.66),
]


def create_data():
    rng = random.Random(6)
    csv_rows = []
    summary = []
    for item, label, distribution, expected_mean, expected_fav in DATA:
        scores = [score for score, count in distribution.items() for _ in range(count)]
        rng.shuffle(scores)
        n = len(scores)
        mean = statistics.mean(scores)
        favorable = sum(score >= 4 for score in scores) / n
        assert n == 50
        assert abs(mean - expected_mean) < 1e-10
        assert abs(favorable - expected_fav) < 1e-10
        summary.append((item, label, n, mean, favorable))
        for i, score in enumerate(scores):
            csv_rows.append({
                "respondent": f"SIM{i // 10 + 1:02d}",
                "card": i % 10 + 1,
                "item": item,
                "score": score,
                "data_kind": "simulated",
            })
    SURVEY.mkdir(parents=True, exist_ok=True)
    with (SURVEY / "simulated-responses.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["respondent", "card", "item", "score", "data_kind"])
        writer.writeheader()
        writer.writerows(csv_rows)
    return summary


def create_chart(summary):
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": "#D4D1CA",
        "text.color": "#28251D",
        "axes.labelcolor": "#28251D",
        "figure.facecolor": "white",
    })
    fig, (left, right) = plt.subplots(1, 2, figsize=(10, 4.8))
    fig.subplots_adjust(left=0.18, right=0.97, top=0.76, bottom=0.22, wspace=0.40)
    fig.suptitle("Survey Summary (simulated example, not collected responses)", x=0.08, y=0.97, ha="left", fontsize=15, weight="bold")
    fig.text(0.08, 0.88, "Clarity, actionability, correctness, and priority order | n = 50 ratings per item | simulated data",
             fontsize=10, color="#5F5D57")
    positions = list(range(4))
    labels = [r[1] for r in summary]
    means = [r[3] for r in summary]
    favorable = [r[4] for r in summary]
    left.barh(positions, means, color="#20808D", height=0.56)
    right_bars = right.barh(
        positions, favorable, color=["#20808D", "#20808D", "#20808D", "#A84B2F"], height=0.56,
    )
    right_bars[-1].set_hatch("///")
    for ax in (left, right):
        ax.set_yticks(positions, labels)
        ax.invert_yaxis()
        ax.set_axisbelow(True)
        ax.grid(axis="x", color="#ECEAE4", linewidth=0.7)
    # Avoid repeating the same labels in the second panel.
    right.set_yticklabels([])
    right.tick_params(axis="y", length=0)
    left.set_xlim(0, 5.0)
    left.set_xticks(range(6))
    left.set_xlabel("Mean rating (scale 1 to 5)")
    left.set_title("Mean rating", loc="left", pad=14, fontsize=12, weight="bold")
    left.axvline(3.5, ls="--", color="#7A7974", lw=1.2, zorder=0)
    for i, value in enumerate(means):
        left.text(value + 0.09, i, f"{value:.2f}", va="center", fontsize=11, weight="bold")
    right.set_xlim(0, 1.0)
    right.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    right.xaxis.set_major_formatter(PercentFormatter(1))
    right.set_xlabel("Ratings of 4 or 5")
    right.set_title("Favorable responses", loc="left", pad=14, fontsize=12, weight="bold")
    right.axvline(0.70, ls="--", color="#7A7974", lw=1.2, zorder=0)
    for i, value in enumerate(favorable):
        right.text(value + 0.018, i, f"{value:.0%}", va="center", fontsize=11, weight="bold")
    fig.text(0.08, 0.045, "Dashed reference lines: mean rating 3.5 and favorable responses 70%.\n"
             "n counts card-level ratings, not individual participants.",
             fontsize=9, color="#5F5D57")
    fig.savefig(SURVEY / "fig08-survey-summary.png", dpi=220, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)


if __name__ == "__main__":
    summary = create_data()
    create_chart(summary)
    print("ILLUSTRATIVE SUMMARY: simulated data, not collected survey responses.")
    print("| Item | n | Mean | Favorable (4 or 5) |")
    print("|---|---:|---:|---:|")
    for _, label, n, mean, favorable in summary:
        print(f"| {label} | {n} | {mean:.2f} | {favorable:.0%} |")
    print(f"Chart: {SURVEY / 'fig08-survey-summary.png'}")
    print(f"Example CSV: {SURVEY / 'simulated-responses.csv'}")
