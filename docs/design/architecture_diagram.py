"""Render the CloudSpendGuard architecture diagram.

Run from the repository root:
    python3 docs/design/architecture_diagram.py

Writes docs/design/architecture.png. Reflects the shipped implementation:
a pure-Go Parquet reader (parquet-go) and an embedded pure-Go SQLite store,
the read-only live S3 collector, and the generate-then-verify safety gate.
Needs: python3 -m pip install matplotlib
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = Path(__file__).resolve().parent
OUT = HERE / "architecture.png"

TEAL = "#20808D"
RUST = "#A84B2F"
DARK = "#1B474D"
GREY = "#7A7974"
SAND = "#EDE9E0"
LIGHT_TEAL = "#DDE9EB"
LIGHT_RUST = "#F0DFD8"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def save(fig, name):
    fig.savefig(OUT, dpi=200, bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)
    print("wrote", OUT)


def architecture():
    fig, ax = plt.subplots(figsize=(13.6, 8.6))
    ax.set_xlim(0, 136)
    ax.set_ylim(-9, 88)
    ax.axis("off")

    def box(x, y, w, h, title, sub, fc, ec, tfs=10, sfs=8.2):
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                     boxstyle="round,pad=0.4,rounding_size=1.2",
                     fc=fc, ec=ec, lw=1.4))
        ax.text(x + w / 2, y + h - 2.6, title, ha="center", va="top",
                fontsize=tfs, fontweight="bold", color=DARK)
        ax.text(x + w / 2, y + h - 6.6, sub, ha="center", va="top",
                fontsize=sfs, color="#3F3D37", linespacing=1.45)

    def varrow(x, ytop, ybot):
        ax.add_patch(FancyArrowPatch((x, ytop), (x, ybot),
                     arrowstyle="-|>", mutation_scale=15,
                     color=GREY, lw=1.5))

    def diagarrow(x1, y1, x2, y2):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                     arrowstyle="-|>", mutation_scale=15,
                     color=GREY, lw=1.5))

    def harrow(x1, x2, y):
        ax.add_patch(FancyArrowPatch((x1, y), (x2, y),
                     arrowstyle="-|>", mutation_scale=15,
                     color=GREY, lw=1.5))

    ax.text(68, 85, "CloudSpendGuard System Architecture (v1.0.0)",
            ha="center", fontsize=16, fontweight="bold", color=DARK)
    ax.text(68, 81.2, "Local-first Go CLI unifying AWS FinOps and Cloud Security Posture Management  |  layered pipeline  |  single static binary",
            ha="center", fontsize=9.5, color=GREY)
    ax.text(68, 77.4, "M11 CLI orchestrator (cmd/csg) sequences every stage; local-file mode needs no AWS credentials. M10 renders the backlog with or without verified patches.",
            ha="center", fontsize=8.6, color=GREY, style="italic")

    LX = 11  # layer labels in the left gutter

    # Row A: sources (y 63-75)
    yA, hA = 63, 12
    box(14, yA, 26, hA, "AWS CUR", "Cost & Usage Report\nParquet / CSV export", SAND, "#C9C2B4")
    box(44, yA, 26, hA, "AWS CloudTrail", "JSON event logs\nAPI activity", SAND, "#C9C2B4")
    box(74, yA, 26, hA, "Terraform", "tfstate + *.tf\ndeclared config", SAND, "#C9C2B4")
    box(104, yA, 26, hA, "Live AWS APIs", "read-only, optional\nS3 inventory", SAND, "#C9C2B4")
    ax.text(LX, yA + hA / 2, "L0\nsources", ha="right", va="center",
            fontsize=8, color=GREY, style="italic", linespacing=1.3)

    # Row B: ingestion (y 46-58)
    yB, hB = 46, 12
    box(14, yB, 54, hB, "M1-M3 Ingesters", "CUR (parquet-go, columnar), CloudTrail (streaming JSON),\nTerraform (state v4 + HCL AST)", LIGHT_TEAL, TEAL)
    box(74, yB, 56, hB, "M3b Live Collector", "AWS SDK v2, read-only S3 calls\n(ListBuckets, GetBucketLocation, PAB, policy, lifecycle)", LIGHT_TEAL, TEAL)
    ax.text(LX, yB + hB / 2, "L1\ningestion", ha="right", va="center",
            fontsize=8, color=GREY, style="italic", linespacing=1.3)

    # Row C: store (y 31-41)
    yC, hC = 31, 10
    box(14, yC, 116, hC, "M4 Normalizer + Local Store", "canonical schema, tag flattening, embedded pure-Go SQLite (cgo-free), in-memory path for csg run",
         LIGHT_TEAL, TEAL)
    ax.text(LX, yC + hC / 2, "L2\nstore", ha="right", va="center",
            fontsize=8, color=GREY, style="italic", linespacing=1.3)

    # Row D: analysis (y 15-27)
    yD, hD = 15, 12
    box(14, yD, 54, hD, "M5 Cost Analyzer", "15 waste rules + anomaly detector\n(STL + modified z-score + Isolation Forest)", LIGHT_TEAL, TEAL)
    box(74, yD, 56, hD, "M6 Security Analyzer", "20 CIS-mapped rules (CIS AWS v3.0.0,\nPCI-DSS, GDPR), AST + CloudTrail evidence", LIGHT_TEAL, TEAL)
    ax.text(LX, yD + hD / 2, "L3\nanalysis", ha="right", va="center",
            fontsize=8, color=GREY, style="italic", linespacing=1.3)

    # Row E: prioritize -> remediate -> verify -> report (y 0-11), four equal boxes
    yE, hE = 0, 11
    box(14, yE, 27, hE, "M7 Prioritizer", "S = a*savings + b*risk\n- c*blast; profiles", LIGHT_RUST, RUST, tfs=9, sfs=7.4)
    box(45, yE, 27, hE, "M8 LLM Remediation", "Ollama local, redaction,\nnonce-fenced prompt", LIGHT_RUST, RUST, tfs=9, sfs=7.4)
    box(76, yE, 27, hE, "M9 Verifier", "re-parse + re-run rules,\nreject new findings", LIGHT_RUST, RUST, tfs=9, sfs=7.4)
    box(107, yE, 27, hE, "M10 Reporter", "Markdown, HTML, JSON,\nSARIF 2.1.0", "#E8E4DA", GREY, tfs=9, sfs=7.4)
    ax.text(LX, yE + hE / 2, "L4-L6", ha="right", va="center",
            fontsize=8, color=GREY, style="italic")

    # vertical arrows between rows (5-unit gaps, clear stems)
    varrow(27, yA, yB + hB)      # CUR -> M1-M3
    varrow(50, yA, yB + hB)     # CloudTrail -> M1-M3
    diagarrow(87, yA, 62, yB + hB)   # Terraform -> M1-M3
    varrow(117, yA, yB + hB)   # Live APIs -> M3b
    varrow(41, yB, yC + hC)     # M1-M3 -> M4
    varrow(102, yB, yC + hC)    # M3b -> M4
    varrow(41, yC, yD + hD)     # M4 -> M5
    varrow(102, yC, yD + hD)    # M4 -> M6
    varrow(29, yD, yE + hE)     # M5 -> M7
    diagarrow(80, yD, 38, yE + hE)  # M6 -> M7

    # horizontal chain in row E
    harrow(41, 45, yE + hE / 2)
    harrow(72, 76, yE + hE / 2)
    harrow(103, 107, yE + hE / 2)

    # rejection loop: curved arc below row E, from M9 back to M8
    ax.add_patch(FancyArrowPatch((90, yE), (59, yE), arrowstyle="-|>",
                 mutation_scale=13, color=RUST, lw=1.2, linestyle="--",
                 connectionstyle="arc3,rad=-0.32"))
    ax.text(74.5, -6.2, "reject and regenerate (max 3)", ha="center", va="top",
            fontsize=8, color=RUST, style="italic")

    save(fig, OUT.name)


if __name__ == "__main__":
    architecture()
