import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

INK = "#152030"
MUTED = "#54657a"

PAL = {
    "src":  ("#eef2f6", "#8595a8"),
    "ing":  ("#dbeafe", "#2563eb"),
    "store":("#e0e7ff", "#4338ca"),
    "cost": ("#d1fae5", "#059669"),
    "sec":  ("#fee2e2", "#dc2626"),
    "prio": ("#fef3c7", "#c97706"),
    "llm":  ("#f3e8ff", "#7c3aed"),
    "ver":  ("#ccfbf1", "#0d9488"),
    "rep":  ("#ffe4e6", "#be123c"),
    "cli":  ("#eef2f7", "#334155"),
}

TITLE_FS, BODY_FS = 12.0, 9.6
PAD_TOP, TITLE_H, LINE_H, PAD_BOT = 2.1, 2.7, 2.45, 1.7

fig, ax = plt.subplots(figsize=(17.0, 21.0))
ax.set_xlim(0, 100)
ax.set_ylim(-60, 128)
ax.axis("off")
fig.patch.set_facecolor("white")

boxes = {}


def bh(nlines):
    """Height needed for a box with nlines body lines."""
    return PAD_TOP + TITLE_H + nlines * LINE_H + PAD_BOT


def box(key, x, ytop, w, title, lines, kind):
    """Draw a box whose TOP edge is at ytop. Returns (x, ybot, w, h)."""
    h = bh(len(lines))
    y = ytop - h
    fc, ec = PAL[kind]
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0,rounding_size=1.3",
                 facecolor=fc, edgecolor=ec, linewidth=2.0, zorder=3))
    ax.text(x + w / 2, ytop - PAD_TOP, title, ha="center", va="top",
            fontsize=TITLE_FS, fontweight="bold", color=INK, zorder=4)
    by = ytop - PAD_TOP - TITLE_H
    for ln in lines:
        ax.text(x + w / 2, by, ln, ha="center", va="top", fontsize=BODY_FS,
                color=MUTED, zorder=4)
        by -= LINE_H
    boxes[key] = (x, y, w, h)
    return boxes[key]


def band(ytop, ybot, label):
    ax.add_patch(Rectangle((6.5, ybot), 92.0, ytop - ybot, facecolor="#f8fafc",
                 edgecolor="#cbd5e1", linewidth=1.0, linestyle=(0, (5, 4)),
                 zorder=1))
    ax.text(3.6, (ytop + ybot) / 2, label, rotation=90, ha="center",
            va="center", fontsize=10.0, fontweight="bold", color="#8d9bab",
            zorder=2)


def arrow(p1, p2, color="#46576b", lw=1.9, rad=0.0, ls="-"):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=17,
                 color=color, linewidth=lw, linestyle=ls, zorder=5,
                 connectionstyle=f"arc3,rad={rad}", shrinkA=1, shrinkB=1))


def bot(k, fx=0.5):
    x, y, w, h = boxes[k]
    return (x + w * fx, y)


def top(k, fx=0.5):
    x, y, w, h = boxes[k]
    return (x + w * fx, y + h)


# ------------------------------------------------------------------ title
ax.text(52, 127.0, "CloudSpendGuard: System Architecture and Module Blueprint",
        ha="center", va="top", fontsize=19.5, fontweight="bold", color=INK)
ax.text(52, 123.6,
        "Local-first Go CLI unifying AWS FinOps and Cloud Security Posture "
        "Management   |   Layered pipeline architecture   |   Wisnu Anggoro, MSIT 5910",
        ha="center", va="top", fontsize=10.8, color=MUTED)

COLS = [(8.0, 20.0), (30.67, 20.0), (53.33, 20.0), (76.0, 20.0)]
HDR = 1.9   # band padding above boxes
FTR = 1.9   # band padding below boxes

# ------------------------------------------------------------------ L0
t = 118.0
box("s1", COLS[0][0], t - HDR, COLS[0][1], "AWS Cost & Usage Report",
    ["Parquet / CSV export", "cost and usage line items"], "src")
box("s2", COLS[1][0], t - HDR, COLS[1][1], "AWS CloudTrail",
    ["JSON event logs", "API activity history"], "src")
box("s3", COLS[2][0], t - HDR, COLS[2][1], "Terraform State / HCL",
    ["terraform.tfstate, *.tf", "declared infrastructure"], "src")
box("s4", COLS[3][0], t - HDR, COLS[3][1], "Live AWS APIs (optional)",
    ["SDK v2, read-only IAM", "ce:Get*, ec2:Describe*"], "src")
band(t, boxes["s1"][1] - FTR, "LAYER 0\nDATA SOURCES")

# ------------------------------------------------------------------ L1
t = boxes["s1"][1] - FTR - 3.2
box("m1", COLS[0][0], t - HDR, COLS[0][1], "M1   CUR Ingester",
    ["in: Parquet / CSV path", "out: []CostRecord", "Apache Arrow reader"], "ing")
box("m2", COLS[1][0], t - HDR, COLS[1][1], "M2   CloudTrail Ingester",
    ["in: JSON event files", "out: []AuditEvent", "streaming decoder"], "ing")
box("m3", COLS[2][0], t - HDR, COLS[2][1], "M3   Terraform Ingester",
    ["in: tfstate / HCL files", "out: []Resource", "AST walk"], "ing")
box("m3b", COLS[3][0], t - HDR, COLS[3][1], "M3b   Live Collector",
    ["in: IAM role ARN", "out: []Resource", "paginated Describe*"], "ing")
band(t, boxes["m1"][1] - FTR, "LAYER 1\nINGESTION")
for s, m in (("s1", "m1"), ("s2", "m2"), ("s3", "m3"), ("s4", "m3b")):
    arrow(bot(s), top(m))

# ------------------------------------------------------------------ L2
t = boxes["m1"][1] - FTR - 3.2
box("m4", 21.0, t - HDR, 62.0, "M4   Normalizer + DuckDB Local Store",
    ["in: heterogeneous records        out: canonical relational schema",
     "columnar time-series queries executed entirely on the local machine",
     "no network egress at any point in this layer"], "store")
band(t, boxes["m4"][1] - FTR, "LAYER 2\nPERSISTENCE")
for i, m in enumerate(("m1", "m2", "m3", "m3b")):
    arrow(bot(m), top("m4", 0.12 + 0.253 * i))

# ------------------------------------------------------------------ L3
t = boxes["m4"][1] - FTR - 3.2
box("m5", 8.0, t - HDR, 41.0, "M5   Cost Analyzer",
    ["in: cost records + resource inventory",
     "out: []Finding{savings, confidence}",
     "15+ waste detectors (idle EBS, unattached EIP, …)",
     "STL decomposition, z-score, Isolation Forest"], "cost")
box("m6", 55.0, t - HDR, 41.0, "M6   Security Analyzer",
    ["in: resources + audit events",
     "out: []Finding{severity, control_id}",
     "20+ misconfiguration rules over the HCL AST",
     "mapped to CIS AWS Benchmark, PCI-DSS, GDPR"], "sec")
band(t, boxes["m5"][1] - FTR, "LAYER 3\nANALYSIS")
arrow(bot("m4", 0.32), top("m5", 0.62), rad=0.10)
arrow(bot("m4", 0.68), top("m6", 0.38), rad=-0.10)

# ------------------------------------------------------------------ L4
t = boxes["m5"][1] - FTR - 3.2
box("m7", 19.0, t - HDR, 66.0, "M7   Joint Prioritizer",
    ["in: unified []Finding        out: single ranked remediation backlog",
     "S(r) = a·savings(r) + b·risk_reduction(r) − c·blast_radius(r)",
     "weights a, b, c configurable per stakeholder profile"], "prio")
band(t, boxes["m7"][1] - FTR,
     "LAYER 4\nPRIORITIZATION")
arrow(bot("m5", 0.55), top("m7", 0.22), rad=-0.08)
arrow(bot("m6", 0.45), top("m7", 0.78), rad=0.08)

# ------------------------------------------------------------------ L5
t = boxes["m7"][1] - FTR - 3.2
box("m8", 8.0, t - HDR, 41.0, "M8   LLM Remediation Engine",
    ["in: ranked finding + rule context",
     "out: candidate Terraform patch (diff)",
     "sanitizer redacts ARNs, account IDs, IP addresses",
     "Ollama local by default; cloud API is opt-in only"], "llm")
box("m9", 55.0, t - HDR, 41.0, "M9   Verifier   (safety gate)",
    ["in: candidate Terraform patch",
     "out: approved patch or rejection reason",
     "re-parses patched HCL and re-runs every M6 rule",
     "rejects any patch that introduces a new finding"], "ver")
l5b = boxes["m8"][1]
band(t, l5b - 7.0, "LAYER 5\nREMEDIATION")
arrow(bot("m7", 0.28), top("m8", 0.55), rad=0.10)
ymid = l5b + boxes["m8"][3] * 0.62
arrow((49.0, ymid), (55.0, ymid))
ax.text(52.0, ymid + 0.9, "generate", ha="center", va="bottom", fontsize=9.4,
        color="#7c3aed", fontweight="bold")
arrow((55.0, l5b + 1.6), (49.0, l5b + 1.6), color="#dc2626", rad=-0.45,
      ls=(0, (4, 3)))
ax.text(52.0, l5b - 3.0, "reject and regenerate   (maximum 3 attempts)",
        ha="center", va="top", fontsize=9.4, color="#dc2626", fontweight="bold")

# ------------------------------------------------------------------ L6
t = l5b - 7.0 - 3.2
box("m10", 19.0, t - HDR, 66.0, "M10   Reporter",
    ["in: approved backlog + verified patches        out: Markdown, HTML, JSON, SARIF",
     "SARIF feeds GitHub / GitLab code scanning; JSON feeds CI quality gates",
     "HTML is the stakeholder-facing review artifact"], "rep")
band(t, boxes["m10"][1] - FTR, "LAYER 6\nPRESENTATION")
arrow(bot("m9", 0.45), top("m10", 0.72), rad=0.10)

# ------------------------------------------------------------------ CLI
t = boxes["m10"][1] - FTR - 3.2
box("m11", 19.0, t - HDR, 66.0, "M11   CLI Orchestrator   (cmd/csg)",
    ["cross-cutting concern: command parsing, configuration and weight profiles,",
     "structured logging, exit codes; orchestrates modules M1 through M10",
     "commands:  csg ingest  |  csg analyze  |  csg report  |  csg run"], "cli")
band(t, boxes["m11"][1] - FTR, "CROSS-CUTTING\nORCHESTRATION")
arrow(top("m11"), bot("m10"), color="#334155")

ymin = min(b[1] for b in boxes.values()) - 3.0
ax.set_ylim(ymin, 128.8)
fig.set_size_inches(16.5, 16.5 * (128.8 - ymin) / 100.0)

fig.savefig("/home/user/workspace/architecture.png", dpi=170,
            bbox_inches="tight", facecolor="white", pad_inches=0.3)
print("ok")
