"""Generate the diagrams that go INTO THE REPOSITORY.

The repo has had zero diagrams of any kind. The ones I already build live in
a gitignored scratchpad and end up only inside .docx/.pptx files -- so from
the repository's point of view, and from a marker's, they do not exist.

These are written to docs/images/ and committed. Deliberately SVG: it is
text, so git can diff it, and it stays sharp at any size.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "images")
os.makedirs(OUT, exist_ok=True)

ACCENT = "#1F3B57"
MUTED = "#6B7684"
GOOD = "#2E7D32"
WARN = "#E08A2B"
BAD = "#C0392B"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9})


def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  {name}")


def box(ax, x, y, w, h, title, sub, colour, text="white"):
    ax.add_patch(mpatches.FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.06",
        facecolor=colour, edgecolor="none"))
    ax.text(x + w / 2, y + h - 0.30, title, ha="center", color=text,
            fontsize=9, fontweight="bold")
    ax.text(x + w / 2, y + 0.30, sub, ha="center", color=text, fontsize=7.6)


# --- 1. the three layers ------------------------------------------------------
fig, ax = plt.subplots(figsize=(7.2, 3.6))
ax.set_xlim(0, 10)
ax.set_ylim(0, 6)
ax.axis("off")

box(ax, 0.3, 3.6, 2.7, 1.5, "LAYER 1  Analysis",
    "Batfish in Docker\npybatfish -> findings", ACCENT)
box(ax, 3.65, 3.6, 2.7, 1.5, "LAYER 2  Explanation",
    "local model via Ollama\nnever invents a fact", "#4E7CA8")
box(ax, 7.0, 3.6, 2.7, 1.5, "LAYER 3  Interface",
    "FastAPI + dashboard\nupload, scan, ask", "#6E93B8")

for x0, x1 in ((3.05, 3.60), (6.40, 6.95)):
    ax.annotate("", xy=(x1, 4.35), xytext=(x0, 4.35),
                arrowprops=dict(arrowstyle="->", lw=1.6, color=MUTED))

ax.add_patch(mpatches.FancyBboxPatch(
    (0.3, 1.7), 2.7, 1.0, boxstyle="round,pad=0.06",
    facecolor="#EDF1F5", edgecolor=MUTED))
ax.text(1.65, 2.2, "exported config files\nnever a live device",
        ha="center", fontsize=8, color=ACCENT)
ax.annotate("", xy=(1.65, 3.55), xytext=(1.65, 2.75),
            arrowprops=dict(arrowstyle="->", lw=1.6, color=MUTED))

ax.add_patch(mpatches.FancyBboxPatch(
    (7.0, 1.7), 2.7, 1.0, boxstyle="round,pad=0.06",
    facecolor="#EDF1F5", edgecolor=MUTED))
ax.text(8.35, 2.2, "the user\nupload | Scan Now | ask",
        ha="center", fontsize=8, color=ACCENT)
ax.annotate("", xy=(8.35, 2.75), xytext=(8.35, 3.55),
            arrowprops=dict(arrowstyle="<->", lw=1.6, color=MUTED))

ax.text(5.0, 0.9,
        "The shared finding format (F-1) is what lets Layer 1's output flow "
        "into Layers 2 and 3\nwithout either of them knowing anything about "
        "Batfish, ACLs or routing.",
        ha="center", fontsize=7.6, color=MUTED, style="italic")
ax.text(5.0, 5.55, "Netwise — three layers, one machine, nothing leaves it",
        ha="center", fontsize=10.5, color=ACCENT, fontweight="bold")
save(fig, "architecture-layers.svg")

# --- 2. F-4 -------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(7.2, 2.2))
ax.set_xlim(0, 10)
ax.set_ylim(0, 3.2)
ax.axis("off")
for x, name, desc, colour, shows in (
    (0.4, "found", "the check ran\nand found a problem", BAD, "the finding"),
    (3.6, "none", "the check ran\nand found nothing", GOOD, "a green tick"),
    (6.8, "error", "the check\nCOULD NOT RUN", WARN, "an amber warning"),
):
    ax.add_patch(mpatches.FancyBboxPatch(
        (x, 0.85), 2.8, 1.6, boxstyle="round,pad=0.06",
        facecolor=colour, edgecolor="none"))
    ax.text(x + 1.4, 2.05, name, ha="center", color="white",
            fontsize=11.5, fontweight="bold")
    ax.text(x + 1.4, 1.32, desc, ha="center", color="white", fontsize=8)
    ax.text(x + 1.4, 0.5, shows, ha="center", color=MUTED, fontsize=7.6)
ax.text(5.0, 2.85,
        "F-4 — Batfish has no concept of \"could not check\". This "
        "distinction is ours.",
        ha="center", fontsize=10, color=ACCENT, fontweight="bold")
save(fig, "f4-three-states.svg")

# --- 3. one config's journey --------------------------------------------------
fig, ax = plt.subplots(figsize=(7.4, 4.9))
# ylim extends BELOW zero so the closing caption has its own space. At
# ylim(0, ...) it sat on top of the last box, which the PNG check caught.
ax.set_xlim(0, 10)
ax.set_ylim(-1.4, 8.6)
ax.axis("off")
steps = [
    ("1  upload", "web/main.py stages the file.\nStaged is not checked (#82).", "#EDF1F5", ACCENT),
    ("2  Scan Now", "pipeline connects, loads the snapshot,\nconfirms Batfish parsed it.", "#DCE6EF", ACCENT),
    ("3  checks run, isolated", "access_control | policy_compliance | routing\none crashing cannot stop the others.", "#C5D6E4", ACCENT),
    ("4  risk re-rates", "a post-processor over the combined list.\nIt may not downgrade or drop an error.", "#AEC5D9", ACCENT),
    ("5  explain", "only status=found reaches the model,\nand only to rephrase a computed fact.", "#97B4CE", ACCENT),
    ("6  dashboard", "found / none / error, never confused.", "#8000", None),
]
y = 7.5
for title, sub, colour, _ in steps[:-1]:
    ax.add_patch(mpatches.FancyBboxPatch(
        (0.5, y - 0.95), 9.0, 0.95, boxstyle="round,pad=0.04",
        facecolor=colour, edgecolor="none"))
    ax.text(0.8, y - 0.30, title, fontsize=9, fontweight="bold", color=ACCENT)
    ax.text(4.0, y - 0.50, sub, fontsize=7.6, color=ACCENT)
    y -= 1.20
ax.add_patch(mpatches.FancyBboxPatch(
    (0.5, y - 0.95), 9.0, 0.95, boxstyle="round,pad=0.04",
    facecolor=ACCENT, edgecolor="none"))
ax.text(0.8, y - 0.30, "6  dashboard", fontsize=9, fontweight="bold",
        color="white")
ax.text(4.0, y - 0.50, "found / none / error, never confused.",
        fontsize=7.6, color="white")

ax.text(5.0, 8.3, "One config's journey — every decision point is ours",
        ha="center", fontsize=10.5, color=ACCENT, fontweight="bold")
ax.text(5.0, -0.75,
        "Batfish decides nothing here. The model decides nothing here. What "
        "counts as a problem,\nhow bad it is, and whether we may speak at all "
        "— all of that is code we wrote.",
        ha="center", fontsize=7.6, color=MUTED, style="italic")
save(fig, "config-journey.svg")

print("done")
