"""The architecture diagram, rewritten after supervisor feedback.

THE FEEDBACK (8 September, from the supervisor and Asanthika)
    "the diagram only says 1. 2. 3 steps.. would be great to mention how each
    step is done .. what's your contribution rather than just using exiting
    apps and tools.. what you have done. e.g., step 3 - what's the model?"

So every stage now names the MECHANISM, not the intention: the actual file
formats, the actual Batfish questions, the actual model and its temperature,
the actual record shape. Grey is Batfish and Ollama, which we drive and did
not write; every colour is a person on this team, and the line counts are
real so "what we built" is a number rather than a claim.

Eight stages, two rows of four. Owner tag top-left of each box so it can
never collide with wrapped body text -- the previous version needed four
layout iterations to learn that.
"""
import pathlib
import subprocess

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[1] / "Demo"
OUT.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans"})

ARSH, ANKEET, SHUBHAM, SAMIKA = "#4f46e5", "#0f766e", "#b45309", "#be123c"
THIRD, INK, MUTED = "#7C8697", "#1a1a1a", "#5A6472"
ALL_FOUR = "#3F4C63"


def box(ax, x, y, w, h, title, lines, colour, who=None, stripe=None,
        fs=7.3, gap=0.235, top=0.82):
    ax.add_patch(mpatches.FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.04",
        facecolor=colour, edgecolor="none"))
    if who:
        ax.text(x + 0.13, y + h - 0.20, who.upper(), ha="left", va="center",
                color="white", fontsize=6.8, fontweight="bold", alpha=0.8)
    ax.text(x + w / 2, y + h - 0.52, title, ha="center", va="center",
            color="white", fontsize=9.6, fontweight="bold")
    for i, ln in enumerate(lines):
        ax.text(x + w / 2, y + h - top - i * gap, ln, ha="center", va="center",
                color="white", fontsize=fs, alpha=0.97)
    if stripe:                       # four thin bars = all four contribute
        sw = w / len(stripe)
        for i, c in enumerate(stripe):
            ax.add_patch(mpatches.Rectangle((x + i * sw, y + 0.03), sw, 0.075,
                                            facecolor=c, edgecolor="none"))


def arrow(ax, x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", lw=1.9, color=MUTED,
                                shrinkA=0, shrinkB=0))


fig, ax = plt.subplots(figsize=(13.33, 7.5))
ax.set_xlim(0, 13.33); ax.set_ylim(0, 7.5); ax.axis("off")

ax.text(6.66, 7.24, "How Netwise works — what happens at each step, and who built it",
        ha="center", fontsize=15.5, fontweight="bold", color=INK)
ax.text(6.66, 6.95,
        "Grey is software we drive and did not write. Every colour is one of us.",
        ha="center", fontsize=9.8, color=MUTED)

for i, (c, label) in enumerate([
        (ARSH, "Arsh"), (ANKEET, "Ankeet"), (SHUBHAM, "Shubham"),
        (SAMIKA, "Samika"), (THIRD, "Batfish / Ollama — third party")]):
    lx = 1.30 + i * 2.28
    ax.add_patch(mpatches.Rectangle((lx, 6.52), 0.24, 0.15, facecolor=c,
                                    edgecolor="none"))
    ax.text(lx + 0.33, 6.60, label, ha="left", va="center", fontsize=8.8, color=INK)

W, H = 3.02, 1.92
XS = [0.30, 3.65, 7.00, 10.35]
YA, YB = 4.20, 1.72

ROW_A = [
    ("1. You upload a file", [
        "Cisco IOS text, or pfSense XML",
        "saved under a fixed name, so your",
        "filename never reaches the disk",
        "each browser session kept apart"], SAMIKA, "Samika", None),
    ("2. Translate, if needed", [
        "pfSense XML → Cisco IOS  (1,073 lines)",
        "models pfSense last-match-wins",
        "against Cisco first-match-wins",
        "refuses/skips what it can't model"], ANKEET, "Ankeet", None),
    ("3. Build a network model", [
        "Batfish parses the config and builds",
        "a vendor-neutral model of the network",
        "we did NOT write this",
        "we check its parse status and refuse"], THIRD, None, None),
    ("4. Ask formal questions", [
        "testFilters · searchFilters",
        "filterLineReachability",
        "undefinedReferences",
        "traceroute · compareFilters",
        "differentialReachability"], ALL_FOUR, "all four",
     [ARSH, ANKEET, SHUBHAM, SAMIKA]),
]

ROW_B = [
    ("5. Shape every answer alike", [
        "one 7-field record per finding:",
        "id · check · severity · device ·",
        "summary · evidence · status",
        "a crashing check becomes a finding"], ARSH, "Arsh", None),
    ("6. Rate and sort", [
        "documented rules re-rate severity",
        "worst first, never alphabetical",
        "marking a device critical raises it",
        "by ONE level — never lowers, never hides"], SAMIKA, "Samika", None),
    ("7. Put it in plain English", [
        "netwise-warden, built on llama3.2:3b",
        "temperature 0.2, 300-token cap",
        "gets ONE already-verified finding",
        "never sees your config file"], ANKEET, "Ankeet", None),
    ("8. Screen, and a file to send", [
        "problems, clean results and",
        "“could not check” kept apart",
        "HTML or CSV you can hand to an",
        "auditor — caveats printed FIRST"], ARSH, "Arsh + Samika", None),
]

for x, (t, lines, c, who, stripe) in zip(XS, ROW_A):
    dense = len(lines) > 4
    box(ax, x, YA, W, H, t, lines, c, who, stripe,
        fs=6.9 if dense else 7.3, gap=0.208 if dense else 0.235,
        top=0.78 if dense else 0.82)
for x, (t, lines, c, who, stripe) in zip(XS, ROW_B):
    box(ax, x, YB, W, H, t, lines, c, who, stripe)

for x in XS[:-1]:
    arrow(ax, x + W + 0.04, YA + H / 2, x + W + 0.29, YA + H / 2)
    arrow(ax, x + W + 0.04, YB + H / 2, x + W + 0.29, YB + H / 2)
# Wrap from the end of row A to the start of row B. An arc here cuts straight
# through boxes 2 and 3, so it runs as an L through the gap between the rows.
_mid = (YA + YB + H) / 2
_x_from, _x_to = XS[3] + W / 2, XS[0] + W / 2
ax.plot([_x_from, _x_from], [YA - 0.03, _mid], color=MUTED, lw=1.9,
        solid_capstyle="butt", zorder=1)
ax.plot([_x_from, _x_to], [_mid, _mid], color=MUTED, lw=1.9,
        solid_capstyle="butt", zorder=1)
arrow(ax, _x_to, _mid, _x_to, YB + H + 0.03)

ax.add_patch(mpatches.FancyBboxPatch(
    (0.30, 0.30), 13.07 - 0.30 - 0.07, 1.05, boxstyle="round,pad=0.04",
    facecolor="#FDF3E3", edgecolor="#B45309", linewidth=1.6))
ax.text(6.66, 1.10, "Enforced at every stage above: each check must say WHICH OF THREE "
        "things happened",
        ha="center", va="center", fontsize=10.2, fontweight="bold", color="#92400E")
ax.text(6.66, 0.79,
        "found a problem   ·   checked it and it is clean   ·   COULD NOT CHECK",
        ha="center", va="center", fontsize=9.4, color="#92400E")
ax.text(6.66, 0.51,
        "The third is never shown as the second. A post-processor may not "
        "downgrade or drop a “could not check” — that is enforced in code, not trusted.",
        ha="center", va="center", fontsize=8.2, color="#92400E")

path = OUT / "team-architecture.png"
fig.savefig(path, dpi=170, bbox_inches="tight", facecolor="white")
print(f"  wrote {path}")
try:
    from PIL import Image
    with Image.open(path) as im:
        print(f"  {im.width}x{im.height}px, aspect {im.width/im.height:.2f} (16:9 = 1.78)")
except Exception:                                            # noqa: BLE001
    pass
