"""The diagram the supervisor asked for: architecture, coloured by who built it.

Each person points at their own colour while speaking. No jargon: written for
someone who has never seen a firewall.

Layout notes, because the first two attempts had collisions: the owner's name
sits as a small tag at the TOP-LEFT of each box, not the bottom, so it can
never collide with wrapped subtitle text. The legend has its own horizontal
band with nothing else in it.
"""
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parents[1] / "Demo"
plt.rcParams.update({"font.family": "DejaVu Sans"})

ARSH, ANKEET, SHUBHAM, SAMIKA = "#4f46e5", "#0f766e", "#b45309", "#be123c"
THIRD, INK, MUTED = "#8A94A6", "#1a1a1a", "#5A6472"


def box(ax, x, y, w, h, title, sub, colour, who=None):
    ax.add_patch(mpatches.FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.05",
        facecolor=colour, edgecolor="none"))
    if who:
        ax.text(x + 0.14, y + h - 0.22, who.upper(), ha="left", va="center",
                color="white", fontsize=7.4, fontweight="bold", alpha=0.75)
    tl = title.split("\n")
    top = y + h - (0.62 if who else 0.34)
    for i, ln in enumerate(tl):
        ax.text(x + w / 2, top - i * 0.31, ln, ha="center", va="center",
                color="white", fontsize=10.2, fontweight="bold")
    sy = top - len(tl) * 0.31 - 0.10
    for i, ln in enumerate(sub.split("\n")):
        ax.text(x + w / 2, sy - i * 0.26, ln, ha="center", va="center",
                color="white", fontsize=8.0)


fig, ax = plt.subplots(figsize=(13.33, 7.5))     # 16:9
ax.set_xlim(0, 13.33)
ax.set_ylim(0, 7.5)
ax.axis("off")

ax.text(6.66, 7.22, "How Netwise works, and who built each part",
        ha="center", fontsize=17, fontweight="bold", color=INK)
ax.text(6.66, 6.90, "Follow your file from left to right. Each colour is one of us.",
        ha="center", fontsize=10.5, color=MUTED)

# --- legend band, nothing else on this line ---------------------------------
for i, (c, label) in enumerate([
        (ARSH, "Arsh"), (ANKEET, "Ankeet"), (SHUBHAM, "Shubham"),
        (SAMIKA, "Samika"), (THIRD, "Batfish — open source, not ours")]):
    lx = 1.55 + i * 2.15
    ax.add_patch(mpatches.Rectangle((lx, 6.46), 0.26, 0.16,
                                    facecolor=c, edgecolor="none"))
    ax.text(lx + 0.36, 6.54, label, ha="left", va="center",
            fontsize=9.2, color=INK)

# --- row 1: the journey ------------------------------------------------------
Y1, H1, W1 = 5.05, 1.30, 2.35
xs = [0.30, 2.90, 5.50, 8.10, 10.70]
for x, (t, s, c, w) in zip(xs, [
    ("1. Your file", "your router or firewall settings", THIRD, None),
    ("2. Read it in", "checked, translated if needed", ANKEET, "Ankeet"),
    ("3. Build a model", "what the rules actually do", THIRD, None),
    ("4. Run the checks", "four analyses, kept apart", ARSH, "Arsh"),
    ("5. Sort them", "worst problems first", SAMIKA, "Samika"),
]):
    box(ax, x, Y1, W1, H1, t, s, c, w)
for x in xs[:-1]:
    ax.annotate("", xy=(x + W1 + 0.22, Y1 + H1 / 2), xytext=(x + W1 + 0.03,
                Y1 + H1 / 2),
                arrowprops=dict(arrowstyle="->", lw=2.0, color=MUTED))

# --- row 2: the four checks --------------------------------------------------
ax.text(6.66, 4.72, "Inside step 4 — the four things we look for",
        ha="center", fontsize=11.5, fontweight="bold", color=INK)
Y2, H2, W2 = 3.05, 1.45, 3.05
for i, (t, s, c, w) in enumerate([
    ("Can the wrong\ntraffic get in?", "across every possible packet", ARSH, "Arsh"),
    ("Can the right traffic\nget through?", "does it reach where it should", ANKEET, "Ankeet"),
    ("Does it match\nYOUR rules?", "your policy file, not ours", SHUBHAM, "Shubham"),
    ("What would this\nchange do?", "simulated, never applied", SHUBHAM, "Shubham"),
]):
    box(ax, 0.35 + i * 3.20, Y2, W2, H2, t, s, c, w)

# --- row 3: output -----------------------------------------------------------
Y3, H3 = 1.30, 1.45
box(ax, 0.35, Y3, 6.25, H3, "6. Explain it in plain English",
    "a small AI, on this laptop, rewords one verified finding\n"
    "it never sees your file, so it cannot invent anything", ANKEET, "Ankeet")
box(ax, 6.90, Y3, 6.08, H3, "7. On screen, and in a file you can send",
    "problems, clean results and “could not check” kept apart\n"
    "a report you can hand to a manager or an auditor", SAMIKA, "Samika")

# --- the rule underneath -----------------------------------------------------
ax.add_patch(mpatches.FancyBboxPatch(
    (0.35, 0.18), 12.63, 0.80, boxstyle="round,pad=0.05",
    facecolor="#FDF3E3", edgecolor="#B45309", linewidth=1.7))
ax.text(6.66, 0.70, "Underneath all of it, one rule: every check must say which "
        "of three things happened",
        ha="center", va="center", fontsize=11, fontweight="bold", color="#92400E")
ax.text(6.66, 0.37,
        "found a problem    ·    checked and it is fine    ·    COULD NOT CHECK "
        "— and the third is never shown as the second",
        ha="center", va="center", fontsize=9.6, color="#92400E")

fig.savefig(OUT / "team-architecture.png", dpi=170, bbox_inches="tight",
            facecolor="white")
print(f"  wrote {OUT / 'team-architecture.png'}")
