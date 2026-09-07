"""Netwise class presentation.

Built against Ankeet's demo script (docs/Demo/Netwise - Demo Script.docx) and
the supervisor's four instructions:

  1. a non-technical person must follow it with no confusion
  2. a visual showing how it works, where each person can point at their part
  3. tell it as a story
  4. cover real industry use, why anyone would pay for it, and the questions

So: almost no jargon on the slides, one idea per slide, the detail lives in
the speaker notes, and the arc runs problem -> stakes -> product -> people ->
demo -> industry -> honesty -> next.

Every fact is from the demo script or measured from the repository.
"""
import pathlib

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

DOCS = pathlib.Path(__file__).resolve().parents[1]
SP = DOCS / "Demo"          # the diagram the deck embeds
OUT = DOCS / "Demo" / "Netwise - Class Presentation.pptx"

INK = RGBColor(0x1A, 0x1A, 0x1A)
MUTED = RGBColor(0x5A, 0x64, 0x72)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
ARSH = RGBColor(0x4F, 0x46, 0xE5)
ANKEET = RGBColor(0x0F, 0x76, 0x6E)
SHUBHAM = RGBColor(0xB4, 0x53, 0x09)
SAMIKA = RGBColor(0xBE, 0x12, 0x3C)
AMBER = RGBColor(0xB4, 0x53, 0x09)
PAPER = RGBColor(0xFB, 0xFB, 0xFD)
DARK = RGBColor(0x14, 0x18, 0x1F)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
BLANK = prs.slide_layouts[6]


def slide(bg=None):
    s = prs.slides.add_slide(BLANK)
    if bg is not None:
        s.background.fill.solid()
        s.background.fill.fore_color.rgb = bg
    return s


def text(s, x, y, w, h, content, size=20, bold=False, colour=INK,
         align=PP_ALIGN.LEFT, italic=False, spacing=1.0, font="Calibri"):
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, line in enumerate(content.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = spacing
        r = p.add_run()
        r.text = line
        r.font.size = Pt(size)
        r.font.bold = bold
        r.font.italic = italic
        r.font.color.rgb = colour
        r.font.name = font
    return tb


def bullets(s, x, y, w, h, items, size=18, colour=INK, gap=10):
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap)
        p.line_spacing = 1.15
        r = p.add_run()
        r.text = "•   " + item if not item.startswith(" ") else item
        r.font.size = Pt(size)
        r.font.color.rgb = colour
        r.font.name = "Calibri"
    return tb


def band(s, x, y, w, h, colour):
    from pptx.enum.shapes import MSO_SHAPE
    sh = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y),
                            Inches(w), Inches(h))
    sh.fill.solid()
    sh.fill.fore_color.rgb = colour
    sh.line.fill.background()
    sh.shadow.inherit = False
    return sh


def note(s, txt):
    s.notes_slide.notes_text_frame.text = txt.strip()


def picture(s, name, x, y, w):
    return s.shapes.add_picture(str(SP / name), Inches(x), Inches(y),
                                width=Inches(w))


# ============================================================ 1  TITLE
s = slide(DARK)
text(s, 1.0, 2.5, 11.3, 1.4, "Netwise", 60, True, WHITE)
text(s, 1.0, 3.7, 11.3, 1.0,
     "Finding the security mistakes hiding in network settings —\n"
     "and explaining them in plain English.", 22, False, RGBColor(0xC2, 0xCA, 0xD6))
text(s, 1.0, 5.5, 11.3, 0.8,
     "Arsh Vhora   ·   Ankeet Patel   ·   Shubham Kataria   ·   Samika Perera",
     16, False, RGBColor(0x8E, 0x99, 0xA8))
text(s, 1.0, 6.0, 11.3, 0.5, "Studio 5  ·  Block 3, 2026  ·  Client: Senaka Amarakeerthi",
     13, False, RGBColor(0x5A, 0x64, 0x72))
note(s, """
Do not start with the technology. Start with the story on the next slide.
Say the team names and move on -- 20 seconds maximum on this slide.
""")

# ============================================================ 2  THE HOOK
s = slide()
text(s, 1.0, 1.5, 11.3, 2.6,
     "One wrong line in a settings file\ncan leave a company's front door open\n"
     "for months.", 40, True, INK, spacing=1.15)
text(s, 1.0, 4.4, 11.3, 1.2,
     "Nobody notices, because nothing looks broken.\n"
     "Everything still works. That is exactly the problem.",
     22, False, MUTED, spacing=1.2)
note(s, """
THE HOOK. Say it slowly and then pause.

Every router and firewall is controlled by a long text file of rules. Those
files get edited by different people over years. Somebody widens one rule at
2am to fix an urgent problem, and never narrows it again.

Nothing breaks. No alarm goes off. The website still loads. The only sign is
in the file, and nobody reads the file.

Misconfiguration like this is one of the leading causes of real breaches. Do
not quote a statistic you cannot source -- just say "one of the leading
causes", which is what our research found.
""")

# ============================================================ 3  WHY HARD
s = slide()
text(s, 0.9, 0.6, 11.5, 0.8, "Why can't someone just read the file?", 34, True, INK)
text(s, 0.9, 1.7, 11.5, 0.7,
     "Because the answer is never in one line. It is in how the lines interact.",
     20, False, MUTED)

band(s, 0.9, 2.7, 11.5, 1.5, RGBColor(0xF4, 0xF6, 0xFA))
text(s, 1.3, 2.95, 10.7, 1.1,
     "Rule 1:  block everything from outside\n"
     "Rule 2:  ...except web traffic to the office network",
     19, False, INK, font="Consolas", spacing=1.3)

text(s, 0.9, 4.6, 11.5, 1.8,
     "Reading those two lines tells you almost nothing.\n\n"
     "Whether an outsider can reach your payroll server depends on both rules,\n"
     "the order they are in, and every other rule in the file.",
     20, False, INK, spacing=1.25)
note(s, """
Keep this concrete. The point for a non-technical audience:

You cannot answer "can an outsider reach my payroll server?" by reading any
single line. It depends on all of them together, in order. A file with 200
rules has far more combinations than a person can hold in their head.

That is why this is a computer's job, not a careful-reading job.
""")

# ============================================================ 4  WHAT IT IS
s = slide()
text(s, 0.9, 1.3, 11.5, 0.9, "What Netwise does", 34, True, INK)
text(s, 0.9, 2.4, 11.5, 1.6,
     "You give it a copy of your settings file.\n"
     "It finds the mistakes, and tells you what each one means in plain English.",
     26, False, INK, spacing=1.3)
band(s, 0.9, 4.5, 11.5, 1.5, RGBColor(0xE8, 0xEE, 0xFC))
text(s, 1.3, 4.8, 10.7, 1.0,
     "It runs entirely on your own laptop.\n"
     "Your settings never leave the machine and are never sent to any cloud service.",
     20, True, RGBColor(0x2F, 0x5F, 0xD0), spacing=1.25)
note(s, """
Two sentences and then STOP. Do not list features here.

The blue box is not marketing -- it is a hard rule the whole system is built
around, and it comes back three more times in this talk (the AI slide, the
industry slide, and Q&A). Say it once here and let it land.

A copy of the settings file. Not access to the network. Nothing is ever
connected to, scanned, or changed.
""")

# ============================================================ 5  DIAGRAM
s = slide()
picture(s, "team-architecture.png", 0.25, 0.15, 12.85)
note(s, """
THE SLIDE THE SUPERVISOR ASKED FOR. Each of us points at our own colour.

Walk the top row left to right first -- that is the file's journey. Then say
"inside step 4 there are four separate checks", and point at the second row.

Hand over as you go: Ankeet takes the green boxes, Arsh the blue, Shubham the
orange, Samika the red.

Grey = Batfish. Say plainly: "the grey boxes are an open-source tool called
Batfish. We did not write it. We drive it." Never claim the grey boxes.

The amber strip at the bottom is the single most important idea in the talk.
Do not explain it here -- it gets its own slide later.
""")

# ============================================================ 6  ARSH
s = slide()
band(s, 0.0, 0.0, 0.35, 7.5, ARSH)
text(s, 1.0, 0.7, 11.0, 0.6, "ARSH", 14, True, ARSH)
text(s, 1.0, 1.2, 11.0, 1.0, "The backbone, and the first check", 32, True, INK)
bullets(s, 1.0, 2.5, 11.0, 3.4, [
    "Something has to read the file, connect it to the engine, and keep going "
    "when one part fails.",
    "If one check crashes, the other three still run — and the broken one says "
    "so instead of going quiet.",
    "My own check asks the hardest question: is there ANY traffic at all that "
    "gets in when it shouldn't?",
], 20)
band(s, 1.0, 5.6, 11.0, 1.2, RGBColor(0xEE, 0xF0, 0xFE))
text(s, 1.4, 5.85, 10.2, 0.8,
     "Not \u201cdoes this one packet get through\u201d — but \u201cout of every possible "
     "packet, is there one that does\u201d.",
     18, True, ARSH)
note(s, """
The blue box is the part worth slowing down on, and it is a genuine research
result, not a design preference.

We tried the obvious approach first: pick one packet, ask if it arrives. On
our own insecure test file -- the one with "allow everything" in it -- that
came back EMPTY, meaning "no path found". That reads like good news. It was
actually because that test file has no route between those two networks at
all, for a completely unrelated reason.

A tool that read "empty" as "you're fine" would have printed a green tick on a
configuration that allows everything through. We measured that happening.

So we ask the stronger question instead: across the entire space of possible
packets, is there one that gets through when it shouldn't? An empty answer to
THAT question is a proof, not a guess.
""")

# ============================================================ 7  ANKEET
s = slide()
band(s, 0.0, 0.0, 0.35, 7.5, ANKEET)
text(s, 1.0, 0.7, 11.0, 0.6, "ANKEET", 14, True, ANKEET)
text(s, 1.0, 1.2, 11.0, 1.0, "Real firewalls, and plain English", 32, True, INK)
bullets(s, 1.0, 2.5, 11.0, 3.4, [
    "Our client's firewall speaks a different language to the analysis engine. "
    "I wrote the translator.",
    "When part of a real file can't be translated safely, it says which part "
    "and why — instead of guessing.",
    "Then a small AI, running on this laptop, turns each technical finding into "
    "a sentence a person can act on.",
], 20)
band(s, 1.0, 5.6, 11.0, 1.2, RGBColor(0xE6, 0xF4, 0xF2))
text(s, 1.4, 5.85, 10.2, 0.8,
     "The AI never sees your file. It is only ever handed one already-proven "
     "finding and asked to reword it.",
     18, True, ANKEET)
note(s, """
Expect: "why not just use ChatGPT?"

Two answers, in this order.

FIRST, and it is not a preference: sending a client's real network layout to
an outside company is itself a security exposure. Not allowed, full stop.

SECOND: the job here is narrow. Take one already-verified fact and say it in
plain English. That is translation, not creative writing, and a small local
model is genuinely good enough for it.

And the important one: the AI cannot invent a finding, because it is never
shown a raw config at all. It only ever receives a result that a real analysis
already produced. If it adds anything not in the evidence, a validation step
rejects it and we fall back to a plain fixed sentence.
""")

# ============================================================ 8  SHUBHAM
s = slide()
band(s, 0.0, 0.0, 0.35, 7.5, SHUBHAM)
text(s, 1.0, 0.7, 11.0, 0.6, "SHUBHAM", 14, True, SHUBHAM)
text(s, 1.0, 1.2, 11.0, 1.0, "Your rules, and testing a change safely", 32, True, INK)
bullets(s, 1.0, 2.5, 11.0, 3.4, [
    "Every organisation's security rules are different. What is fine for one "
    "company is a serious problem for another.",
    "So you can hand Netwise your own rules, in a small file, and it checks "
    "against those — not against our examples.",
    "And before you change anything: it simulates the change and tells you "
    "exactly what it would newly allow or block.",
], 20)
band(s, 1.0, 5.6, 11.0, 1.2, RGBColor(0xFD, 0xF1, 0xE1))
text(s, 1.4, 5.85, 10.2, 0.8,
     "The simulation runs on a throwaway copy. Nothing is ever applied to a "
     "real device — that rule never bends.",
     18, True, SHUBHAM)
note(s, """
The "your own rules" point matters commercially. A tool that only checks
against one fixed generic ruleset tells every customer the same thing,
regardless of what they actually care about.

On the simulation: this answers the question every network engineer actually
has, which is not "is my config wrong" but "if I make this change at 9pm, what
breaks?"

If asked "does it touch my network?" -- no. It writes to a temporary copy that
is deleted immediately. Nothing ever reaches a real device. This is the same
non-negotiable rule as everywhere else in the project.
""")

# ============================================================ 9  SAMIKA
s = slide()
band(s, 0.0, 0.0, 0.35, 7.5, SAMIKA)
text(s, 1.0, 0.7, 11.0, 0.6, "SAMIKA", 14, True, SAMIKA)
text(s, 1.0, 1.2, 11.0, 1.0, "What matters most, and getting it off the screen",
     30, True, INK)
bullets(s, 1.0, 2.5, 11.0, 3.4, [
    "Twenty problems in a list is not useful. Which one do you fix before lunch?",
    "You can mark a machine as business-critical — the same problem on your "
    "payroll server matters more than on a spare lab switch.",
    "And you can download the whole result as a file to hand to a manager or "
    "an auditor.",
], 20)
band(s, 1.0, 5.6, 11.0, 1.2, RGBColor(0xFD, 0xEE, 0xF1))
text(s, 1.4, 5.85, 10.2, 0.8,
     "Marking something important can raise attention by one level. It can "
     "never hide a real problem.",
     18, True, SAMIKA)
note(s, """
The cap is the interesting design decision and it is worth saying out loud.

If a user's opinion about their own network could override the actual evidence
by any amount, the feature would be able to talk over the analysis instead of
just prioritising it. So: it can raise by exactly one level, never lower
anything, and never touch a result the tool could not check.

It is allowed to say "look at this one first". It is never allowed to say
"don't worry about that".

If asked "could someone hide a problem by marking things unimportant?" -- no,
and that is enforced in code, not left to good behaviour.
""")

# ============================================================ 10  THE IDEA
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "The one idea to take away", 34, True, INK)
text(s, 0.9, 1.5, 11.5, 0.6, "Every check ends in one of three answers — never two.",
     21, False, MUTED)

for i, (t, sub, col, fill) in enumerate([
    ("Found a problem", "Here it is, and here is\nthe exact line that causes it.",
     RGBColor(0xB4, 0x23, 0x1F), RGBColor(0xFB, 0xE9, 0xE6)),
    ("Checked — it's fine", "We looked properly.\nThis one is genuinely clean.",
     RGBColor(0x15, 0x80, 0x3D), RGBColor(0xEA, 0xF6, 0xEE)),
    ("Could NOT check", "We tried and couldn't.\nNothing is known here.",
     AMBER, RGBColor(0xFD, 0xF3, 0xE3)),
]):
    x = 0.9 + i * 3.95
    band(s, x, 2.4, 3.6, 2.0, fill)
    text(s, x + 0.25, 2.6, 3.1, 0.6, t, 19, True, col)
    text(s, x + 0.25, 3.25, 3.1, 1.0, sub, 14, False, INK, spacing=1.2)

band(s, 0.9, 4.75, 11.5, 2.35, RGBColor(0xFD, 0xF3, 0xE3))
text(s, 1.3, 5.0, 10.7, 1.95,
     "\u201cWe looked and it's fine\u201d and \u201cwe don't actually know\u201d are two "
     "completely different sentences.\n\n"
     "Mixing them up is exactly how a security tool tells someone they are safe "
     "when nobody checked.",
     19, True, RGBColor(0x92, 0x40, 0x0E), spacing=1.2)
note(s, """
If the audience remembers ONE thing, it should be this slide.

Most tools have two states: a problem, or a tick. That means "we could not
check this" quietly becomes a tick -- and the person reading it believes they
are safe.

We refuse to do that. The amber state is not a weaker green. It is a different
claim entirely.

Say this too: the code itself refuses to let a later step turn amber into
green. It is not a promise we are making, it is enforced, and we have tests
that fail if anyone breaks it.

If asked "doesn't 'could not check' mean it doesn't work?" -- it means it is
honest about its edges instead of guessing. That is the safety feature.
""")

# ============================================================ 11  DEMO
s = slide(DARK)
text(s, 1.0, 2.7, 11.3, 1.2, "Let's look at it running.", 44, True, WHITE)
text(s, 1.0, 4.1, 11.3, 0.8,
     "A real settings file, with a real mistake in it.", 22, False,
     RGBColor(0xC2, 0xCA, 0xD6))
note(s, """
DEMO ORDER -- follow the file, not the team list:

1. ARSH   upload rtr-us5-insecure, Scan Now. Five problems, one amber card.
          Click one finding, show the exact line it came from.
          Then upload rtr-us5-secure -- clean, and the amber card is still
          there. Explain the amber card HERE.

2. ANKEET upload the pfSense file -- a real client firewall format, converted.
          Show an explanation and the link back to its evidence.
          Ask a question in the chat box. Point at the line that repeats the
          question back before answering.

3. SHUBHAM upload the policy file. Re-scan. Findings now cite YOUR rules.
          Show a proposed change and its before/after.

4. SAMIKA  mark a device critical, re-scan, severity goes up.
          Download the report. Point out "could not check" is FIRST in the
          file, before any results.

Before you start: Docker up, Ollama up, refresh the page so nothing is staged.
And run one throwaway scan first -- the first scan of the day is slow while
the engine warms up.
""")

# ============================================================ 12  INDUSTRY
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "Who would actually use this?", 34, True, INK)
text(s, 0.9, 1.45, 11.5, 0.6, "Four real moments, all of them common.", 20, False, MUTED)

for i, (when, who) in enumerate([
    ("\u201cI'm about to change the firewall.\nWhat will this actually do?\u201d",
     "A network engineer, before a change goes live"),
    ("\u201cI just inherited this network.\nWhat is even in here?\u201d",
     "Someone who joined a company last month"),
    ("\u201cThe auditor is here.\nShow me what was checked.\u201d",
     "Compliance, before an audit or after an incident"),
    ("\u201cI look after forty client firewalls.\nSame questions, every time.\u201d",
     "A managed service provider"),
]):
    x = 0.9 + (i % 2) * 5.9
    y = 2.3 + (i // 2) * 2.3
    band(s, x, y, 5.5, 2.0, RGBColor(0xF4, 0xF6, 0xFA))
    text(s, x + 0.3, y + 0.25, 4.9, 1.1, when, 17, True, INK, spacing=1.2)
    text(s, x + 0.3, y + 1.35, 4.9, 0.5, who, 13, False, MUTED, italic=True)
note(s, """
This is the slide that answers "so what?"

The second one is worth dwelling on: inheriting an undocumented network is
extremely common, and there is currently no good way to answer "what does this
actually allow?" other than reading thousands of lines by hand.

The fourth one is the commercial case. An MSP does the same review for forty
customers. Anything that turns a two-hour manual read into a two-minute check
is worth real money to them.

If asked "is this a product or a project?" -- say it honestly: it is a working
tool, built for one real client, that solves a real problem. Whether it becomes
a product depends on the next stage, not this one.
""")

# ============================================================ 13  WHY US
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "Why would they choose this one?", 34, True, INK)

band(s, 0.9, 1.7, 11.5, 1.7, RGBColor(0xE8, 0xEE, 0xFC))
text(s, 1.3, 1.95, 10.7, 1.2,
     "Most security tools send your data to their cloud to analyse it.\n"
     "Banks, hospitals, government and defence networks often simply cannot do that.",
     20, True, RGBColor(0x2F, 0x5F, 0xD0), spacing=1.25)

bullets(s, 0.9, 3.8, 11.5, 3.0, [
    "Netwise runs on your machine. Nothing is uploaded, so there is nothing to "
    "approve, and no data-sharing agreement to negotiate.",
    "It shows the evidence, not just a verdict — you can check every claim it "
    "makes against your own file.",
    "It tells you what it could NOT check. Most tools quietly show you a tick "
    "instead.",
    "It reads exported files only. It never connects to your live network, so "
    "it cannot break anything.",
], 18, gap=14)
note(s, """
The blue box is the commercial insight and it is worth stating as one: our
hardest constraint turned out to be the market.

We were told at the start that nothing may leave the machine. That removed the
obvious, easy architecture -- a cloud service with a big AI model. But it is
also exactly why a hospital or a bank could actually run this, when they cannot
run most of the alternatives.

The third bullet is the one that separates us from a checklist scanner, and it
comes straight from the amber slide.
""")

# ============================================================ 14  HONEST
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "What it does not do yet", 34, True, INK)
text(s, 0.9, 1.45, 11.5, 0.6,
     "Said before anyone asks, because a security tool that oversells itself is "
     "worse than useless.", 18, False, MUTED)

bullets(s, 0.9, 2.4, 11.5, 3.6, [
    "Two of our four checks still use our own example device names. On somebody "
    "else's network they say \u201ccould not check\u201d instead of pretending.",
    "The firewall translator cannot yet handle a few things in a real export — "
    "it names each one it skipped, and analyses the rest.",
    "The question feature understands a small, fixed set of questions. Anything "
    "else is refused with a reason.",
    "It has been tested on our own files and one real client export. It has not "
    "been run against an unfamiliar production network.",
], 18, gap=16)

band(s, 0.9, 6.1, 11.5, 0.95, RGBColor(0xFD, 0xF3, 0xE3))
text(s, 1.3, 6.3, 10.7, 0.6,
     "Every one of these is reported honestly on screen, not hidden.",
     18, True, RGBColor(0x92, 0x40, 0x0E))
note(s, """
Do not rush this slide and do not sound defensive. A team that names its own
limits is more credible than one that does not, and every marker knows it.

The last bullet is the honest caveat about our five-of-five result: those are
our own test files, and we wrote the checks knowing what we had planted. It
proves the checks do what they were designed to do. It does not prove Netwise
would catch an unknown mistake in a file nobody has seen.

The one real-world test we do have: the client's own firewall export produced
a genuine finding once we closed a naming gap -- and before that, it silently
produced nothing at all. That is the honest version.
""")

# ============================================================ 15  NEXT
s = slide()
text(s, 0.9, 0.8, 11.5, 0.9, "What we would build next", 34, True, INK)
for i, (n, t, why) in enumerate([
    ("1", "Let your own rules reach every check",
     "Closes the biggest gap. Turns it from a tool that analyses our example "
     "network into one that analyses yours."),
    ("2", "Finish reading the client's real firewall",
     "Three questions are with him now. NAT and VPN interfaces are the "
     "remaining pieces."),
    ("3", "Remember previous scans",
     "So you can ask \u201cwhat changed since last month?\u201d — which turns a one-off "
     "report into something worth running weekly."),
]):
    y = 1.9 + i * 1.65
    band(s, 0.9, y, 0.9, 1.3, RGBColor(0x2F, 0x5F, 0xD0))
    text(s, 1.05, y + 0.35, 0.6, 0.6, n, 26, True, WHITE, align=PP_ALIGN.CENTER)
    text(s, 2.1, y + 0.12, 10.2, 0.5, t, 21, True, INK)
    text(s, 2.1, y + 0.62, 10.2, 0.7, why, 15, False, MUTED, spacing=1.15)
note(s, """
Keep this short -- it is the last content slide and the audience is ready for
questions.

Number 1 is the honest headline: the tool works, and it works best on networks
named like ours. Fixing that is worth more than any new feature.

If asked "how long would that take?" -- say you do not know precisely, and
that the team has scoped it but not estimated it. Do not invent a timeline in
front of a client.
""")

# ============================================================ 16  QUESTIONS
s = slide(DARK)
text(s, 1.0, 2.9, 11.3, 1.2, "Questions", 46, True, WHITE)
text(s, 1.0, 4.2, 11.3, 0.8,
     "Happy to show any part of it running.", 21, False, RGBColor(0xC2, 0xCA, 0xD6))
note(s, """
PREPARED ANSWERS -- the five most likely questions.

"How do you know it works?"
Five test files with deliberately planted mistakes: found all five. Two clean
files: zero false alarms. Then say the caveat before being asked -- those are
our files and we wrote the checks knowing what was in them.

"Can the AI make things up?"
Structurally no. It never sees a config file. It only ever receives a finding
a real analysis already produced, and only ever rewords it. There is a link on
every explanation back to the evidence it came from.

"Why not just use ChatGPT for all of it?"
An AI reading a raw config has no way to tell a genuinely broken rule from one
working as intended, and would invent plausible-sounding findings. A security
tool that occasionally makes something up is worse than no tool.

"Is it finished?"
No, and do not say it is. Say: it works end to end, and specific pieces are
still in review. Then name one.

"What did you build, if Batfish does the analysis?"
Batfish is a calculator. Ours is: which questions to ask and with what
parameters, the three-answer rule and everywhere it is enforced, the pipeline
that keeps one broken check from taking down the others, the refusal logic,
the whole pfSense translator, and the explanation layer.

If nobody can answer something confidently: say so and offer to follow up. A
guessed answer in front of a client is worse than "let me confirm that".
""")

# ================================ 17-18  BACKUP, if the demo will not run
SHOTS = DOCS / "screenshots"

for fname, title, caption, note_txt in [
    ("1-dashboard-rtr-us5-insecure.png",
     "Backup: the dashboard",
     "Five problems found, one amber “could not check”. The three counts "
     "are kept separate and are never added together.",
     """
ONLY USE THIS IF THE LIVE DEMO WILL NOT RUN. Say so honestly -- "Docker isn't
cooperating, here is the same thing from a real run this week" -- rather than
pretending it is live.

This is a real screenshot from a real scan, not a mock-up. Walk it the same way
you would walk the live version: the counts at the top, then one finding, then
the amber card and why it is amber.
"""),
    ("3-exported-report-could-not-check-first.png",
     "Backup: the downloaded report",
     "“Could not check” is the FIRST section in the file — before the "
     "problems and before the clean results.",
     """
The section order is the point. In most tools the caveats are a footnote at the
bottom that nobody reads. Here the things we could NOT check are the first
thing you see when you open the file.

If asked why the header says device.cfg when the upload was rtr-us5.cfg: the
upload deliberately never writes a user-supplied filename to disk, so a
filename cannot be used to reach the filesystem. The screen shows the name you
chose; the report names the file we staged.
"""),
]:
    s = slide()
    text(s, 0.7, 0.35, 11.9, 0.55, title, 26, True, INK)
    text(s, 0.7, 0.92, 11.9, 0.5, caption, 14, False, MUTED)
    pic = s.shapes.add_picture(str(SHOTS / fname), Inches(0), Inches(0))
    scale = min(11.9 / Emu(pic.width).inches, 5.7 / Emu(pic.height).inches)
    pic.width = Inches(Emu(pic.width).inches * scale)
    pic.height = Inches(Emu(pic.height).inches * scale)
    pic.left = Inches((13.333 - Emu(pic.width).inches) / 2)
    pic.top = Inches(1.55)
    note(s, note_txt)

OUT.parent.mkdir(parents=True, exist_ok=True)
prs.save(str(OUT))
print(f"wrote: {OUT.name}")
print(f"  {len(prs.slides._sldIdLst)} slides, 16:9")
