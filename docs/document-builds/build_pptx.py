"""Netwise class presentation.

REBUILT 8 September after supervisor feedback on the first version:

    "It lacks insights into the system and your working. e.g., the diagram
    only says 1. 2. 3 steps.. would be great to mention how each step is done
    .. what's your contribution rather than just using exiting apps and
    tools.. what you have done. e.g., step 3 - what's the model? Please
    mention for each of your contribution.. what is the input .. what process
    you have done.. whats the output.. Do it for each member to clarify the
    contribution and making the full story understandable"

That does not contradict the earlier instruction to keep it understandable
for a non-technical audience. The first version kept the language plain and
had nothing underneath it. So: same plain sentences, real specifics inside
them -- the actual model and its temperature, the actual Batfish questions,
the actual file formats, the actual line counts.

Structure:
    1-4   the story: why this matters and what the tool is
    5     the architecture diagram, every stage naming its mechanism
    6     what we drive versus what we wrote, with measured line counts
    7-10  one slide per member: INPUT -> WHAT I BUILT -> OUTPUT
    11    the three-answer rule, which is the design spine
    12-16 demo, industry, honesty, next, questions
    17-18 backup screenshots if the live demo will not run

Every figure measured at origin/main ce125b5 on 8 September 2026. Nothing
here is remembered.
"""
import pathlib

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

DOCS = pathlib.Path(__file__).resolve().parents[1]
DEMO = DOCS / "Demo"
SHOTS = DOCS / "screenshots"
OUT = DEMO / "Netwise - Class Presentation.pptx"

INK = RGBColor(0x1A, 0x1A, 0x1A)
MUTED = RGBColor(0x5A, 0x64, 0x72)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
ARSH = RGBColor(0x4F, 0x46, 0xE5)
ANKEET = RGBColor(0x0F, 0x76, 0x6E)
SHUBHAM = RGBColor(0xB4, 0x53, 0x09)
SAMIKA = RGBColor(0xBE, 0x12, 0x3C)
THIRD = RGBColor(0x7C, 0x86, 0x97)
AMBER = RGBColor(0xB4, 0x53, 0x09)
DARK = RGBColor(0x14, 0x18, 0x1F)

TINT = {  # a pale wash of each member's colour, for the panel backgrounds
    "ARSH": RGBColor(0xEE, 0xF0, 0xFE), "ANKEET": RGBColor(0xE6, 0xF4, 0xF2),
    "SHUBHAM": RGBColor(0xFD, 0xF1, 0xE1), "SAMIKA": RGBColor(0xFD, 0xEE, 0xF1),
}

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


def bullets(s, x, y, w, h, items, size=13.5, colour=INK, gap=7, bullet="•   "):
    tb = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap)
        p.line_spacing = 1.12
        r = p.add_run()
        r.text = bullet + item
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


def member(name, colour, tint_key, title, subtitle, columns, hard_part, notes):
    """One member's slide: INPUT -> WHAT I BUILT -> OUTPUT, in three panels.

    The supervisor asked for exactly this shape, per person, so the four
    slides are deliberately identical in layout: the only thing that changes
    between them is the content, which makes the comparison readable.
    """
    s = slide()
    band(s, 0.0, 0.0, 0.3, 7.5, colour)
    text(s, 0.75, 0.35, 11.9, 0.4, name.upper(), 13, True, colour)
    text(s, 0.75, 0.72, 11.9, 0.55, title, 27, True, INK)
    text(s, 0.75, 1.32, 11.9, 0.4, subtitle, 14, False, MUTED, italic=True)

    heads = ["INPUT — what arrives", "WHAT I BUILT — the process",
             "OUTPUT — what comes out"]
    xs = [0.75, 4.87, 8.99]
    for x, head, items in zip(xs, heads, columns):
        band(s, x, 1.92, 3.72, 3.80, TINT[tint_key])
        text(s, x + 0.22, 2.04, 3.3, 0.32, head, 10.5, True, colour)
        bullets(s, x + 0.14, 2.44, 3.48, 3.22, items, 11.5, INK, 5)

    band(s, 0.75, 5.75, 11.96, 1.3, colour)
    text(s, 1.05, 5.87, 11.4, 0.35, "THE HARD PART", 10, True, WHITE)
    text(s, 1.05, 6.18, 11.4, 0.8, hard_part, 14.5, False, WHITE, spacing=1.15)
    note(s, notes)
    return s


# ============================================================ 1  TITLE
s = slide(DARK)
text(s, 1.0, 2.4, 11.3, 1.4, "Netwise", 60, True, WHITE)
text(s, 1.0, 3.6, 11.3, 1.0,
     "Finding the security mistakes hiding in network settings —\n"
     "and explaining them in plain English.", 22, False, RGBColor(0xC2, 0xCA, 0xD6))
text(s, 1.0, 5.5, 11.3, 0.8,
     "Arsh Vhora   ·   Ankeet Patel   ·   Shubham Kataria   ·   Samika Perera",
     16, False, RGBColor(0x8E, 0x99, 0xA8))
text(s, 1.0, 6.0, 11.3, 0.5,
     "Studio 5  ·  Block 3, 2026  ·  Client: Senaka Amarakeerthi",
     13, False, RGBColor(0x5A, 0x64, 0x72))
note(s, """
Do not start with the technology. Start with the story on the next slide.
Names, then move on -- 20 seconds maximum.
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
THE HOOK. Say it slowly, then pause.

Every router and firewall is controlled by a long text file of rules, edited
by different people over years. Somebody widens one rule at 2am to fix an
urgent problem and never narrows it again.

Nothing breaks. No alarm goes off. The website still loads. The only sign is
in the file, and nobody reads the file.

Say "one of the leading causes of real breaches" -- do not quote a statistic
you cannot source.
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
The point for a non-technical audience: you cannot answer "can an outsider
reach my payroll server?" by reading any single line. It depends on all of
them together, in order. A file with 200 rules has more combinations than a
person can hold in their head.

That is why this is a computer's job, not a careful-reading job -- and it is
why we drive a verification engine rather than writing a text search.
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
Two sentences, then STOP. Do not list features here -- the next two slides do
that properly.

The blue box is a hard requirement (N-1), not marketing, and it decided the
architecture at two separate layers: no hosted model, no cloud analysis.
""")

# ============================================================ 5  DIAGRAM
s = slide()
s.shapes.add_picture(str(DEMO / "team-architecture.png"),
                     Inches(0.25), Inches(0.15), width=Inches(12.85))
note(s, """
THE SLIDE THE SUPERVISOR ASKED FOR. Every stage names HOW it is done, not just
that it happens. Each of us points at our own colour.

Walk the top row left to right, then the wrap arrow down to the bottom row.
Hand over as you go.

Two things to say out loud:
  - GREY IS NOT OURS. Batfish builds the model; Ollama runs the model. We
    drive both. Everything coloured is ours.
  - Step 7 answers "what's the model": netwise-warden, built on llama3.2:3b,
    temperature 0.2 so it does not get creative, capped at 300 tokens, and it
    is handed ONE already-verified finding. It never sees a config file.

The amber strip is the rule underneath everything. It gets its own slide
later -- do not explain it here.
""")

# ============================================================ 6  OURS v THEIRS
s = slide()
text(s, 0.9, 0.45, 11.5, 0.78, "What we drive, and what we actually wrote",
     32, True, INK)
text(s, 0.9, 1.15, 11.5, 0.45,
     "Measured from the repository on 8 September, not estimated.",
     14, False, MUTED, italic=True)

band(s, 0.9, 1.8, 5.5, 4.05, RGBColor(0xF1, 0xF3, 0xF6))
text(s, 1.2, 1.95, 4.9, 0.35, "WE DID NOT WRITE THIS", 11, True, THIRD)
bullets(s, 1.15, 2.4, 5.0, 3.3, [
    "Batfish — builds a vendor-neutral model of the network and answers "
    "formal questions about it",
    "Ollama — runs a language model locally, so nothing is uploaded",
    "llama3.2:3b — the base model we build ours on top of",
    "FastAPI, pandas, Docker",
], 13, INK, 9)

band(s, 6.85, 1.8, 5.6, 4.05, RGBColor(0xE8, 0xEE, 0xFC))
text(s, 7.15, 1.95, 5.0, 0.35, "WE WROTE THIS", 11, True, ARSH)
bullets(s, 7.1, 2.4, 5.1, 3.3, [
    "11,224 lines of product code across 27 files",
    "20,444 lines of tests across 66 files — almost twice the product",
    "2,359 lines of measuring tools we wrote to check our own claims",
    "Six analyses, one shared record format, one pipeline",
], 13, INK, 9)

band(s, 0.9, 6.05, 11.55, 1.0, RGBColor(0xE8, 0xEE, 0xFC))
text(s, 1.2, 6.2, 11.0, 0.7,
     "Batfish answers questions. Choosing which question to ask, deciding "
     "whether the answer can be trusted,\nand saying what it means to a "
     "person — that is the part we built.",
     15, True, RGBColor(0x2F, 0x5F, 0xD0), spacing=1.15)
note(s, """
This slide exists because the feedback said we looked like we were "just using
existing apps and tools". Say the numbers -- they are the answer.

The test figure is the one worth pausing on. We wrote almost twice as much
test code as product code, and that is not padding: the team standard is that
a reviewer breaks the guard deliberately and confirms a test fails. A passing
test proves nothing until you have watched it fail for the right reason.

If asked "so what did you actually build?": every Batfish question returns a
table with no severity, no judgement and no English in it. Everything the user
sees, Netwise added.
""")

# ============================================================ 7  ARSH
member(
    "Arsh Vhora", ARSH, "ARSH",
    "The backbone, the first check, and the report",
    "analysis/pipeline.py · access_control.py · policy.py · report.py",
    [[
        "A folder of Cisco IOS configuration files",
        "Optionally, a policy file the user wrote saying what should be "
        "allowed and denied",
        "Whatever the other three checks return",
    ], [
        "The pipeline (861 lines): connect, load the snapshot, check the "
        "parse status, run every check in isolation, guard duplicate ids",
        "My own check (604 lines) asks four Batfish questions: testFilters, "
        "searchFilters, filterLineReachability, undefinedReferences",
        "The report writer (408 lines): pure function, no web import",
    ], [
        "One combined list, every finding the same 7 fields",
        "An HTML or CSV file, with “could not check” printed FIRST",
        "If a check crashes, a visible finding — never a silent gap",
    ]],
    "Not “does this one packet get through”, but “across every possible "
    "packet, is there one that does”. An empty answer to that is a proof.",
    """
The hard part is a real research result, not a design preference.

We tried the obvious approach first: pick one packet, ask if it arrives. On
our deliberately insecure test file -- the one containing "permit ip any any"
-- that came back EMPTY, which reads as "you're fine". It was empty because
that file has no route between those two networks, for a completely unrelated
reason.

A tool that read empty as safe would have printed a green tick over a
configuration that allows everything. We measured that happening.

searchFilters asks the stronger question: across the whole space of possible
packets, is there one that gets through when it should not? An empty answer to
THAT is a proof, not a guess. It is the strongest thing in the project.

The isolation in the pipeline is the other half: a bug in my feature cannot
take down anyone else's, because the pipeline turns an exception into a
finding you can see.
""")

# ============================================================ 8  ANKEET
member(
    "Ankeet Patel", ANKEET, "ANKEET",
    "Real firewalls in, plain English out",
    "pfsense_convert.py · routing.py · ai/explain.py · ai/query.py",
    [[
        "The client's real pfSense firewall export — XML, 1,998 elements "
        "against our test file's 54",
        "For the AI: ONE finding that a real analysis already produced",
        "A question typed in ordinary English",
    ], [
        "The converter (1,074 lines): pfSense XML → Cisco IOS, modelling "
        "their last-match-wins against Cisco's first-match-wins",
        "A rule it cannot model exactly is skipped and named, not "
        "emitted as something that parses and is wrong",
        "The explainer (983 lines) calls netwise-warden — llama3.2:3b, "
        "temperature 0.2, 300-token cap, locked system prompt",
        "Questions (445 lines): matched against three fixed intents. No "
        "model is used to classify — that would be guessing at intent",
    ], [
        "A converted config, plus a named list of what was skipped and why",
        "One plain-English sentence per finding, labelled model or fallback",
        "A grounded answer, or a refusal with a reason — never a guess",
    ]],
    "The model never sees your configuration file. It is handed one "
    "already-verified finding and asked only to reword it.",
    """
"What's the model?" was in the feedback, so answer it precisely: netwise-warden,
an Ollama model built from llama3.2:3b -- 3.2 billion parameters, 4-bit
quantised, 2.0 GB on disk. Temperature 0.2 and a 300-token cap because
rewording a verified fact is a translation job, not a creative one.

Expect "why not just use ChatGPT?" Two answers, in this order.

FIRST, and it is not a preference: sending a client's real network layout to
an outside company is itself a security exposure. Requirement N-1. Not allowed.

SECOND: an AI reading a raw config has no way to tell a genuinely broken rule
from one working as intended, and would invent plausible findings. Our model
structurally cannot, because it is never shown a config -- only a result that
a real analysis already produced.

The converter is the other half of this slide and it is the piece that met the
real world first. When the client's actual export arrived it did NOT produce a
plausible wrong answer. It stopped and named the construct it could not
handle. That is the strongest evidence in the project that refusing rather
than guessing was the right default.
""")

# ============================================================ 9  SHUBHAM
member(
    "Shubham Kataria", SHUBHAM, "SHUBHAM",
    "Your rules, and testing a change before you make it",
    "policy_compliance.py · change_impact.py · docs/policy-rules.md",
    [[
        "A policy file the user wrote — what traffic should be allowed, and "
        "what must be denied",
        "Or two configurations: the one running now, and the one proposed",
    ], [
        "Policy compliance (692 lines): searchFilters across a whole space "
        "of traffic against YOUR rules, not our example ones",
        "Every finding records whose policy produced it — yours or ours",
        "If rules were supplied that a check cannot read, it says so out "
        "loud instead of staying quiet",
        "Change impact (485 lines): compareFilters for which rule lines "
        "moved, differentialReachability for which traffic changed fate",
    ], [
        "Findings that cite the rule they came from",
        "A before/after list: what this change would newly allow, and newly "
        "block, with opening traffic rated higher than tightening it",
        "All of it simulated on a throwaway copy — never applied",
    ]],
    "A changed rule that moves no traffic is noise. Moved traffic with no "
    "changed rule is the case a text diff misses. It takes both questions.",
    """
The "your own rules" point matters commercially. A tool that only checks
against one fixed generic ruleset tells every customer the same thing,
regardless of what they actually care about. What is fine for one company is
a serious problem for another.

The change-impact half answers the question a network engineer actually has,
which is not "is my config wrong" but "if I make this change at 9pm, what
breaks?"

Why it needs two questions rather than one is the thing worth explaining: a
diff of the text tells you a line changed, but not whether any traffic cares.
And traffic can change fate with no line visibly changing, because rules
interact. compareFilters answers the first, differentialReachability the
second, and you need both.

If asked "does it touch my network?" -- no. It writes to a temporary copy that
is deleted immediately. There is no code path that connects to a device.
""")

# ============================================================ 10  SAMIKA
member(
    "Samika Perera", SAMIKA, "SAMIKA",
    "What matters most, and getting it off the screen",
    "risk.py · business_context.py · web/ — the dashboard and secure upload",
    [[
        "The combined findings from every check, in one list",
        "Optionally, a file marking devices critical, important or standard",
        "The uploaded configuration file itself",
    ], [
        "Risk scoring (440 lines): a documented ruleset re-rates severity "
        "and sorts worst-first — never alphabetically, never by check",
        "A finding that could not be checked is never re-rated. Not rated "
        "carefully — not rated at all",
        "Business context (350 lines): marking a device critical raises its "
        "findings by at most ONE level, and can never lower one",
        "The web layer: your filename never reaches the disk, and each "
        "browser session is kept apart from every other",
    ], [
        "Findings sorted worst-first, with the reason visible",
        "A dashboard that keeps the three states apart on screen",
        "A downloadable report you can hand to a manager or an auditor",
    ]],
    "It is allowed to say “look at this one first”. It is never allowed to "
    "say “don't worry about that”. The cap is enforced in code.",
    """
The cap is the design decision worth saying out loud.

If a user's opinion about their own network could override the evidence by any
amount, the feature would be able to talk over the analysis instead of
prioritising it. So it raises by exactly one level, never lowers anything, and
never touches a result the tool could not check.

Measured on the insecure test file: marking the device critical took the
severity spread from {high 4, medium 1} to {high 5}. One level, no more.

If asked "could someone hide a problem by marking things unimportant?" -- no,
and that is enforced in code rather than left to good behaviour. There is a
test that fails if anyone removes it.

The upload detail is worth thirty seconds too: the file is staged under a
fixed name, so a filename someone chose can never reach the filesystem. That
is why the downloaded report says device.cfg rather than whatever you uploaded.
""")

# ============================================================ 11  THE IDEA
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "The one idea to take away", 34, True, INK)
text(s, 0.9, 1.5, 11.5, 0.6,
     "Every check ends in one of three answers — never two.", 21, False, MUTED)
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
     "“We looked and it's fine” and “we don't actually know” are two "
     "completely different sentences.\n\n"
     "Mixing them up is exactly how a security tool tells someone they are "
     "safe when nobody checked.",
     19, True, RGBColor(0x92, 0x40, 0x0E), spacing=1.2)
note(s, """
If the audience remembers ONE thing, it should be this.

Most tools have two states: a problem, or a tick. That means "we could not
check this" quietly becomes a tick, and the person reading it believes they
are safe.

This is not a promise we make -- it is enforced. A post-processor may not
downgrade a "could not check" finding, and may not drop one; both limits are
checked in code rather than trusted, and there are tests that fail if anyone
breaks them.

If asked "doesn't 'could not check' mean it doesn't work?" -- it means it is
honest about its edges instead of guessing. That is the safety feature.
""")

# ============================================================ 12  DEMO
s = slide(DARK)
text(s, 1.0, 2.7, 11.3, 1.2, "Let's look at it running.", 44, True, WHITE)
text(s, 1.0, 4.1, 11.3, 0.8,
     "A real settings file, with a real mistake in it.", 22, False,
     RGBColor(0xC2, 0xCA, 0xD6))
note(s, """
DEMO ORDER -- follow the file, not the team list.

1. ARSH    upload rtr-us5-insecure, Scan Now. Five problems, one amber card.
           Click one finding and show the exact line it came from.
           Then rtr-us5-secure: clean, and the amber card is STILL there.
           Explain the amber card here.

2. ANKEET  upload the pfSense file -- a real client firewall format,
           converted. Show an explanation and the link back to its evidence.
           Ask a question in the chat box; point at the line that repeats the
           question back before answering.

3. SHUBHAM upload the policy file, re-scan. Findings now cite YOUR rules.
           Show a proposed change and its before/after.

4. SAMIKA  mark a device critical, re-scan, severity goes up by one.
           Download the report. Point out "could not check" is FIRST in the
           file, before any results.

Before you start: Docker up, Ollama up, refresh so nothing is staged, and RUN
ONE THROWAWAY SCAN -- the first scan of a session costs about 22 seconds of
engine warm-up against about 16 seconds of narration.
""")

# ============================================================ 13  INDUSTRY
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "Who would actually use this?", 34, True, INK)
text(s, 0.9, 1.45, 11.5, 0.6, "Four real moments, all of them common.",
     20, False, MUTED)
for i, (when, who) in enumerate([
    ("“I'm about to change the firewall.\nWhat will this actually do?”",
     "A network engineer, before a change goes live"),
    ("“I just inherited this network.\nWhat is even in here?”",
     "Someone who joined a company last month"),
    ("“The auditor is here.\nShow me what was checked.”",
     "Compliance, before an audit or after an incident"),
    ("“I look after forty client firewalls.\nSame questions, every time.”",
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

The fourth is the commercial case. An MSP does the same review for forty
customers. Turning a two-hour manual read into a two-minute check is worth
real money.

If asked "is this a product or a project?" -- be honest: it is a working tool
built for one real client that solves a real problem. Whether it becomes a
product depends on the next stage, not this one.
""")

# ============================================================ 14  WHY US
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "Why would they choose this one?", 34, True, INK)
band(s, 0.9, 1.7, 11.5, 1.7, RGBColor(0xE8, 0xEE, 0xFC))
text(s, 1.3, 1.95, 10.7, 1.2,
     "Most security tools send your data to their cloud to analyse it.\n"
     "Banks, hospitals, government and defence networks often simply cannot "
     "do that.",
     20, True, RGBColor(0x2F, 0x5F, 0xD0), spacing=1.25)
bullets(s, 0.9, 3.8, 11.5, 3.0, [
    "Netwise runs on your machine. Nothing is uploaded, so there is nothing "
    "to approve and no data-sharing agreement to negotiate.",
    "It shows the evidence, not just a verdict — you can check every claim "
    "against your own file.",
    "It tells you what it could NOT check. Most tools quietly show a tick "
    "instead.",
    "It reads exported files only. It never connects to your live network, "
    "so it cannot break anything.",
], 18, INK, 14)
note(s, """
The blue box is the commercial insight, and it is worth stating as one: our
hardest constraint turned out to be the market.

We were told at the start that nothing may leave the machine. That removed the
easy architecture -- a cloud service with a big model. It is also exactly why
a hospital or a bank could run this when they cannot run the alternatives.

The third bullet is what separates us from a checklist scanner, and it comes
straight from the three-answers slide.
""")

# ============================================================ 15  HONEST
s = slide()
text(s, 0.9, 0.55, 11.5, 0.9, "What it does not do yet", 34, True, INK)
text(s, 0.9, 1.45, 11.5, 0.6,
     "Said before anyone asks, because a security tool that oversells itself "
     "is worse than useless.", 18, False, MUTED)
bullets(s, 0.9, 2.4, 11.5, 3.6, [
    "Two of our checks still use our own example device names. On somebody "
    "else's network they say “could not check” instead of pretending.",
    "The firewall translator cannot yet handle a few things in a real "
    "export — it names each one it skipped, and analyses the rest.",
    "The question feature understands a small, fixed set of questions. "
    "Anything else is refused with a reason.",
    "It has been tested on our own files and one real client export. It has "
    "not been run against an unfamiliar production network.",
], 18, INK, 16)
band(s, 0.9, 6.1, 11.5, 0.95, RGBColor(0xFD, 0xF3, 0xE3))
text(s, 1.3, 6.3, 10.7, 0.6,
     "Every one of these is reported honestly on screen, not hidden.",
     18, True, RGBColor(0x92, 0x40, 0x0E))
note(s, """
Do not rush this and do not sound defensive. A team that names its own limits
is more credible than one that does not.

The last bullet is the honest caveat about the five-of-five result: those are
our own test files, and we wrote the checks knowing what we had planted. It
proves the checks do what they were designed to do. It does not prove Netwise
would catch an unknown mistake in a file nobody has seen.

The one real-world test we do have: the client's own firewall export produced
a genuine finding once we closed a naming gap -- and before that it silently
produced nothing at all. That is the honest version.
""")

# ============================================================ 16  NEXT
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
     "So you can ask “what changed since last month?” — which turns a one-off "
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

# ============================================================ 17  QUESTIONS
s = slide(DARK)
text(s, 1.0, 2.9, 11.3, 1.2, "Questions", 46, True, WHITE)
text(s, 1.0, 4.2, 11.3, 0.8, "Happy to show any part of it running.",
     21, False, RGBColor(0xC2, 0xCA, 0xD6))
note(s, """
PREPARED ANSWERS.

"What did you actually build, if Batfish does the analysis?"
11,224 lines of product code and 20,444 lines of tests. Specifically: which
questions to ask and with what parameters, the three-answer rule and
everywhere it is enforced, the pipeline that keeps one broken check from
taking down the others, the refusal logic, the whole pfSense translator, and
the explanation layer. Batfish is a calculator; none of the above is in it.

"What's the model?"
netwise-warden, built on llama3.2:3b -- 3.2B parameters, 4-bit quantised,
2.0 GB. Temperature 0.2, top_p 0.8, 300-token cap, locked system prompt. It
runs under Ollama on this laptop.

"How do you know it works?"
Five test files with deliberately planted mistakes: found all five. Two clean
files: zero false alarms. Then say the caveat before being asked -- those are
our files and we wrote the checks knowing what was in them.

"Can the AI make things up?"
Structurally no. It never sees a config file. It only ever receives a finding
a real analysis already produced, and only ever rewords it. Every explanation
links back to the evidence it came from.

"Is it finished?"
No, and do not say it is. Say: it works end to end, and specific pieces are
still in review. Then name one.

If nobody can answer something confidently: say so and offer to follow up. A
guessed answer in front of a client is worse than "let me confirm that".
""")

# ============================================ 18-19  BACKUP, IF THE DEMO DIES
for fname, title, caption, note_txt in [
    ("1-dashboard-rtr-us5-insecure.png", "Backup: the dashboard",
     "Five problems found, one amber “could not check”. The three counts are "
     "kept separate and are never added together.",
     """
ONLY IF THE LIVE DEMO WILL NOT RUN. Say so honestly -- "Docker isn't
cooperating, here is the same thing from a real run this week" -- rather than
pretending it is live.

This is a real screenshot from a real scan. Walk it the same way you would
walk the live version: the counts, then one finding, then the amber card.
"""),
    ("3-exported-report-could-not-check-first.png", "Backup: the downloaded report",
     "“Could not check” is the FIRST section in the file — before the "
     "problems and before the clean results.",
     """
The section order is the point. In most tools the caveats are a footnote at
the bottom that nobody reads. Here the things we could NOT check are the first
thing you see when you open the file.

If asked why the header says device.cfg when the upload was rtr-us5.cfg: the
upload deliberately never writes a user-supplied filename to disk, so a
filename cannot be used to reach the filesystem.
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
