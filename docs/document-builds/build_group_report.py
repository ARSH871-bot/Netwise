"""Group Final Report, built to Studio_5_Group_Final_Report_Template.

Follows the template's twelve sections exactly, in the group voice it asks for.
Written plainly: short sentences, ordinary words, numbers where a number is
better than an adjective.

Things I cannot produce are marked in the document with a visible ACTION box
rather than left blank or invented -- above all the signed client letter the
template asks for at 10.2.

Measured at commit d3879b4, 8 September 2026.
"""
import pathlib

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt, RGBColor

DOCS = pathlib.Path(__file__).resolve().parents[1]

# Student names and IDs live in docs/identity.json, which is NOT tracked --
# see _identity.py and #290. `python -P` drops the script's own directory
# from sys.path, so the sibling import has to be explicit.
import sys as _sys                                            # noqa: E402
_sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _identity                                              # noqa: E402
_IDENTITY = _identity.load()
SP = DOCS / "screenshots"
OUT = DOCS / "Studio 5 - Group Final Report - Netwise.docx"

d = Document()
st = d.styles["Normal"]
st.font.name = "Calibri"
st.font.size = Pt(11)
st.paragraph_format.space_after = Pt(7)
st.paragraph_format.line_spacing = 1.13
for name, size in (("Heading 1", 16), ("Heading 2", 12.5), ("Heading 3", 11)):
    s = d.styles[name]
    s.font.name = "Calibri"
    s.font.size = Pt(size)
    s.font.color.rgb = RGBColor.from_string("1F3B57")
    s.font.bold = True


def h(t, level=1):
    d.add_heading(t, level=level)


def p(t):
    return d.add_paragraph(t)


def bullets(items):
    for i in items:
        d.add_paragraph(i, style="List Bullet")


def action(title, body):
    """A visible box for something the team must supply."""
    par = d.add_paragraph()
    r = par.add_run("ACTION BEFORE SUBMISSION \u2014 " + title)
    r.bold = True
    r.font.size = Pt(10)
    r.font.color.rgb = RGBColor.from_string("B4231F")
    par2 = d.add_paragraph()
    r2 = par2.add_run(body)
    r2.font.size = Pt(10)
    r2.font.color.rgb = RGBColor.from_string("B4231F")
    par2.paragraph_format.left_indent = Inches(0.25)
    par2.paragraph_format.space_after = Pt(10)


def table(headers, rows, widths=None, fs=9.5):
    t = d.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, txt in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        run = c.paragraphs[0].add_run(txt)
        run.bold = True
        run.font.size = Pt(fs)
    for row in rows:
        cells = t.add_row().cells
        for i, txt in enumerate(row):
            cells[i].text = ""
            run = cells[i].paragraphs[0].add_run(str(txt))
            run.font.size = Pt(fs)
    if widths:
        for r in t.rows:
            for i, w in enumerate(widths):
                r.cells[i].width = Inches(w)
    d.add_paragraph()


def figure(png, cap, width=5.7):
    d.add_picture(str(SP / png), width=Inches(width))
    d.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
    c = d.add_paragraph(cap)
    c.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = c.runs[0]
    r.font.size = Pt(9)
    r.font.italic = True
    r.font.color.rgb = RGBColor.from_string("5A6472")


def code(t):
    par = d.add_paragraph()
    r = par.add_run(t)
    r.font.name = "Consolas"
    r.font.size = Pt(8.5)
    par.paragraph_format.left_indent = Inches(0.25)
    par.paragraph_format.space_after = Pt(9)


# ================================================================ COVER
h("Studio 5 — Group Final Report", 1)
h("Netwise — offline network configuration analysis", 2)
table(["", ""], [
    ["Team / group", "Netwise (four members)"],
    ["Team members", _identity.team_members_line(_IDENTITY)],
    ["Client / stakeholder", "Senaka Amarakeerthi, Senior Lecturer"],
    ["Supervisor / lecturer", "Dr Asanthika Imbulpitiya; Dr Sonia Gul"],
    ["Submission date", "10 September 2026"],
    ["Document version", "Final v1.0"],
    ["Measured at", "commit d3879b4, 8 September 2026"],
], widths=[1.7, 4.6], fs=10)

action("student IDs",
       "Shubham's and Samika's student IDs are missing from the cover table. "
       "Ankeet's is taken from his cover sheet on an earlier report; please "
       "confirm it is right.")

# ================================================================ EXEC
h("Executive summary", 1)
p("Netwise reads exported network device configuration files, finds security "
  "mistakes in them, and explains those mistakes in plain English. Everything "
  "runs on one machine. It never connects to a live network and no "
  "configuration data is sent anywhere.")
p("The tool works end to end. A user uploads a configuration file, presses "
  "Scan Now, and gets a list of problems sorted worst first, each with the "
  "evidence it came from and a plain-English explanation. The user can also "
  "ask a question in ordinary English, propose a configuration change and see "
  "it simulated before it is applied to anything, and download the whole "
  "result as a file.")
p("We did not write the analysis engine. Netwise drives Batfish, an "
  "open-source tool that reads vendor configuration text and answers formal "
  "questions about it. What we built is everything around that: which "
  "questions to ask, how to be honest about what could not be checked, and how "
  "to say the answer in language somebody can act on. Section 4.1 draws that "
  "line explicitly.")
p("The design decision the whole product rests on is the difference between "
  "\u201cwe checked and found nothing\u201d and \u201cwe could not check\u201d. Those are "
  "different claims. If a tool shows them the same way, it can tell somebody "
  "they are safe when the truth is that nobody looked. Every analysis has to "
  "say which one it means, and the screen shows a green tick for the first and "
  "an amber warning for the second.")
table(["Measure", "Result"], [
    ["Analysis features delivered", "6 (five checks plus change impact)"],
    ["Automated tests", "1,305 passing across 62 files"],
    ["Python written", "32,245 lines across 97 Python files "
                       "(195 tracked files in all)"],
    ["Commits / pull requests", "640 commits, 207 pull requests, 197 merged"],
    ["Code review", "375 reviews; every merged change was reviewed"],
    ["Sprints", "6 run, 5 closed"],
    ["Planted faults detected", "5 of 5"],
    ["False alarms on clean configurations", "0 of 2"],
    ["Unreadable configuration reported as clean", "never"],
], widths=[2.9, 3.4])
p("One line in that table is weaker than it looks and we would rather say so "
  "than have a reader find it. \u201cFive of five planted faults\u201d is about our own "
  "test files. We planted the faults and then wrote the checks that find them. "
  "It shows the checks do what they were built to do. It is not evidence that "
  "Netwise would find an unknown fault in a configuration nobody on the team "
  "had seen. Section 10.3 measures how much weaker the claim gets on somebody "
  "else's network.")

d.add_page_break()

# ================================================================ 1
h("1  Introduction", 1)

h("1.1  Project overview", 2)
p("Routers, switches and firewalls are controlled by long text files full of "
  "rules. The rules decide which traffic is allowed, which is blocked, and "
  "where packets go. These files are edited by different people over several "
  "years, and mistakes hide in them: a rule that accidentally exposes an "
  "internal server, a rule that can never take effect because an earlier rule "
  "already caught the traffic, or a rule pointing at something that was "
  "deleted. Mistakes like these cause real security breaches and they are very "
  "hard to spot by reading the files.")
p("Our client is a Senior Lecturer who offered his own network as the test "
  "case and gave us an anonymised copy of his firewall configuration. That "
  "file shaped a lot of this project. It is real, it is in a format the "
  "analysis engine cannot read at all, and it broke assumptions we had been "
  "working on for two weeks.")
p("The hard part of the project was never finding the mistakes. Batfish "
  "already does that very well. The hard part is translation. A result that "
  "reads \u201caccess-list line 460 denies 10.10.10.42\u201d is no use to the person "
  "who has to decide whether it matters. \u201cOne machine cannot reach the DNS "
  "server because an earlier rule blocks it\u201d is.")

h("1.2  Project goals and objectives", 2)
p("The client asked for translation in two directions, and both were in scope:")
bullets([
    "Output direction. Turn the analysis results into human language. Not "
    "\u201cport 80 is denied\u201d but \u201cwebsites are blocked\u201d.",
    "Input direction. The user types what they want in English, and the "
    "system proposes a configuration change. If the change would create a "
    "security problem, it warns instead of quietly applying it.",
])
table(["Objective", "Status at submission"], [
    ["Analyse real configuration files offline",
     "Met. Six analysis features run through one pipeline against Cisco IOS, "
     "plus a converter for the client's PF Sense format."],
    ["Explain each finding in plain English",
     "Met. Every problem carries an explanation. When the local model is not "
     "running the text falls back to a fixed wording and the screen says so."],
    ["Answer plain-English questions",
     "Met. Backend and chat pane both work. The scope is deliberately narrow "
     "and anything outside it is refused with a reason."],
    ["Propose a configuration change and push back on unsafe ones",
     "Met. The tool writes the change, simulates it against a throwaway copy, "
     "and warns when it opens traffic that was previously blocked."],
    ["Let a user state their own security policy",
     "Partly met. One of the three checks reads a user policy. The other two "
     "still use our example device names and now say so on screen. This is "
     "the largest remaining gap."],
], widths=[2.3, 4.0])

h("1.3  Final project scope", 2)
p("In scope: reading exported configuration files, analysing them offline, "
  "explaining the results, answering a narrow set of questions, proposing and "
  "simulating changes, and exporting a report.")
p("Out of scope, and set by the client at the start: Netwise must never push a "
  "change to a live device. It generates and simulates; it does not apply. "
  "Blocking a specific website by name is genuinely difficult and we treated "
  "it as a proposal feature at best, never as something the tool enforces.")
p("One scope change during the project is worth recording. In August the "
  "client's real firewall export arrived and we measured it. It carried 1,998 "
  "elements against our test file's 54, and none of its seven filter rules "
  "used the setting our converter assumed. That reordered the roadmap: work on "
  "the converter moved ahead of new analysis features, because without it the "
  "client's own network could not be read at all.")

d.add_page_break()

# ================================================================ 2
h("2  Project requirements and final scope", 1)

h("2.1  Functional requirements", 2)
table(["ID", "Requirement", "Priority", "Final status"], [
    ["R-1", "Accept an uploaded configuration file and validate it before use", "High", "Met"],
    ["R-2", "Check access-control rules against a stated expectation", "High", "Met"],
    ["R-3", "Find access-list lines that can never take effect", "High", "Met"],
    ["R-4", "Find references to things the configuration never defines", "Med", "Met"],
    ["R-5", "Check whether traffic actually reaches where it should", "High", "Met"],
    ["R-6", "Check policy compliance across a whole space of traffic", "High", "Met"],
    ["R-7", "Rank findings by risk and sort worst first", "High", "Met"],
    ["R-8", "Explain each finding in plain English", "High", "Met"],
    ["R-9", "Compare two configurations and report what changed", "Med", "Met"],
    ["R-10", "Answer plain-English questions about reachability", "Med", "Met"],
    ["R-11", "Convert a PF Sense export so it can be analysed", "High", "Partly. It refuses or skips what it cannot model exactly, and names what it skipped"],
    ["R-12", "Accept a security policy written by the user", "High", "Partly. One check of three reads it; the other two report that they did not"],
    ["R-13", "Propose a configuration change from English and simulate it", "Med", "Met"],
    ["R-14", "Export the findings as a file", "Low", "Met. HTML and CSV"],
], widths=[0.5, 3.1, 0.8, 1.9])

h("2.2  Non-functional and quality requirements", 2)
table(["ID", "Requirement", "How it is met"], [
    ["N-1", "No configuration data may leave the machine",
     "No cloud services. The language model runs locally, the analysis engine "
     "runs in a local container, real configuration files are excluded from "
     "version control, and a model host that is not on this machine is refused "
     "unless an operator deliberately allows it"],
    ["N-2", "The tool must never change a live network",
     "It only reads exported files. There is no code path that connects to a device"],
    ["N-3", "A check that could not run must never look like a clean result",
     "Written into the data format every analysis returns, and tested directly"],
    ["N-4", "The AI must never invent network behaviour",
     "Structural. The model only ever receives real analysis output and is only "
     "ever asked to reword it"],
    ["N-5", "All four members must be able to read and explain any part",
     "Reviewed in every pull request; we chose the obvious solution over the clever one"],
    ["N-6", "The test suite must not need the analysis engine or the model",
     "1,302 of the 1,305 tests run with neither. The three that do not are "
     "integration tests and they skip"],
    ["N-7", "One user's upload, scan and policy must not reach another",
     "Per-session upload directories, analysis cache and staged policy. Added "
     "after #242 found a single process-wide flag made one person's upload "
     "change what every other browser analysed"],
], widths=[0.5, 2.1, 3.7])
p("N-1 is the requirement that shaped everything. It removed the obvious "
  "choice at two separate layers: a hosted language model, and any cloud "
  "analysis service.")

h("2.3  Tools and technologies", 2)
table(["Tool", "What we used it for"], [
    ["Batfish (in Docker)", "The analysis engine. It reads vendor configuration text, builds a "
                            "model of the network, and answers formal questions about it"],
    ["pybatfish", "The Python client we drive Batfish through. Pinned to match the container"],
    ["Ollama + llama3.2 (3B)", "Runs the language model on the same machine, so no configuration "
                              "data has to be sent anywhere"],
    ["FastAPI", "The web backend. Chosen over Flask for generated API documentation and for "
                "async, which the chat pane needs"],
    ["pytest and ruff", "Tests and linting. Both run in CI and locally in seconds"],
    ["GitHub", "Source control, pull requests, Actions for CI, Projects for the sprint board, "
               "Discussions for decisions"],
    ["Docker", "Runs the analysis engine so every member has the same version"],
], widths=[1.7, 4.6])

d.add_page_break()

# ================================================================ 3
h("3  Methodology and project management", 1)

h("3.1  Development methodology", 2)
p("We ran weekly SCRUM sprints. Six sprints, five of them closed. Each sprint "
  "had a plan agreed before it started and a record written inside it, so the "
  "record is what we thought at the time and not what we remembered "
  "afterwards.")
p("The team's first plan split the work horizontally: two people on the "
  "analysis engine, two on the web interface. We replaced it early with "
  "vertical slices, where each person owns one analysis all the way from the "
  "engine, through the shared output format, to the screen. The reason was "
  "practical. With a horizontal split nobody can demonstrate anything until "
  "two people have both finished, and we had weekly sprints and a client who "
  "wanted to see progress.")

h("3.2  Team roles and work allocation", 2)
table(["Role / workstream", "Primary responsibility", "Coordination and dependencies"], [
    ["Arsh Vhora — SCRUM Master", "Access-control analysis; the shared pipeline; the "
     "output contract; the sprint board",
     "The pipeline is what the other three build against, so changes to it were "
     "agreed before they were made"],
    ["Ankeet Patel", "Routing analysis; the local AI layer; the PF Sense converter",
     "The AI layer reads whatever the checks produce, so it depends on the "
     "output format staying stable"],
    ["Shubham Kataria", "Policy compliance; change-impact analysis",
     "Policy compliance consumes the user policy loader, which Arsh wrote"],
    ["Samika Perera", "Risk scoring; the web interface; secure upload",
     "Risk sees the combined findings from every check, so it depends on all "
     "three of them"],
], widths=[1.6, 2.2, 2.5])

h("3.3  Planning, tracking and change control", 2)
p("Work was tracked as GitHub issues on a Projects board, one milestone per "
  "sprint. Every issue is closed by a pull request that names it, and every "
  "pull request runs the test suite. That gives a chain from a requirement to "
  "merged code that can be followed in either direction.")
p("Decisions that change something shared are handled differently from "
  "ordinary work. The output format has a written contract with a signature "
  "table inside the document, and changing it needs all four of us. There have "
  "been four such amendments and all four are now signed by everybody.")
p("Part way through we noticed a problem with how we recorded decisions. Three "
  "of them had been filed as issues, so they sat on sprint milestones and "
  "counted in the burndown as outstanding work, when what was outstanding was "
  "an answer. We moved that kind of item to GitHub Discussions with one rule: "
  "if it can be closed by a pull request it is an issue, and if it ends when we "
  "agree it is a discussion.")

d.add_page_break()

# ================================================================ 4
h("4  Solution design and architecture", 1)

h("4.1  What Batfish does, and what we built", 2)
p("This section exists because feedback at our practice review said, in "
  "several separate comments, that we had not made this clear enough. It was a "
  "fair criticism.")
p("Batfish is an open-source network verification engine. It reads vendor "
  "configuration text, builds a model of the network, and answers formal "
  "questions about that model. It is very good and it is not ours. Ollama and "
  "the language model are also third-party.")
figure("ownership-boundary.png",
       "Figure 1. Grey is somebody else's work; blue is ours. "
       "Generated by tools/make_diagrams.py and committed to the repository.")
p("Everything in blue is ours. Put simply: Batfish answers questions. "
  "Choosing which question to ask, deciding whether the answer can be trusted, "
  "and saying what it means to a person are the parts we wrote.")
p("Every Batfish question returns a table. It contains no severity, no "
  "judgement and no English. Everything the user sees is something Netwise "
  "added.")
table(["Question we ask", "What Batfish gives back", "What we do with it"], [
    ["testFilters", "For one specific flow: permitted or denied, and the exact rule line "
                    "that decided it",
     "Compare it against what the policy says should happen; a mismatch becomes a finding"],
    ["searchFilters", "Example flows matching a condition, across the whole space of "
                      "possible traffic",
     "No rows is a proof that no such flow exists. One row is a counter-example"],
    ["filterLineReachability", "Rules that can never match, and the earlier rule shadowing them",
     "Report it as a tidiness problem and rate it low, because a dead rule cannot expose anything"],
    ["undefinedReferences", "Things the configuration mentions but never defines",
     "Report it directly. This is a silent failure risk"],
    ["traceroute", "The hop-by-hop path and whether the traffic arrived",
     "Used by the routing check and by the question-answering feature"],
], widths=[1.4, 2.3, 2.6])
p("The second row is the strongest thing in the project. searchFilters does "
  "not sample. It searches a space of flows and returns a counter-example if "
  "one exists, so an empty result is a proof that the rule holds. That is a "
  "much stronger statement than any number of spot checks.")

h("4.2  Key design decisions", 2)
table(["Decision", "Alternatives we considered", "What we chose, and why"], [
    ["Analysis engine", "Write our own parser and reachability model; Batfish; vendor tools",
     "Batfish. It proves properties across a whole space of traffic instead of "
     "sampling, it works with several vendors, and it runs offline. Writing our "
     "own in ten weeks would have produced a worse answer and much more code"],
    ["Where the language model runs", "A hosted API; a local model through Ollama",
     "Local. Requirement N-1 decided this, not preference. A hosted model means "
     "sending firewall configurations to a third party"],
    ["Web framework", "Flask; FastAPI",
     "FastAPI, for generated API documentation and for async, which the chat pane needs"],
    ["Policy file format", "A custom language; YAML; JSON",
     "JSON. A custom language would need its own tests and its own failure modes"],
    ["How we validate input", "A schema library; validate by hand",
     "By hand, failing loudly, next to a mechanism that already worked"],
], widths=[1.1, 1.7, 3.5])
figure("process-flow.png",
       "Figure 2. What happens when a user presses Scan Now. The two amber "
       "steps are the ones that can stop and say so.", width=4.4)

h("4.3  Ethical, legal and professional considerations", 2)
table(["Consideration", "What we did about it"], [
    ["Confidentiality of client data",
     "No configuration data leaves the machine. The client's file is inspected by "
     "a tool that reports structure only and never prints a value. Real "
     "configurations are excluded from version control; the ignore file was the "
     "first commit in the repository"],
    ["Not touching a live network",
     "Netwise only reads exported files. Proposed changes are simulated and never applied"],
    ["Honest claims about security",
     "A tool that reports a configuration clean when it could not analyse it is "
     "dangerous, not merely unhelpful. This is why the three-way status is part "
     "of the contract and not a convention"],
    ["Licensing", "Apache 2.0, for its patent grant and warranty disclaimer, and because it "
                  "matches the licence of the engine we drive"],
    ["Academic integrity",
     "AI assistance is declared in the repository NOTICE file, in README.md, and "
     "in each member's individual portfolio"],
], widths=[1.6, 4.7])

d.add_page_break()

# ================================================================ 5
h("5  Implementation and final deliverables", 1)

h("5.1  Implementation summary", 2)
p("The product is three layers. The analysis layer drives Batfish and turns "
  "its tables into findings. The explanation layer turns a finding into a "
  "sentence a person can read. The web layer takes the upload, runs the scan "
  "and shows the result.")
p("A check is one file with one function and one line in a registry. It does "
  "not connect to anything, does not load configuration files, and does not "
  "handle its own crashes; the shared pipeline does all three. If a check "
  "raises an error, the pipeline turns it into a visible finding, so a bug in "
  "one member's feature cannot take down another's.")
p("Two features deliberately do not fit that shape, and we did not force them. "
  "Risk scoring needs to see all the findings together, so it runs after the "
  "checks. Change impact needs two configurations to compare, and a check is "
  "only ever given one, so it is a separate entry point. Recognising that "
  "early is what stopped two features being bent to fit a contract that could "
  "not hold them.")

h("5.2  Final deliverables", 2)
table(["Deliverable", "Description", "Status", "Location"], [
    ["Analysis pipeline and five checks", "Access control, routing, policy compliance, "
     "risk scoring, plus change impact", "Complete", "analysis/"],
    ["AI explanation layer", "Local model that rewords one finding at a time, with a "
     "fixed-wording fallback", "Complete", "ai/explain.py"],
    ["Question answering", "A narrow set of plain-English questions, answered from real "
     "analysis output", "Complete", "ai/query.py, /api/ask"],
    ["Propose a change", "Writes a configuration change from English and simulates it",
     "Complete", "ai/propose.py, /api/propose"],
    ["Web dashboard", "Upload, scan, findings, filtering, chat and propose panes",
     "Complete", "web/"],
    ["PF Sense converter", "Translates the client's firewall format so it can be analysed",
     "Partial \u2014 refuses or skips what it cannot model exactly", "analysis/pfsense_convert.py"],
    ["Report export", "The findings as a self-contained HTML or CSV file", "Complete",
     "analysis/report.py, /api/report"],
    ["Test suite", "1,305 tests across 62 files", "Complete", "tests/"],
    ["Documentation", "User guide, contributor guide, the output contract, nine design "
     "notes, five sprint records", "Complete", "README.md, CONTRIBUTING.md, docs/"],
], widths=[1.5, 2.5, 1.0, 1.3])

h("5.3  Deployment and handover", 2)
p("Netwise runs on one machine. Installation is eight steps in README.md, and "
  "a script called preflight checks whether the machine is actually set up: "
  "Python and its packages, the container daemon, the analysis engine and the "
  "language model, each reported separately because they fail separately.")
p("Both optional pieces can be missing and the tool still works honestly. "
  "Without the language model, explanations become fixed wording and the "
  "screen says which one you are reading. Without the analysis engine nothing "
  "can be analysed, and the tool says that too.")
code("git clone <repository>\n"
     "pip install -r requirements.txt\n"
     "docker run -d --name batfish -p 9996:9996 -p 9997:9997 batfish/allinone\n"
     "ollama create netwise-warden -f ai/Modelfile      # optional\n"
     "python -m tools.preflight                        # check the machine\n"
     "uvicorn web.main:app --reload                    # then open the page")

d.add_page_break()

# ================================================================ 6
h("6  Evaluation of problems and technologies", 1)

h("6.1  The problems that shaped the project", 2)
p("Three, and the first is the one everything else follows from.")
p("A check that cannot run returns nothing, and nothing looks exactly like a "
  "clean result. Early on, a check that failed to run and a check that ran and "
  "found no problems were indistinguishable on screen. For a security tool "
  "that is not a small bug: it tells somebody they are safe when the truth is "
  "that nobody looked. We fixed it by making every finding state which of "
  "three things happened, and by testing that directly. The same confusion has "
  "since reappeared four times in different places, and each time the rule "
  "already existed to point at.")
p("The second is the client's firewall. It is PF Sense, which exports a format "
  "the engine cannot read, so we wrote a converter. The hard part was not "
  "translation but a real disagreement between the two systems: PF Sense "
  "normally applies the last matching rule, and a Cisco access list applies "
  "the first. The same rules in the same order can decide the same traffic "
  "differently. Where none of the rules use the setting that changes this "
  "(which is the client's whole rule set) we reverse the list, which gives "
  "provably the same answer for every packet. Where the two models genuinely "
  "disagree, the converter refuses.")
p("The third is putting a language model near a security tool. The risk is "
  "obvious: a model that invents a finding in a security report is worse than "
  "no report. Our answer is structural. The model is only ever handed a "
  "finding that already exists, and only ever asked to reword it. It is never "
  "called for a finding that could not be checked, so a card that says "
  "\u201cnothing is known\u201d can never acquire text that reads as though something "
  "was.")

h("6.2  Technology evaluation", 2)
table(["Technology", "Why it suited the project", "Limitations we hit"], [
    ["Batfish", "Proves properties across a space of traffic instead of sampling; "
                "works across vendors; runs offline",
     "It cannot read the client's PF Sense format at all, which is why we had to "
     "write a converter. First use in a session is slow while it warms up"],
    ["Ollama with a 3B model", "Runs locally, which requirement N-1 forced; small "
                               "enough to answer in a few seconds",
     "A small model is fine for rewording a verified finding and would not be "
     "enough for open-ended reasoning. We never ask it to reason"],
    ["FastAPI", "Generated API documentation, useful as review evidence; async for "
                "the chat pane", "None that affected us"],
    ["pytest", "Fast, and the whole suite runs without the engine or the model",
     "Three integration tests genuinely need the engine; they skip when it is absent"],
    ["GitHub Actions", "Runs the suite on two Python versions on every pull request",
     "It cannot block a merge on a private repository without a paid plan, so it "
     "is a signal and not a gate"],
], widths=[1.2, 2.5, 2.6])

d.add_page_break()

# ================================================================ 7
h("7  Testing, validation and quality assurance", 1)

h("7.1  How we tested", 2)
p("Three levels. Unit tests for individual functions. Integration tests that "
  "run the real analysis engine against test configuration files we wrote. And "
  "browser-level tests that load the real page in a small harness and check "
  "what a user would actually see.")
p("The standard the team settled on is that a reviewer re-runs the claim "
  "instead of reading the diff, and where there is a safety guard, deliberately "
  "breaks it and confirms a test fails. A passing test proves nothing until "
  "somebody has watched it fail for the right reason.")
p("That rule came from a real incident. One feature arrived with fifteen "
  "passing tests. When the exact bug it had been built to prevent was put back "
  "into the code, all fifteen still passed. The tests were checking that the "
  "code ran, not that it was right.")

h("7.2  Results", 2)
table(["Test / validation", "Requirement", "Expected", "Actual", "Outcome"], [
    ["Full automated suite", "All", "All pass", "1,305 passed, 8 skipped", "Pass"],
    ["Insecure test configuration", "R-2, R-8",
     "Problems found and explained", "5 problems, 1 could not check, 5 of 5 explained", "Pass"],
    ["Secure test configuration", "R-2",
     "No false alarms", "0 problems, 2 checked clean, 1 could not check", "Pass"],
    ["Unreadable configuration", "N-3", "Reported, never called clean",
     "Reported as could not check", "Pass"],
    ["Client's PF Sense export with a user policy", "R-11, R-12",
     "A real finding on his device", "PC-001, high, on pfsense-us5", "Pass"],
    ["Someone else's network (device renamed)", "R-12",
     "Honest reduction, no false clean", "6 findings drop to 3; the rest report "
     "could not check", "Pass, with a known gap"],
    ["Two users at once", "N-7", "Each sees only their own scan",
     "Verified live with two sessions; no leakage either way", "Pass"],
], widths=[1.6, 0.9, 1.3, 1.6, 0.9])

h("7.3  Quality assessment and limitations", 2)
p("What we are confident about: the tool does not report a configuration clean "
  "when it could not read it, and it has never done so in testing. Zero false "
  "alarms on the two clean configurations. Every merged change was reviewed by "
  "somebody other than its author.")
p("What we are not claiming is set out in the executive summary and "
  "measured in section 10.3: the five-of-five figure is about faults we "
  "planted ourselves, and nothing here shows Netwise would find an unknown "
  "one.")

d.add_page_break()

# ================================================================ 8
h("8  Team communication and sustainable productivity", 1)

h("8.1  How the team communicated", 2)
p("The main technical channel was the pull request. Design disagreements were "
  "argued there so they stay attached to the code they are about, and anyone "
  "can read the reasoning later. Chat was used for scheduling and quick "
  "questions and deliberately not for decisions.")
p("Written design notes came before solutions. There are nine of them, each "
  "stating a problem before anybody proposed an answer. Several were written "
  "by one member about a problem another member had spotted.")

h("8.2  Professional use of collaboration tools", 2)
p("The tools are configured deliberately and the configuration is itself "
  "tested. Three examples of the difference:")
bullets([
    "The linter is pinned to an exact version. An unpinned one gave 207 errors "
    "on one machine and none on another, and a linting step that is red on "
    "arrival teaches everybody to ignore it.",
    "CODEOWNERS routes each area of the code to its owner, and there is a test "
    "that fails if a rule points at a path that does not exist \u2014 because "
    "GitHub silently ignores such a rule, and it looks exactly like coverage.",
    "Continuous integration merges the current main branch before running, so "
    "a green tick answers \u201cdoes this pass against main as it is now\u201d and not "
    "\u201cdid it pass against main last week\u201d.",
])

h("8.3  Team effectiveness", 2)
table(["Member", "Commits", "Pull requests", "Reviews given"], [
    ["Arsh", "202", "110", "91"],
    ["Ankeet", "86", "36", "128"],
    ["Samika", "66", "27", "73"],
    ["Shubham", "30", "23", "83"],
], widths=[1.6, 1.4, 1.6, 1.7])
p("Commits exclude merge commits and the automated accounts. The distribution "
  "is uneven and we are not going to smooth it over. The thing worth noticing "
  "is that the member who wrote the most code did not do the most reviewing: "
  "Ankeet gave 128 reviews against Arsh's 91. On this project the reviews are "
  "where the real defects were caught, so that is arguably the more valuable "
  "half.")
p("Disagreement is in the repository with the reasoning attached. The merge "
  "rule that governs the whole team was rewritten by Shubham after Arsh "
  "drafted a weaker version. Ankeet asked for one rule to be made stricter "
  "than it had been drafted. Samika caught that a proposed fix covered only a "
  "minority of the cases it claimed to.")

d.add_page_break()

# ================================================================ 9
h("9  Challenges, risks and project changes", 1)

h("9.1  Major challenges", 2)
p("The biggest challenge was not technical. It was that almost every serious "
  "defect we found had the same shape: a weaker claim quietly standing in for "
  "a stronger one. \u201cNo findings\u201d standing in for \u201cwe checked\u201d. \u201cThe tests "
  "are green\u201d standing in for \u201cthe behaviour is protected\u201d. \u201cThe packages "
  "import\u201d standing in for \u201cthe versions match what we declared\u201d. None of "
  "those produce an error message. They just leave somebody believing "
  "something that is not true.")
p("Most of the project's effort went into making the machine answer questions "
  "we had previously been answering from memory: a script that checks the "
  "environment, a script that measures the policy gap, a generated traceability "
  "document instead of a hand-typed one.")
p("The second challenge was the client's file. It arrived in August, it was "
  "far larger and more complex than our test files, and it contained "
  "constructs we do not model. The converter did not produce a plausible and "
  "wrong result. It stopped and named what it could not handle, which we count "
  "as the strongest evidence in the project that refusing was the right "
  "default.")

h("9.2  Risk management", 2)
table(["Risk", "Likelihood", "Impact", "Response", "Final status"], [
    ["The AI invents a finding", "Med", "High",
     "Made structural: the model only receives real output and only rewords it. "
     "Never called for a finding that could not be checked", "Closed"],
    ["Configuration data leaves the machine", "Low", "High",
     "No cloud services; local model; real configs excluded from version "
     "control; a non-local model host is refused unless explicitly allowed", "Closed"],
    ["A check reports clean when it could not run", "High", "High",
     "Three-way status in the shared format, enforced in code and tested", "Closed"],
    ["The client's format cannot be read", "High", "High",
     "Wrote a converter; it refuses what it cannot model exactly", "Partly open \u2014 "
     "NAT and two interfaces still need client decisions"],
    ["A green test suite that protects nothing", "Med", "Med",
     "Reviews re-run the claim and break the guard to confirm a test fails", "Closed"],
    ["Documentation going stale", "High", "Med",
     "Measurements written with the date and commit they came from; generated "
     "documents where possible", "Open \u2014 managed, not solved"],
], widths=[1.5, 0.75, 0.7, 2.5, 0.85])

h("9.3  Scope and requirement changes", 2)
p("Two material changes. The client's export reordered the roadmap in August, "
  "as described in 1.3. And the user-policy feature was split: we had planned "
  "for all three checks to read a user policy in one piece of work, and "
  "delivered it for one check only, with the other two changed to say clearly "
  "that they had not read it. Section 10.3 measures what that costs.")


d.add_page_break()

# ================================================================ 10
h("10  Project outcomes and evaluation", 1)

h("10.1  Achievement against objectives", 2)
table(["Objective", "Success measure", "Final outcome", "Assessment"], [
    ["Analyse configurations offline", "Findings produced with no network access",
     "Six analysis features through one pipeline; 1,305 tests", "Achieved"],
    ["Explain findings in plain English", "Every problem carries an explanation",
     "All found problems explained; fixed wording when the model is absent, and "
     "the screen says which", "Achieved"],
    ["Answer plain-English questions", "A question gets a grounded answer or a reason",
     "Narrow set answered; everything else refused with a reason", "Achieved"],
    ["Propose and simulate a change", "A change is written and simulated, never applied",
     "Working, with a warning when a change opens traffic that was blocked", "Achieved"],
    ["Let the user state their own policy", "All three checks read the user's rules",
     "One check of three reads it; detections on somebody else's network go "
     "from 3 to 8", "Partly achieved"],
    ["Analyse the client's own firewall", "His export produces a real finding",
     "It does \u2014 PC-001 on pfsense-us5 \u2014 with a policy naming his device",
     "Partly achieved; NAT and two interfaces still need his decisions"],
], widths=[1.5, 1.5, 2.3, 1.0])

h("10.2  Client and stakeholder feedback", 2)
p("The client gave us requirements in person, an anonymised copy of his "
  "firewall, and correction when we were heading the wrong way. The export in "
  "particular changed the plan: measuring it told us none of his seven filter "
  "rules used the setting our converter assumed, which meant our model "
  "disagreed with his firewall wherever two rules overlapped. We fixed the "
  "model instead of shipping a converter that produced clean-looking output "
  "and wrong answers.")
p("Four questions are currently with him, and one of them blocks the other "
  "three: the WAN interface that carries rules has no fixed address, and a "
  "Cisco access list needs an address to attach rules to.")
action("signed client letter",
       "The template asks for a letter signed by the client indicating "
       "satisfaction. We do not have one. Ask Senaka for a short signed note "
       "confirming he gave us the requirements and the firewall export, and "
       "whether he is satisfied with what was delivered. Attach it as Appendix "
       "C. This is the only item in this report that cannot be reconstructed "
       "later, so it should be requested first.")

h("10.3  Project limitations", 2)
p("Two, stated plainly.")
p("The user policy only reaches one of three checks. Take a working "
  "configuration, rename the device, and change nothing else: findings drop "
  "from six to three. What survives is the two analyses that need no policy at "
  "all \u2014 dead rules and undefined references. Supplying a user policy takes "
  "policy-driven detections on somebody else's network from three to eight. "
  "The other two checks still use our example device names, and since August "
  "they say so on screen instead of staying quiet.")
p("Nothing has been verified against a production network. Every result in "
  "this report is from configuration files we wrote, or from one anonymised "
  "export.")

d.add_page_break()

# ================================================================ 11
h("11  Conclusion and recommendations", 1)

h("11.1  Conclusion", 2)
p("Netwise works end to end and does what it was built for. A user uploads a "
  "configuration, gets problems backed by evidence, reads them in plain "
  "English, asks follow-up questions, proposes a change and sees it simulated, "
  "and exports the result. All of it runs on one machine and none of it "
  "touches a live network.")
p("What we would defend is the set of refusals. Netwise refuses to convert a "
  "configuration it cannot model exactly, refuses to answer a question it "
  "cannot ground in real output, and refuses to call a check clean when that "
  "check could not run. Each refusal cost us a feature that would have "
  "demonstrated well and been wrong. A missing finding is a missed problem; a "
  "confidently wrong finding is a decision made on false information. For a "
  "security tool the first is a limitation and the second is a failure.")

h("11.2  Recommendations and future work", 2)
table(["Priority", "Work", "Why it matters"], [
    ["1", "Make access control and routing read a user-supplied policy",
     "Closes the gap measured in 10.3 and is worth more than anything else here. "
     "It turns Netwise from a tool that analyses our example network into one "
     "that analyses somebody else's"],
    ["2", "Finish the client's export: an address for the DHCP WAN, a decision "
          "on the two VPN interfaces, and a decision on NAT",
     "The client is waiting on these, and they are questions only he can answer"],
    ["3", "Keep findings between scans so a user can see what changed since last month",
     "Turns a one-off report into something worth running weekly"],
    ["4", "Add a published benchmark pack such as CIS for Cisco IOS",
     "Lets a user check against an industry standard and not only their own rules"],
], widths=[0.7, 2.6, 3.0])

# ================================================================ 12
h("12  References", 1)
p("APA 7th edition. Each entry notes what it was used for, because a reference "
  "list is only evidence if it says why the source mattered.")
for ref, why in [
    ("Apache Software Foundation. (2004). Apache license, version 2.0. "
     "https://www.apache.org/licenses/LICENSE-2.0",
     "Read before choosing our licence, for the patent grant and warranty disclaimer."),
    ("Astral Software. (2026). Ruff: An extremely fast Python linter and code "
     "formatter. https://docs.astral.sh/ruff/",
     "Rule selection, and pinning an exact version after an unpinned linter behaved "
     "differently on two machines."),
    ("Batfish. (2026). Batfish: Network configuration analysis. https://batfish.org/",
     "The engine this project drives. Used to understand what it does and what it does not."),
    ("Batfish. (2026). Pybatfish documentation. https://pybatfish.readthedocs.io/",
     "The reference for the five questions described in section 4.1."),
    ("Docker, Inc. (2026). Docker documentation. https://docs.docker.com/",
     "Container setup for the analysis engine, and the separation of the container "
     "from the service that preflight checks separately."),
    ("GitHub, Inc. (2026). About code owners. https://docs.github.com/en/repositories/"
     "managing-your-repositorys-settings-and-features/customizing-your-repository/"
     "about-code-owners",
     "Writing CODEOWNERS, and the source of the fact that an invalid path is silently "
     "ignored \u2014 which is why we test for it."),
    ("GitHub, Inc. (2026). GitHub Actions documentation. https://docs.github.com/en/actions",
     "The CI workflow, including making it merge current main before running."),
    ("Krekel, H., Oliveira, B., Pfannschmidt, R., Bruynooghe, F., Laugher, B., & "
     "Bruhin, F. (2026). Pytest documentation. https://docs.pytest.org/",
     "Fixtures, parametrisation and skip behaviour, which is why an absent engine "
     "skips instead of failing."),
    ("National Institute of Standards and Technology. (2020). Security and privacy "
     "controls for information systems and organizations (NIST SP 800-53 Rev. 5). "
     "https://doi.org/10.6028/NIST.SP.800-53r5",
     "Consulted for vocabulary around configuration control and least privilege when "
     "writing the policy rules."),
    ("Ollama. (2026). Ollama: Get up and running with large language models locally. "
     "https://ollama.com/",
     "Local model hosting, and the API behaviour the explanation layer degrades around "
     "when the model is absent."),
    ("Ramirez, S. (2026). FastAPI documentation. https://fastapi.tiangolo.com/",
     "Chosen over Flask; the generated API documentation is itself review evidence."),
    ("Schwaber, K., & Sutherland, J. (2020). The Scrum guide. "
     "https://scrumguides.org/scrum-guide.html",
     "The sprint structure and the split between review and retrospective."),
    ("The pandas development team. (2026). Pandas documentation. "
     "https://pandas.pydata.org/docs/",
     "Batfish answers arrive as data frames; this is how they are read before they "
     "become findings."),
]:
    par = d.add_paragraph()
    par.paragraph_format.left_indent = Inches(0.35)
    par.paragraph_format.first_line_indent = Inches(-0.35)
    par.add_run(ref)
    note = d.add_paragraph()
    note.paragraph_format.left_indent = Inches(0.35)
    r = note.add_run("Used for: " + why)
    r.font.size = Pt(9.5)
    r.font.italic = True
    r.font.color.rgb = RGBColor.from_string("5A6472")

d.add_page_break()

# ================================================================ APPENDICES
h("Appendices", 1)

h("Appendix A — How to reproduce every figure in this report", 2)
code("python -m tools.preflight                            # check the machine\n"
     "pytest tests/ -q                                     # 1,305 tests\n"
     "git log --no-merges --format='%aN' | sort | uniq -c  # commits per member\n"
     "gh pr list --state all --json author,reviews         # pull requests and reviews\n"
     "python -m tools.stranger_config                      # the gap in section 10.3\n"
     "python -m tools.make_diagrams                        # Figures 1 and 2\n"
     "python -m analysis.pipeline tests/fixtures/rtr-us5-insecure")
p("These commands report the repository as it is when you run them, not as "
  "it was at the commit named on the cover. The two move apart every time "
  "something merges, which is why the cover names a commit at all -- check "
  "out that commit first if you want the exact figures in this report.")
p("The test count depends on whether the analysis engine is running: 1,305 "
  "pass with it up, three fewer with it down. Those three are integration tests "
  "and they skip when the engine is absent, because they will not claim a "
  "result they could not verify.")

h("Appendix B — Screenshots", 2)
p("Three screenshots, taken from a real run on 7 September 2026 against the "
  "repository at commit 00243fb. Nothing here is mocked or staged: the "
  "dashboard and the report were produced by uploading a test configuration "
  "and pressing Scan Now, and the report image is of the file the download "
  "button actually produces.")

figure("1-dashboard-rtr-us5-insecure.png",
       "Screenshot 1. The dashboard after scanning a deliberately insecure test "
       "configuration. The three counts read 5 problems, 0 checked-clean and 1 "
       "could-not-check, and the amber card appears above the problems. The "
       "counts are shown separately and are never added together.", width=5.9)

figure("2-github-projects-board.png",
       "Screenshot 2. The GitHub Projects board, one column per state. This is "
       "the board the team worked from, with one milestone per sprint.", width=5.9)

figure("3-exported-report-could-not-check-first.png",
       "Screenshot 3. The exported HTML report, opened from the file the "
       "download button produces. \u201cCould not check\u201d is the first findings "
       "section, before problems found and before the clean results, and the "
       "clean section is present even though it is empty.", width=5.4)

p("The report header names the file as device.cfg although the upload was "
  "rtr-us5.cfg. That is deliberate: the upload never writes a user-supplied "
  "filename to disk, so a client string cannot reach the filesystem. The "
  "dashboard shows the name the user chose; the report names the file we "
  "staged.")
h("Appendix C — Client confirmation", 2)
action("client letter",
       "Empty until Senaka provides the signed note described in section 10.2. "
       "This is the single item in the report that cannot be produced later by "
       "anyone on the team.")

h("Appendix D — Acknowledgement of AI assistance", 2)
p("AI assistance was used on this project. It is declared here, in the "
  "repository NOTICE file and in README.md, in line with the university's "
  "academic integrity policy and the Responsible AI usage guidance for this "
  "course.")
p("It was used for drafting and editing prose, including parts of this report; "
  "for suggesting code and tests; and as a reviewer that questioned claims we "
  "had made. Every AI-assisted change went through the same branch, pull "
  "request and peer review process as any other, and was tested before it was "
  "merged.")
p("It was not used to make the engineering decisions this report describes. "
  "The output contract, the three-way status distinction, the choice to refuse "
  "instead of guess, and the amendments to our merge process were argued and "
  "agreed between the four of us, and each one is traceable to a signed record "
  "or a review thread in the repository. Feedback at our practice review on "
  "3 September noted that sections of our earlier documentation read as AI "
  "generated. That was a fair observation and this version has been rewritten.")

OUT.parent.mkdir(parents=True, exist_ok=True)
# `python -P` drops the script's own directory from sys.path -- that is
# exactly what it is for -- so a sibling import has to be explicit.
import sys as _sys, pathlib as _pl                          # noqa: E402
_sys.path.insert(0, str(_pl.Path(__file__).resolve().parent))
from _guard import refuse_if_edited                         # noqa: E402
import _guard                                               # noqa: E402
refuse_if_edited(OUT, _guard.blocks(d))
d.save(str(OUT))
print(f"wrote: {OUT.name}")
print(f"  paragraphs {len(d.paragraphs)}  tables {len(d.tables)}  "
      f"~{sum(len(x.text.split()) for x in d.paragraphs)} words (excl. tables)")
