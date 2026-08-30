"""Generate docs/traceability.md from the repository.

WHY THIS IS GENERATED AND NOT TYPED
    A traceability table is a promise that every requirement reaches code and
    every piece of code is proved by a test. A HAND-TYPED one makes that
    promise once, on the day it is written, and then quietly stops being
    true -- which is worse than not having one, because it looks like
    evidence.

    Every hand-typed number in this project has rotted at least once. Test
    counts, commit counts, PR counts, review counts, the line count, and a
    self-test's own baseline. The fix has been the same every time: read it
    rather than recall it.

    So the columns that CAN be derived are derived: which checks the pipeline
    actually registers (imported, not parsed), which Batfish questions each
    module actually calls, which fixtures exist, and which test files actually
    IMPORT each module (read from the AST, not matched as a word). The columns
    that cannot -- what the client asked for, which story it became -- are
    declared in one table below, where a stale entry is at least visible in
    one place instead of scattered through prose.

WHAT IT CANNOT DO
    It cannot tell you a test is a GOOD test. `tests/test_suite_hygiene.py`
    and mutation testing do that. This answers "is there a path from the
    requirement to something executable", which is a weaker and still useful
    question -- stated plainly rather than oversold.

RUN
    python -m tools.make_traceability      (either form works)
    python tools/make_traceability.py
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "traceability.md"

#: The only hand-maintained part: what somebody asked for, and where it came
#: from. Everything else on the row is looked up. Keep this short -- a long
#: declared table is a hand-typed table with extra steps.
REQUIREMENTS = [
    ("Find rules that expose an internal system", "US-9", "access_control"),
    ("Check the config against a written security policy", "US-17",
     "policy_compliance"),
    ("Check traffic actually reaches where it should", "US-11", "routing"),
    ("Say what a proposed change would actually do", "US-18", "change_impact"),
    ("Show the worst problems first", "US-19", "risk"),
    ("Explain a finding in plain English", "US-19", "explain"),
    ("Answer a plain-English question about the network", "US-11", "query"),
    ("Propose a config change from plain English, and push back",
     "US-13/US-14", "propose"),
    ("Read the client's PF Sense firewall", "US-6", "pfsense_convert"),
]

#: Where each feature lives. Checked to exist; a missing file is reported as
#: a gap rather than skipped.
MODULES = {
    "access_control": "analysis/checks/access_control.py",
    "policy_compliance": "analysis/checks/policy_compliance.py",
    "routing": "analysis/checks/routing.py",
    "change_impact": "analysis/change_impact.py",
    "risk": "analysis/checks/risk.py",
    "explain": "ai/explain.py",
    "query": "ai/query.py",
    "propose": "ai/propose.py",
    "pfsense_convert": "analysis/pfsense_convert.py",
}

BATFISH_QUESTIONS = [
    "testFilters", "searchFilters", "filterLineReachability",
    "undefinedReferences", "traceroute", "compareFilters",
    "differentialReachability",
]


def registries() -> tuple:
    """The real CHECKS and POST_PROCESSORS, IMPORTED rather than parsed.

    The first version of this regexed `pipeline.py` for the CHECKS block and
    reported `risk` as a registered check. It is not -- it is a
    POST_PROCESSOR, and the paragraph two lines below in the generated
    document said so, so the file contradicted itself on its first run.

    The regex was matching past the end of the dict. Importing cannot make
    that mistake: whatever the pipeline actually holds is what gets printed.
    Same principle as everywhere else here -- read the thing, not a
    description of it.
    """
    from analysis.pipeline import CHECKS, POST_PROCESSORS
    return sorted(CHECKS), sorted(POST_PROCESSORS)


def questions_used(path: Path) -> list:
    if not path.exists():
        return []
    src = path.read_text(encoding="utf-8")
    # Only count a real call, not a mention in prose.
    return [q for q in BATFISH_QUESTIONS if re.search(rf"\bq\.{q}\b", src)]


def imported_modules(tree: ast.Module) -> set:
    """Every module a file imports, fully qualified, read from its AST.

    Both spellings resolve to the same name, which is the whole point:

        from analysis.checks import access_control   -> analysis.checks.access_control
        from analysis.checks.access_control import run -> analysis.checks.access_control
        import analysis.checks.access_control          -> analysis.checks.access_control
    """
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
            for alias in node.names:
                mods.add(f"{node.module}.{alias.name}")
    return mods


def tests_for(dotted: str) -> tuple:
    """(test files that IMPORT this module, count that only mention its name).

    WHY THIS IS AN AST WALK AND NOT A WORD MATCH
        Two earlier versions were both wrong, in opposite directions, and
        both looked reasonable.

        Counting every test in any file CONTAINING the feature's name gave
        access_control "9 files, 201 tests" out of a suite of ~545. That is
        not a number about access_control; it is a number about how often
        the word appears.

        Tightening it to files whose NAME carries the feature then reported
        "no test file is named for this" for access_control, policy_compliance
        and risk -- all three of which are thoroughly tested, under topic
        names like `test_device_scoping.py` and `test_severity_rules.py`. An
        overstated gap is no better than an overstated number.

        An import is the real join: this test file reaches that module. It is
        exact, it is derived, and it cannot be fooled by the word turning up
        in a docstring. Files that merely mention the name are still counted,
        separately and without a test total, because a mention is weaker
        evidence and should not be dressed up as the same thing.
    """
    tail = dotted.rsplit(".", 1)[-1]
    importers, mentions = [], 0
    for path in sorted((REPO / "tests").glob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        try:
            mods = imported_modules(ast.parse(text))
        except SyntaxError:          # a test file that does not parse is a
            mods = set()             # bigger problem than this table's rows
        if dotted in mods:
            importers.append((path.name,
                              len(re.findall(r"^def (test_\w+)", text, re.M))))
        elif tail in text:
            mentions += 1
    return importers, mentions


def fixtures() -> list:
    root = REPO / "tests" / "fixtures"
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir())


def suite_total() -> str:
    r = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q",
                        "--collect-only"], cwd=str(REPO), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    ids = [ln for ln in (r.stdout or "").splitlines() if "::" in ln]
    return str(len(ids)) if ids else "could not collect"


def head() -> str:
    r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(REPO),
                       capture_output=True, text=True, encoding="utf-8")
    return (r.stdout or "").strip() or "unknown"


def build() -> str:
    checks, posts = registries()
    lines = []
    add = lines.append

    add("# Requirements traceability")
    add("")
    add("**Generated by `tools/make_traceability.py`. Do not edit by hand.**")
    add("")
    add(f"Measured at `{head()}`. Total tests collected: **{suite_total()}**.")
    add("")
    add("Read each row left to right: somebody asked for this → it became a")
    add("story → here is the code → here is what proves it. A row that cannot")
    add("be completed is work that was never really finished.")
    add("")
    add("This is generated because a hand-typed traceability table makes its")
    add("promise once and then quietly stops being true — which is worse than")
    add("not having one, because it still looks like evidence.")
    add("")
    add("**Read the last column precisely.** A file is listed when it")
    add("*imports* the module — a real join, read from the AST, not a word")
    add("match. The number beside it is how many tests **that file** holds,")
    add("not how many are about this feature: `test_device_scoping.py` imports")
    add("three checks and is counted under all three. It is an upper bound on")
    add("the evidence, and saying so is cheaper than pretending otherwise.")
    add("")
    add("**The last column and the total above it count different things,**")
    add("deliberately, and the column now says which so nobody has to work")
    add("it out by subtraction. The column counts `def test_` FUNCTIONS in")
    add("the file; the total counts what pytest actually COLLECTS, and")
    add("collection expands each parametrised function into one case per")
    add("parameter. So a file holding parametrised tests contributes more to")
    add("the total than its own column shows. Neither number is wrong, but")
    add("adding the column up will not reach the total, and a reader who")
    add("tries deserves to be told why rather than concluding the table is")
    add("broken. No worked example is given here on purpose: it would be a")
    add("hand-written number inside a generated file, which is the failure")
    add("this document exists to avoid.")
    add("")

    add("## The features")
    add("")
    add("| What was asked for | Story | Implemented in | Batfish questions "
        "used | Test files that import it (test functions in that file) |")
    add("|---|---|---|---|---|")
    for asked, story, feature in REQUIREMENTS:
        path_rel = MODULES.get(feature, "")
        path = REPO / path_rel if path_rel else None
        if path is None or not path.exists():
            add(f"| {asked} | {story} | **MISSING: {path_rel}** | — | — |")
            continue
        qs = questions_used(path)
        q_text = ", ".join(f"`{q}`" for q in qs) if qs else "*none — not a "\
            "Batfish feature*"
        dotted = path_rel[:-3].replace("/", ".")
        importers, mentions = tests_for(dotted)
        extra = f" (+{mentions} more mention it)" if mentions else ""
        if importers:
            files = "; ".join(f"`{n}` ({c})" for n, c in importers)
            t_text = f"{files}{extra}"
        elif mentions:
            t_text = (f"**no test imports this module** — {mentions} file(s) "
                      f"mention it, which is weaker")
        else:
            t_text = "**nothing in `tests/` reaches this module**"
        add(f"| {asked} | {story} | `{path_rel}` | {q_text} | {t_text} |")
    add("")

    add("## The three feature shapes, read from the registries themselves")
    add("")
    add("| Shape | Registered in | Features |")
    add("|---|---|---|")
    add(f"| Producer `run(bf)` | `CHECKS` | "
        f"{', '.join(f'`{c}`' for c in checks) or '*none*'} |")
    add(f"| Post-processor `refine(results)` | `POST_PROCESSORS` | "
        f"{', '.join(f'`{p}`' for p in posts) or '*none*'} |")
    add("| Separate entry point | *neither* | `change_impact` |")
    add("")
    add("`change_impact` is in **neither** registry on purpose: it needs two")
    add("snapshots, so it cannot satisfy `run(bf)`. See")
    add("`docs/design/pipeline-feature-shapes.md`, adopted by all four.")
    add("")

    add("## Fixtures the tests run against")
    add("")
    for name in fixtures():
        add(f"- `tests/fixtures/{name}`")
    add("")
    add("These are committed on purpose and are the single exception to the")
    add("no-configs-in-git rule: we invented them, so they describe nobody's")
    add("real network.")
    add("")

    add("## What this table does NOT prove")
    add("")
    add("That a test is a **good** test. A path from a requirement to")
    add("something executable is a weaker claim than \"this is verified\", and")
    add("conflating the two is the failure this project keeps finding.")
    add("")
    add("Test quality is checked elsewhere: `tests/test_suite_hygiene.py`")
    add("asserts every test file can fail, and every non-trivial safety guard")
    add("is mutation-tested — deliberately broken, with the suite confirmed to")
    add("die — under both Batfish states.")
    return "\n".join(lines) + "\n"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(REPO)}")

    text = OUT.read_text(encoding="utf-8")
    gaps = text.count("MISSING:") + text.count("**no")
    print(f"gaps reported in the table: {gaps}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
