"""Exercise the real system end to end against real fixtures, and say which
layer broke if one did.

WHY THIS EXISTS, AND WHY IT IS NOT tools/preflight.py
    preflight answers "is this machine set up to run Netwise" -- ports open,
    packages installed, a container present. It never calls the pipeline, so
    it cannot tell you the pipeline still does the right thing.

    This answers a different question: "given a working environment, does
    Netwise still behave correctly end to end" -- Batfish connects, a known
    check produces the SPECIFIC findings it should on a fixture with a known
    answer, the AI explanation layer never raises, and the AI query layer
    both answers a real question and refuses a nonsense one. `tools/` had
    exactly three scripts before this one, and none of them touched a live
    service end to end -- this is the manually-triggered live check the
    workflow comment left room for and nobody had built.

WHAT THIS IS NOT, AND WHY THE NAME CHANGED FROM THE OBVIOUS ONE
    There was an `analysis/smoke_test.py`, deleted in #146. It called Batfish
    and printed the raw result, with no found/none/error distinction at all --
    so anyone running it got output that LOOKED authoritative and carried
    none of F-1's guarantees. That is the one thing this file must never
    become: **it must never print a Batfish result as if it were a finding.**
    Its own pass/fail is the entire point; the moment it starts describing
    network behaviour in its own words, in its own English, it is the thing
    that got removed. Named `live_check.py` rather than reusing
    `smoke_test.py`, so a `git log` on the old name still tells the truth
    about what happened to it instead of looking like a rename.

    So every check below asserts against KNOWN, MEASURED expectations on the
    project's own fixtures (tests/fixtures/rtr-us5-insecure,
    tests/fixtures/rtr-us5-secure) -- ids and statuses, not prose about what
    the network does. A mismatch is reported as "expected AC-001 found, got
    X", never as a sentence describing the flow.

WHY EACH FAILURE NAMES ITS OWN LAYER
    "The system is broken" sends the next person to check everything. Naming
    the layer -- the same discipline preflight uses to separate the Docker
    daemon from the container from the service -- sends them to check one
    thing. A Batfish connection failure and a regression in `access_control`
    look identical from outside ("the analysis is wrong") and need entirely
    different fixes.

RUN
    python -m tools.live_check       (either form works)
    python tools/live_check.py

EXIT CODE
    0 if every layer behaved as measured, 1 otherwise, naming which layer.
    Never touches a live network -- both fixtures are synthetic, committed,
    and already used by the test suite (see CLAUDE.md §7b).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# RUN AS A SCRIPT, NOT ONLY AS A MODULE -- see tools/preflight.py and #176.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: (label, status, detail). status is PASS or FAIL -- deliberately not
#: OK/MISSING/BROKEN (preflight's vocabulary) or found/none/error (F-1's).
#: This tool answers one question, "did it behave as measured", and reusing
#: either existing vocabulary here would invite exactly the confusion this
#: file exists to prevent -- a live_check FAIL is not an F-1 error finding.
Result = Tuple[str, str, str]

PASS, FAIL = "PASS", "FAIL"

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
INSECURE = FIXTURES / "rtr-us5-insecure"
SECURE = FIXTURES / "rtr-us5-secure"

# Measured directly against the real fixtures, not assumed. Re-measure with:
#   python -c "from analysis import pipeline as p; import collections
#   r = p.analyse('tests/fixtures/rtr-us5-insecure')
#   print({f['status']: sorted(x['id'] for x in r if x['status']==f['status'])
#          for f in r})"
EXPECTED_INSECURE = {
    "found": ["AC-001", "AC-002", "PC-001", "PC-002", "PC-003"],
    "error": ["RT-050"],
}
EXPECTED_SECURE = {
    "none": ["AC-000", "PC-000"],
    "error": ["RT-050"],
}


def _by_status(results: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    grouped: Dict[str, List[str]] = {}
    for finding in results:
        grouped.setdefault(finding["status"], []).append(finding["id"])
    for ids in grouped.values():
        ids.sort()
    return grouped


# ---------------------------------------------------------------------------
# Individual checks. Each returns (label, status, detail) and never raises --
# a broken layer is reported, not propagated, so one bad layer does not stop
# the rest of the sweep from telling you about the others.
# ---------------------------------------------------------------------------


def check_batfish_connection() -> Result:
    """Layer 1: can we connect and load a real snapshot at all."""
    try:
        from analysis.pipeline import connect, load_snapshot

        bf = connect("localhost")
        load_snapshot(bf, SECURE, "netwise", "live-check")
    except Exception as error:  # noqa: BLE001 -- report anything, never raise
        return (
            "Batfish connection",
            FAIL,
            f"could not connect or load a snapshot: "
            f"{type(error).__name__}: {str(error)[:150]}. Run "
            f"`python -m tools.preflight` first -- this checks BEHAVIOUR, "
            f"not readiness.",
        )
    return ("Batfish connection", PASS, "connected, snapshot loaded")


def check_pipeline_on_a_violating_fixture() -> Result:
    """Layer 2a: the checks find what this fixture is KNOWN to contain.

    Not "did it run without raising" -- that would pass on a pipeline that
    silently returns nothing. Asserts the exact ids and statuses measured
    directly against this fixture, so a regression that makes access_control
    stop finding a real violation fails HERE, specifically, rather than
    surfacing as "the dashboard looks empty" three layers away.
    """
    try:
        from analysis import pipeline

        results = pipeline.analyse(str(INSECURE))
    except Exception as error:  # noqa: BLE001
        return (
            "Pipeline (violating fixture)",
            FAIL,
            f"analyse() raised, which it must not: "
            f"{type(error).__name__}: {str(error)[:150]}",
        )

    actual = _by_status(results)
    if actual == EXPECTED_INSECURE:
        return (
            "Pipeline (violating fixture)",
            PASS,
            f"{sum(len(v) for v in actual.values())} findings, "
            f"matches the measured shape exactly",
        )
    return (
        "Pipeline (violating fixture)",
        FAIL,
        f"expected {EXPECTED_INSECURE}, got {actual}. A check that should "
        f"have found something did not, or found something different.",
    )


def check_pipeline_on_a_clean_fixture() -> Result:
    """Layer 2b: the checks stay quiet on a fixture KNOWN to be clean.

    The other direction of the same guarantee -- a check that always reports
    a violation, regardless of the config, would pass 2a and fail silently
    here, which is why both fixtures are checked rather than one.
    """
    try:
        from analysis import pipeline

        results = pipeline.analyse(str(SECURE))
    except Exception as error:  # noqa: BLE001
        return (
            "Pipeline (clean fixture)",
            FAIL,
            f"analyse() raised, which it must not: "
            f"{type(error).__name__}: {str(error)[:150]}",
        )

    actual = _by_status(results)
    if actual == EXPECTED_SECURE:
        return (
            "Pipeline (clean fixture)",
            PASS,
            f"{sum(len(v) for v in actual.values())} findings, "
            f"matches the measured shape exactly",
        )
    return (
        "Pipeline (clean fixture)",
        FAIL,
        f"expected {EXPECTED_SECURE}, got {actual}. A check that should "
        f"have stayed quiet reported something, or vice versa.",
    )


def check_explanation_layer() -> Result:
    """Layer 3: explain_with_source() never raises, on a real found finding.

    Deliberately does NOT assert model vs. fallback -- #52 makes both
    correct, and which one you get depends on whether Ollama is running,
    which is preflight's question, not this one. What is asserted is the
    CONTRACT: a non-empty string, a source of "model" or "fallback", no
    exception either way.

    THE PRECONDITION IS NOT THE THING UNDER TEST -- found live, by Arsh,
    reviewing this PR.
        The old version wrapped `pipeline.analyse()`, finding a "found"
        result, and `explain_with_source()` in one try, so a stopped
        Batfish container reported as "explain_with_source() raised,
        which #52 exists to prevent" -- explain_with_source() was never
        even called. `analyse()` failed to produce a found finding, and
        the message blamed the wrong layer for it. Reproduced live before
        fixing: with Batfish down, this used to say `StopIteration`, which
        is `next()` finding no found finding, not the AI layer failing.
        Splitting the precondition from the assertion is the same fix
        `check_batfish_connection()` already exists to make unnecessary
        for every OTHER check in this file -- this one just hadn't gotten
        it applied to its own body.
    """
    from analysis import pipeline

    results = pipeline.analyse(str(INSECURE))
    found = next((f for f in results if f["status"] == "found"), None)
    if found is None:
        return (
            "AI explanation layer",
            FAIL,
            "could not obtain a found finding to explain -- the pipeline "
            "returned only " + ", ".join(sorted({f["status"] for f in results}))
            + ". This says nothing about the AI layer, which was never "
            "reached.",
        )

    try:
        from ai.explain import explain_with_source

        text, source = explain_with_source(found)
    except Exception as error:  # noqa: BLE001
        return (
            "AI explanation layer",
            FAIL,
            f"explain_with_source() raised, which #52 exists to prevent: "
            f"{type(error).__name__}: {str(error)[:150]}",
        )

    if not text or source not in ("model", "fallback"):
        return (
            "AI explanation layer",
            FAIL,
            f"returned an invalid shape: text={text!r}, source={source!r}",
        )
    return (
        "AI explanation layer",
        PASS,
        f"produced a {source} explanation without raising",
    )


def check_query_layer() -> Result:
    """Layer 4: the AI query layer answers a real question and refuses a
    nonsense one -- both halves, since a layer that always refuses would
    pass a check that only tried the refusal case, and one that always
    answers would pass a check that only tried the real question.

    THE PRECONDITION IS NOT THE THING UNDER TEST -- the same shape Arsh
    found in check_explanation_layer() above, flagged as unverified here
    and reproduced live before fixing. With Batfish down, `connect()`
    raised, and the message said "answer_question() raised, which it
    must not" -- answer_question() was never called. connect() and
    load_snapshot() are the precondition; only the two answer_question()
    calls are the thing this check is actually about.
    """
    from analysis.pipeline import connect, load_snapshot

    try:
        bf = connect("localhost")
        load_snapshot(bf, SECURE, "netwise", "live-check")
    except Exception as error:  # noqa: BLE001
        return (
            "AI query layer",
            FAIL,
            f"could not connect or load the snapshot -- this says "
            f"nothing about the query layer, which was never reached: "
            f"{type(error).__name__}: {str(error)[:150]}",
        )

    try:
        from ai.query import answer_question

        answerable = answer_question(
            "can rtr-us5 reach 10.20.0.5 on tcp/443", bf
        )
        refused = answer_question("block youtube", bf)
    except Exception as error:  # noqa: BLE001
        return (
            "AI query layer",
            FAIL,
            f"answer_question() raised, which it must not: "
            f"{type(error).__name__}: {str(error)[:150]}",
        )

    problems = []
    if answerable.get("grounded") is not True:
        problems.append("a well-formed question was not grounded")
    if not answerable.get("question_understood"):
        problems.append("a well-formed question echoed no understood text")
    if refused.get("grounded") is not False:
        problems.append("a nonsense question was not refused")

    if problems:
        return ("AI query layer", FAIL, "; ".join(problems))
    return (
        "AI query layer",
        PASS,
        "answered a real question and refused a nonsense one",
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

CHECKS = [
    check_batfish_connection,
    check_pipeline_on_a_violating_fixture,
    check_pipeline_on_a_clean_fixture,
    check_explanation_layer,
    check_query_layer,
]

_SYMBOL = {PASS: " PASS ", FAIL: " FAIL "}


def run() -> int:
    print("Netwise live check")
    print("=" * 72)

    results: List[Result] = []
    for check in CHECKS:
        result = check()
        results.append(result)
        label, status, detail = result
        print(f"[{_SYMBOL[status]}] {label}")
        print(f"          {detail}")

    print("=" * 72)

    failed = [label for label, status, _ in results if status == FAIL]
    if failed:
        print(f"FAILED -- {len(failed)} layer(s) did not behave as "
              f"measured: {', '.join(failed)}")
        return 1

    print("PASSED -- every layer behaved exactly as measured.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
