"""The scan-wait message is pinned to one agreed sentence (#331, #388).

WHAT THE PIN DOES
    The message is compared to one constant. Changing MESSAGE is a deliberate
    edit to this test, and the new wording is a claim to be justified in
    review -- which puts the claim in the diff instead of letting it drift.

    The pushed version of this file (`a0fba41`) described what the message
    may not say, and was beaten three times on #388: "up to ninety seconds"
    (@patelankeet2), "a couple of minutes" and `"up to " + 15 + " seconds"`
    (@ARSH871-bot, where the number was in the source and the fixture joined
    only the quoted literals). An inverted sentence passed every one of its
    checks as well.

    A wider rule-based version was then tried locally and never pushed. It
    caught all four of those and still missed "Hang tight, nearly there" and
    "Give it a bit" -- ordinary phrasings with no digit, no time unit and no
    listed word. Rules of that kind cannot enumerate English, which is why
    the guard below is an exact comparison and a digit check, and nothing
    else.

WHAT IT CANNOT PROVE
    That the sentence is TRUE. Truth depends on the machine, on whether
    Ollama is running, on whether Batfish is warm, and on how many problems
    the config has -- measured on #331 at 7.4s to 163.9s on one machine. No
    assertion over a string reaches any of that. This file stops a claim
    drifting in unnoticed; it cannot verify one.

    NOT MEASURED BY US: the cold-container case. US-39's text says ~22s of
    warm-up (`tools/make_phase3_backlog.py:286`) and the docs say "a few
    minutes" (`CONTRIBUTING.md:187`), and every run behind the #331 figures
    used a container that had been up for days.

"STAGED CONFIG", NOT "UPLOAD"
    `runScan()` is the only place that renders this (`app.js:925`), and it is
    reached after the bundled sample is loaded too -- that loader enables
    Scan Now (`app.js:2042`) and the user clicks the same button. Nothing was
    uploaded on that path.
"""

import re
from pathlib import Path

import pytest

APP = Path(__file__).parent.parent / "web" / "static" / "app.js"

#: The agreed wording. See the docstring: editing this is editing the test.
MESSAGE = (
    "Analysing the staged config. "
    "The results will appear here when the scan has finished."
)


@pytest.fixture(scope="module")
def scan_call() -> str:
    """The RAW source of the notice call, not just its string literals.

    Raw on purpose. A previous fixture returned `"".join(literals)`, so
    `"up to " + 15 + " seconds"` arrived as `up to  seconds` and passed every
    check -- the number was in the source and invisible to the test.
    """
    source = APP.read_text(encoding="utf-8")
    start = source.index("async function runScan()")
    end = source.index("await loadFindings()", start)
    body = source[start:end]

    marker = body.index('"notice loading"')
    tail = body[marker + len('"notice loading"'):]
    call = tail[: tail.index(");")]
    assert call.strip(), f"no notice call text found in: {tail[:200]!r}"
    return call


@pytest.fixture(scope="module")
def scan_message(scan_call) -> str:
    """Just the words a user reads."""
    return "".join(re.findall(r'"([^"]*)"', scan_call))


def test_the_message_is_exactly_the_agreed_sentence(scan_message):
    """THE GUARD. The other two are a backstop.

    A failure is not necessarily a bug -- it means the wording changed. If
    that was deliberate, update MESSAGE in the same commit and say in the PR
    what the new sentence claims and on what evidence.
    """
    assert scan_message == MESSAGE, (
        f"the scan-wait message changed.\n"
        f"  expected: {MESSAGE!r}\n"
        f"  found:    {scan_message!r}\n"
        f"Any wording here is a claim about our own behaviour. Measured on "
        f"#331: 7.4s to 163.9s on one machine depending on Ollama and the "
        f"config. If this change is deliberate, edit MESSAGE and justify the "
        f"new sentence in review."
    )


def test_the_message_contains_no_digit(scan_call):
    """Backstop, read from the RAW call so concatenation cannot hide one.

    Structural rather than a word list: this is the one check that sees
    `"up to " + SCAN_SECONDS + " seconds"`, where the number never appears
    in a string literal at all.
    """
    found = re.findall(r"\d", scan_call)
    assert not found, (
        f"the message's source contains digits {found}. No fixed number is "
        f"true: the wait depends on the machine, on Ollama, on whether "
        f"Batfish is warm, and on how many problems the config has (#331)."
    )


def test_it_still_says_an_analysis_is_running(scan_message):
    """The message's only job: #331's story is telling work from a hang."""
    assert "analys" in scan_message.lower(), (
        f"the message no longer says an analysis is running: {scan_message!r}"
    )
