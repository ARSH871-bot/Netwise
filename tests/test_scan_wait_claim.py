"""The scan-wait message must not promise a time we have measured it missing.

WHAT THIS PINS, AND WHY A NUMBER WAS THE PROBLEM
    `runScan()` told every user "this can take up to 15 seconds". Measured on
    #331, cold, through the real `GET /api/findings` on a CPU-only machine:

        rtr-us5-insecure, Ollama running   median 68.0s   (5 found findings)
        rtr-us5-messy, model not resident         163.9s  (6 found findings)
        rtr-us5-insecure, Ollama unreachable        7.4s
        multi-device-10 (largest fixture)           7.6s  (0 found findings)

    So the sentence was true only when the AI layer did no work, and false by
    4.5x to 11x in the configuration this project ships and demos. That is a
    false claim about our own behaviour, on the surface a user stares at while
    waiting, in a product whose whole premise is not overstating what it knows.

WHY THE TEST FORBIDS A NUMBER RATHER THAN CHECKING A BIGGER ONE
    The obvious fix is "up to 90 seconds". That would be false in the other
    direction on Arsh's machine, which has a dedicated GPU and measures about
    1s per finding -- and it would be false again the moment a config has
    twelve findings instead of five. The wait scales with the number of
    `found` findings and with whether the model is resident, and the server
    cannot know either before it starts.

    There is no honest fixed number, so the test asserts there is no number.
    A duration here would have to be re-measured on every machine and every
    config to stay true, which is the property that made the old one rot.

    `_attach_remediation` is deliberately not mentioned: 0.00s in all eleven
    measured runs. It is deterministic text with no model call.

Reads the source rather than driving the DOM, which is what the other
`app.js` assertions in this suite do. Nothing drives `runScan()` through a
harness today -- it issues a real fetch -- so a source assertion is the
honest level to pin a CLAIM at, as opposed to a rendering.
"""

import re
from pathlib import Path

import pytest

APP = Path(__file__).parent.parent / "web" / "static" / "app.js"


@pytest.fixture(scope="module")
def scan_message() -> str:
    """The string `runScan()` shows while the analysis is running."""
    source = APP.read_text(encoding="utf-8")

    start = source.index("async function runScan()")
    # Up to the `await loadFindings()` that replaces the message with results.
    end = source.index("await loadFindings()", start)
    body = source[start:end]

    # The notice is built by the `el("div", "notice loading", ...)` call, and
    # its text may be SEVERAL string literals concatenated with `+`. Join all
    # of them from that call to its closing paren.
    #
    # An earlier version of this fixture filtered the literals to the ones
    # containing "analys", which silently dropped the rest of a concatenated
    # sentence -- so a message that did mention the explanations looked as
    # though it did not. A fixture that sees only part of the claim cannot
    # test the claim.
    marker = body.index('"notice loading"')
    tail = body[marker + len('"notice loading"'):]
    literals = re.findall(r'"([^"]*)"', tail[: tail.index(");")])
    assert literals, (
        f"no message literals found after 'notice loading' in: {tail[:200]!r}"
    )
    return "".join(literals)


def test_the_waiting_message_promises_no_duration(scan_message):
    """THE ASSERTION THIS FILE EXISTS FOR.

    No digits, and no spelled-out number followed by a unit. "up to 15
    seconds" and "up to fifteen seconds" are the same promise and both are
    unkeepable, so neither spelling gets a free pass.
    """
    assert not re.search(r"\d", scan_message), (
        f"the scan-wait message contains a number: {scan_message!r}. The wait "
        f"scales with the count of `found` findings and with whether the model "
        f"is resident -- measured 7.4s to 163.9s on one machine (#331) -- so no "
        f"fixed duration is true. Say what is slow and in what order, not how long."
    )

    spelled = r"\b(one|two|three|four|five|six|seven|eight|nine|ten|fifteen|twenty|thirty|sixty)\b"
    numberish = re.search(spelled + r"\s*\W*\s*(second|seconds|minute|minutes)\b",
                          scan_message, re.IGNORECASE)
    assert numberish is None, (
        f"the message spells out a duration: {numberish.group(0)!r}. Writing "
        f"the number as a word does not make it measurable."
    )


def test_it_still_says_something_is_happening(scan_message):
    """The message's actual job, kept while the promise goes.

    #331's story is "I want to tell work from a hang". Removing the duration
    must not leave a sentence that fails to say work is underway.
    """
    assert "analys" in scan_message.lower(), (
        f"the message no longer says an analysis is running: {scan_message!r}"
    )


def test_it_names_the_explanations_as_the_slow_part(scan_message):
    """WHERE THE TIME ACTUALLY GOES, SINCE THE USER CANNOT SEE IT.

    89-96% of the wait is the explanation loop whenever the model runs, and
    `analyse()` is a steady 6-8s. A message that mentioned only "the checks"
    would be accurate about the fast 8% and silent about the slow 92%, which
    is how the old sentence came to be believed.
    """
    lowered = scan_message.lower()
    assert "explanation" in lowered or "explanations" in lowered, (
        f"the message does not mention the explanations: {scan_message!r}. They "
        f"are 89-96% of the wait when the model runs (#331); naming only the "
        f"checks would describe the fast part and omit the slow one."
    )


def test_it_says_the_first_time_is_slowest(scan_message):
    """The 2.6 GB model load, which is the worst single case a user meets.

    Measured: 163.9s with the model not resident against 73.4s warm, same
    config. A user whose first scan of the day takes three times as long as
    their second should be told that is expected, not left to conclude it
    broke and then recovered.
    """
    lowered = scan_message.lower()
    assert "first" in lowered, (
        f"the message does not say the first run is slowest: {scan_message!r}. "
        f"Cold 163.9s against warm 73.4s on the same config (#331)."
    )
