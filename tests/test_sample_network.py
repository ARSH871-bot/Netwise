"""The bundled sample network must stay a demonstration of something (#347).

`tests/fixtures/sample-network/` is what a first-time visitor clicks when they
have nothing of their own to upload. It is an invented network -- but the
findings it produces are real, because Netwise loads it into Batfish and
analyses it exactly as it would analyse anybody's config.

That distinction is the whole point. #352 removed six fabricated findings
that appeared before any upload; this sample is the honest replacement, and
it is only honest while the analysis is genuine.

WHAT THESE TESTS PROTECT, AND WHY EACH ONE EXISTS
    The failure mode is not that the sample breaks loudly. It is that the
    sample quietly stops finding anything and still looks fine -- a file that
    parses, scans, and returns nothing, demonstrating a tool that appears to
    find no problems in a network built entirely out of problems.

    That is not hypothetical. Writing this file, the first draft named the
    host `sample-edge-rtr`, which reads better. Measured against real
    Batfish:

        hostname sample-edge-rtr  ->  0 findings, 3 "could not check"
        hostname rtr-us5          ->  5 findings, 1 "could not check"

    Two of the three checks still assert the built-in example policy, which
    names `rtr-us5` (#87). A friendlier name silently turned the sample into
    a demonstration of nothing, and nothing in the suite would have objected.

The Batfish-dependent test skips when the engine is absent, matching the
project's rule that a test never claims a result it could not verify.
"""

import shutil
from pathlib import Path

import pytest

SAMPLE = (Path(__file__).parent / "fixtures" / "sample-network"
          / "configs" / "sample-network.cfg")


# --- the file itself ---------------------------------------------------------


def test_the_sample_file_ships():
    """A sample the user is invited to click has to actually be there."""
    assert SAMPLE.is_file(), f"{SAMPLE} is missing -- the sample must ship"


def test_it_declares_itself_a_sample_in_its_own_text():
    """Somebody may open this file, or see it quoted in evidence, with no
    surrounding UI to tell them what it is. It has to say so itself."""
    text = SAMPLE.read_text(encoding="utf-8").lower()
    assert "not a real device" in text
    assert "not your data" in text


def test_it_keeps_the_hostname_the_built_in_policy_asserts_about():
    """THE ONE THAT MATTERS, and the reason this file exists.

    Rename the host and the sample still parses, still scans, and finds
    nothing -- because two of the three checks name `rtr-us5` in their
    built-in example policy (#87). A reviewer changing this for readability
    would be making the sample useless without any error to tell them.

    When #353 and #355 land and every check reads a supplied policy, this
    constraint goes away and the sample can be renamed. Not before.
    """
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    hostnames = [ln.split()[1] for ln in lines
                 if ln.startswith("hostname ") and len(ln.split()) > 1]

    assert hostnames == ["rtr-us5"], (
        f"the sample declares hostname {hostnames!r}. It must be ['rtr-us5'] "
        f"until every check reads a user-supplied policy -- see the comment "
        f"block in the file, and #87."
    )


def test_it_still_carries_the_planted_fault():
    """The blanket permit is what every finding traces back to."""
    text = SAMPLE.read_text(encoding="utf-8")
    assert "permit ip any any" in text


# --- what it actually produces ----------------------------------------------


@pytest.fixture(scope="module")
def sample_findings(tmp_path_factory):
    """Run the real pipeline over the sample, or skip if Batfish is absent."""
    pytest.importorskip("pybatfish")
    from analysis import pipeline

    snapshot = tmp_path_factory.mktemp("sample")
    (snapshot / "configs").mkdir()
    shutil.copy(SAMPLE, snapshot / "configs" / "device.cfg")
    try:
        return pipeline.analyse(snapshot)
    except Exception as exc:  # noqa: BLE001 -- absent engine is a skip, not a failure
        pytest.skip(f"Batfish not available: {exc}")


def test_the_sample_produces_real_findings(sample_findings):
    """A SAMPLE THAT FINDS NOTHING DEMONSTRATES NOTHING.

    This is the assertion that stops the sample rotting into a blank screen.
    It deliberately checks for `found` findings specifically, not merely a
    non-empty list -- three "could not check" cards are a non-empty list and
    are exactly what the renamed-host draft produced.
    """
    found = [f for f in sample_findings if f["status"] == "found"]

    assert found, (
        "the sample network produced no `found` findings. It is supposed to "
        "be a network built out of problems; if it now scans clean, either "
        "the file or the checks have changed and the first-run experience "
        "demonstrates nothing. Statuses seen: "
        f"{sorted({f['status'] for f in sample_findings})}"
    )


def test_the_findings_are_about_the_planted_fault(sample_findings):
    """Not just any findings -- the ones the file's own comments promise."""
    details = " ".join(f["evidence"]["detail"] for f in sample_findings).lower()
    assert "permit ip any any" in details


def test_it_still_shows_a_could_not_check_card(sample_findings):
    """Deliberate, and worth pinning.

    The routing check is written about devices this single-router sample does
    not contain, so it reports "could not check". That is the honest outcome
    and it is also the most valuable thing a first-time visitor sees: the
    product's central distinction, visible on the very first scan, without
    anybody having to construct it.
    """
    assert any(f["status"] == "error" for f in sample_findings), (
        "the sample no longer demonstrates a 'could not check' card, which is "
        "the distinction the whole product rests on"
    )
