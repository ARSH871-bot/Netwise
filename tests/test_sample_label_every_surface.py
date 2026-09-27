"""The sample label reaches every surface, or the claim is not being made (#308).

THE RULE THIS FILE ENFORCES
    #308: a statement about what the data *is* must appear on every surface
    that shows the data, or on none. Not most. Not the ones somebody thought
    of.

WHY IT NEEDED ITS OWN FILE, MEASURED RATHER THAN ASSUMED
    The first version of #347 labelled the sample on two surfaces out of
    three and shipped CI-green. @ARSH871-bot found both gaps by running the
    branch instead of reading it:

        dashboard after a reload   no label   (the banner was set by the
                                              click handler, and a reload
                                              is not a click)
        HTML export                labelled
        CSV export                 no label   (render_csv took no subject)

    Neither miss was a wrong claim. Both were a true claim that reached
    some surfaces, which is the failure mode #308 exists for and the one
    that survives review most easily -- every surface anybody checked was
    correct.

    Nothing in the suite objected, and the reason is worth keeping: the
    report tests requested `format=html` only, and no test exercised a
    reload. `grep -ci csv` was 0 across all four of the feature's test
    files. Each surface was covered by somebody's test; the PROPERTY THAT
    THEY AGREE was covered by nobody's.

SO THIS FILE ASSERTS THE AGREEMENT, NOT THE SURFACES
    Three surfaces, one test each for presence, and then -- the part that
    actually encodes #308 -- one test that they must agree, written so it
    fails if ANY of them disagrees with the others. That last one is the
    only assertion here that would survive somebody adding a fourth surface
    and forgetting it, provided they add it to SURFACES.

Needs neither Batfish nor Ollama: the pipeline is stubbed, per N-6. What is
being tested is the LABEL, not the analysis.
"""

import csv
import io

import pytest
from fastapi.testclient import TestClient

from web import main

LABEL = "SAMPLE NETWORK"


@pytest.fixture
def analysed(monkeypatch):
    """Analyse without Batfish -- the same stub tests/test_sample_endpoint.py
    uses, for the same reason: every assertion here is about the label, and
    none of them reads a finding's content."""

    def fake_analyse(snapshot_dir, snapshot_name=None, **kwargs):
        return [{
            "id": "AC-001", "check": "access_control", "severity": "high",
            "device": "rtr-us5", "summary": "stub finding",
            "evidence": {"detail": "stub", "source": "stub"}, "status": "found",
        }]

    monkeypatch.setattr(main.analysis_pipeline, "analyse", fake_analyse)
    monkeypatch.setattr(main, "_attach_explanations", lambda results: results)
    main.reset_analysis_cache()


@pytest.fixture
def client():
    return TestClient(main.app)


# --- the three surfaces, each read the way a user would reach it --------------


def _dashboard_says_sample(client) -> bool:
    """What a BOOTING page can discover, not what a click left behind.

    This is the reload case. The browser has just loaded index.html and has
    no memory of any click; the only thing it can do is ask. If this returns
    False the banner cannot be shown, however good the click handler is.
    """
    return client.get("/api/sample").json()["is_sample"] is True


def _html_says_sample(client) -> bool:
    return LABEL in client.get("/api/report?format=html").text


def _csv_says_sample(client) -> bool:
    """Parsed as CSV, not searched as a string.

    A substring search would also pass if the label leaked into a summary or
    a detail cell, which is not the same claim at all -- and would pass over
    a preamble line above the header, which breaks real CSV readers. This
    asserts the label is in the structured data a spreadsheet would show.
    """
    rows = list(csv.DictReader(io.StringIO(client.get("/api/report?format=csv").text)))
    return bool(rows) and all(LABEL in (row.get("report_subject") or "")
                              for row in rows)


SURFACES = {
    "dashboard on load": _dashboard_says_sample,
    "HTML export": _html_says_sample,
    "CSV export": _csv_says_sample,
}


# --- presence -----------------------------------------------------------------


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_each_surface_carries_the_label_for_a_sample_session(
    client, analysed, surface
):
    """One per surface, named, so a failure says WHICH one lost the label."""
    client.post("/api/sample")
    client.get("/api/findings")

    assert SURFACES[surface](client), (
        f"a sample session is not labelled on the {surface!r} surface. "
        f"Every surface that shows the data must carry the claim (#308) -- "
        f"the findings are real analysis of an invented network, so nothing "
        f"in the results themselves would raise a doubt."
    )


# --- agreement, which is the actual rule --------------------------------------


def test_the_three_surfaces_agree_for_a_sample_session(client, analysed):
    """THE ASSERTION THIS FILE EXISTS FOR.

    Not "each is labelled" -- that is the three tests above, and all three
    passed on a branch where two surfaces were unlabelled, because each of
    them only existed for the surface its author was thinking about.

    This one compares them to each other. It fails if any surface disagrees
    with any other, in EITHER direction, which is what makes it survive a
    future change that labels a new surface and forgets an old one.
    """
    client.post("/api/sample")
    client.get("/api/findings")

    verdicts = {name: probe(client) for name, probe in SURFACES.items()}

    assert len(set(verdicts.values())) == 1, (
        f"the surfaces disagree about whether this is sample data: "
        f"{verdicts}. A claim about what the data is must appear on every "
        f"surface that shows the data, or on none (#308)."
    )
    assert all(verdicts.values()), verdicts


def test_the_three_surfaces_agree_for_a_real_upload(client, analysed):
    """THE OTHER DIRECTION, AND IT IS NOT REDUNDANT.

    A label stuck ON after a real upload is worse than one missing from a
    sample: it invites somebody to disregard true findings about their own
    network as demonstration data. Same rule, opposite failure, and a test
    that only ever checked the sample case would not see it.
    """
    client.post("/api/sample")
    client.post(
        "/api/upload",
        files={"file": ("mine.cfg", b"!\nhostname rtr-mine\n!\n", "text/plain")},
    )
    client.get("/api/findings")

    verdicts = {name: probe(client) for name, probe in SURFACES.items()}

    assert not any(verdicts.values()), (
        f"a real upload is still labelled as sample data somewhere: "
        f"{verdicts}. This is the mislabel running in the reassuring "
        f"direction, and it invites a user to ignore true findings."
    )


# --- the boot path specifically -----------------------------------------------


def test_the_label_survives_a_reload(client, analysed):
    """The gap that started this file, reproduced as a test.

    A reload is exactly this: the findings are still served from the staged
    snapshot, and the page has to ask again what it is looking at. Before
    the fix the findings came back and nothing could tell the browser they
    described an invented network.
    """
    client.post("/api/sample")
    first = client.get("/api/findings").json()

    # A "reload": no click, no state in the page, just the boot requests.
    again = client.get("/api/findings").json()
    assert again == first, "the findings did not survive -- wrong premise"

    assert client.get("/api/sample").json()["is_sample"] is True, (
        "after a reload the findings are still there and the page can no "
        "longer discover that they describe the sample network"
    )


def test_a_session_that_never_loaded_the_sample_is_not_labelled(client):
    """The default has to be the claim that says LESS."""
    assert client.get("/api/sample").json()["is_sample"] is False
