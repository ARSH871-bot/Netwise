"""The mock data is product code, and it had no test.

WHY THIS FILE EXISTS
    `web/mock_findings.py` is served by `/api/findings` until the first upload,
    so it is **the first thing every user sees**. It is imported by
    `web/main.py`, it is 156 lines, and nothing imported it in `tests/`.

    Found by auditing which product modules no test touches. It was one of
    three; the other two turned out to be superseded scripts and were removed
    in the same change.

WHY "IT LOOKS FINE" IS NOT ENOUGH
    It IS valid F-1 today, checked by hand. But it has already drifted once
    without anyone noticing: amendment A-2 (#102) gave `change_impact` the
    `CH-` prefix, and this file's ids changed from `PC-000` to `CH-000`
    silently, because it builds them through `findings.PREFIX_BY_CHECK` rather
    than hard-coding them.

    That drift happened to leave it valid. Nothing guaranteed it would. A
    future prefix change, a renamed check, or a hand-edited id would be caught
    by no test at all, and the failure would appear on a user's screen rather
    than in CI.

    "The mock data looks right" is a weaker claim than "the mock data is
    validated", and this project has a long history of the first standing in
    for the second.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis import findings
from analysis.pipeline import duplicate_id_findings
from web.mock_findings import get_mock_findings

F1_FIELDS = {"id", "check", "severity", "device", "summary", "evidence", "status"}


@pytest.fixture(scope="module")
def mocks():
    return get_mock_findings()


def test_there_is_actually_mock_data(mocks):
    """Guards this whole file being vacuously green: every test below iterates,
    and an empty list would pass all of them while checking nothing."""
    assert mocks, "get_mock_findings() returned nothing"
    assert len(mocks) >= 3, f"only {len(mocks)} mock findings; the dashboard shows sections"


def test_every_mock_finding_has_exactly_the_f1_fields(mocks):
    """Not a subset and not a superset. An extra key would be a contract change
    arriving through the back door -- `explanation` is deliberately added
    downstream in `web/main.py`, never here."""
    for m in mocks:
        assert set(m) == F1_FIELDS, (
            f"{m.get('id', '?')} has fields {sorted(set(m) ^ F1_FIELDS)} "
            "that differ from F-1"
        )
        assert set(m["evidence"]) == {"detail", "source"}


def test_every_mock_finding_uses_the_real_vocabulary(mocks):
    """`status`, `check` and `severity` must be values the rest of the system
    recognises -- not plausible-looking strings that only exist here."""
    for m in mocks:
        assert m["status"] in findings.VALID_STATUSES, f"{m['id']}: {m['status']!r}"
        assert m["check"] in findings.VALID_CHECKS, f"{m['id']}: {m['check']!r}"
        assert m["severity"] in findings.VALID_SEVERITIES, f"{m['id']}: {m['severity']!r}"


def test_every_mock_id_matches_its_check_prefix(mocks):
    """The drift that already happened, now pinned.

    A-2 moved `change_impact` from `PC-` to `CH-`. These ids followed
    automatically because they are built from `PREFIX_BY_CHECK` -- but nothing
    verified that they did, and a hand-edited id would not have.
    """
    for m in mocks:
        expected = findings.PREFIX_BY_CHECK[m["check"]]
        assert m["id"].startswith(f"{expected}-"), (
            f"{m['id']} is served for check {m['check']!r}, whose prefix is "
            f"{expected!r}. Either the id or PREFIX_BY_CHECK is wrong."
        )


def test_the_mock_data_shows_all_three_statuses(mocks):
    """The point of mock data is to demonstrate the interface before a user has
    uploaded anything. If it only contained `found` findings, nobody would ever
    see what a clean result or an unrunnable check looks like -- and F-4's whole
    argument is that those three must be visually distinct."""
    statuses = {m["status"] for m in mocks}

    assert statuses == set(findings.VALID_STATUSES), (
        f"mock data shows {sorted(statuses)}; a reader never sees "
        f"{sorted(set(findings.VALID_STATUSES) - statuses)}"
    )


def test_the_mock_data_would_survive_f1_validation(mocks):
    """The strongest available check: rebuild each mock through the real
    helpers. If `make_finding()` would refuse it, the dashboard is being handed
    something the pipeline could never produce."""
    for m in mocks:
        number = int(m["id"].split("-")[1])
        rebuilt = findings.make_finding(
            check=m["check"],
            severity=m["severity"],
            device=m["device"],
            summary=m["summary"],
            detail=m["evidence"]["detail"],
            source=m["evidence"]["source"],
            status=m["status"],
            number=number,
        )
        assert rebuilt["id"] == m["id"], (
            f"mock {m['id']} does not round-trip: the real helper would have "
            f"produced {rebuilt['id']}"
        )


def test_every_mock_source_naming_a_repo_file_names_one_that_exists(mocks):
    """Found after the six tests above were already approved.

    `CH-000`'s source read `analysis/checks/change_impact.py`. That file has
    never existed -- the real module landed at `analysis/change_impact.py` in
    #140 -- and the path was wrong in a second, worse way: putting
    change_impact under `checks/` asserts precisely what
    `analysis/checks/__init__.py` forbids in capitals, *"DO NOT add
    change_impact.py here or to CHECKS"*. The mock data is the first thing
    every user sees, and it was contradicting the architecture in an evidence
    field.

    Why nothing caught it: `source` is free text by design, and rightly so --
    most sources are `rtr-us5:acl_in` or `rtr-us5.cfg:21`, which name a device
    or a config line rather than anything in this repository. F-1 validation
    cannot help, because there is nothing malformed about a string.

    So this checks only the sources that *claim* to be repository files, and
    leaves every other form alone. A source that points at a file we do not
    ship is a citation to nothing.
    """
    repo_root = Path(__file__).resolve().parent.parent

    missing = []
    for m in mocks:
        source = m["evidence"]["source"]
        if not source.endswith((".py", ".md")):
            continue  # names a device, an ACL, or a config line -- not ours
        if not (repo_root / source).exists():
            missing.append(f"{m['id']}: {source}")

    assert not missing, (
        "mock findings cite repository files that do not exist, so the "
        "dashboard shows a user evidence pointing at nothing:\n  "
        + "\n  ".join(missing)
    )


def test_no_two_mock_findings_share_an_id(mocks):
    """Raised by @shubhamkataria2005 in review, and he is right that this is
    the one invariant this file's own history is about.

    THE GAP HE FOUND
        `test_every_mock_id_matches_its_check_prefix` checks each id against
        its OWN check. It cannot see two findings that each agree with their
        own check and collide with each other. He demonstrated it by making
        `change_impact`'s error sentinel a `policy_compliance` one:

            ids: ['AC-001', 'PC-000', 'RT-001', 'PC-000', 'AC-002', 'RK-001']
            duplicates: True   ->   7 passed

        Two `PC-000`, and nothing noticed -- in the pull request whose whole
        stated justification is that this file *"has already drifted once
        without anyone noticing"*, guarding against precisely that drift.

    WHY IT MATTERS HERE SPECIFICALLY
        `PC-000` appearing twice is why `web/static/app.js` carries its rule
        never to key findings by id, why `tests/test_findings_rendering.py`
        exists, and why A-2 was raised at all. If a consumer keys by id, one
        of a colliding pair disappears -- and if the vanished one is a
        `status="error"`, the user reads "all clear" while a check never ran.
        F-4's failure reached through `id` instead of through `status`.

    WHY IT ASSERTS AGAINST `duplicate_id_findings` RATHER THAN COUNTING IDS
        Also his suggestion, and the better half of it. A `len(set(ids))`
        assertion would test a copy of the guard's logic; this tests the mock
        data against the guard the product actually runs. #84 is the reason
        that distinction is not pedantic -- there, a guard's self-test
        verified a re-implementation while the real path was free to break
        independently of it.
    """
    collisions = duplicate_id_findings(mocks)

    assert collisions == [], (
        "two mock findings share an id, so anything downstream keying by id "
        "silently loses one of them:\n  "
        + "\n  ".join(c["summary"] for c in collisions)
    )
