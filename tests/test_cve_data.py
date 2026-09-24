"""#239 AC-3 and AC-4: a versioned, dated, offline CVE dataset.

    AC-3  the dataset is versioned and its date is shown, so staleness is visible
    AC-4  works fully offline -- the dataset ships, never fetched at scan time

The offline test is the one worth reading. It asserts the property by reading
`analysis/cve_data.py`'s own imports rather than by mocking a network call,
because a mock proves only that the path under test did not fetch THIS TIME.
"""

import ast
import json
from pathlib import Path

import pytest

from analysis import cve_data
from analysis.cve_data import CveData, CveDataError, load_cve_data

DATASET = Path("analysis/data/cisco_ios_cves.json")


# --- AC-4: offline, structurally ---------------------------------------------


def test_the_module_imports_nothing_that_could_reach_a_network():
    """THE AC-4 GUARANTEE, asserted against the source rather than behaviour.

    A test that called `load_cve_data()` with `socket` patched would prove
    only that this code path did not fetch on this run. This proves the module
    has no way to: the names it imports are the whole of what it can call.
    """
    tree = ast.parse(Path("analysis/cve_data.py").read_text(encoding="utf-8"))

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {
        "requests", "urllib", "urllib2", "urllib3", "http", "httpx", "socket",
        "ftplib", "telnetlib", "aiohttp", "asyncio", "subprocess",
    }
    offending = imported & forbidden
    assert not offending, (
        f"analysis/cve_data.py imports {sorted(offending)}. Netwise is "
        f"air-gapped by requirement; the dataset ships with the repository and "
        f"is never fetched"
    )


def test_there_is_no_url_anywhere_in_the_loader():
    """Belt and braces on the same claim, and cheap.

    A URL in the loader would be the first sign someone had started building a
    fetch path. The DATASET may carry URLs -- they are references for a human
    to open -- but the code that reads it must not.
    """
    source = Path("analysis/cve_data.py").read_text(encoding="utf-8")
    for marker in ("http://", "https://"):
        assert marker not in source, f"a {marker} URL appeared in the loader"


def test_the_dataset_is_committed_to_the_repository():
    """"Ships" means present, not "documented as present"."""
    assert DATASET.is_file(), f"{DATASET} is missing -- the dataset must ship"


# --- AC-3: versioned and dated -----------------------------------------------


def test_the_dataset_carries_a_version_and_a_date():
    data = load_cve_data()
    assert data.dataset_version
    assert data.generated


def test_provenance_names_both_so_staleness_is_visible_on_the_finding():
    """AC-3 says the date must be SHOWN. A version recorded only in the file
    is visible to whoever opens the file, which is not the person reading the
    result -- so this string is what the check puts in the evidence."""
    line = load_cve_data().provenance()
    data = load_cve_data()

    assert data.dataset_version in line
    assert data.generated in line


# --- the shipped dataset is coherent -----------------------------------------


def test_the_shipped_dataset_loads():
    assert isinstance(load_cve_data(), CveData)


def test_every_cve_id_is_shaped_like_a_real_one():
    """Cannot prove an id EXISTS -- that is a matter of having transcribed it
    from a real advisory -- but a mistyped one is the error a reader cannot
    catch by eye. "CVE-2018-0171" and "CVE-2018-171" look alike."""
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    for train, entries in raw["advisories"].items():
        for entry in entries:
            assert cve_data._CVE_ID.match(entry["id"]), (
                f"{entry['id']!r} under train {train!r} is not a CVE identifier"
            )


def test_every_advisory_names_what_it_requires():
    """A train match cannot prove exposure; most of these advisories also
    need a feature switched on. If an entry does not say what, the finding
    cannot tell the reader what to go and check."""
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    for train, entries in raw["advisories"].items():
        for entry in entries:
            assert entry.get("requires"), (
                f"{entry['id']} under {train!r} does not say what it requires"
            )


def test_the_dataset_reaches_all_four_acceptance_outcomes():
    """The dataset is not just valid, it is USEFUL: it can produce every state
    #239 asks for. A dataset where no train was assessed-and-clean would make
    status="none" unreachable, and the check would look correct while never
    exercising the branch that matters most."""
    data = load_cve_data()

    with_findings = [t for t in data.assessed_trains if data.advisories_for(t)]
    assessed_clean = [t for t in data.assessed_trains if not data.advisories_for(t)]

    assert with_findings, "no train has advisories -- status='found' unreachable"
    assert assessed_clean, (
        "no train is assessed-with-nothing-recorded -- status='none' is "
        "unreachable, and it is the branch AC-2 turns on"
    )
    assert not data.is_assessed("12.2"), (
        "12.2 is assessed, so the 'no data for this version' path has no "
        "fixture -- rtr-us5-messy is pinned to it"
    )


# --- the two questions are genuinely separate --------------------------------


def test_assessed_with_nothing_recorded_is_not_the_same_as_no_data():
    """AC-2 IN ONE ASSERTION.

    Both return an empty advisory list. Only `is_assessed()` tells them apart,
    and a caller that read the empty list alone would call an unknown train
    clean.
    """
    data = load_cve_data()

    assert data.is_assessed("15.9") and data.advisories_for("15.9") == []
    assert not data.is_assessed("12.2") and data.advisories_for("12.2") == []


@pytest.mark.parametrize("value", [None, 0, [], {}, 15.2])
def test_a_non_string_train_is_never_assessed(value):
    data = load_cve_data()
    assert data.is_assessed(value) is False
    assert data.advisories_for(value) == []


def test_advisories_for_returns_copies_not_the_internal_list():
    """A caller editing a finding must not corrupt the dataset for the next
    one. Same reasoning as `apply_business_context()` copying its input."""
    data = load_cve_data()
    first = data.advisories_for("15.2")
    first[0]["id"] = "CVE-0000-0000"
    assert data.advisories_for("15.2")[0]["id"] != "CVE-0000-0000"


# --- validation refuses rather than half-loading -----------------------------


def _write(tmp_path, payload):
    p = tmp_path / "d.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


BASE = {
    "dataset_version": "test-1",
    "generated": "2026-01-01",
    "assessed": ["15.2"],
    "advisories": {},
}


def test_a_missing_file_is_an_error_not_an_empty_dataset(tmp_path):
    with pytest.raises(CveDataError) as raised:
        load_cve_data(tmp_path / "nope.json")
    assert "never downloaded" in str(raised.value)


def test_malformed_json_is_an_error(tmp_path):
    p = tmp_path / "d.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(CveDataError):
        load_cve_data(p)


@pytest.mark.parametrize("missing", ["dataset_version", "generated", "assessed", "advisories"])
def test_a_missing_top_level_key_is_an_error(tmp_path, missing):
    payload = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(CveDataError) as raised:
        load_cve_data(_write(tmp_path, payload))
    assert missing in str(raised.value)


def test_a_train_with_advisories_but_no_assessment_is_refused(tmp_path):
    """THE INVARIANT. The drift is silent in the dangerous direction: the
    check asks `is_assessed()` first, so this file would make it report "no
    data" for a train we hold real CVEs for."""
    payload = dict(BASE, assessed=["15.2"], advisories={
        "16.9": [{"id": "CVE-2023-20198", "title": "x", "cisco_severity": "critical"}]
    })
    with pytest.raises(CveDataError) as raised:
        load_cve_data(_write(tmp_path, payload))
    assert "not in 'assessed'" in str(raised.value)


def test_an_invented_cve_id_is_refused(tmp_path):
    payload = dict(BASE, advisories={
        "15.2": [{"id": "NOT-A-CVE", "title": "x", "cisco_severity": "high"}]
    })
    with pytest.raises(CveDataError) as raised:
        load_cve_data(_write(tmp_path, payload))
    assert "not a CVE identifier" in str(raised.value)


@pytest.mark.parametrize("key", ["id", "title", "cisco_severity"])
def test_an_advisory_missing_a_required_key_is_refused(tmp_path, key):
    entry = {"id": "CVE-2018-0171", "title": "x", "cisco_severity": "critical"}
    del entry[key]
    payload = dict(BASE, advisories={"15.2": [entry]})
    with pytest.raises(CveDataError) as raised:
        load_cve_data(_write(tmp_path, payload))
    assert key in str(raised.value)


def test_a_train_that_is_not_major_minor_is_refused(tmp_path):
    """A config's version line only ever carries major.minor. A key like
    "15.2(4)M6" would never match anything the parser can produce, so it is a
    silent no-op rather than a useful entry."""
    with pytest.raises(CveDataError) as raised:
        load_cve_data(_write(tmp_path, dict(BASE, assessed=["15.2(4)M6"])))
    assert "major.minor" in str(raised.value)


def test_an_empty_but_valid_dataset_loads(tmp_path):
    """Valid and asserting nothing. Every train is then "no data", which is
    the cautious answer -- not an error."""
    data = load_cve_data(_write(tmp_path, BASE))
    assert data.assessed_trains == ["15.2"]
    assert data.advisories_for("15.2") == []
