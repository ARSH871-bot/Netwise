"""#239: the CVE-mapping check, tested against its four acceptance criteria.

    AC-1  the software version is extracted, or the check SAYS it could not
          find one -- status="error", never a silent skip
    AC-2  "no CVE data available" is status="error", never status="none" --
          an unmatched version is not a clean bill of health
    AC-3  the dataset is versioned and its date is SHOWN, so staleness is
          visible on the finding rather than only in the file
    AC-4  works fully offline -- the dataset ships, never fetched at scan time

Plus the severity cap, which is not an acceptance criterion but is the claim
this check makes about its own confidence: a train-level match can only ever
say "worth checking", so it never reports `high`, and business-context
escalation may not raise it there either.

NO BATFISH IS NEEDED. The check reaches config text through the session --
`fileParseStatus()` then `get_snapshot_input_object_text()` -- so a stub with
those two methods is the whole surface. That is deliberate on the check's part
and it is what makes this file fast; `tests/test_cve_mapping_live.py` would be
where a real-Batfish test went, and the four outcomes were verified that way
by hand before these were written.
"""

import pandas as pd
import pytest

from analysis import cve_data as cve_dataset
from analysis import findings
from analysis.business_context import load_business_context
from analysis.checks import cve_mapping
from analysis.checks.risk import apply_business_context, refine

# --- a stub session ----------------------------------------------------------


class StubSession:
    """The two methods the check actually uses, and nothing else.

    Written as a class rather than a Mock so that a change to WHICH session
    methods the check calls shows up as an AttributeError here, rather than a
    Mock silently answering a question nobody meant to ask.
    """

    def __init__(self, files, unreadable=(), parse_raises=None):
        # files: {filename: (config_text, [node, ...])}
        self._files = files
        self._unreadable = set(unreadable)
        self._parse_raises = parse_raises
        self.q = self._Questions(self)

    class _Questions:
        def __init__(self, outer):
            self._outer = outer

        def fileParseStatus(self):
            outer = self._outer

            class _Answer:
                def answer(self_inner):
                    return self_inner

                def frame(self_inner):
                    if outer._parse_raises is not None:
                        raise outer._parse_raises
                    return pd.DataFrame(
                        [{"File_Name": name, "Status": "PASSED", "Nodes": nodes}
                         for name, (_, nodes) in outer._files.items()]
                    )

            return _Answer()

    def get_snapshot_input_object_text(self, filename):
        if filename in self._unreadable:
            raise RuntimeError("could not read that file")
        return self._files[filename][0]


def _session(config_text, node="rtr-us5", filename="configs/rtr-us5.cfg", **kw):
    return StubSession({filename: (config_text, [node])}, **kw)


def _cfg(version=None):
    body = "!\n! synthetic\n!\n"
    if version is not None:
        body += f"version {version}\n"
    return body + "hostname rtr-us5\n!\n"


def _only(results):
    assert len(results) == 1, f"expected one finding, got {len(results)}"
    return results[0]


# --- every finding is a valid F-1 finding ------------------------------------


@pytest.mark.parametrize(
    "config",
    [_cfg("15.2"), _cfg("15.9"), _cfg("12.2"), _cfg(None)],
    ids=["found", "clean", "no-data", "no-version"],
)
def test_every_finding_the_check_can_produce_is_valid_f1(config):
    """The contract, on all four paths. A malformed finding must fail in the
    check that made it, not quietly downstream."""
    for finding in cve_mapping.run(_session(config)):
        assert set(finding) == {
            "id", "check", "severity", "device", "summary", "evidence", "status",
        }
        assert finding["check"] in findings.VALID_CHECKS
        assert finding["severity"] in findings.VALID_SEVERITIES
        assert finding["status"] in findings.VALID_STATUSES
        assert set(finding["evidence"]) == {"detail", "source"}
        assert finding["id"].startswith("CV-")


# --- AC-1: no version found -> the check SAYS so -----------------------------


def test_ac1_a_config_with_no_version_line_produces_an_error():
    finding = _only(cve_mapping.run(_session(_cfg(None))))

    assert finding["status"] == "error"
    assert "No software version is declared" in finding["summary"]


def test_ac1_the_missing_version_is_never_silently_skipped():
    """THE CRITERION IS THE OPPOSITE OF SILENCE.

    Producing nothing at all would leave the device absent from the results,
    and an absent device reads as one with nothing wrong. The check must emit
    a finding for every device it looked at, whatever the outcome.
    """
    results = cve_mapping.run(
        StubSession({
            "a.cfg": (_cfg(None), ["rtr-a"]),
            "b.cfg": (_cfg("15.2"), ["rtr-b"]),
        })
    )
    assert {f["device"] for f in results} == {"rtr-a", "rtr-b"}


def test_ac1_says_explicitly_that_this_is_not_a_statement_about_currency():
    """"We could not read a version" must not be heard as "the software is
    fine". The card says which one it is, in words."""
    detail = _only(cve_mapping.run(_session(_cfg(None))))["evidence"]["detail"].lower()
    assert "not a statement that the software is current" in detail
    assert "nothing is known" in detail


def test_ac1_an_unreadable_config_file_still_reports_the_device():
    """One unreadable file must not lose the device entirely -- it becomes
    "no version found", which is the honest outcome for it."""
    session = _session(_cfg("15.2"), unreadable=["configs/rtr-us5.cfg"])
    finding = _only(cve_mapping.run(session))
    assert finding["status"] == "error"
    assert finding["device"] == "rtr-us5"


# --- AC-2: an unmatched version is an ERROR, never a clean result ------------


def test_ac2_a_version_the_dataset_does_not_cover_is_an_error():
    finding = _only(cve_mapping.run(_session(_cfg("12.2"))))

    assert finding["status"] == "error"
    assert "No CVE data available" in finding["summary"]


def test_ac2_an_unmatched_version_is_never_status_none():
    """THE SINGLE MOST IMPORTANT ASSERTION IN THIS FILE.

    "We have no data about your software" and "your software is fine" are
    different sentences, and only the first is true here. `none` renders as a
    green tick under "checked, nothing found"; reaching it from an unknown
    version would tell a user they were safe when nobody looked. That is
    F-4's failure, arriving through a reference dataset.
    """
    for unknown in ("12.2", "11.0", "99.99", "15.3"):
        finding = _only(cve_mapping.run(_session(_cfg(unknown))))
        assert finding["status"] == "error", (
            f"version {unknown} is not in the dataset and produced "
            f"status={finding['status']!r}. It must be 'error'."
        )


def test_ac2_the_card_says_out_loud_that_it_is_not_a_clean_result():
    detail = _only(cve_mapping.run(_session(_cfg("12.2"))))["evidence"]["detail"]
    assert "NOT a clean result" in detail
    assert "nobody looked" in detail


def test_ac2_the_error_names_what_the_dataset_does_cover():
    """So the reader can tell "unsupported vendor" from "we are out of date"."""
    detail = _only(cve_mapping.run(_session(_cfg("12.2"))))["evidence"]["detail"]
    for train in cve_dataset.load_cve_data().assessed_trains:
        assert train in detail


def test_ac2_assessed_with_nothing_recorded_IS_allowed_to_be_none():
    """The other side of the criterion, and the reason it is not simply
    "never emit none": a train we assessed and found nothing for is a real,
    checked, clean result and must be reported as one."""
    finding = _only(cve_mapping.run(_session(_cfg("15.9"))))

    assert finding["status"] == "none"
    assert "assessed that train and recorded no advisories" in finding["evidence"]["detail"]


def test_ac2_the_two_empty_advisory_cases_are_told_apart():
    """Both 12.2 and 15.9 have zero advisories. Only `is_assessed` separates
    them, and the check must ask that first."""
    unknown = _only(cve_mapping.run(_session(_cfg("12.2"))))
    assessed = _only(cve_mapping.run(_session(_cfg("15.9"))))

    assert (unknown["status"], assessed["status"]) == ("error", "none")


# --- AC-3: the dataset version and date are shown ON the finding -------------


@pytest.mark.parametrize(
    "config", [_cfg("15.2"), _cfg("15.9"), _cfg("12.2"), _cfg(None)],
    ids=["found", "clean", "no-data", "no-version"],
)
def test_ac3_every_finding_carries_the_dataset_version_and_date(config):
    """Staleness has to be visible where the reader is looking. A version
    recorded only in the JSON is visible to whoever opens the JSON."""
    data = cve_dataset.load_cve_data()
    for finding in cve_mapping.run(_session(config)):
        detail = finding["evidence"]["detail"]
        assert data.dataset_version in detail
        assert data.generated in detail


# --- a genuine match: "worth checking", never "confirmed" --------------------


def test_a_matched_version_produces_a_found_finding_listing_the_real_cves():
    finding = _only(cve_mapping.run(_session(_cfg("15.2"))))

    assert finding["status"] == "found"
    for cve in ("CVE-2018-0171", "CVE-2017-3881", "CVE-2018-0151"):
        assert cve in finding["evidence"]["detail"]


def test_the_finding_never_claims_the_device_is_confirmed_vulnerable():
    """THE HONESTY REQUIREMENT, and it is load-bearing rather than tone.

    A reader who takes this as confirmation will act on a claim the check
    never made. A train-level match cannot support it: the exact build is not
    in an exported config, and most of these advisories need a feature
    enabled as well.
    """
    finding = _only(cve_mapping.run(_session(_cfg("15.2"))))
    detail = finding["evidence"]["detail"]

    assert "NOT CONFIRMATION" in detail
    assert "worth checking" in finding["summary"]
    assert "TRAIN, not the exact build" in detail
    assert "Confirm the running build" in detail


def test_the_finding_names_what_each_advisory_requires():
    """So the reader knows what to go and check, rather than only that they
    might be affected."""
    detail = _only(cve_mapping.run(_session(_cfg("15.2"))))["evidence"]["detail"]
    assert "Smart Install" in detail
    assert "requires" in detail


def test_the_summary_pluralises_honestly():
    """One advisory must not read as "1 known advisories"."""
    single = "!\nversion 16.9\nhostname r\n"
    data = cve_dataset.load_cve_data()
    count = len(data.advisories_for("16.9"))
    summary = _only(cve_mapping.run(_session(single)))["summary"]
    assert f"{count} known advisor" in summary
    assert ("advisories" in summary) == (count != 1)


# --- the severity cap, in the check ------------------------------------------


def test_the_check_never_emits_high_for_any_input():
    """Even though the dataset holds advisories rated critical at CVSS 10.0.

    The cap is about THIS CHECK'S CONFIDENCE, not the advisory's seriousness:
    `high` in a worst-first list means "act on this", and a train-level match
    cannot support that instruction.
    """
    for config in (_cfg("15.2"), _cfg("15.9"), _cfg("16.9"), _cfg("17.3"), _cfg("12.4")):
        for finding in cve_mapping.run(_session(config)):
            if finding["status"] == "found":
                assert finding["severity"] != "high", (
                    f"the check emitted high for {config!r} -- the cap is gone"
                )
                assert finding["severity"] == cve_mapping.MAX_SEVERITY


def test_the_advisory_severity_is_deliberately_not_consulted():
    """`_severity_for` takes the advisories and ignores them, on purpose.

    This pins that: a hand-made list rated critical still scores medium. The
    tempting change is to map cisco_severity onto our scale, and it would be
    wrong for a reason that is about evidence, not vocabulary.
    """
    critical = [{"id": "CVE-2018-0171", "title": "x", "cisco_severity": "critical",
                 "cvss_v3": 10.0}]
    assert cve_mapping._severity_for(critical) == "medium"
    assert cve_mapping._severity_for([]) == "medium"


# --- the severity cap, in risk.py (the second place) -------------------------


def _found(check, severity, device="rtr-us5"):
    return {
        "id": "CV-001" if check == "cve_mapping" else "AC-001",
        "check": check, "severity": severity, "device": device,
        "summary": "s", "evidence": {"detail": "d", "source": "s"},
        "status": "found",
    }


CRITICAL_CONTEXT = load_business_context(
    [{"device": "rtr-us5", "tier": "critical", "description": "Edge router"}]
)


def test_business_context_cannot_escalate_a_capped_finding_above_medium():
    """THE SECOND HALF OF THE CAP, AND IT IS NOT A DUPLICATE OF THE FIRST.

    The check never emits `high`. But escalation takes a `medium` finding on
    a device the user tagged `critical` up one level -- which is `high` -- and
    would undo the check's own reasoning from outside, through a feature that
    knows nothing about why the cap exists. Without the ceiling in
    `risk.py` this passes everywhere else and fails here.
    """
    out = apply_business_context([_found("cve_mapping", "medium")], CRITICAL_CONTEXT)
    assert out[0]["severity"] == "medium"


def test_a_capped_check_below_its_ceiling_may_still_escalate():
    """The ceiling caps; it does not freeze. `low` -> `medium` is under the
    ceiling and is allowed, so the ceiling is not quietly a no-op-everything
    rule."""
    out = apply_business_context([_found("cve_mapping", "low")], CRITICAL_CONTEXT)
    assert out[0]["severity"] == "medium"


def test_the_ceiling_never_lowers_a_severity():
    """Limit 2 of `apply_business_context` forbids downgrading, and a ceiling
    could quietly become one. A capped finding that somehow arrived as `high`
    keeps `high` -- the ceiling limits what THIS PASS raises, nothing more."""
    out = apply_business_context([_found("cve_mapping", "high")], CRITICAL_CONTEXT)
    assert out[0]["severity"] == "high"


def test_other_checks_are_completely_unaffected_by_the_ceiling():
    """THE REGRESSION GUARD. A ceiling keyed too broadly would silently stop
    business-context escalation working at all, which is #254's whole
    feature."""
    out = apply_business_context([_found("access_control", "medium")], CRITICAL_CONTEXT)
    assert out[0]["severity"] == "high"


def test_the_cap_holds_through_the_whole_refine_pipeline():
    """End to end rather than on `apply_business_context` alone: R-rules then
    context then sort, which is the order a real scan uses."""
    out = refine([_found("cve_mapping", "medium")], CRITICAL_CONTEXT)
    assert out[0]["severity"] == "medium"


def test_no_cve_finding_can_reach_high_through_any_supported_tier():
    for tier in ("critical", "important", "standard"):
        context = load_business_context(
            [{"device": "rtr-us5", "tier": tier, "description": "x"}]
        )
        out = refine([_found("cve_mapping", "medium")], context)
        assert out[0]["severity"] != "high", f"tier {tier!r} broke the cap"


# --- error paths that are about the check, not a device ----------------------


def test_a_dataset_that_will_not_load_is_an_error_not_a_silent_pass(monkeypatch):
    def boom(*_a, **_k):
        raise cve_dataset.CveDataError("dataset is corrupt")

    monkeypatch.setattr(cve_mapping.cve_dataset, "load_cve_data", boom)
    finding = _only(cve_mapping.run(_session(_cfg("15.2"))))

    assert finding["status"] == "error"
    assert "could not be loaded" in finding["summary"]
    assert "Nothing is claimed" in finding["evidence"]["detail"]


def test_a_failure_reading_the_snapshot_is_an_error():
    session = _session(_cfg("15.2"), parse_raises=RuntimeError("batfish is down"))
    finding = _only(cve_mapping.run(session))

    assert finding["status"] == "error"
    assert "could not be read" in finding["summary"]


def test_a_snapshot_with_no_parsed_files_is_an_error_not_an_empty_pass():
    """An empty result list would be indistinguishable from "nothing wrong"."""
    finding = _only(cve_mapping.run(StubSession({})))

    assert finding["status"] == "error"
    assert "No device configurations" in finding["summary"]


# --- ids do not collide within one run ---------------------------------------


def test_a_run_producing_a_clean_result_and_errors_has_no_duplicate_ids():
    """`make_finding` does not enforce uniqueness within a check, and
    `pipeline.duplicate_id_findings()` is a backstop rather than a licence.
    The clean sentinel is 000 and errors start at 051 so they cannot meet.
    """
    results = cve_mapping.run(
        StubSession({
            "a.cfg": (_cfg("15.9"), ["rtr-a"]),   # none, CV-000
            "b.cfg": (_cfg("12.2"), ["rtr-b"]),   # error
            "c.cfg": (_cfg(None), ["rtr-c"]),     # error
            "d.cfg": (_cfg("15.2"), ["rtr-d"]),   # found
        })
    )
    ids = [f["id"] for f in results]
    assert len(ids) == len(set(ids)), f"duplicate ids in one run: {ids}"


def test_multiple_devices_each_get_their_own_finding():
    results = cve_mapping.run(
        StubSession({
            "a.cfg": (_cfg("15.2"), ["rtr-a"]),
            "b.cfg": (_cfg("15.9"), ["rtr-b"]),
            "c.cfg": (_cfg("12.2"), ["rtr-c"]),
        })
    )
    by_device = {f["device"]: f["status"] for f in results}
    assert by_device == {"rtr-a": "found", "rtr-b": "none", "rtr-c": "error"}


# --- AC-4, at the check level ------------------------------------------------


def test_the_check_module_imports_nothing_that_could_reach_a_network():
    """AC-4 again, one layer up. The loader was checked in
    tests/test_cve_data.py; this is the module that calls it."""
    import ast
    from pathlib import Path

    tree = ast.parse(Path("analysis/checks/cve_mapping.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {"requests", "urllib", "urllib3", "httpx", "socket", "http", "ftplib"}
    assert not (imported & forbidden)


# --- registration: deliberately absent ---------------------------------------


def test_the_check_is_deliberately_not_registered_in_CHECKS():
    """NOT AN OVERSIGHT, AND THIS TEST IS THE PROOF IT WAS A DECISION.

    Running it requires "cve_mapping" in `findings.VALID_CHECKS`, which that
    file says takes team agreement. Registering it would put an unratified
    vocabulary addition into every scan -- exactly what
    `docs/finding-format.md` regrets about A-2.

    When the team ratifies it, this test is what should be deleted, in the
    same commit that adds the registration. If it fails without that, someone
    wired it in without the agreement.
    """
    from analysis import pipeline

    assert "cve_mapping" not in pipeline.CHECKS, (
        "cve_mapping has been registered. That needs team ratification of the "
        "VALID_CHECKS addition first -- see the note in analysis/findings.py"
    )


def test_the_vocabulary_entries_exist_so_the_check_can_be_reviewed():
    assert "cve_mapping" in findings.VALID_CHECKS
    assert findings.PREFIX_BY_CHECK["cve_mapping"] == "CV"


def test_the_prefix_is_unique_across_every_check():
    prefixes = list(findings.PREFIX_BY_CHECK.values())
    assert len(prefixes) == len(set(prefixes)), (
        f"two checks share an id prefix: {prefixes}. A-2 exists to prevent "
        f"exactly this"
    )
