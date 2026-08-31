"""The analysis cache (#92b) -- the larger cost, and the one that must never
freeze an outage.

WHY THIS FILE EXISTS
    `/api/findings` re-ran the WHOLE Batfish pipeline on every hit, and
    `loadFindings()` runs at script load in static/app.js, so every page load
    paid it. Measured on rtr-us5-insecure with Batfish up:

        hit 1:  3.72s   6 findings
        hit 2:  3.61s   6 findings
        hit 3:  3.61s   6 findings
        hit 4:  3.60s   6 findings

    Unlike the model calls #92a removed, that price is paid **whether or not
    Ollama is installed** -- so on CI and on every machine we have
    demonstrated this on, it was the entire observable cost.

THE TWO THINGS THAT CAN GO WRONG, AND BOTH ARE F-4
    1. Serving one network's findings for another. #82 exists because a
       staged config and a checked one were once confused; a cache keyed on
       "the current snapshot" would bring that straight back, since an
       upload replaces the file at a fixed path. The key is the file's
       CONTENT for exactly that reason, and the upload endpoint clears the
       cache as well.

    2. Remembering an outage. If Batfish is down every check reports "could
       not run", and caching that would make a stopped container the
       permanent answer -- "we could not check" frozen into place, which is
       F-4's own failure made durable.

WHY THE OUTAGE RULE IS WHAT IT IS
    The obvious rule -- refuse to cache anything containing status="error" --
    would disable the cache completely. Every fixture produces one structural
    error on every healthy run. Measured:

        BATFISH UP     rtr-us5-insecure  {'found': 5, 'error': 1}
                       rtr-us5-secure    {'none': 2,  'error': 1}
                         RT-050, routing assertions naming rtr-hq/rtr-branch
                         that do not apply here. Stable and correct.

        BATFISH DOWN   rtr-us5-insecure  {'error': 3}
                       rtr-us5-secure    {'error': 3}
                         AC-000 / PC-000 / RT-000, every check, and no found
                         or none anywhere.

    So: cache only when at least one check produced a real result. That
    separates the measured cases exactly without parsing summaries or
    depending on id numbering.

These need neither Batfish nor Ollama -- `analysis_pipeline.analyse` is
substituted, the same way the rest of the web tests substitute the model.

RUN
    pytest tests/ -v
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from web import main


# --- helpers ------------------------------------------------------------------


def _found(fid: str = "AC-001", detail: str = "some evidence") -> Dict[str, Any]:
    return {
        "id": fid,
        "check": "access_control",
        "severity": "high",
        "device": "rtr-us5",
        "summary": "A finding",
        "evidence": {"detail": detail, "source": "rtr-us5:acl_in"},
        "status": "found",
    }


def _error(fid: str, check: str, summary: str) -> Dict[str, Any]:
    return {
        "id": fid,
        "check": check,
        "severity": "high",
        "device": "rtr-us5",
        "summary": summary,
        "evidence": {"detail": summary, "source": "n/a"},
        "status": "error",
    }


#: What analyse() really returns with Batfish stopped -- copied from a
#: measured run, not invented. Every check, no found, no none.
BATFISH_DOWN = [
    _error("AC-000", "access_control", "Analysis could not run: Batfish is not reachable"),
    _error("PC-000", "policy_compliance", "Analysis could not run: Batfish is not reachable"),
    _error("RT-000", "routing", "Analysis could not run: Batfish is not reachable"),
]

#: What a HEALTHY run really returns -- note the structural error that is
#: present every time and must NOT prevent caching.
HEALTHY = [
    _found("AC-001"),
    _found("AC-002", detail="another"),
    _error("RT-050", "routing",
           "2 route assertion(s) could not be checked against this config"),
]


class _Analyser:
    """Stands in for analysis_pipeline.analyse, counting real runs."""

    def __init__(self, results: List[Dict[str, Any]]):
        self.results = results
        self.calls = 0

    def __call__(self, *_a, **_k):
        self.calls += 1
        # A fresh list of fresh dicts each time, exactly as the real pipeline
        # produces -- so a test cannot pass because two runs share objects.
        return [dict(f, evidence=dict(f["evidence"])) for f in self.results]


@pytest.fixture
def staged(tmp_path, monkeypatch):
    """Point the app at a temporary snapshot we control, and mark it uploaded."""
    configs = tmp_path / "current" / "configs"
    configs.mkdir(parents=True)
    # Patch the FUNCTIONS, not the old module constants. Since #242 storage
    # is per session, so `configs_dir()` resolves through a ContextVar --
    # setting a module attribute would be shadowed and silently ignored,
    # which is a test that redirects nothing while appearing to.
    monkeypatch.setattr(main, "configs_dir", lambda session_id=None: configs)
    monkeypatch.setattr(
        main, "snapshot_dir", lambda session_id=None: tmp_path / "current"
    )
    monkeypatch.setattr(main, "_uploaded", True)
    monkeypatch.setattr(main, "explain_with_source",
                        lambda finding: ("explained", "model"))
    main.reset_analysis_cache()
    return configs


# --- The defect ---------------------------------------------------------------


def test_an_unchanged_snapshot_is_analysed_once(staged, monkeypatch):
    """Three page loads, one analysis. The measured 3.6s x N becomes 3.6s."""
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    for _ in range(3):
        main.get_findings()

    assert analyser.calls == 1, (
        f"three requests over an unchanged snapshot ran the pipeline "
        f"{analyser.calls} times; expected 1, was 3 before the cache"
    )


def test_the_findings_are_the_same_on_a_cache_hit(staged, monkeypatch):
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    first = main.get_findings()
    second = main.get_findings()

    assert [f["id"] for f in first] == [f["id"] for f in second]
    assert [f["status"] for f in first] == [f["status"] for f in second]


# --- Criterion: a new snapshot is never served the old one's findings ---------


def test_a_different_config_is_analysed_again(staged, monkeypatch):
    """The #82 failure, in cache form.

    An upload replaces the file at a FIXED path, so a key of "the current
    snapshot" would be identical for two different networks.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)

    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")
    main.get_findings()
    assert analyser.calls == 1

    # Same filename, same path, different network.
    (staged / "device.cfg").write_text("hostname rtr-hq\n", encoding="utf-8")
    main.get_findings()

    assert analyser.calls == 2, (
        "a different configuration at the same path was served the previous "
        "network's findings -- this is the #82 failure through the cache"
    )


def test_the_two_networks_get_their_own_findings(staged, monkeypatch):
    """Not just 'analysed again' -- the right results come back.

    A cache that re-ran the analysis and then returned the stale list would
    pass the call-count test above while being exactly as wrong.
    """
    insecure = [_found("AC-001", detail="permit ip any any on acl_in")]
    messy = [_found("AC-001", detail="ACL rule never takes effect in acl_in")]

    current = {"results": insecure}

    def analyse(*_a, **_k):
        return [dict(f, evidence=dict(f["evidence"]))
                for f in current["results"]]

    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyse)

    (staged / "device.cfg").write_text("network one\n", encoding="utf-8")
    first = main.get_findings()

    current["results"] = messy
    (staged / "device.cfg").write_text("network two\n", encoding="utf-8")
    second = main.get_findings()

    assert first[0]["evidence"]["detail"] != second[0]["evidence"]["detail"], (
        "both networks were served the same evidence despite sharing an id"
    )
    assert "permit ip any any" in first[0]["evidence"]["detail"]
    assert "never takes effect" in second[0]["evidence"]["detail"]


def test_a_second_file_in_the_snapshot_is_a_different_key(staged, monkeypatch):
    """The fingerprint covers the whole directory, not one file.

    Adding a second device changes the model Batfish builds, so it must
    change the key even though the first file is untouched.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)

    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")
    main.get_findings()
    (staged / "second.cfg").write_text("hostname rtr-hq\n", encoding="utf-8")
    main.get_findings()

    assert analyser.calls == 2


def test_a_renamed_file_with_identical_bytes_is_a_different_key(staged, monkeypatch):
    """Filenames are part of the fingerprint.

    Batfish derives device identity from the file, so two snapshots with the
    same bytes under different names are not necessarily the same analysis.
    Hashing only the content would collapse them.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)

    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")
    main.get_findings()

    (staged / "device.cfg").unlink()
    (staged / "renamed.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")
    main.get_findings()

    assert analyser.calls == 2


# --- Criterion: an outage is never remembered ---------------------------------


def test_a_batfish_outage_is_not_cached(staged, monkeypatch):
    """The F-4 failure this cache could make permanent.

    Every check reporting "could not run" means nothing was checked. Storing
    that would keep answering "we could not check" after Batfish came back.
    """
    down = _Analyser(BATFISH_DOWN)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", down)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    main.get_findings()
    main.get_findings()
    assert down.calls == 2, "an all-error analysis was cached"

    # Batfish comes back. Same snapshot, so a cached outage would win.
    up = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", up)
    results = main.get_findings()

    assert up.calls == 1
    assert any(f["status"] == "found" for f in results), (
        "a recovered Batfish was shadowed by a cached outage"
    )


def test_a_healthy_run_is_cached_even_though_it_contains_an_error(staged, monkeypatch):
    """The other half, and the reason the rule is not 'no errors'.

    RT-050 is present on every healthy run of every fixture. A rule that
    refused to cache anything containing an error would never cache at all,
    and would look like a working cache in a unit test built from
    error-free data.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    assert any(f["status"] == "error" for f in HEALTHY), "fixture is wrong"

    main.get_findings()
    main.get_findings()

    assert analyser.calls == 1, (
        "a healthy run was refused caching because it contained the "
        "structural RT-050 error that every healthy run contains"
    )


def test_an_all_none_result_is_still_cached(staged, monkeypatch):
    """A clean config produces no findings at all. That IS a result."""
    clean = [
        {"id": "AC-100", "check": "access_control", "severity": "low",
         "device": "rtr-us5", "summary": "No problems found",
         "evidence": {"detail": "checked", "source": "rtr-us5"},
         "status": "none"},
    ]
    analyser = _Analyser(clean)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    main.get_findings()
    main.get_findings()
    assert analyser.calls == 1


# --- The cached list must never be modified -----------------------------------


def test_the_cached_findings_never_acquire_the_explanation_keys(staged, monkeypatch):
    """The condition web/main.py set on itself before caching here.

    `_attach_explanations()` used to mutate in place. With a cached list that
    would write two non-F-1 keys onto the cached dicts, and every later
    request would receive an object F-1 validation is entitled to see in its
    exact contracted shape.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    served = main.get_findings()
    assert any("explanation" in f for f in served), "nothing was explained"

    cached = list(main._analysis_cache.values())[0]
    for finding in cached:
        assert "explanation" not in finding, (
            "the cached findings list acquired an explanation key"
        )
        assert "explanation_source" not in finding
        assert set(finding) == {"id", "check", "severity", "device",
                                "summary", "evidence", "status"}, (
            f"the cached finding is no longer the F-1 shape: {sorted(finding)}"
        )


def test_a_cache_hit_still_gets_explanations(staged, monkeypatch):
    """Not mutating must not mean not explaining."""
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    main.get_findings()
    second = main.get_findings()

    assert analyser.calls == 1
    assert any(f.get("explanation") == "explained" for f in second)


# --- Upload clears it ---------------------------------------------------------


def test_uploading_clears_the_analysis_cache(staged, monkeypatch):
    """Belt and braces over #82.

    Content-keying already makes a stale hit impossible. This asserts the
    second guarantee anyway, because #82 exists precisely because a staged
    config and a checked one were once confused, and the invariant should
    hold even if the fingerprint is ever weakened.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    main.get_findings()
    assert len(main._analysis_cache) == 1

    main.reset_analysis_cache()
    assert main._analysis_cache == {}

    main.get_findings()
    assert analyser.calls == 2


def test_the_upload_endpoint_actually_calls_it():
    """The wiring, not just the function.

    A reset that exists and is never called is the same as no reset, and it
    would test green in every unit test written against the function itself.
    """
    import inspect

    source = inspect.getsource(main.upload_config)
    assert "reset_analysis_cache()" in source, (
        "upload_config does not clear the analysis cache"
    )


# --- Bounded ------------------------------------------------------------------


def test_the_cache_is_bounded(staged, monkeypatch):
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)
    monkeypatch.setattr(main, "ANALYSIS_CACHE_MAX", 3)

    for i in range(12):
        (staged / "device.cfg").write_text(f"config {i}\n", encoding="utf-8")
        main.get_findings()

    assert analyser.calls == 12
    assert len(main._analysis_cache) <= 3


# --- The fingerprint ----------------------------------------------------------


def test_a_fingerprint_that_cannot_be_computed_returns_none(staged, monkeypatch):
    """A fingerprint that cannot be computed must not collapse to a constant.

    Returning a fixed string on failure would give EVERY snapshot the same
    key -- the id-keyed mistake #92a exists to prevent, wearing a different
    hat, and strictly worse because it would apply to whole networks rather
    than single findings.

    THIS TEST REPLACED ONE THAT COULD NOT FAIL. The first version asserted:

        assert main._snapshot_fingerprint(missing) in (
            None, main._snapshot_fingerprint(missing))

    `x in (None, x)` is true for every x. It was a tautology, it passed, and
    mutation-testing the constant-collapse guard is what exposed it -- the
    mutation was the only one of six that survived. Its premise was wrong
    too: `rglob` on a missing directory yields nothing rather than raising,
    so that path returns a real hash of an empty set of files, not None.

    An unreadable file is simulated rather than created, because making one
    genuinely unreadable is not portable to the Windows machines this team
    develops on. Stated rather than hidden: this tests the handler, and the
    handler is what the mutation attacks.
    """
    (staged / "device.cfg").write_text("hostname rtr-us5\n", encoding="utf-8")

    def unreadable(self):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_bytes", unreadable)

    assert main._snapshot_fingerprint(staged) is None


def test_an_uncomputable_fingerprint_does_not_make_two_snapshots_share_a_key(
        staged, monkeypatch):
    """The consequence, which is what actually matters.

    If the failure path returned a constant, two different configurations
    would collide on it and the second would be served the first's findings
    -- silently, and only on the machine where reading failed.
    """
    analyser = _Analyser(HEALTHY)
    monkeypatch.setattr(main.analysis_pipeline, "analyse", analyser)

    def unreadable(self):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_bytes", unreadable)

    (staged / "device.cfg").write_text("network one\n", encoding="utf-8")
    main.get_findings()
    (staged / "device.cfg").write_text("network two\n", encoding="utf-8")
    main.get_findings()

    assert analyser.calls == 2, (
        "two different configurations shared a cache key because the "
        "fingerprint collapsed to a constant when it could not be computed"
    )
    assert main._analysis_cache == {}, (
        "an uncomputable fingerprint was still used as a key"
    )


def test_an_empty_snapshot_has_a_real_fingerprint(tmp_path):
    """"No files" is a legitimate state with a legitimate fingerprint, and
    must not be confused with "could not read", which is None."""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert isinstance(main._snapshot_fingerprint(empty), str)


def test_a_none_key_is_never_stored_or_matched():
    main.reset_analysis_cache()
    main._remember_analysis(None, HEALTHY)
    assert main._analysis_cache == {}
    assert main._cached_analysis(None) is None
