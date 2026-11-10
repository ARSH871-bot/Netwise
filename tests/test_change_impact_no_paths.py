"""
Netwise -- change impact never shows a folder it was handed (#462).

WHY THIS FILE EXISTS
    Propose-a-change passes the session's upload folder to analyse_change(),
    and that folder is named after the `netwise_session` cookie. Every card
    carried the folder in `evidence.source`, so the dashboard printed the
    cookie that `httponly` exists to hide, plus the user's own folders.
    Measured by Arsh on main d424e05:

        source: C:\\Users\\vhora\\...\\sessions\\hCf7lpCUZ2e753zhNbblAA\\current
                -> C:\\Users\\vhora\\AppData\\Local\\Temp\\netwise-proposal-...\\after

    `labels` names the two sides instead, and one replacement runs over
    every string in every finding, so no path of the caller's survives in
    a summary, a detail, an error message or a source. Without labels, as
    from the command line, the paths the user typed are shown as typed.

RUN
    pytest tests/test_change_impact_no_paths.py -v
"""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from ai import propose
from analysis import change_impact
from conftest import needs_batfish

SESSION = "hCf7lpCUZ2e753zhNbblAA"
LABELS = ("your uploaded config", "the proposed config")
FIXTURES = Path(__file__).parent / "fixtures"


def _folders(tmp_path):
    before = tmp_path / "sessions" / SESSION / "current"
    after = tmp_path / "netwise-proposal-xyz" / "after"
    before.mkdir(parents=True)
    after.mkdir(parents=True)
    return before, after


def _leaks(results, *folders):
    text = json.dumps(results)
    found = [str(f) for f in folders if str(f) in text or Path(f).as_posix() in text]
    if SESSION in text:
        found.append(SESSION)
    return found


def _quiet_stages(monkeypatch):
    monkeypatch.setattr(change_impact, "connect",
                        lambda host=None: SimpleNamespace(set_network=lambda n: None,
                                                          set_snapshot=lambda n: None))
    monkeypatch.setattr(change_impact, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(change_impact, "find_parse_problems", lambda bf: [])
    monkeypatch.setattr(change_impact, "_devices", lambda bf: ({"rtr-us5"}, {"rtr-us5"}))
    monkeypatch.setattr(change_impact, "_reachability_change_findings", lambda bf, n: ([], n))
    monkeypatch.setattr(change_impact, "_policy_change_findings",
                        lambda bf, n, b=None, a=None: {"findings": [], "unchanged": [], "number": n})


def test_unreachable_batfish_card_shows_labels_not_folders(tmp_path, monkeypatch):
    before, after = _folders(tmp_path)

    def down(host=None):
        raise ConnectionError(f"could not reach Batfish while reading {before}")
    monkeypatch.setattr(change_impact, "connect", down)

    results = change_impact.analyse_change(before, after, labels=LABELS)

    assert _leaks(results, before, after) == []
    assert results[0]["evidence"]["source"] == "your uploaded config -> the proposed config"


def test_a_load_error_quoting_the_folder_is_cleaned(tmp_path, monkeypatch):
    """The path can arrive inside an error message, not only in `source`."""
    before, after = _folders(tmp_path)
    _quiet_stages(monkeypatch)

    def bad(bf, folder, network, name):
        if name == change_impact.AFTER_SNAPSHOT:
            raise FileNotFoundError(f"no configs folder under {folder}")
    monkeypatch.setattr(change_impact, "load_snapshot", bad)

    results = change_impact.analyse_change(before, after, labels=LABELS)

    assert _leaks(results, before, after) == []
    assert results[0]["evidence"]["source"] == "the proposed config"
    assert "the proposed config" in results[0]["evidence"]["detail"]


def test_a_parse_failure_card_names_the_side_not_the_folder(tmp_path, monkeypatch):
    before, after = _folders(tmp_path)
    _quiet_stages(monkeypatch)
    monkeypatch.setattr(change_impact, "find_parse_problems", lambda bf: ["rtr-us5.cfg"])

    results = change_impact.analyse_change(before, after, labels=LABELS)

    assert _leaks(results, before, after) == []
    assert results[0]["evidence"]["source"] == "your uploaded config"


def test_the_ordinary_cards_carry_the_labels(tmp_path, monkeypatch):
    before, after = _folders(tmp_path)
    _quiet_stages(monkeypatch)

    def broken(bf, n):
        raise RuntimeError("compareFilters failed")
    monkeypatch.setattr(change_impact, "_filter_change_findings", broken)

    results = change_impact.analyse_change(before, after, labels=LABELS)

    assert _leaks(results, before, after) == []
    assert any(f["evidence"]["source"] == "your uploaded config -> the proposed config"
               for f in results)


def test_no_string_in_any_finding_keeps_a_folder(tmp_path, monkeypatch):
    """The guarantee is every string, not only `source`: a stage that ever
    names a folder in a summary or detail is cleaned too."""
    before, after = _folders(tmp_path)
    _quiet_stages(monkeypatch)
    card = change_impact.findings.make_finding(
        check="change_impact", severity="high", device="rtr-us5",
        summary=f"A line moved in {after}", detail=f"compared {before} with {after}",
        source="rtr-us5:acl_in", status="found", number=1)
    monkeypatch.setattr(change_impact, "_filter_change_findings", lambda bf, n: ([card], n + 1))

    results = change_impact.analyse_change(before, after, labels=LABELS)

    assert _leaks(results, before, after) == []
    moved = [f for f in results if f["summary"].startswith("A line moved")][0]
    assert moved["summary"] == "A line moved in the proposed config"
    assert moved["evidence"]["detail"] == "compared your uploaded config with the proposed config"


def test_without_labels_the_command_line_still_shows_the_paths(tmp_path, monkeypatch):
    """The user typed these paths, so they are useful there, and not secret."""
    before, after = _folders(tmp_path)

    def down(host=None):
        raise ConnectionError("down")
    monkeypatch.setattr(change_impact, "connect", down)

    results = change_impact.analyse_change(before, after)

    assert results[0]["evidence"]["source"] == f"{before} -> {after}"


def test_propose_passes_labels(monkeypatch, tmp_path):
    seen = {}

    def fake(before_dir, after_dir, host=None, labels=None):
        seen["labels"] = labels
        return []
    monkeypatch.setattr(propose.change_impact, "analyse_change", fake)
    # propose_change() connects and loads BEFORE it reaches analyse_change(),
    # through its own imported copies. Without these it refuses early when no
    # Batfish is running, as on CI, and the fake is never called (#463 review).
    monkeypatch.setattr(propose, "connect", lambda host=None: object())
    monkeypatch.setattr(propose, "load_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(propose, "find_parse_problems", lambda bf: [])
    monkeypatch.setattr(propose.snapshot, "device_names", lambda bf: {"rtr-us5"})
    propose.propose_change("block 10.10.10.5 to 10.20.0.5 on tcp/22 on rtr-us5",
                           FIXTURES / "rtr-us5-secure")

    assert seen["labels"] == ("your uploaded config", "the proposed config")


@needs_batfish
def test_live_a_proposal_from_a_session_folder_never_shows_the_session_id(tmp_path):
    """Arsh's measurement, end to end against real Batfish."""
    import shutil
    before = tmp_path / "sessions" / SESSION / "current"
    shutil.copytree(FIXTURES / "rtr-us5-secure", before)

    out = propose.propose_change("allow 10.10.10.0/24 to 8.8.8.8 on tcp/80 on rtr-us5", before)

    assert out["impact"], "the proposal produced no impact cards to check"
    text = json.dumps(out)
    assert SESSION not in text
    assert str(tmp_path) not in text and "netwise-proposal-" not in text


def test_a_contradictory_policy_is_a_message_not_a_traceback(tmp_path):
    """#440, N5: the command line used to print a traceback."""
    rule = {"kind": "prohibition", "filter": "acl_in", "violation_severity": "high",
            "violation_summary": "x"}
    policy = {"device": "rtr-us5", "policy_compliance": [
        dict(rule, number=1, description="forbid", queries=[{"dstIps": "10.20.0.5"}]),
        dict(rule, number=2, description="require", kind="requirement",
             queries=[{"dstIps": "10.20.0.5", "ipProtocols": ["tcp"], "dstPorts": "443"}]),
    ]}
    path = tmp_path / "contra.json"
    path.write_text(json.dumps(policy))

    run = subprocess.run(
        [sys.executable, "-m", "analysis.change_impact",
         str(FIXTURES / "rtr-us5-secure"), str(FIXTURES / "rtr-us5-insecure"), str(path)],
        capture_output=True, text=True, cwd=Path(__file__).parent.parent)

    assert run.returncode != 0
    assert "Traceback" not in run.stderr
    assert "Policy not loaded, so nothing was analysed." in run.stderr
    assert "contradicts itself" in run.stderr
