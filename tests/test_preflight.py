"""Tests for the environment preflight (US-16).

WHAT THIS PROTECTS
    `tools/preflight.py` exists because a dead environment produces results
    that read as good news. During one week the Batfish container was
    OOM-killed four times and Docker Desktop was down once, and on that
    occasion two verification runs looked like clean passes while checking
    nothing.

    A tool written to stop that must not itself be the thing that lies. The
    property that matters is the one it borrows from F-4:

        REQUIRED failing      -> NOT READY, exit 1
        OPTIONAL missing      -> READY, exit 0, and SAID so
        everything working    -> READY, exit 0

    Conflating the middle row with either neighbour is the whole failure this
    tool is against. Report a missing Ollama as a failure and people learn to
    ignore the tool; report it as nothing and they are surprised later.

WHY THE CHECKS ARE NOT ALL EXERCISED FOR REAL
    Several depend on Docker, a container, and a live service. The suite must
    keep running with none of them (CLAUDE.md §8), so the individual checks
    that touch the outside world are exercised through their pure parts and
    the aggregation logic is tested directly with substituted results.

    That is a real limit, stated rather than hidden: these tests prove the
    tool REPORTS correctly, not that every probe detects correctly. The probes
    were verified by hand against a genuinely stopped container.

These need neither Batfish nor Docker.
"""

from __future__ import annotations

import pytest

from tools import preflight


# ---------------------------------------------------------------------------
# The three-outcome rule
# ---------------------------------------------------------------------------


def _fake(label: str, status: str):
    return lambda: (label, status, "detail")


def test_all_required_passing_is_ready(monkeypatch, capsys):
    monkeypatch.setattr(preflight, "REQUIRED", [_fake("A", preflight.OK)])
    monkeypatch.setattr(preflight, "OPTIONAL", [_fake("B", preflight.OK)])

    code = preflight.run()

    assert code == 0
    assert "READY -- everything" in capsys.readouterr().out


def test_a_missing_optional_is_still_ready_but_says_what_it_costs(monkeypatch, capsys):
    """The row this tool exists to keep distinct.

    A missing Ollama is a designed degradation, not a broken install. It must
    not fail the run, and it must not be silent either.
    """
    monkeypatch.setattr(preflight, "REQUIRED", [_fake("A", preflight.OK)])
    monkeypatch.setattr(preflight, "OPTIONAL", [_fake("Ollama", preflight.MISSING)])

    code = preflight.run()
    out = capsys.readouterr().out

    assert code == 0, "an absent optional dependency must not fail the run"
    assert "READY" in out
    assert "Ollama" in out, "it must name what is absent, not just tolerate it"
    assert "optional item(s) absent" in out


@pytest.mark.parametrize("bad", [preflight.BROKEN, preflight.MISSING])
def test_a_failing_required_check_is_not_ready(monkeypatch, capsys, bad):
    monkeypatch.setattr(preflight, "REQUIRED", [_fake("Batfish", bad)])
    monkeypatch.setattr(preflight, "OPTIONAL", [])

    code = preflight.run()
    out = capsys.readouterr().out

    assert code == 1, f"a required check reporting {bad} must exit non-zero"
    assert "NOT READY" in out
    assert "Batfish" in out, "it must name which check failed"


def test_a_broken_required_check_is_not_masked_by_healthy_ones(monkeypatch, capsys):
    """The failure mode of a summary line: one bad row among several good.

    A tool that says READY because most things worked is worse than no tool.
    """
    monkeypatch.setattr(
        preflight,
        "REQUIRED",
        [_fake("A", preflight.OK), _fake("B", preflight.BROKEN), _fake("C", preflight.OK)],
    )
    monkeypatch.setattr(preflight, "OPTIONAL", [])

    assert preflight.run() == 1
    assert "NOT READY" in capsys.readouterr().out


def test_the_detail_is_printed_for_anything_not_ok(monkeypatch, capsys):
    """The fix is the entire value of this tool; printing only a status is useless."""
    monkeypatch.setattr(
        preflight, "REQUIRED",
        [lambda: ("Docker", preflight.BROKEN, "start Docker Desktop first")]
    )
    monkeypatch.setattr(preflight, "OPTIONAL", [])

    preflight.run()

    assert "start Docker Desktop first" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# The checks that can be exercised without Docker
# ---------------------------------------------------------------------------


def test_every_check_returns_the_documented_shape():
    """Each check returns (label, status, detail) and never raises.

    Run against the REAL environment, whatever it is -- so this passes on a
    machine with Docker and on one without, and would catch a check that
    crashes instead of reporting.
    """
    for check in preflight.REQUIRED + preflight.OPTIONAL:
        result = check()

        assert isinstance(result, tuple) and len(result) == 3, (
            f"{check.__name__} returned {result!r}, not (label, status, detail)"
        )
        label, status, detail = result
        assert isinstance(label, str) and label
        assert status in {preflight.OK, preflight.MISSING, preflight.BROKEN}, (
            f"{check.__name__} returned status {status!r}"
        )
        assert isinstance(detail, str) and detail, (
            f"{check.__name__} gave no detail; the fix is the point of the tool"
        )


def test_the_python_check_agrees_with_the_interpreter_running_it():
    label, status, detail = preflight.check_python()

    import sys
    assert f"{sys.version_info.major}.{sys.version_info.minor}" in detail


def test_dependencies_check_passes_here_because_the_suite_imported():
    """If this fails, the suite could not have run at all -- so it is a
    check on the CHECK, not on the environment."""
    label, status, detail = preflight.check_dependencies()

    assert status == preflight.OK, (
        f"the dependency check reports {status} while pytest is running with "
        f"those same packages importable: {detail}"
    )


def test_port_probe_is_honest_both_ways():
    """The primitive under every service check. If it answered yes to
    everything, three checks would report OK on a dead machine."""
    import socket

    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])
        assert preflight._port_open("127.0.0.1", port, timeout=2.0) is True

    # Same port, nothing listening now.
    assert preflight._port_open("127.0.0.1", port, timeout=1.0) is False
