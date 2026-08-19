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

import builtins
import os
import subprocess
import sys
from pathlib import Path

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


# ---------------------------------------------------------------------------
# check_dependency_versions -- "it imports" is not "it is what we declare"
# ---------------------------------------------------------------------------


def _fake_requirements(tmp_path, text: str, monkeypatch):
    """Point the check at a requirements.txt we control.

    The check locates the real file relative to its own __file__, so the
    redirect replaces that lookup rather than the file on disk.
    """
    req = tmp_path / "requirements.txt"
    req.write_text(text, encoding="utf-8")

    class _FakePath:
        def __init__(self, *_a, **_k):
            pass

        def resolve(self):
            return self

        @property
        def parent(self):
            return self

        def __truediv__(self, _other):
            return req

    monkeypatch.setattr(preflight, "Path", _FakePath)
    return req


def test_a_version_below_the_declared_floor_is_broken(tmp_path, monkeypatch):
    """The failure this check was written for.

    Measured on 17 August: five of seven packages did not satisfy
    requirements.txt while check_dependencies() reported "all importable",
    because every one of them imports perfectly well. CI installs the file on
    a clean machine, so CI and local were running different pandas majors and
    both were green.
    """
    _fake_requirements(tmp_path, "pytest>=9999.0.0\n", monkeypatch)
    label, status, detail = preflight.check_dependency_versions()
    assert label == "Package versions"
    assert status == preflight.BROKEN, "a version below the floor must not be OK"
    assert "pytest" in detail
    assert ">=9999.0.0" in detail


def test_versions_that_satisfy_the_file_are_ok(tmp_path, monkeypatch):
    _fake_requirements(tmp_path, "pytest>=0.0.1\n", monkeypatch)
    _label, status, _detail = preflight.check_dependency_versions()
    assert status == preflight.OK


def test_a_declared_package_that_is_absent_is_broken(tmp_path, monkeypatch):
    _fake_requirements(tmp_path, "definitely-not-installed-xyzzy>=1.0\n", monkeypatch)
    _label, status, detail = preflight.check_dependency_versions()
    assert status == preflight.BROKEN
    assert "not installed" in detail


def test_comments_and_blank_lines_are_ignored(tmp_path, monkeypatch):
    """requirements.txt in this project is mostly comments, and a check that
    choked on them would be abandoned within a day."""
    _fake_requirements(
        tmp_path,
        "# a comment\n\n   \npytest>=0.0.1  # trailing comment\n",
        monkeypatch,
    )
    _label, status, _detail = preflight.check_dependency_versions()
    assert status == preflight.OK


def test_it_reports_could_not_check_rather_than_ok_when_it_cannot_compare(
    tmp_path, monkeypatch
):
    """F-4 applied to the preflight tool itself.

    Version comparison needs `packaging`, which is not in requirements.txt. If
    it is absent, the honest answer is "I could not check" -- never a silent
    pass, and never a hand-rolled comparison that gets 0.9 vs 0.10 wrong.
    """
    _fake_requirements(tmp_path, "pytest>=0.0.1\n", monkeypatch)

    real_import = builtins.__import__

    def _no_packaging(name, *args, **kwargs):
        if name.startswith("packaging"):
            raise ImportError("no module named packaging")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_packaging)
    _label, status, detail = preflight.check_dependency_versions()
    assert status == preflight.BROKEN, "unable to compare must not report OK"
    assert "not run" in detail or "cannot compare" in detail


def test_the_version_check_is_required_not_optional():
    """An environment that does not match requirements.txt fails the exit
    code, because a local test run on it is not testing what CI tests."""
    assert preflight.check_dependency_versions in preflight.REQUIRED
    assert preflight.check_dependency_versions not in preflight.OPTIONAL
# Both invocation forms must reach the same conclusion (#172)
# ---------------------------------------------------------------------------
#
# THE BUG THIS DEFENDS, which was live on main and had no test
#     `python tools/preflight.py` puts tools/ on sys.path instead of the
#     repository root, so `import analysis` fails inside
#     check_batfish_service(). Before #172 that ImportError was caught by a
#     broad `except Exception` and reported as:
#
#         [ BROKEN ] Batfish service
#                    port is open but the service did not answer:
#                    ModuleNotFoundError: No module named 'analysis'
#
#     Batfish was fine. A sys.path problem was reported as a specific,
#     confident, wrong diagnosis -- in the one tool whose entire purpose is
#     attributing failures to the right cause. Somebody would have restarted
#     the container, watched it fail again, and gone looking at Docker.
#
# WHY THESE TESTS ARE SHAPED THIS WAY
#     `tests/test_preflight.py` imports preflight as a module, with the root
#     already on sys.path, so it CANNOT reproduce the broken invocation. That
#     is structural rather than an oversight: the failure only exists when the
#     file is run as a script from a shell.
#
#     So the first test runs both documented forms as real subprocesses and
#     asserts they agree. It needs no Batfish and no Docker:
#
#         Batfish up      both say OK                      -> agree
#         Batfish down    both say the port is not open    -> agree
#         sys.path broken module says one thing, script
#                         says "could not import"          -> DISAGREE, fails
#
#     The second test is a unit test for the other half of the fix: an import
#     failure must never be described as a service failure.
#
# A THIRD TEST WAS WRITTEN AND THEN REMOVED, WHICH IS WORTH RECORDING
#     It asserted that the script form never prints the original wording --
#     "did not answer" alongside a ModuleNotFoundError. It cost 6.3 seconds
#     per run, and when both halves of the fix were mutated it caught
#     NEITHER: the invocation test below catches the sys.path half, and the
#     unit test catches the attribution half. A subprocess test that fails
#     for no mutation is paying for coverage it does not provide, which is
#     the same standard tests/test_suite_hygiene.py applies to assertions.


def _batfish_line(output: str) -> str:
    """The Batfish service check's status and detail, as one string."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if "Batfish service" in line:
            detail = lines[i + 1].strip() if i + 1 < len(lines) else ""
            return (line + " " + detail).strip()
    return ""


def _status_of(line: str) -> str:
    for status in ("BROKEN", "MISSING", "OK"):
        if status in line:
            return status
    return "UNKNOWN"


def _run(args, cwd):
    """Run preflight in a subprocess with PYTHONPATH REMOVED.

    This matters more than it looks. The subprocess inherits the parent
    environment, and a developer who has exported PYTHONPATH=. gets the
    repository root on sys.path for free -- which papers over exactly the
    missing sys.path handling this test exists to detect.

    Found by mutation: with PYTHONPATH unset the mutation was caught, and
    with PYTHONPATH=. exported the same mutation passed. A guard that holds
    only against an unstated condition is the defect this whole file is
    about, so the condition is removed rather than assumed.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(cwd), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=180, env=env,
    )


def test_both_documented_invocations_agree_about_batfish():
    """The regression #172 fixed, and the one no existing test could reach.

    Both forms are documented -- the README gives the module form and refers
    to the file by path -- so both must work and both must reach the same
    conclusion about the same machine.
    """
    root = Path(preflight.__file__).resolve().parent.parent

    as_module = _run(["-m", "tools.preflight"], root)
    as_script = _run([str(Path("tools") / "preflight.py")], root)

    module_line = _batfish_line(as_module.stdout)
    script_line = _batfish_line(as_script.stdout)

    assert module_line, "module form produced no Batfish service line"
    assert script_line, "script form produced no Batfish service line"

    assert _status_of(module_line) == _status_of(script_line), (
        "the two documented ways of running preflight disagree about Batfish, "
        "which means one of them is reporting something about itself rather "
        "than about the service:\n"
        f"  python -m tools.preflight   {module_line}\n"
        f"  python tools/preflight.py   {script_line}"
    )


def test_an_import_failure_is_not_reported_as_a_service_failure(monkeypatch):
    """The other half of #172, as a unit test.

    Even with the sys.path fix in place, something else could break the
    import -- a broken install, a renamed package. When that happens the
    honest answer is that we could not check, not that Batfish is at fault.
    """
    monkeypatch.setattr(preflight, "_port_open", lambda *a, **k: True)

    real_import = builtins.__import__

    def _no_analysis(name, *args, **kwargs):
        if name.startswith("analysis"):
            raise ImportError("No module named 'analysis'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_analysis)

    label, status, detail = preflight.check_batfish_service()
    assert label == "Batfish service"
    assert status == preflight.BROKEN

    lowered = detail.lower()
    assert "did not answer" not in lowered, (
        "an import failure is being described as the service not answering: " + detail
    )
    assert "nothing" in lowered or "could not check" in lowered or "import" in lowered, (
        "the detail should say the import failed and that this says nothing "
        "about Batfish; got: " + detail
    )
