"""Every script in tools/ must work BOTH documented ways.

WHY THIS FILE EXISTS
    #172 fixed `python tools/preflight.py` failing to import the package, and
    #174 defended that fix with tests. Both were about `preflight.py`.

    `tools/` has three scripts. Probing all of them from the repository root,
    with PYTHONPATH stripped:

        script                as module   as script
        preflight.py          ok          ok                    (fixed by #172)
        stranger_config.py    ok          IMPORT FAILS
        pfsense_shape.py      --          --   (imports no package, unaffected)

    So the bug was still live in a second file for as long as it had been
    fixed in the first. That is this project's most reliable failure shape
    arriving in a new place: **a fix applied to the instance rather than to
    the property.** #58 fixed one converter refusal and a test now enforces
    the rule; #145's inversion was fixed for one evidence shape while three
    findings used the other.

    So this test does not name a script. It enumerates `tools/*.py` and holds
    every one of them to the rule, which means the next script anybody adds is
    covered on the day it lands rather than the day it breaks.

WHY IT ONLY REQUIRES IT OF SCRIPTS THAT IMPORT THE PACKAGE
    `pfsense_shape.py` deliberately imports nothing from `analysis/`, `ai/` or
    `web/` -- it reads XML and reports structure, and CLAUDE.md section 8 keeps
    tools/ out of the product's import graph on purpose. Demanding the guard
    there would be demanding a fix for a bug it cannot have.

WHAT "WORKS" MEANS HERE
    Only that the package becomes importable. These scripts talk to Docker,
    Batfish and the filesystem, so running them for real is not something a
    test suite that needs neither can do (CONTRIBUTING section 4a). The
    property under test is the sys.path mechanism, and that is checkable
    offline.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"

#: Scripts that import the product package, and so must carry the guard.
#: Derived rather than listed, so adding a tool cannot quietly opt out of this.
PACKAGE_IMPORTS = ("from analysis", "import analysis",
                   "from ai", "import ai",
                   "from web", "import web")


def _scripts() -> list[Path]:
    return sorted(p for p in TOOLS.glob("*.py") if p.name != "__init__.py")


def _imports_the_package(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    # Only lines that actually start an import -- a mention inside a docstring
    # or a comment is not an import and must not make a test demand a fix.
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith(PACKAGE_IMPORTS):
            return True
    return False


def _run(args: list[str]) -> subprocess.CompletedProcess:
    """Run from the repository root with PYTHONPATH REMOVED.

    Without stripping it, a shell that happens to export PYTHONPATH=. makes
    every invocation work and the test passes for a reason that has nothing
    to do with the code. That exact contamination made an earlier version of
    the #174 tests pass on one machine and fail on another.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )


def test_there_are_scripts_to_check():
    """Guard the guard.

    If `tools/` is ever moved or renamed, every parametrised test below would
    collect zero cases and the file would pass by testing nothing -- a green
    tick meaning "we checked and found nothing wrong" when it means "we did
    not check". That is F-4 wearing a pytest hat, and it is worth one
    assertion to keep it out.
    """
    assert _scripts(), f"no scripts found in {TOOLS} -- this file tests nothing"


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_a_tool_that_imports_the_package_carries_the_script_guard(script):
    """The property #172 fixed, required of the folder rather than one file.

    Checked statically as well as by execution below, because the static
    check names the missing line and so tells whoever added the script what
    to do, while a subprocess failure only says an import blew up.
    """
    if not _imports_the_package(script):
        pytest.skip(f"{script.name} imports nothing from the package, so the "
                    f"guard would be a fix for a bug it cannot have")

    source = script.read_text(encoding="utf-8")
    assert "__package__" in source and "sys.path.insert" in source, (
        f"{script.name} imports the product package but has no guard for the "
        f"script invocation. `python tools/{script.name}` will fail with "
        f"ModuleNotFoundError while `python -m tools.{script.stem}` works.\n\n"
        f"Add, after the imports:\n\n"
        f"    if __package__ in (None, ''):\n"
        f"        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))"
    )


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_both_invocations_make_the_package_importable(script):
    """Execute the mechanism rather than trusting the static check above.

    A script could carry both strings in a comment and still not work; this
    runs the file the way `python tools/x.py` does -- tools/ on sys.path,
    __package__ None -- and then imports the package.

    The probe strips the working directory from sys.path first. `python -c`
    puts the CURRENT DIRECTORY there and the real script form does not, so
    without stripping it the probe imports the package from the working
    directory and rescues the very fix it is meant to test. That mistake got
    past a round of review on #174 before it was caught.
    """
    if not _imports_the_package(script):
        pytest.skip(f"{script.name} imports nothing from the package")

    rel = f"tools/{script.name}"
    probe = (
        "import os, sys\n"
        "here = os.getcwd()\n"
        "sys.path = [q for q in sys.path if q not in ('', here, os.curdir)]\n"
        "sys.path.insert(0, os.path.join(here, 'tools'))\n"
        f"src = open({rel!r}, encoding='utf-8').read()\n"
        "ns = {'__name__': 'tool_probe',\n"
        f"      '__file__': os.path.abspath({rel!r}),\n"
        "      '__package__': None}\n"
        "try:\n"
        f"    exec(compile(src, {rel!r}, 'exec'), ns)\n"
        "except SystemExit:\n"
        # A tool that parses arguments at import time may exit; the guard has
        # already run by then, which is the only thing under test here.
        "    pass\n"
        "import analysis.pipeline\n"
        "print('IMPORT_OK')\n"
    )

    result = _run(["-c", probe])

    assert "IMPORT_OK" in (result.stdout or ""), (
        f"running {rel} the way `python {rel}` does left the package "
        f"unimportable.\n\nstdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
    )
