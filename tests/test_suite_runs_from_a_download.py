"""The suite must run from a copy downloaded as a ZIP, not only from a clone.

GitHub's "Download ZIP" gives every tracked file and no `.git` folder. On
21 October, running `pytest tests/` from exactly that download gave 20 red
failures, all in `test_no_configs_in_git.py`, and every one a false alarm:
those tests ask git what it ignores, and with no repository git cannot answer.
Two more passed there having checked nothing -- `git ls-files` lists no files
outside a repository, and `git check-ignore` says "not ignored" for every path.

So these tests copy that module somewhere with no `.git`, run it on its own,
and check what a person holding the ZIP would see. The last one is the
positive control: in a real checkout the git checks must still run, or a
broken checkout test would quietly skip constraint 1's guard everywhere.

These need neither Batfish nor Docker.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULE = "tests/test_no_configs_in_git.py"

#: Everything that module reads from the repository, apart from git itself.
NEEDS = [
    MODULE,
    ".gitignore",
    "README.md",
    "tests/fixtures/pfsense-source/config.xml",
]

#: The reason the module gives when it skips. Asserted on, so a skip for any
#: OTHER reason (a missing file, an import error) does not count as success.
SKIP_REASON = "not a git checkout"


def _download_like_copy(parent: Path) -> Path:
    """A folder holding what the ZIP holds for this module, and no .git."""
    copy = parent / "Netwise-main"
    for name in NEEDS:
        (copy / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / name, copy / name)
    return copy


def _run_module(folder: Path, ci: bool) -> tuple[int, str]:
    """Run the module from `folder` in a fresh pytest, as a user would."""
    env = {k: v for k, v in os.environ.items() if k != "CI"}
    if ci:
        env["CI"] = "true"  # what GitHub Actions sets
    result = subprocess.run(
        [sys.executable, "-m", "pytest", MODULE, "-q", "-rs",
         "-p", "no:cacheprovider"],
        cwd=folder, env=env, capture_output=True, text=True, timeout=300,
    )
    return result.returncode, result.stdout + result.stderr


def test_a_downloaded_copy_skips_the_git_checks_instead_of_failing(tmp_path):
    code, out = _run_module(_download_like_copy(tmp_path), ci=False)

    assert code == 0, out
    assert " failed" not in out and " error" not in out, out
    assert SKIP_REASON in out, out
    # The checks that need no git -- the config detector -- still ran.
    assert " passed" in out, out


def test_on_ci_a_missing_checkout_fails_rather_than_skips(tmp_path):
    """CI always runs from a checkout. If it ever does not, the guard has
    silently stopped running, and that must be red, not a quiet skip."""
    code, out = _run_module(_download_like_copy(tmp_path), ci=True)

    assert code != 0, out
    assert "CI is not running from a git checkout" in out, out


def test_a_copy_inside_some_other_repository_is_not_mistaken_for_ours(tmp_path):
    """Unzipped inside another git repository, git WOULD answer -- for that
    repository, whose tracked files and ignore rules are not ours."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    code, out = _run_module(_download_like_copy(tmp_path), ci=False)

    assert code == 0, out
    assert SKIP_REASON in out, out


def test_in_this_checkout_the_git_checks_really_run():
    """The positive control: in a real clone nothing is skipped."""
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("this copy is itself a download, not a git checkout")

    code, out = _run_module(REPO_ROOT, ci=False)

    assert code == 0, out
    assert SKIP_REASON not in out, out
    assert " skipped" not in out, out
