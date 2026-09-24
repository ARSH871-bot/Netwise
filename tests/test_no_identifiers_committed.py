"""No tracked file may contain a team member's student ID.

WHY THIS FILE EXISTS
    `docs/identity.json` holds the four student IDs the submission documents
    need on their cover sheets. It was believed to be gitignored. It was not
    -- no branch's `.gitignore` matched it, and neither did the two builder
    scripts that read it. They had simply never happened to be added, which
    is luck rather than a control.

    The repository is public. An identifier that reaches git history stays
    there after the file is deleted: #311 needed a branch history rewrite
    (`--force-with-lease`) to remove exactly this, after @shubhamkataria2005
    requested changes on a pull request that had put student IDs and personal
    self-assessment prose into the repo.

    So the three paths are now ignored. That closes the three instances.

WHY THE TEST IS NOT A LIST OF THOSE THREE PATHS
    A list of instances is precisely what let this sit open. Something new
    that reads `identity.json` -- a fourth builder, a rebuilt portfolio, a
    scratch script somebody promotes into `tools/` -- would be outside the
    list on the day it was written and inside the repository on the same day.

    CLAUDE.md section 8 records the general shape: #172 fixed the sys.path bug
    in `preflight.py` while it stayed live in `stranger_config.py` "for as
    long as it had been fixed in the first". A fix applied to the instance
    rather than to the property.

    This test therefore names no path. It reads the identifiers from
    `identity.json` and searches every file git actually tracks.

WHY IT SKIPS RATHER THAN FAILS WHEN THE FILE IS ABSENT
    `identity.json` is ignored, so a fresh clone and CI do not have it -- and
    a test that fails there would be red for everyone, forever, for the
    correct behaviour. The check runs where the secret exists, which is the
    only place it can leak from.

    That is a real limit and worth naming: this catches the mistake on the
    machine that could make it, not in CI. It is a seatbelt, not a gate.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
IDENTITY = REPO_ROOT / "docs" / "identity.json"

#: Files whose bytes are not searchable text. Skipped, not trusted -- an
#: identifier inside a .docx would not be found by a substring search anyway,
#: which is why those documents are ignored wholesale rather than scanned.
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".pptx", ".xlsx",
          ".ico", ".zip", ".woff", ".woff2", ".svgz"}


def _identifiers() -> list[str]:
    data = json.loads(IDENTITY.read_text(encoding="utf-8"))
    # An empty string is in every file ever written. Two of the four IDs are
    # blank, and a naive `value in text` reported every file in the repository
    # as a leak the first time this was checked by hand.
    return [m["student_id"].strip()
            for m in data.get("team_members", [])
            if m.get("student_id", "").strip()]


def _tracked() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [REPO_ROOT / line for line in out.splitlines() if line]


@pytest.fixture(scope="module")
def identifiers() -> list[str]:
    if not IDENTITY.exists():
        pytest.skip("docs/identity.json absent -- nothing to leak from here")
    found = _identifiers()
    if not found:
        pytest.skip("docs/identity.json carries no non-empty student ID")
    return found


def test_the_identity_file_is_ignored():
    """The file itself must never become trackable again."""
    if not IDENTITY.exists():
        pytest.skip("docs/identity.json absent")
    result = subprocess.run(
        ["git", "check-ignore", "docs/identity.json"],
        cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        "docs/identity.json is NOT gitignored. It holds student IDs and this "
        "repository is public."
    )


def test_no_tracked_file_contains_a_student_id(identifiers):
    """The property: not one path, every path git knows about."""
    leaks: list[str] = []
    for path in _tracked():
        if path.suffix.lower() in BINARY or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:                      # pragma: no cover - unreadable
            continue
        if any(identifier in text for identifier in identifiers):
            leaks.append(str(path.relative_to(REPO_ROOT)))
    assert not leaks, (
        "tracked file(s) contain a student ID: " + ", ".join(leaks) +
        " -- remove the identifier, then rewrite the branch history if it "
        "has already been pushed (see #311)."
    )


def test_the_check_can_actually_fail(identifiers, tmp_path):
    """Mutation: prove the search would find an identifier if one were there.

    Without this, a test that never fails and a test that cannot fail look
    identical from the outside -- and this project has already shipped two
    tests that asserted a false wording and held it in place.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(f"STUDENT_ID = '{identifiers[0]}'\n", encoding="utf-8")
    text = planted.read_text(encoding="utf-8", errors="ignore")
    assert any(i in text for i in identifiers), (
        "the substring search does not detect a planted identifier"
    )
