"""Tests about the repository's own configuration files.

WHY THIS FILE EXISTS
    `.github/CODEOWNERS` had an entry for change-impact ownership in a comment
    -- "Shubham -- policy compliance and change impact" -- and no rule for the
    file, because the file did not exist when the comment was written. When
    `analysis/change_impact.py` landed on 17 August (#140) nothing noticed, and
    GitHub carried on routing its reviews to the catch-all.

    That is the same shape as `test_suite_hygiene.py`'s subject, moved into the
    configuration: a stated intention with nothing behind it. And CODEOWNERS
    fails in the quietest way an ops file can -- **a rule whose path matches no
    file is not an error.** GitHub does not warn. The Pull Request tab looks
    exactly the same. The only symptom is a review request that never arrives,
    which nobody notices because you cannot see the absence of a notification.

    So the paths get checked here, where a mistake is loud.

WHAT THIS DOES NOT DO
    It does not check that the *right* person owns a file -- that is a team
    judgement recorded in CLAUDE.md section 10, not something a test can hold
    an opinion about. It checks that every rule points at something real and
    that every owner is a real handle. Wrong-but-live beats right-but-dead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CODEOWNERS = REPO_ROOT / ".github" / "CODEOWNERS"

#: The four team members, as GitHub handles. From CLAUDE.md section 10.
KNOWN_OWNERS = {
    "@ARSH871-bot",
    "@patelankeet2",
    "@shubhamkataria2005",
    "@SamikaPerera",
}


def _codeowners_rules() -> list[tuple[int, str, list[str]]]:
    """(line number, pattern, owners) for every rule, skipping blanks/comments."""
    rules = []
    for number, raw in enumerate(CODEOWNERS.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        rules.append((number, parts[0], parts[1:]))
    return rules


def test_codeowners_exists_and_has_rules():
    assert CODEOWNERS.exists(), "CODEOWNERS is gone -- review routing is off"
    assert _codeowners_rules(), "CODEOWNERS has no rules, so it does nothing"


def test_every_codeowners_path_matches_something_real():
    """The failure this file was written for.

    A rule for a path that does not exist is silently ignored by GitHub. It
    reads as coverage and provides none.
    """
    missing = []
    for number, pattern, _owners in _codeowners_rules():
        if pattern == "*":
            continue
        target = REPO_ROOT / pattern.strip("/")
        if not target.exists():
            missing.append(f"line {number}: {pattern}")

    assert not missing, (
        "CODEOWNERS rules point at paths that do not exist, so GitHub ignores "
        "them and those reviews are routed to the catch-all instead:\n  "
        + "\n  ".join(missing)
    )


def test_every_codeowners_rule_has_at_least_one_owner():
    ownerless = [
        f"line {n}: {pat}" for n, pat, owners in _codeowners_rules() if not owners
    ]
    assert not ownerless, (
        "a CODEOWNERS rule with no owner silently removes the catch-all for "
        "that path, which is the opposite of what writing a rule looks like "
        "it does:\n  " + "\n  ".join(ownerless)
    )


def test_codeowners_names_only_real_team_handles():
    """A typo in a handle fails the same silent way a bad path does.

    Kept as an explicit set rather than a regex so that adding a fifth person
    is a deliberate edit to this list, with a reviewer, rather than something
    that arrives unnoticed.
    """
    unknown = set()
    for _n, _pat, owners in _codeowners_rules():
        unknown |= {o for o in owners if o not in KNOWN_OWNERS}

    assert not unknown, (
        f"CODEOWNERS names handles that are not on the team: {sorted(unknown)}. "
        "If someone joined, add them to KNOWN_OWNERS in this test as well."
    )


@pytest.mark.parametrize(
    "owned_path",
    [
        "analysis/findings.py",
        "analysis/pipeline.py",
        "analysis/change_impact.py",
        "ai/",
        "web/",
        "docs/finding-format.md",
    ],
)
def test_the_files_that_must_have_a_named_owner_have_one(owned_path):
    """Specific paths where the catch-all is not good enough.

    These are the shared contract, the backbone, and the three vertical
    slices' entry points. `analysis/change_impact.py` is in this list because
    it is the one that was missing -- a test that only checked the general
    rule would have passed on the day the gap existed.
    """
    patterns = {pattern.strip("/") for _n, pattern, _o in _codeowners_rules()}
    assert owned_path.strip("/") in patterns, (
        f"{owned_path} has no explicit CODEOWNERS rule, so its reviews go to "
        "the catch-all rather than to the person who owns it."
    )


def test_f1_contract_requires_all_four_reviewers():
    """CLAUDE.md section 7a: changing F-1 needs all four members.

    CODEOWNERS cannot enforce that -- without branch protection nothing is
    required (CONTRIBUTING section 6). It can still *request* all four, which
    is the difference between someone deciding not to wait and someone never
    knowing they should have.
    """
    for _n, pattern, owners in _codeowners_rules():
        if pattern.strip("/") == "docs/finding-format.md":
            assert set(owners) == KNOWN_OWNERS, (
                "docs/finding-format.md is the F-1 contract and needs all four "
                f"members requested; currently requests {sorted(owners)}"
            )
            return
    pytest.fail("no CODEOWNERS rule for docs/finding-format.md")


def test_dependabot_and_workflow_config_are_present():
    """Both are load-bearing and both are one deletion from being absent.

    Deliberately does not assert their contents. A test that pins the schedule
    or the Python matrix would fail every time someone legitimately tunes them,
    and a test people routinely edit to make it pass is worse than no test.
    """
    assert (REPO_ROOT / ".github" / "dependabot.yml").exists()
    assert (REPO_ROOT / ".github" / "workflows" / "tests.yml").exists()


def test_the_lint_step_pins_its_ruff_version():
    """CI comment explains why: a bare `pip install ruff` was clean on one
    machine and produced 207 errors on a newer release (#84). The pin is the
    fix, and an unpinned bare install would quietly undo it.
    """
    workflow = (REPO_ROOT / ".github" / "workflows" / "tests.yml").read_text(
        encoding="utf-8"
    )
    assert re.search(r'ruff==\d+\.\d+\.\d+', workflow), (
        "the CI lint step no longer pins a ruff version -- a new ruff release "
        "can then widen the rule set underneath the team, which is what #84 was"
    )
