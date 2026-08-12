"""Constraint 1 -- no real network configuration data is ever committed.

WHY THIS FILE EXISTS
    `CLAUDE.md` §5 lists this first and calls it non-negotiable, and
    `.gitignore` was deliberately the first commit of the project. Until now
    the entire enforcement was that file, and **nothing tested it**.

    That is this project's recurring failure family: a guarantee that holds
    against an unstated condition rather than one the repo enforces. Delete a
    line from `.gitignore`, or widen a negation, and nothing goes red. The
    damage is also the hard kind to undo -- once client data is in git history,
    removing it means rewriting history everyone has pulled.

    Audited 12 August. The directory rules are solid: `configs/`, `snapshots/`
    and `web/uploaded_configs/` ignore everything inside them regardless of
    extension. The gap is a config saved somewhere else under a name nobody
    listed:

        configs/no_extension_at_all      IGNORED
        router.cfg                       IGNORED
        export.xml                       IGNORED
        client-config.txt                COMMITTABLE   <--
        backup.bak                       COMMITTABLE   <--
        router-running-config            COMMITTABLE   <--

    The last one is not hypothetical -- `show running-config` output is
    routinely saved with no extension at all, and `git add -A` is used
    constantly in this project.

WHY THE FIX IS NOT `*.txt`
    That would ignore `requirements.txt`, which is committed and must be. The
    extension is a proxy for the thing we care about. So the second test below
    checks the thing itself: does any committed file *look like* a real network
    configuration?

These need neither Batfish nor Docker. They do need `git`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
    )


def _is_ignored(path: str) -> bool:
    """True if git would refuse to add this path. The file need not exist."""
    return _git("check-ignore", "-q", path).returncode == 0


# ---------------------------------------------------------------------------
# 1. The .gitignore rules themselves
# ---------------------------------------------------------------------------

# Paths that MUST stay ignored. Each is a plausible place real client data
# lands, not an invented one: `configs/` is where CLAUDE.md tells people to put
# it, `web/uploaded_configs/` is where the dashboard writes uploads, and the
# bare extensions cover a file dropped anywhere in the tree.
MUST_BE_IGNORED = [
    "configs/router.cfg",
    "configs/no_extension_at_all",
    "configs/deep/nested/anything.txt",
    "web/uploaded_configs/current/config.xml",
    "web/uploaded_configs/anything",
    "snapshots/snap/configs/device.cfg",
    "router.cfg",
    "firewall.conf",
    "export.xml",
    "backup.pfsense",
    ".env",
    ".env.local",
    "private.pem",
    "server.key",
]


@pytest.mark.parametrize("path", MUST_BE_IGNORED)
def test_config_and_secret_paths_stay_ignored(path: str):
    """One deleted .gitignore line is all this protects against, and that is
    exactly the change nobody would notice in review."""
    assert _is_ignored(path), (
        f"{path!r} is NOT ignored by git. Constraint 1 says no configuration "
        "data is ever committed, and .gitignore is the whole of that "
        "enforcement -- check whether a line was removed or a negation widened."
    )


def test_the_committed_fixtures_are_still_the_deliberate_exception():
    """The negations must keep working, or the test suite loses its inputs.

    `tests/fixtures/` is the single documented exception to constraint 1
    (CLAUDE.md §7b) -- we invented those configs and they describe nobody's
    real network. If the negation broke, the fixtures would silently stop
    being tracked, which is a different failure but still a failure.
    """
    assert not _is_ignored("tests/fixtures/rtr-us5-secure/configs/rtr-us5.cfg")
    assert not _is_ignored("tests/fixtures/pfsense-source/config.xml")

    tracked = set(_git("ls-files", "tests/fixtures").stdout.split())
    assert any(f.endswith(".cfg") for f in tracked), "no .cfg fixture is tracked"
    assert any(f.endswith(".xml") for f in tracked), "no .xml fixture is tracked"


def test_the_ignore_check_can_actually_fail():
    """Proof this guard is not vacuously green.

    `check-ignore` returning 0 for everything -- a bad path, a wrong repo root
    -- would make every assertion above pass while checking nothing. So pin a
    path that must NOT be ignored.
    """
    assert not _is_ignored("README.md"), (
        "README.md reports as ignored, so _is_ignored() is answering yes to "
        "everything and the assertions above prove nothing"
    )


# ---------------------------------------------------------------------------
# 2. The thing the extensions are a proxy for
# ---------------------------------------------------------------------------

#: Signatures of a real device configuration. Deliberately specific: `hostname`
#: alone appears in scripts that GENERATE config, so a single hit means
#: nothing.
_SIGNATURES = {
    "cisco-acl": re.compile(r"^\s*ip access-list (standard|extended) ", re.M),
    "cisco-interface": re.compile(
        r"^\s*interface (GigabitEthernet|FastEthernet|Vlan)\S*", re.M
    ),
    "cisco-hostname": re.compile(r"^\s*hostname \S+", re.M),
    "pfsense": re.compile(r"<pfsense>", re.I),
}

#: Two distinct signatures, not one. Measured across all 66 tracked files:
#: every real fixture config scores 2-3, while the two source files that merely
#: mention config syntax score exactly 1. The threshold is the gap in that
#: measurement rather than a guess.
_MINIMUM_SIGNATURES = 2

#: Python is skipped because `analysis/pfsense_convert.py` exists to EMIT Cisco
#: configuration and will always look like one. That is a real hole -- a config
#: pasted into a `.py` file would pass -- accepted because it is implausible
#: and would be glaring in review, whereas `router-running-config` sitting in
#: the working directory is neither.
_SKIP_SUFFIXES = {".py"}


def _looks_like_a_device_config(text: str) -> list:
    return sorted(n for n, r in _SIGNATURES.items() if r.search(text))


def test_no_committed_file_outside_fixtures_looks_like_a_real_config():
    """Catches the extension holes without ignoring requirements.txt.

    This is the test that would have caught the client's PF Sense export if it
    had ever been committed -- regardless of what it was named.
    """
    offenders = {}

    for name in _git("ls-files").stdout.split():
        if name.startswith("tests/fixtures/"):
            continue  # the documented exception, CLAUDE.md §7b
        path = REPO_ROOT / name
        if path.suffix in _SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        matched = _looks_like_a_device_config(text)
        if len(matched) >= _MINIMUM_SIGNATURES:
            offenders[name] = matched

    assert not offenders, (
        "these committed files look like real network configuration:\n  "
        + "\n  ".join(f"{n}  {m}" for n, m in sorted(offenders.items()))
        + "\n\nConstraint 1: no configuration data is ever committed. If this "
        "is a synthetic config for testing, it belongs in tests/fixtures/."
    )


def test_the_detector_catches_a_config_planted_outside_fixtures(tmp_path: Path):
    """The guard aimed at itself, by calling it rather than copying it.

    Without this, the scan above could match nothing -- a broken `ls-files`
    call, a wrong root, a regex that never fires -- and pass while checking
    nothing at all. That is the empty-result-reads-as-good-news pattern.
    """
    planted = (
        "hostname rtr-client\n"
        "!\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n"
        "!\n"
        "ip access-list extended acl_in\n"
        " permit ip any any\n"
    )

    matched = _looks_like_a_device_config(planted)
    assert len(matched) >= _MINIMUM_SIGNATURES, (
        f"the detector scored a real Cisco config at only {len(matched)} "
        f"signature(s) ({matched}); it would not be caught"
    )

    # And the other half: source that merely mentions config syntax must not
    # trip it, or the guard gets switched off.
    mentions_only = 'CISCO_TEMPLATE = "hostname {name}\\n"\n'
    assert len(_looks_like_a_device_config(mentions_only)) < _MINIMUM_SIGNATURES
