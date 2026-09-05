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
    # Deliberately NOT a .docx: *.docx is already ignored globally, so a
    # .docx case here would pass with the folder rule deleted and would
    # be testing a different line. These three are caught by nothing else.
    "docs/Feedback/anything-a-marker-wrote.pdf",
    "docs/Feedback/marker-notes-with-my-student-id.txt",
    "docs/Feedback/scan-of-a-marked-script.png",
    "scratchpad/client-export-with-no-extension",
    "scratchpad/notes-about-a-real-firewall.md",
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

#: DEFINITIVE signatures -- one is enough, because nothing legitimate contains
#: them.
#:
#: This split exists because the first version of this file had a single
#: threshold of two, and @shubhamkataria2005 found the hole on #98: a PF Sense
#: export trips exactly ONE signature, since the other three are Cisco-specific
#: and never match XML. So the threshold was calibrated on Cisco configs and
#: silently exempted the entire PF Sense format -- **the client's actual
#: firewall, in the actual format he sends.** The docstring below claimed the
#: opposite, which makes it the third claim this week that was asserted rather
#: than re-run.
#:
#: Measured before splitting, across all 67 tracked files: exactly one non-`.py`
#: file contains `<pfsense>`, and it is the fixture that is already exempt. So
#: treating it as sufficient on its own produces zero false positives today.
_DEFINITIVE_SIGNATURES = {
    "pfsense": re.compile(r"<pfsense>", re.I),
}

#: WEAK signatures -- each can appear in prose or in code that generates config,
#: so two are required together.
#:
#: Measured across all tracked files: every real Cisco fixture scores 2-3 of
#: these, while source files that merely mention config syntax score exactly 1.
#: The threshold is the gap in that measurement rather than a guess.
_WEAK_SIGNATURES = {
    "cisco-acl": re.compile(r"^\s*ip access-list (standard|extended) ", re.M),
    "cisco-interface": re.compile(
        r"^\s*interface (GigabitEthernet|FastEthernet|Vlan)\S*", re.M
    ),
    "cisco-hostname": re.compile(r"^\s*hostname \S+", re.M),
}

_MINIMUM_WEAK_SIGNATURES = 2

#: Python is skipped because `analysis/pfsense_convert.py` exists to EMIT Cisco
#: configuration and will always look like one. That is a real hole -- a config
#: pasted into a `.py` file would pass -- accepted because it is implausible
#: and would be glaring in review, whereas `router-running-config` sitting in
#: the working directory is neither.
_SKIP_SUFFIXES = {".py"}


def _looks_like_a_device_config(text: str) -> list:
    """Return the matched signature names if this text is a device config.

    Empty list means it is not. One DEFINITIVE match is enough; weak matches
    need `_MINIMUM_WEAK_SIGNATURES` of them together.
    """
    definitive = sorted(n for n, r in _DEFINITIVE_SIGNATURES.items() if r.search(text))
    weak = sorted(n for n, r in _WEAK_SIGNATURES.items() if r.search(text))

    if definitive:
        return definitive + weak
    if len(weak) >= _MINIMUM_WEAK_SIGNATURES:
        return weak
    return []


def test_no_committed_file_outside_fixtures_looks_like_a_real_config():
    """Catches the extension holes without ignoring requirements.txt.

    Catches the client's PF Sense export regardless of what it was named --
    but only since #98's review. The first version of this file made that
    claim while a flat threshold of two silently exempted the entire PF Sense
    format; see `test_the_detector_catches_the_clients_pfsense_format`.
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
        if matched:
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
    assert matched, "a real Cisco config was not detected at all"
    assert len(matched) >= _MINIMUM_WEAK_SIGNATURES, (
        f"the detector scored a real Cisco config at only {len(matched)} "
        f"signature(s) ({matched}); it would not be caught"
    )

    # And the other half: source that merely mentions config syntax must not
    # trip it, or the guard gets switched off.
    mentions_only = 'CISCO_TEMPLATE = "hostname {name}\\n"\n'
    assert not _looks_like_a_device_config(mentions_only)


def test_the_detector_catches_the_clients_pfsense_format():
    """The case the first version of this file got wrong -- and claimed it did not.

    Found by @shubhamkataria2005 on #98. A PF Sense export trips exactly ONE
    signature, because the other three are Cisco-specific and never match XML.
    With a flat threshold of two, the file that would do the most real damage
    -- the client's actual firewall, in the actual format he sends, under a
    name `.gitignore` does not cover -- was the single case that walked
    through. The docstring above claimed the opposite.

    Measured on the real fixture before the fix:

        signatures matched: ['pfsense']   count 1   threshold 2   -> NOT CAUGHT

    `<pfsense>` is now definitive: one match is enough. Safe because nothing
    legitimate contains it -- across all 67 tracked files exactly one non-.py
    file does, and it is the fixture already exempt for living under
    tests/fixtures/.
    """
    real_pfsense = (
        REPO_ROOT / "tests" / "fixtures" / "pfsense-source" / "config.xml"
    ).read_text(encoding="utf-8", errors="ignore")

    assert _looks_like_a_device_config(real_pfsense), (
        "the client's PF Sense format is not detected as a configuration at all"
    )

    # Specifically: ONE definitive hit is sufficient. That is the whole point
    # of the split -- a flat threshold would still need two.
    assert _looks_like_a_device_config("<pfsense><version>21.7</version></pfsense>") == [
        "pfsense"
    ]
