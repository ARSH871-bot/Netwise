"""Measure what Netwise actually does for a network that is not ours (#87).

WHY THIS EXISTS
    `README.md` and `CLAUDE.md` both quote one number for the policy gap:

        our device name      6 findings
        a stranger's name    3 findings

    That is a real measurement and it is the **best case**. It comes from
    `rtr-us5-messy`, which happens to carry three flaws that need no policy at
    all -- two dead ACL rules and a reference to an ACL that does not exist.
    Quoting it alone understates the gap, and #87 is the largest gap in the
    product, so it deserves better evidence than its friendliest data point.

    This measures every fixture instead of one, so the claim in the report is
    a range rather than an anecdote.

WHAT IT DOES
    Copies a fixture, renames every device in it, and runs the same pipeline
    over both. Nothing else changes: same rules, same topology, same planted
    flaws, same Batfish. The only difference is whether our hardcoded policy
    happens to name the device.

    Fixtures are copied to a temporary directory and never modified in place.

WHY IT IS IN tools/ AND NOT tests/
    It needs a running Batfish. The pytest suite deliberately needs neither
    Batfish nor Docker (CONTRIBUTING section 4a), and that property is worth
    more than this check being automatic. So it is a helper you run by hand,
    like `pfsense_shape.py` and `preflight.py`.

WHAT TO DO WITH THE RESULT
    Two things, and the second matters more.

    Before #87: this is the honest description of what a stranger gets.

    After #87: re-run it. The `stranger` column should move. If it does not,
    whatever was built did not solve the problem it was built for -- which is
    exactly the kind of claim this project has learned to measure rather than
    assume.

RUN
    python -m tools.stranger_config
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, List

FIXTURE_ROOT = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

#: Every fixture the pipeline can read. `unparseable` is excluded on purpose:
#: it produces three errors either way, so renaming its device measures
#: nothing. `pfsense-source` is for the converter, not the pipeline.
FIXTURES = [
    "rtr-us5-insecure",
    "rtr-us5-messy",
    "rtr-us5-secure",
    "routing-secure",
    "routing-missing-route",
]

_HOSTNAME = re.compile(r"(?m)^hostname\s+(\S+)")


def _make_stranger_copy(source: Path, destination: Path) -> None:
    """Copy a fixture and rename every device inside it.

    Renaming the hostname is the whole intervention. It is enough because
    every policy assertion in this project binds to a device NAME -- see
    `access_control`, `policy_compliance` and `routing`, which name `rtr-us5`
    and `rtr-hq`/`rtr-branch` literally.
    """
    shutil.copytree(source, destination)
    for config in (destination / "configs").glob("*"):
        text = config.read_text(encoding="utf-8")
        config.write_text(_HOSTNAME.sub(r"hostname stranger-\1", text), encoding="utf-8")


def _counts(findings: List[Dict]) -> Counter:
    return Counter(f["status"] for f in findings)


def _surviving_detections(findings: List[Dict]) -> List[str]:
    """The `found` findings, which is what a stranger actually gets told."""
    return [f"{f['id']} {f['summary']}" for f in findings if f["status"] == "found"]


def run() -> int:
    from analysis.pipeline import analyse  # imported late: needs pybatfish

    print("What Netwise finds on the same config, renamed (#87)")
    print("=" * 78)
    print(f"{'fixture':24} {'ours f/n/e':>14}   {'stranger f/n/e':>14}")
    print("-" * 78)

    total_ours = Counter()
    total_theirs = Counter()
    survivors: Dict[str, List[str]] = {}

    for name in FIXTURES:
        source = FIXTURE_ROOT / name
        if not source.exists():
            print(f"{name:24} SKIPPED -- fixture not found")
            continue

        ours = analyse(str(source))
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / name
            _make_stranger_copy(source, destination)
            theirs = analyse(str(destination))

        a, b = _counts(ours), _counts(theirs)
        total_ours.update(a)
        total_theirs.update(b)
        survivors[name] = _surviving_detections(theirs)

        def fmt(c: Counter) -> str:
            return f"{c['found']:>3} /{c['none']:>3} /{c['error']:>3}"

        print(f"{name:24} {fmt(a):>14}   {fmt(b):>14}")

    print("-" * 78)
    print(
        f"{'TOTAL':24} {total_ours['found']:>3} /{total_ours['none']:>3} /"
        f"{total_ours['error']:>3}   {total_theirs['found']:>3} /"
        f"{total_theirs['none']:>3} /{total_theirs['error']:>3}"
    )

    print("\nWhat still gets detected on a stranger's config:")
    any_found = False
    for name, found in survivors.items():
        for line in found:
            print(f"  {name:24} {line}")
            any_found = True
    if not any_found:
        print("  (nothing)")

    # The one property that must hold regardless of how #87 is answered.
    # A stranger must never be shown a green tick, because nothing was checked.
    if total_theirs["none"] > 0:
        print(
            f"\n*** F-4 VIOLATION: {total_theirs['none']} 'checked clean' finding(s) "
            "on a config whose devices we know nothing about. A stranger is being "
            "told a check passed when it never ran."
        )
        return 1

    print(
        f"\nF-4 holds: {total_theirs['none']} 'checked clean' findings on a "
        f"stranger's config, and {total_theirs['error']} 'could not check'. "
        "The tool is useless here, but it is not lying."
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
