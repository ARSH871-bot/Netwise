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
    python -m tools.stranger_config      (either form works -- see below)
    python tools/stranger_config.py
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, List

# RUN AS A SCRIPT, NOT ONLY AS A MODULE.
#     The same fix #172 made to tools/preflight.py, and the reason it is here
#     is that #172 fixed the FILE rather than the property. `python -m
#     tools.stranger_config` puts the repository root on sys.path; `python
#     tools/stranger_config.py` puts tools/ there instead, so `from
#     analysis.pipeline import analyse` raised ModuleNotFoundError and the
#     script died before measuring anything.
#
#     Measured before the fix, from the repository root with PYTHONPATH
#     stripped so the shell could not rescue it:
#
#         script                as module   as script
#         preflight.py          ok          ok                      (#172)
#         stranger_config.py    ok          IMPORT FAILS
#
#     tests/test_tools_invocation.py now asserts this for every script in
#     tools/ that imports the package, so the next one added is covered
#     without anyone remembering this comment exists.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def _stranger_policy(destination: Path):
    """Build the policy a stranger would write for their OWN device.

    WHY THIS COLUMN EXISTS (#87, the vertical slice)
        The two columns above measure "their config, OUR policy", and that
        number is unchanged by the wiring -- correctly, because nothing about
        the no-policy case changed. Running this tool after the wiring and
        reporting "12/3/7 -> 3/0/15, unchanged" would be true and would miss
        the point entirely.

        The question the wiring answers is a different one: if the stranger
        ALSO supplies a policy naming their device, do the findings come back?
        So there is a third column, and it is the only one that can move.

    HOW THE POLICY IS BUILT, AND WHY THAT IS FAIR
        By taking our own rules and changing ONLY the device name to the one
        `_make_stranger_copy` produced. Nothing else differs, so the column
        isolates exactly the variable this issue is about. Writing a
        different policy would measure the policy, not the gap.

    It goes through `load_policy()`, not straight into the check, so this
    exercises the real validation path a user's file would take.
    """
    from analysis.checks import access_control, policy_compliance, routing
    from analysis.policy import load_policy

    names = set()
    for config in (destination / "configs").glob("*"):
        match = _HOSTNAME.search(config.read_text(encoding="utf-8"))
        if match:
            names.add(match.group(1))
    if not names:
        return None

    # One device per fixture in practice; if a fixture ever has more, bind
    # every rule to the first by sorted name so the result is deterministic.
    node = sorted(names)[0]

    # BOTH WIRED CHECKS, NOT JUST ONE (#316).
    #     This used to build a policy_compliance section and nothing else,
    #     because policy_compliance was the only check that read a user
    #     policy. `access_control` now does too, and a tool that supplies no
    #     access_control entries reports the same FOUND column whether that
    #     wiring works or not -- a blind spot, not a measurement.
    #
    #     The rule in this function's docstring is unchanged and is what
    #     keeps this honest: the policy is OURS with only the device name
    #     rebound. Both sections get the same transformation.
    #
    #     `routing` joined on #319, when its check started reading one. All
    #     three sections are now represented, which is what makes the third
    #     column a fair measurement of #87 rather than of two thirds of it.
    return load_policy({
        "policy_compliance": [
            dict(rule, node=node) for rule in policy_compliance.POLICY_RULES
        ],
        "access_control": [
            dict(statement, node=node) for statement in access_control.POLICY
        ],
        "routing": [
            dict(route, node=node) for route in routing.ROUTES
        ],
    })


def _counts(findings: List[Dict]) -> Counter:
    return Counter(f["status"] for f in findings)


def _fmt(counter: Counter) -> str:
    """found / none / error, in fixed columns.

    Module level rather than defined inside the loop: the TOTAL line below
    uses it, and a helper defined in a loop body does not exist if the loop
    never runs -- so a missing fixtures directory would turn a clean "nothing
    to measure" into a NameError.
    """
    return f"{counter['found']:>3} /{counter['none']:>3} /{counter['error']:>3}"


def _surviving_detections(findings: List[Dict]) -> List[str]:
    """The `found` findings, which is what a stranger actually gets told."""
    return [f"{f['id']} {f['summary']}" for f in findings if f["status"] == "found"]


def run() -> int:
    from analysis.pipeline import analyse  # imported late: needs pybatfish

    print("What Netwise finds on the same config, renamed (#87)")
    print("=" * 78)
    print(f"{'fixture':22} {'ours':>13}   {'stranger':>13}   "
          f"{'+ their policy':>15}")
    print(f"{'':22} {'f/n/e':>13}   {'our policy':>13}   {'f/n/e':>15}")
    print("-" * 78)

    total_ours = Counter()
    total_theirs = Counter()
    total_with_policy = Counter()
    survivors: Dict[str, List[str]] = {}

    for name in FIXTURES:
        source = FIXTURE_ROOT / name
        if not source.exists():
            print(f"{name:22} SKIPPED -- fixture not found")
            continue

        ours = analyse(str(source))
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / name
            _make_stranger_copy(source, destination)
            theirs = analyse(str(destination))

            # The third column: same config, same rules, THEIR device name.
            policy = _stranger_policy(destination)
            with_policy = (analyse(str(destination), policy=policy)
                           if policy is not None else [])

        a, b, c = _counts(ours), _counts(theirs), _counts(with_policy)
        total_ours.update(a)
        total_theirs.update(b)
        total_with_policy.update(c)
        survivors[name] = _surviving_detections(theirs)

        print(f"{name:22} {_fmt(a):>13}   {_fmt(b):>13}   {_fmt(c):>15}")

    print("-" * 78)
    print(
        f"{'TOTAL':22} {_fmt(total_ours):>13}   {_fmt(total_theirs):>13}   "
        f"{_fmt(total_with_policy):>15}"
    )

    print(
        "\nThe third column is #87's vertical slice: the SAME stranger's "
        "config,\nanalysed against a policy that names THEIR device instead "
        "of ours.\nOnly the device name differs from column one."
    )
    print(
        f"\n  policy-driven detections on a network that is not ours: "
        f"{total_theirs['found']} -> {total_with_policy['found']}"
    )
    print(
        "\n  READ THE ERROR COLUMN HONESTLY. It RISES in column three, and\n"
        "  that is an artifact of how this synthetic policy is built rather\n"
        "  than a regression. Our rules all name the filter `acl_in`, so on\n"
        "  the routing fixtures -- which have no such filter -- every rule\n"
        "  correctly reports 'could not check' instead of being skipped as\n"
        "  belonging to another device. A real stranger would not write\n"
        "  rules about a filter their config does not have.\n"
        "  The number that answers #87 is the FOUND column.\n"
        "\n  AND READ THE FOUND COLUMN THE SAME WAY (#319). Our two routing\n"
        "  assertions are about reachability between rtr-hq and rtr-branch.\n"
        "  Rebinding them onto a stranger's SINGLE router asks whether one\n"
        "  subnet reaches another across a device that spans neither, and\n"
        "  the answer is correctly no -- so RT-001 fires on every\n"
        "  single-router fixture, including the SECURE one. The check is\n"
        "  right; the assertion is one no real user would write about that\n"
        "  config.\n"
        "\n  Measured: 3 of the 13 found in column three are that rebinding.\n"
        "  Quote the smaller number. This tool exists to stop us overstating\n"
        "  what works on somebody else's network, and it would be a poor\n"
        "  joke for it to overstate the fix."
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
