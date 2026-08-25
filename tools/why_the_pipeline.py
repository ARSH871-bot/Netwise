"""Why the pipeline is engineering and not plumbing -- a runnable proof.

THE CLAIM
    Batfish has no concept of "we could not check". It answers, or it raises.
    So a check that fails contributes NOTHING to the results -- and nothing
    is indistinguishable from "no problems found".

    Every green tick this product shows depends on a distinction the
    analysis engine does not have and cannot make. `analysis/pipeline.py`
    is where that distinction is created.

WHAT THIS DEMONSTRATES
    Two failure shapes, each with the guard on and off:

        a check that RAISES     -> without the guard: the run dies, or the
                                   check silently contributes nothing
        a check that RETURNS [] -> without the guard: silence, which reads
                                   as "found nothing wrong"

    With the guards, both become a status="error" finding the user can see:
    an amber "could not check", never a green tick.

WHY IT NEEDS NEITHER BATFISH NOR OLLAMA
    The broken checks fail before they touch the session, so this runs in
    about a second on any machine. That is deliberate: a demonstration
    nobody can run is a claim, not a proof.

RUN
    python -m tools.why_the_pipeline      (either form works)
    python tools/why_the_pipeline.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# RUN AS A SCRIPT, NOT ONLY AS A MODULE -- #172/#176.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import pipeline  # noqa: E402

RULE = "=" * 74


def a_check_that_crashes(bf):
    """The realistic failure: a check hits something it did not expect.

    Not contrived -- this is a KeyError of the kind a malformed policy
    entry produced in #181, and a renamed ACL would produce tomorrow.
    """
    raise KeyError("queries")


def a_check_that_returns_nothing(bf):
    """The quieter failure, and the more dangerous one.

    The check runs to completion and returns an empty list. No exception,
    no log line, nothing to notice.
    """
    return []


def _summarise(findings_list):
    """What the DASHBOARD would show for this list."""
    if not findings_list:
        return "nothing at all -- an empty results list"
    parts = []
    for finding in findings_list:
        parts.append(f"{finding['id']} {finding['status']}: "
                     f"{finding['summary'][:56]}")
    return "\n              ".join(parts)


def _without_the_guard(check, name):
    """What a pipeline that merely COLLECTED results would produce.

    HONEST ABOUT WHAT THIS IS
        This is a re-implementation of the naive collector, NOT the real
        `run_check()` with its guards deleted. It shows what a different
        function would do. That is a weaker claim than it looks, and this
        project has been caught by that exact distinction more than once,
        so it is stated rather than glossed.

        The stronger claim is checked separately, by removing each guard
        from the real function and running the suite:

            the crash guard removed     1 failed
            the silence guard removed   2 failed

        Identical with Batfish up and down. So the guards are pinned by
        tests, and the columns below are an illustration of why they
        matter rather than the evidence that they hold.
    """
    collected = []
    try:
        collected.extend(check(None) or [])
    except Exception:
        # A collector that also swallowed the exception -- the variant that
        # keeps the run alive and is therefore the tempting one to write.
        pass
    return collected


def main() -> int:
    print(RULE)
    print("WHY THE PIPELINE IS NOT PLUMBING")
    print(RULE)
    print("  Batfish answers, or it raises. It has no way to say")
    print("  \"I could not check this\". That distinction is created here.")

    cases = [
        ("a check that CRASHES", a_check_that_crashes,
         "a KeyError of the kind #181's malformed policy produced"),
        ("a check that RETURNS NOTHING", a_check_that_returns_nothing,
         "runs to completion, returns [], nothing to notice"),
    ]

    failures = 0
    for label, check, why in cases:
        print(f"\n{RULE}")
        print(f"{label}")
        print(f"  ({why})")
        print(RULE)

        # --- the "before" -------------------------------------------------
        before = _without_the_guard(check, label)
        print("\n  WITHOUT the pipeline's guards -- just collect what comes back:")
        print(f"      findings returned : {len(before)}")
        print(f"      dashboard shows   : {_summarise(before)}")
        print("      the user concludes: NO PROBLEMS FOUND")

        # --- the real thing -----------------------------------------------
        original = dict(pipeline.CHECKS)
        try:
            pipeline.CHECKS["demo_check"] = check
            # run_check needs a registered name; access_control is a real
            # one, so borrow its slot rather than inventing a check name
            # findings.py would reject.
            pipeline.CHECKS["access_control"] = check
            after = pipeline.run_check(None, "access_control")
        finally:
            pipeline.CHECKS.clear()
            pipeline.CHECKS.update(original)

        print("\n  WITH them:")
        print(f"      findings returned : {len(after)}")
        print(f"      dashboard shows   : {_summarise(after)}")

        statuses = {f["status"] for f in after}
        honest = statuses == {"error"}
        print(f"      the user concludes: "
              f"{'COULD NOT CHECK -- amber, not a green tick' if honest else '??'}")
        if not honest:
            failures += 1

    print(f"\n{RULE}")
    print("THE POINT")
    print(RULE)
    print("  In every row above, the LEFT column is what Batfish gives you and")
    print("  the RIGHT column is what Netwise gives you. Batfish did not")
    print("  change. The difference is entirely code we wrote:")
    print()
    print("      analysis/pipeline.py   run_check()      the two guards")
    print("      analysis/findings.py   error_finding()  the third status")
    print("      docs/finding-format.md F-4              the rule itself")
    print()
    print("  A check that cannot run must never look like a check that ran")
    print("  and found nothing. Nothing in Batfish enforces that, because")
    print("  Batfish has no third answer to give.")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
