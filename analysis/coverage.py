"""Mechanical coverage statements derived from F-1 findings (#235).

This module does not decide whether the network is safe. It only restates the
part of the finding contract a reader otherwise has to infer: which reported
check/device pairs produced evidence, and which ones were blind spots.

The important asymmetry is deliberate:

* status="found" and status="none" both mean a check ran and produced a
  definite result for the device named by the finding.
* status="error" means Netwise could not check something. That row must remain
  visible even when the main finding sections are skimmed, exported, or sorted
  elsewhere.

CONVERSION GAPS ARE A SEPARATE THING FROM A CHECK GAP, AND THEY ARE PASSED IN
SEPARATELY RATHER THAN INFERRED (#302 review, @SamikaPerera)
    A finding-based gap means a CHECK could not run. A conversion gap means
    part of the SOURCE FILE was never turned into anything a check could see
    at all -- today, a pfSense rule `analysis/pfsense_convert.py` could not
    convert (#78). Neither this module nor its caller can derive that from
    the findings list, because a converter-excluded rule leaves no finding
    behind to derive it from -- that is exactly the gap.

    Before this parameter existed, `summarise()` had no way to know a
    conversion had dropped anything, so a config with every CHECK running
    cleanly reported "Every reported check ran. Nothing was skipped." even
    when real rules from the uploaded file were never analysed. Not false
    about the checks -- every one of them did run -- but read by a person as
    a single claim, and the wrong one: skipping a `pass` rule makes the
    emitted config STRICTER than the real device, which can make a policy
    check that should report a violation report `none` instead. See
    `CLAUDE.md` section 7 for the direction analysis. A reader who trusted
    "nothing was skipped" would have no way to know that risk exists for
    this specific report.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple


def _label(finding: Dict[str, Any]) -> Tuple[str, str]:
    return (
        str(finding.get("check") or "unknown"),
        str(finding.get("device") or "unknown"),
    )


def summarise(
    findings: Iterable[Dict[str, Any]],
    conversion_gaps: Sequence[str] = (),
) -> Dict[str, Any]:
    """Return the coverage/certainty view implied by a findings list.

    `conversion_gaps` is optional and additive -- omitting it reproduces this
    function's exact prior behaviour, so every existing caller keeps working
    unchanged. Pass it when the findings came from a converted config and the
    converter excluded anything, so the statement below can stop claiming
    nothing was skipped when something genuinely was -- just not something a
    check could have reported on.

    The result is intentionally plain dicts, matching the rest of the analysis
    layer's F-1 data. It is derived, not cached; if the findings change, the
    coverage statement changes with them.
    """
    checked: set[Tuple[str, str]] = set()
    gaps: List[Dict[str, str]] = []

    for finding in findings:
        check, device = _label(finding)
        status = finding.get("status")

        if status in {"found", "none"}:
            checked.add((check, device))
            continue

        if status != "error":
            continue

        evidence = finding.get("evidence") or {}
        gaps.append({
            "check": check,
            "device": device,
            "summary": str(finding.get("summary") or "The check could not run"),
            "detail": str(evidence.get("detail") or ""),
            "source": str(evidence.get("source") or ""),
        })

    checked_rows = [
        {"check": check, "device": device}
        for check, device in sorted(checked)
    ]
    conversion_gap_rows = [str(note) for note in conversion_gaps]

    if not checked and not gaps:
        # THE THIRD STATE, AND IT IS NOT COMPLETENESS.
        #     An empty findings list is not "everything ran and nothing was
        #     skipped" -- it is "nobody looked". Saying the former under a
        #     green heading is F-4 arriving one layer up from the findings:
        #     "we checked and found nothing" and "we could not check" are
        #     different claims, and an absence of findings is neither.
        complete = False
        statement = (
            "No check reported a result, so this report makes no claim about "
            "coverage. Nothing here says the configuration was examined."
        )
    elif gaps:
        one = len(gaps) == 1
        statement = (
            f"{len(gaps)} reported check/device blind spot"
            f"{'' if one else 's'} {'remains' if one else 'remain'}. "
            f"Findings may be incomplete."
        )
        complete = False
    elif conversion_gap_rows:
        # THE CASE #302's REVIEW FOUND. Every check ran and none of them
        # reported a blind spot -- but that is a claim about the checks,
        # not about the file. Complete is False here on purpose: this
        # report cannot say analysis was exhaustive when part of the
        # source file was excluded before any check ever saw it.
        one = len(conversion_gap_rows) == 1
        statement = (
            f"Every reported check ran, but {len(conversion_gap_rows)} part"
            f"{'' if one else 's'} of the uploaded configuration could not "
            f"be converted and {'was' if one else 'were'} not included in "
            f"this analysis."
        )
        complete = False
    else:
        statement = "Every reported check ran. Nothing was skipped."
        complete = True

    return {
        "complete": complete,
        "statement": statement,
        "checked": checked_rows,
        "gaps": gaps,
        "conversion_gaps": conversion_gap_rows,
    }
