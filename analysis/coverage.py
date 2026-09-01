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
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def _label(finding: Dict[str, Any]) -> Tuple[str, str]:
    return (
        str(finding.get("check") or "unknown"),
        str(finding.get("device") or "unknown"),
    )


def summarise(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the coverage/certainty view implied by a findings list.

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

    if gaps:
        statement = (
            f"{len(gaps)} reported check/device blind spot"
            f"{'' if len(gaps) == 1 else 's'} remain. Findings may be incomplete."
        )
    else:
        statement = "Every reported check ran. Nothing was skipped."

    return {
        "complete": not gaps,
        "statement": statement,
        "checked": checked_rows,
        "gaps": gaps,
    }
