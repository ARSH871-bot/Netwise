"""Netwise -- risk prioritisation (Samika's feature).

THE RULESET IS docs/severity-rules.md. That document is the decision record and
this module is the implementation; if they disagree, one of them is a bug.

THIS IS NOT A CHECK -- IT IS A POST-PROCESSOR
    The second of the three shapes in docs/design/pipeline-feature-shapes.md:

        def refine(results: list[dict]) -> list[dict]

    It gets the COMBINED findings from every check that ran, not a Batfish
    session. That is the whole reason the shape exists. Registered as a check,
    `risk` would be handed a `Session` and be the one feature unable to see the
    thing it is meant to prioritise.

    So it is registered in POST_PROCESSORS, never in CHECKS.

WHAT IT DOES
    Re-rates `severity` on status="found" findings by the documented rules, then
    sorts worst-first. Nothing else. It never reads a config, never calls
    Batfish, and never asks a model anything -- severity is a judgement, and
    docs/finding-format.md is explicit that the AI does not make it.

WHAT IT DELIBERATELY LEAVES ALONE
    status="error" findings, entirely. An unrunnable check is a blind spot
    whatever a rule says about the device, and a scoring pass holds no
    information about whether a check ran. pipeline.run_post_processors()
    enforces this too -- but code that relies on being caught is code that is
    wrong and merely supervised, so the rules below simply never touch them.
"""

from typing import Any, Callable, Dict, List, Optional

CHECK_NAME = "risk"

# Sort order. Worst first, so a LOWER number sorts earlier.
_STATUS_RANK = {"error": 0, "found": 1, "none": 2}
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


# --- The rules --------------------------------------------------------------
#
# Each returns a severity if it applies, or None to pass. They are applied in
# the order listed in _RULES, and the FIRST match wins.
#
# Every rule reads only the finding it is given. No shared state, no lookups,
# no network -- so any re-rating can be recomputed by hand from the finding
# alone, which is what makes this ruleset auditable without a log.


def _evidence(finding: Dict[str, Any]) -> str:
    """The finding's evidence detail, lowercased, safe on a malformed finding."""
    evidence = finding.get("evidence") or {}
    return str(evidence.get("detail", "")).lower()


def _rule_dead_rule_is_low(finding: Dict[str, Any]) -> Optional[str]:
    """R-1: a line that can never match cannot expose anything.

    FIRST ON PURPOSE. A dead-rule finding normally quotes the line that shadows
    it, and that line is very often a blanket permit -- so if R-2 ran first it
    would match the quoted BLOCKER and rate the dead rule "high". The exposure
    is not lost by rating this low: the blanket permit is reported separately on
    its own finding, where R-2 rates it high.
    """
    if "unreachable" in _evidence(finding):
        return "low"
    return None


def _rule_blanket_permit_is_high(finding: Dict[str, Any]) -> Optional[str]:
    """R-2: a permit of any source to any destination is high.

    The client's own example of a serious misconfiguration, and the one that
    most often arrives innocuously -- added to fix a connectivity complaint and
    never removed. It defeats every rule after it on the same filter, so
    whatever else the config says, this is what the device actually does.
    """
    detail = _evidence(finding)
    return "high" if "permit ip any any" in detail else None


def _rule_routing_is_medium(finding: Dict[str, Any]) -> Optional[str]:
    """R-3: a reachability failure is an outage, not an exposure.

    `routing` rates its violations high, which is correct from inside that
    check. But Netwise is a security tool, and ranking a broken path above an
    open firewall misprioritises a list people read top-down. A path that does
    not work is also, sometimes, a control doing its job.

    This is the one rule that routinely rates a finding LOWER than its check
    did, and the one most worth arguing about -- see docs/severity-rules.md,
    where it is written down so the argument can happen.
    """
    return "medium" if finding.get("check") == "routing" else None


# Order matters. See R-1's docstring for the one case where it is load-bearing.
_RULES: List[Callable[[Dict[str, Any]], Optional[str]]] = [
    _rule_dead_rule_is_low,
    _rule_blanket_permit_is_high,
    _rule_routing_is_medium,
]


def severity_for(finding: Dict[str, Any]) -> str:
    """The severity this finding should carry after the rules are applied.

    Returns the check's own severity when no rule matches -- the common case,
    and it should stay the common case. A ruleset that overrides everything is
    not prioritising, it is relocating the judgement somewhere less visible.

    Exposed separately from refine() so the rules can be tested one finding at
    a time, and so anyone reviewing a severity can ask this function directly.
    """
    # status="error" is never re-rated. Not "rated carefully" -- not rated.
    if finding.get("status") != "found":
        return finding["severity"]

    for rule in _RULES:
        verdict = rule(finding)
        if verdict is not None:
            return verdict
    return finding["severity"]


def _sort_key(finding: Dict[str, Any]) -> tuple:
    """Worst first: errors, then found by severity, then clean results."""
    return (
        _STATUS_RANK.get(finding.get("status", ""), 9),
        _SEVERITY_RANK.get(finding.get("severity", ""), 9),
    )


def refine(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Re-rate and prioritise the combined findings. Returns ALL of them.

    Never adds or removes a finding. The list that comes out has exactly the
    ids that went in -- removing one is the same lie as never producing it,
    because a missing finding is indistinguishable from one that was never a
    problem.

    Sorting is stable, so findings of equal rank keep the order their checks
    produced them in.
    """
    rated = []
    for finding in results:
        # Copy before mutating. The pipeline hands us copies already, but a
        # post-processor that mutates its input is only safe by someone else's
        # arrangement, and that arrangement could change.
        updated = dict(finding)
        updated["severity"] = severity_for(finding)
        rated.append(updated)

    return sorted(rated, key=_sort_key)
