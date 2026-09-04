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

import re
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


# The phrases our checks use to ATTRIBUTE a violation to the ACL line that
# decided it. Taken from the code that builds the evidence, not guessed:
#
#   access_control.py:319     "decided by: {Line_Content}"
#   access_control.py:404     "allowed by: {Line_Content}"
#   access_control.py:468     "Blocked by: {blocking}"
#   policy_compliance.py:260  "Decided by: {Line_Content}"
#
# After one of these, the ACL line is a CITATION -- the reason some other
# violation happened -- not the subject of the finding. Spacing is allowed to
# vary; the colon is required, because that is what every producer emits and
# matching more loosely would suppress promotions we have no evidence for.
_ATTRIBUTED_PERMIT = re.compile(
    r"(?:decided|allowed|blocked)\s+by\s*:\s*permit\s+ip\s+any\s+any",
    re.IGNORECASE,
)

_BLANKET_PERMIT = re.compile(r"permit\s+ip\s+any\s+any", re.IGNORECASE)


def _rule_blanket_permit_is_high(finding: Dict[str, Any]) -> Optional[str]:
    """R-2: a permit of any source to any destination is high.

    The client's own example of a serious misconfiguration, and the one that
    most often arrives innocuously -- added to fix a connectivity complaint and
    never removed. It defeats every rule after it on the same filter, so
    whatever else the config says, this is what the device actually does.

    ONLY WHEN THE PERMIT IS THE SUBJECT, NOT A CITATION
        This used to be a bare substring test, which fired whenever the string
        appeared anywhere in the evidence -- including in the trailing
        "decided by: ..." clause that names the line responsible for a
        DIFFERENT violation. Measured on rtr-us5-insecure: all five findings
        end with that clause, quoting the same `permit ip any any`, so R-2
        fired on all five and the list collapsed to 5 high from 4 high + 1
        medium. Every finding became top priority, which is not prioritisation.

        None of those five is ABOUT the blanket permit. They are five
        different exposures that share one cause, and the shared cause is
        already reported on its own finding where R-2 rates it high on its own
        merits. Promoting the citations as well says the same thing five times
        and destroys the ordering the rest of the ruleset produces.

        So attributed mentions are removed before looking. What remains is a
        mention of the permit that is not explained as the reason for
        something else -- which is the permit as subject.

        docs/severity-rules.md section 6.2 proposed exactly this and left it
        open for the team to decide; this implements it.
    """
    detail = _evidence(finding)
    unattributed = _ATTRIBUTED_PERMIT.sub(" ", detail)
    return "high" if _BLANKET_PERMIT.search(unattributed) else None


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


# --- Business context -------------------------------------------------------
#
# DELIBERATELY NOT AN R-RULE, AND NOT IN _RULES.
#
# R-1..R-4 share one property that makes them auditable: every one of them
# reads ONLY the finding it is handed. No shared state, no lookups. Anyone
# reviewing a severity can recompute it from the finding alone.
#
# Business context breaks that property by construction -- it is a second
# input, and the same finding scores differently depending on a file the user
# supplied. Folding it into _RULES would silently cost the whole ruleset a
# guarantee it currently has, and reviewers of R-2 would have no reason to
# notice. So it runs as a separate, clearly-named pass AFTER the rules have
# settled, and this comment is the reason why.

#: The tiers that move a severity. Only one, and that is deliberate.
#:
#: With three severities and a one-level cap, there is no room for
#: `important` to mean something between "critical" and "no change" --
#: giving it +1 as well would make the two tiers identical, which is worse
#: than inert, because the user would believe they had expressed a
#: distinction that does not exist.
#:
#: So `important` and `standard` are recorded and do not move a severity
#: today. They still identify the asset for per-device filtering (#219) and
#: for the report export (#222). **Whether `important` should escalate is a
#: question for the team, not a default to slip in here.**
_ESCALATING_TIERS = frozenset({"critical"})


#: A CEILING SOME CHECKS DECLARE, WHICH ESCALATION MAY NOT BREACH (#239).
#:
#: Not every check can support the same claim. `cve_mapping` matches a
#: software TRAIN against an advisory list, which can only ever say "worth
#: checking" -- the exact build is not in an exported config, and most
#: advisories additionally need a feature enabled. So that check caps itself
#: at `medium` and never emits `high`.
#:
#: Business context would undo that from the outside. A `medium` finding on a
#: device the user marked `critical` escalates by one level, which is `high`
#: -- and the ordering would then claim a certainty the check explicitly
#: declined to claim, through a feature that knows nothing about why.
#:
#: THIS IS NOT THE SAME AS DOWNGRADING, which limit 2 forbids. A ceiling
#: applies only to a severity this pass itself raised; it never lowers a
#: severity a check or an R-rule set. If a check ever emits `high` on its own
#: judgement, this leaves it alone.
#:
#: Keyed on the check rather than hardcoded in the escalation, so the next
#: check with the same property adds a line rather than an `if`.
_SEVERITY_CEILING = {"cve_mapping": "medium"}


def _apply_ceiling(check: Any, severity: str, previous: str) -> str:
    """Hold `severity` at the check's ceiling, if it declares one.

    `previous` is the severity BEFORE escalation, and it is what gets returned
    when the ceiling bites -- not the ceiling value itself. The difference
    matters if a check ever emits something already below its own ceiling:
    returning the ceiling would silently RAISE it, which is the opposite of
    what a cap is for.
    """
    ceiling = _SEVERITY_CEILING.get(check)
    if ceiling is None:
        return severity
    if _SEVERITY_RANK.get(severity, 9) < _SEVERITY_RANK.get(ceiling, 9):
        return previous
    return severity


#: _SEVERITY_RANK read backwards, so a rank can be turned into a name.
_RANK_TO_SEVERITY = {rank: name for name, rank in _SEVERITY_RANK.items()}


def _escalate(severity: str) -> str:
    """One level worse, and never more than one.

    THE CAP IS STRUCTURAL, NOT A GUARD, AND THAT IS THE SECOND ATTEMPT
        `high` is rank 0, so escalating it looks up rank -1, which is not a
        rank -- and the lookup falls back to the severity it was given.
        There is nothing above `high` to invent, and wrapping round to
        `low` would be the worst possible bug in a list read top-down.

        Written first as an explicit `if rank == 0: return severity` on top
        of a loop that ALSO fell through to the same answer. A mutation
        deleting that guard survived, because the cap was enforced twice
        and neither copy was load-bearing on its own -- so a later reader
        could delete either one, watch the tests pass, and leave a cap that
        now rests entirely on the other. One decision point instead.

    An unrecognised severity is returned untouched: a vocabulary this
    module does not own is not one it should start editing.
    """
    rank = _SEVERITY_RANK.get(severity)
    if rank is None:
        return severity
    return _RANK_TO_SEVERITY.get(rank - 1, severity)


def _tier_for(device: Any, context: Any) -> Optional[str]:
    """The tier the user gave this device, or None if they said nothing.

    ONLY `device` ENTRIES MATCH, AND `subnet` ENTRIES ARE NOT SILENTLY IGNORED
        A finding's `device` is a device NAME -- "rtr-us5" -- and a business
        context entry may instead name a `subnet`. Deciding whether
        10.10.10.0/24 IS rtr-us5 needs interface enumeration this project
        does not have, and it is the same limit `ai/query.py` refuses on and
        the same limit that keeps CLAUDE.md section 4's "can the guest
        network reach the finance server" out of scope.

        So a subnet entry matches nothing today. That is a real gap, and the
        dangerous version of it is the silent one: a user tags their finance
        VLAN by subnet, sees no change, and concludes their context was
        applied. `unusable_entries()` below exists so a caller can say so out
        loud. Nothing here guesses.
    """
    if not isinstance(device, str) or not device.strip():
        return None

    name = device.strip()
    for entry in getattr(context, "entries", []):
        if entry.get("device") == name:
            return entry.get("tier")
    return None


def unusable_entries(context: Any) -> List[str]:
    """Context entries that cannot affect any finding yet, described plainly.

    Not findings -- business context never invents one, and an entry the
    user wrote is not a problem with their network. These are notes for the
    caller to surface, so "nothing changed" can be told apart from "nothing
    could be applied".
    """
    notes = []
    for index, entry in enumerate(getattr(context, "entries", []), start=1):
        if "subnet" in entry:
            label = entry.get("description") or entry["subnet"]
            notes.append(
                f"entry {index} ({label}) names a subnet. Netwise matches "
                f"business context by device name only, so this entry did not "
                f"affect any finding"
            )
    return notes


def apply_business_context(
    results: List[Dict[str, Any]], context: Any
) -> List[Dict[str, Any]]:
    """Escalate findings on assets the user told us they care about.

    THE THREE LIMITS, AND WHY EACH ONE IS A LIMIT
        1. **At most one level.** `medium` -> `high`, `low` -> `medium`, and
           `low` never jumps to `high`. Criticality says the asset matters,
           not that the problem is worse than the evidence shows -- the
           evidence is still what R-1..R-4 read. A tier that could move a
           finding two levels would let a file the user wrote overrule
           measured Batfish output, which is the wrong way round.

        2. **Escalation only, never a downgrade.** No tier lowers anything.
           `standard` does not mean safe, it means the user did not single
           the asset out, and quietly filing those findings lower would use
           a shrug as evidence.

        3. **No match means no change, exactly.** A device with no entry
           keeps precisely the severity the rules gave it. This is the R-2
           lesson restated: absence of information is not information. A
           context listing three critical servers says nothing whatsoever
           about the fourth, and treating "unlisted" as "unimportant" would
           invent a judgement the user never made.

    Never adds or removes a finding, and never touches one that is not
    status="found" -- an unrunnable check is a blind spot whatever tier the
    device carries, and there is no severity worth editing on a blind spot.
    """
    # Copies, not the caller's own dicts. `list(results)` here would hand
    # back the very objects that came in, so this function's aliasing
    # behaviour would depend on whether a context happened to be supplied --
    # and a caller that edited a returned finding would corrupt its input
    # only on the no-context path. Found by a mutation surviving: the two
    # paths were indistinguishable to the tests precisely because they were
    # equal by value while differing by identity.
    if context is None or getattr(context, "is_empty", True):
        return [dict(finding) for finding in results]

    adjusted = []
    for finding in results:
        updated = dict(finding)

        # Same guard as severity_for(), stated again rather than inherited:
        # this function is callable on its own, and a caller who reached it
        # directly should not be the reason an error finding gets re-rated.
        if updated.get("status") == "found":
            tier = _tier_for(updated.get("device"), context)
            if tier in _ESCALATING_TIERS:
                before = updated.get("severity", "")
                updated["severity"] = _apply_ceiling(
                    updated.get("check"), _escalate(before), before
                )

        adjusted.append(updated)

    return adjusted


def _sort_key(finding: Dict[str, Any]) -> tuple:
    """Worst first: errors, then found by severity, then clean results."""
    return (
        _STATUS_RANK.get(finding.get("status", ""), 9),
        _SEVERITY_RANK.get(finding.get("severity", ""), 9),
    )


def sort_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order findings worst-first. Stable, so equal ranks keep their order.

    Public because a caller that escalates severities AFTER `refine()` has
    run has to re-order, and re-implementing this ordering elsewhere is how
    two parts of the product start disagreeing about what "worst" means.
    """
    return sorted(results, key=_sort_key)


def refine(
    results: List[Dict[str, Any]], context: Any = None
) -> List[Dict[str, Any]]:
    """Re-rate and prioritise the combined findings. Returns ALL of them.

    Never adds or removes a finding. The list that comes out has exactly the
    ids that went in -- removing one is the same lie as never producing it,
    because a missing finding is indistinguishable from one that was never a
    problem.

    Sorting is stable, so findings of equal rank keep the order their checks
    produced them in.

    `context` IS OPTIONAL, AND A PARAMETER RATHER THAN MODULE STATE
        `POST_PROCESSORS` calls this with one argument, so the default keeps
        that contract intact and today's behaviour byte-for-byte identical:
        with no context, not one severity moves.

        It is passed in rather than stashed on the module deliberately. A
        module-level `set_business_context()` would be the same
        shape as the `_analysis_cache` concurrency assumption raised on #182
        and now tracked as #208 -- two requests, one global, and a severity
        computed from whichever file happened to arrive last. Threading it
        through the call is duller and cannot do that.

    ORDER: RULES FIRST, CONTEXT SECOND
        Escalation applies to the severity the ruleset SETTLED ON, not to
        the check's default. Otherwise R-3 -- which lowers a routing finding
        to medium -- would fight the escalation depending on which ran
        first, and the answer would depend on line order rather than on
        anything anyone decided.

        And both happen before the sort, so the order on screen reflects the
        severities the user is actually shown.
    """
    rated = []
    for finding in results:
        # Copy before mutating. The pipeline hands us copies already, but a
        # post-processor that mutates its input is only safe by someone else's
        # arrangement, and that arrangement could change.
        updated = dict(finding)
        updated["severity"] = severity_for(finding)
        rated.append(updated)

    rated = apply_business_context(rated, context)

    return sort_findings(rated)
