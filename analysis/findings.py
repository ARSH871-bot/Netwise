"""
Netwise -- the F-1 finding format, in code.

THE CONTRACT: docs/finding-format.md. That document is the agreement; this
module is the enforcement. Every check in Netwise returns a list of findings
built by the helpers below.

WHY A MODULE INSTEAD OF JUST WRITING DICTS
    Four people are writing checks independently. If each of us hand-writes
    the dictionary, one typo -- "sevrity", "device" left out, status="ok"
    instead of "none" -- produces a finding that looks fine in Python and
    breaks the dashboard at the worst moment. Building findings here means a
    mistake fails loudly and immediately, in the check that made it, instead
    of quietly downstream.

THE THREE HELPERS, one per status value:

    make_finding(...)      status="found"  -- we found a real problem
    no_issues_finding(...) status="none"   -- we checked, all clear
    error_finding(...)     status="error"  -- we could NOT check

That third one is the safety-critical one (F-4). "We checked and found
nothing" and "we could not check" must never look the same to a user, so they
are separate functions and you have to choose deliberately between them.

PLUS ONE UTILITY, which is not a finding builder:

    describe_error(...)    turn an exception into ONE safe line

    Use it whenever you would otherwise write f"...: {error}". A raw Batfish
    exception carries kilobytes of server log, and that text would go straight
    into evidence.detail -- which the AI layer treats as grounding and the
    dashboard shows the client. See the function for the measurements.
"""

from typing import Any, Dict

# --- The allowed values, taken verbatim from docs/finding-format.md ---------

# Which analysis produced the finding. Add to this ONLY by team agreement --
# the dashboard and the AI layer both switch on these names.
VALID_CHECKS = (
    "access_control",  # Arsh
    "routing",  # Ankeet
    "policy_compliance",  # Shubham
    "change_impact",  # Shubham
    "risk",  # Samika
    # --- NOT RATIFIED. Present so the check can be reviewed; NOT registered
    # in pipeline.CHECKS, so nothing runs before the team agrees (#239).
    #
    # This line is a vocabulary addition, and the comment above this tuple
    # says such an addition takes team agreement. docs/finding-format.md
    # spends two paragraphs regretting A-2's code landing while its table was
    # still incomplete; adding the name AND wiring it into every scan would
    # repeat that exactly. So the name exists and the registration does not.
    "cve_mapping",  # Samika -- #239, awaiting team agreement before it runs
)

# The ID prefix each check uses. ONE PREFIX PER CHECK, never shared -- see
# docs/finding-format.md, amendment A-2. policy_compliance and change_impact
# both mapped to "PC" until then, which made `id` uniqueness a matter of
# discipline between two documents rather than something the contract enforced.
PREFIX_BY_CHECK = {
    "access_control": "AC",
    "routing": "RT",
    "policy_compliance": "PC",
    "change_impact": "CH",
    "risk": "RK",
    # "CV", not "CM": "CM" reads as a second change-impact prefix beside "CH",
    # and A-2's whole point was that two checks sharing a prefix makes `id`
    # uniqueness a matter of discipline rather than of the contract.
    "cve_mapping": "CV",  # #239 -- see the note in VALID_CHECKS above
}

VALID_SEVERITIES = ("high", "medium", "low")
VALID_STATUSES = ("found", "none", "error")

# Findings numbered 000 are the "nothing found" and "could not run" sentinels.
# Real problems are numbered from 001 upwards by the check that found them.
SENTINEL_NUMBER = 0


def describe_error(error: Exception, limit: int = 200) -> str:
    """Condense an exception into ONE line that is safe to put in a finding.

    WHY THIS EXISTS
        The obvious thing -- f"...: {error}" -- looks harmless and is not. A
        failed Batfish query raises BatfishException carrying the server's own
        log: measured at 5241 characters over 20 lines, containing work_item
        JSON, internal UUIDs, container names, and "Loading configurations for
        NetworkSnapshot{...}" repeated many times.

        That text ends up in evidence.detail, which is:
          - what the AI layer receives AS ITS GROUNDING. Five kilobytes of Java
            internals is noise the model must ignore, and exactly the kind of
            input that leaks internal identifiers into a user-facing sentence.
          - what the dashboard renders IN FRONT OF THE CLIENT.

        docs/finding-format.md says evidence.detail is "the config line or
        Batfish result". A stack trace is neither.

    WHAT IT KEEPS
        The exception type and its first line -- which is the part a human can
        act on. The example above becomes:

            BatfishException: Work terminated abnormally

        The full text is NOT lost: log it at debug level if you are chasing a
        bug. Debuggability and a clean contract are not in tension; they just
        belong in different places.

    USE IT everywhere you would otherwise interpolate an exception:

        detail=findings.describe_error(error)
    """
    first_line = (str(error).strip().splitlines() or [""])[0]
    text = f"{type(error).__name__}: {first_line}"
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def make_finding(
    *,  # keyword-only: with eight fields, positional arguments are a trap
    check: str,
    severity: str,
    device: str,
    summary: str,
    detail: str,
    source: str,
    status: str,
    number: int,
) -> Dict[str, Any]:
    """Build ONE finding in the F-1 shape, validating every field.

    Args:
        check:    which analysis produced this -- see VALID_CHECKS
        severity: "high" | "medium" | "low"
        device:   Batfish node name, e.g. "rtr-us5" ("unknown" if we can't tell)
        summary:  one line of plain description, under ~100 chars. The AI
                  EXPANDS this; it does not replace it.
        detail:   the proof -- the config line or Batfish result
        source:   where the proof came from, "filename:line" where possible
        status:   "found" | "none" | "error"
        number:   sequence number within this check; 0 for sentinels

    Raises:
        ValueError: if any field is outside the agreed vocabulary. This is
            deliberate. A malformed finding must fail here, loudly, rather than
            reach the dashboard and be rendered as something misleading.
    """
    if check not in VALID_CHECKS:
        raise ValueError(f"check must be one of {VALID_CHECKS}, got {check!r}")
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {VALID_SEVERITIES}, got {severity!r}")
    if status not in VALID_STATUSES:
        raise ValueError(f"status must be one of {VALID_STATUSES}, got {status!r}")
    if not summary:
        raise ValueError("summary is required -- it is what the user reads first")

    return {
        "id": f"{PREFIX_BY_CHECK[check]}-{number:03d}",
        "check": check,
        "severity": severity,
        "device": device,
        "summary": summary,
        "evidence": {"detail": detail, "source": source},
        "status": status,
    }


def no_issues_finding(
    *,
    check: str,
    device: str,
    summary: str,
    detail: str,
    source: str,
    number: int = SENTINEL_NUMBER,
) -> Dict[str, Any]:
    """status="none" -- the check RAN and found nothing. This is good news.

    Severity is "low" because there is nothing wrong. Use this only when the
    check genuinely completed. If anything stopped it running, use
    error_finding() instead -- see F-4.

    `number` defaults to the 000 sentinel, which is right for every check.

    It was added on #18 for a narrower reason: policy_compliance and
    change_impact then shared the "PC" prefix, so both emitting 000 for "all
    clear" produced the same `id`, and change_impact needed a different one.
    Amendment A-2 gave change_impact its own prefix, so that reason is gone and
    every check may now use the default.

    The parameter stays because it is still useful -- a check that produces
    more than one kind of check-level finding needs to number them apart, which
    is what policy_compliance does with PC-000 and PC-050. Uniqueness WITHIN a
    check is still not enforced by this function, so
    analysis.pipeline.duplicate_id_findings() remains the backstop.
    """
    return make_finding(
        check=check,
        severity="low",
        device=device,
        summary=summary,
        detail=detail,
        source=source,
        status="none",
        number=number,
    )


def error_finding(
    *,
    check: str,
    summary: str,
    detail: str,
    source: str,
    device: str = "unknown",
    number: int = SENTINEL_NUMBER,
) -> Dict[str, Any]:
    """status="error" -- the check COULD NOT RUN. This is not good news.

    Severity is "high" on purpose. An unrunnable check is a blind spot, and a
    blind spot in a security tool deserves the user's attention rather than
    being quietly filed at the bottom of the list.

    `summary` must say what went wrong, in words the user can act on.

    `number` defaults to the 000 sentinel, which suits the common case of one
    error per check. If a single check can fail in several independent ways at
    once, number them 1, 2, 3 ... so the ids stay unique.

    Why unique matters: docs/finding-format.md calls `id` a "unique identifier",
    so anything downstream is entitled to rely on it -- a diff between two runs,
    the AI layer referring to one finding, a consumer keying by id. The
    dashboard deliberately does NOT key by id today, precisely because ids were
    found to collide; that is a defensive choice on its part, not permission for
    ids to be duplicated. analysis.pipeline.duplicate_id_findings() reports any
    that slip through.
    """
    return make_finding(
        check=check,
        severity="high",
        device=device,
        summary=summary,
        detail=detail,
        source=source,
        status="error",
        number=number,
    )
