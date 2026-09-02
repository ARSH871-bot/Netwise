"""
Netwise -- Layer 2, turning one F-1 finding into a plain-English explanation.

WHAT THIS DOES
    explain(finding: dict) -> str
    Takes ONE F-1 finding (see docs/finding-format.md) and returns a plain-
    English explanation, using the local Warden model (ai/Modelfile). That
    function is the main public surface of this module.

    explain_with_source(finding: dict) -> tuple[str, str]
    Same computation, also reports which path produced the text: "model" or
    "fallback". Added for #109 -- the dashboard's "AI explanation" byline is
    unconditional, and had no way to tell a genuine model response apart
    from `_fallback_plain_restatement()`'s deterministic text when Ollama is
    absent. explain() is unchanged and still the right choice for a caller
    that only wants the text.

    remediate_with_source(finding: dict) -> Optional[tuple[str, str]]
    A DIFFERENT question -- not "what does this finding mean" but "what
    would fix it" (#221). Deliberately narrower than explain(): it never
    calls the model, and returns None rather than a fallback string when it
    has nothing confident to say. See section 1d below for why.

TWO DIFFERENT KINDS OF MISTAKE, TWO DIFFERENT FIXES
    Testing against real findings from the pipeline (see ai/Modelfile's
    commit history) turned up two genuinely different failure modes, and
    conflating them would mean fixing neither properly.

    1. WORDING MISTAKES -- the model states an unconfirmed result
       ("the network cannot reach X" for a check that only crashed), or
       hedges an invented consequence into an otherwise fine sentence
       ("...which could potentially cause issues"). These are caught by
       inspecting the generated TEXT for known-bad patterns after the fact
       -- see _looks_like_a_result_claim() and _looks_like_speculation().
       A prompt can reduce how often this happens; it cannot promise zero
       on a 3B model, so the check runs every time regardless.

    2. REASONING MISTAKES -- the model gets an actual TECHNICAL FACT
       backwards. Measured directly: for a dead ACL rule (an unreachable
       PERMIT, shadowed by an earlier DENY), the model once said matching
       traffic "should be blocked... which is not happening" -- backwards.
       The traffic IS blocked; that is the whole finding. No amount of text
       scanning catches this, because the sentence contains no banned word,
       it is simply wrong about what the shadowing rule decides.

       Shadowing logic has one correct answer, computable from the finding
       text alone (which rule wins, and what that rule's own action is).
       That is a job for deterministic code, not a probabilistic model --
       the same principle CLAUDE.md's constraint 2 already applies project-
       wide, extended here to one more place it turned out to matter.
       _compute_dead_rule_outcome() computes the real answer in Python and
       hands it to the model as an already-verified fact to STATE, not a
       question to REASON about. This only fires for the exact evidence
       shape access_control.py's dead-rule check produces, and only when
       every blocking line agrees on the same action -- anything it is not
       fully confident about, it leaves alone rather than guessing.

       The same mistake recurs in a second shape (#145): for a
       policy_compliance finding, the model sometimes attributes the wrong
       action to "the policy" -- e.g. evidence.detail says the flow "is
       permitted but policy forbids it", and the generated text says "the
       policy currently permits this". Found while independently rating
       explanations for #90, confirmed on two findings (PC-001, PC-005).
       Same fix, same reasoning: which side (the device's live configuration
       vs. the written policy) does what is a fact with one correct answer,
       computable from evidence.detail alone, so _compute_policy_outcome()
       computes it the same way _compute_dead_rule_outcome() does.

       A third shape was added on the same reasoning without waiting for a
       third accident: access_control's own policy-statement findings use
       the identical "which of two opposite states is which" attribution
       ("Expected PERMIT but got DENY, decided by: ..."), the same task
       that went wrong twice already. Live-tested six times against a real
       finding in this shape before adding the guard -- no inversion
       reproduced on that occasion, recorded honestly as a clean but limited
       result rather than proof of safety, since both earlier bugs were
       also found on one specific real finding each, not from exhaustive
       testing. _compute_expected_actual_outcome() computes it the same way
       the other two do, and costs nothing when it does not match.

WHY status="error" ALSO GETS ITS OWN CHECK
    For "found"/"none", a wording slip is undesirable but not dangerous --
    the underlying fact was still real, the phrasing was just off. For
    "error", it is dangerous: F-4 exists specifically because "we checked
    and found nothing" and "we could not check" must never be confused, and
    a slip here is the one place a sentence could still assert something
    false about the network. So error responses ALSO reject any wording
    that claims a result, not just speculation, and fall back to a fixed,
    non-generated sentence if two attempts both fail -- see
    _fallback_error_explanation().

RUN IT BY HAND
    python -m ai.explain
    Pulls a real finding out of the pipeline (tests/fixtures/rtr-us5-
    insecure) and prints the explanation, so this can be checked against
    live output rather than an invented example.

PREREQUISITE
    Ollama running locally, with the model built from ai/Modelfile:
        ollama create netwise-warden -f ai/Modelfile
"""

from __future__ import annotations

import os
import socket
import time
import json
import re
import ipaddress
from typing import Any, Dict, Optional

import ollama

# The model this module calls. Built from ai/Modelfile -- see that file for
# the persona, rules, and generation parameters actually in force. Nothing
# in this module tunes the model itself; that all lives in the Modelfile so
# there is one place to look, not two.
MODEL_NAME = "netwise-warden"

# ------------------------------------------------------------------------------
# 1. Deterministic dead-rule outcome computation
# ------------------------------------------------------------------------------

# Matches evidence.detail EXACTLY as produced by
# analysis.checks.access_control._check_dead_rules:
#   "Unreachable line: <line> (action PERMIT|DENY). Blocked by: <lines>. Reason: <reason>"
# Deliberately narrow -- this must only match the one shape it is confident
# about, never a loose approximation of it.
_DEAD_RULE_DETAIL_PATTERN = re.compile(
    r"Unreachable line: .+?\(action (?P<dead_action>PERMIT|DENY)\)\. "
    r"Blocked by: (?P<blocking>.+?)\. Reason:"
)


def _compute_dead_rule_outcome(detail: str) -> Optional[str]:
    """For a dead-ACL-rule finding, compute what actually happens to
    traffic matching the dead line -- rather than asking the model to
    infer it from the raw text, which measurably goes wrong sometimes.

    The rule: whichever line SHADOWS the dead one decides the outcome for
    matching traffic, because it is evaluated first. A dead line's own
    action never takes effect, regardless of what it says.

    Returns a plain-English statement of the real outcome, or None if:
      - `detail` is not in the exact shape access_control.py's dead-rule
        check produces (nothing to compute from), or
      - more than one blocking line is named and they do not all agree on
        the same action (ambiguous -- do not guess which one actually
        decides), or
      - a blocking line's text does not start with a recognisable
        permit/deny keyword (unfamiliar syntax -- do not guess).

    None means "give the model no extra help here" -- explain() still
    generates an explanation from the raw finding either way. This function
    only ever ADDS confidence; it never blocks a finding from being
    explained.
    """
    match = _DEAD_RULE_DETAIL_PATTERN.search(detail)
    if not match:
        return None

    blocking_lines = [line.strip().lower() for line in match.group("blocking").split(",")]
    outcomes = set()
    for line in blocking_lines:
        if line.startswith("permit"):
            outcomes.add("permitted")
        elif line.startswith("deny"):
            outcomes.add("denied")
        else:
            return None  # unrecognised syntax -- do not guess

    if len(outcomes) != 1:
        return None  # blocking lines disagree -- not confident enough to state one outcome

    outcome = outcomes.pop()
    return (
        f"traffic matching the unreachable line's pattern is actually "
        f"{outcome}, because the blocking rule is evaluated first and "
        f"decides instead. The unreachable line's own action never takes "
        f"effect, regardless of what it says."
    )


# ------------------------------------------------------------------------------
# 1b. Deterministic policy-vs-configuration outcome computation (#145)
# ------------------------------------------------------------------------------

# Matches evidence.detail EXACTLY as produced by
# analysis.checks.policy_compliance._describe():
#   "Flow <flow> is permitted but policy forbids it. Decided by: <line>"
#   "Flow <flow> is denied but policy requires it. Decided by: <line>"
# Deliberately narrow, same discipline as _DEAD_RULE_DETAIL_PATTERN -- this
# must only match the two shapes it is confident about, never a loose
# approximation of them.
_POLICY_DETAIL_PATTERN = re.compile(
    r"is (?P<wrong>permitted|denied) but policy requires it to be "
    r"(?P<required>DENIED|PERMITTED)\. Decided by:"
)


def _compute_policy_outcome(detail: str) -> Optional[str]:
    """For a policy_compliance finding, compute -- in unambiguous words --
    which side (the device's live configuration, or the written policy) is
    responsible for what, rather than asking the model to keep the two
    straight itself.

    WHY THIS EXISTS (#145)
        Confirmed on real findings while independently rating explanations
        for #90: the model sometimes attributes the wrong action to "the
        policy". evidence.detail says a flow "is permitted but policy
        forbids it" -- the DEVICE is permitting traffic the POLICY forbids
        -- and the generated text said "the policy currently permits this
        unauthorized access", the exact opposite of what the evidence
        states. A second finding (PC-005) inverted the other direction:
        evidence said "is denied but policy requires it" and the text called
        it "a policy statement that requires blocking of HTTPS traffic".

        Same failure family as the dead-rule case above -- a fact with
        exactly one correct answer, backwards. `evidence.detail` already
        names the flow, the device's actual behaviour and the policy's
        actual requirement; the mistake is entirely in restating which noun
        goes with which verb, not in inferring anything from Batfish output.
        That makes it a job for deterministic code, same principle as
        _compute_dead_rule_outcome() and CLAUDE.md constraint 2.

    Returns a plain-English statement naming both sides explicitly, or None
    if `detail` is not in the exact shape policy_compliance.py's `_describe()`
    produces -- nothing to compute from, so the model gets no extra help and
    reasons from the raw finding alone, same as any other finding shape.
    """
    match = _POLICY_DETAIL_PATTERN.search(detail)
    if not match:
        return None

    if match.group("wrong") == "permitted":
        return (
            "the traffic itself is currently PERMITTED, and that is the "
            "device's own configuration doing it, not the policy -- the "
            "written policy actually FORBIDS this traffic. The device "
            "configuration is what is letting it through despite that."
        )
    return (
        "the traffic itself is currently DENIED, and that is the device's "
        "own configuration doing it, not the policy -- the written policy "
        "actually REQUIRES this traffic to be allowed. The device "
        "configuration is what is blocking it despite that."
    )


# ------------------------------------------------------------------------------
# 1c. Deterministic expected-vs-actual outcome computation (testFilters)
# ------------------------------------------------------------------------------

# Matches evidence.detail EXACTLY as produced by
# analysis.checks.access_control.run()'s policy-statement loop:
#   "Expected PERMIT but got DENY, decided by: <line>"
#   "Expected DENY but got PERMIT, decided by: <line>"
# Deliberately narrow, same discipline as the two patterns above -- this
# must only match the one shape it is confident about, never a loose
# approximation of it.
_EXPECTED_ACTUAL_DETAIL_PATTERN = re.compile(
    r"Expected (?P<expected>PERMIT|DENY) but got (?P<actual>PERMIT|DENY), "
    r"decided by:"
)


def _compute_expected_actual_outcome(detail: str) -> Optional[str]:
    """For an access_control policy-statement finding, state -- in
    unambiguous words -- what the device actually does versus what was
    required, rather than asking the model to keep the two straight itself.

    WHY THIS EXISTS
        Not a bug caught by accident this time -- checked deliberately,
        because this evidence shape is structurally the same "which of two
        opposite states is which" attribution task that #52 (dead rules) and
        #145 (policy_compliance) already got backwards on real findings.
        `evidence.detail` here even uses the same two-sided phrasing
        ("Expected X but got Y") the other two shapes needed a fix for.

        Live-tested against the local model before adding this: six runs of
        a real finding in this shape (`Expected PERMIT but got DENY`) all
        correctly identified DENY as the actual, current behaviour -- no
        inversion reproduced on this occasion. Recorded rather than treated
        as proof of safety: #52 and #145 were both found on one specific
        real finding each, not from exhaustive testing, and this module's
        own docstring is explicit that a 3B model cannot be promised zero
        failures of this kind. The fix costs a few lines and never blocks a
        finding from being explained if it does not match; the failure mode
        it guards against is a security tool stating the opposite of the
        truth. That asymmetry is why this is added on structural risk plus
        a clean but limited live test, the same bar #52 and #145 were
        originally found at, not waited on until it reproduces here too.

    Returns a plain-English statement naming both sides explicitly, or None
    if `detail` is not in the exact shape access_control.py's testFilters
    loop produces -- nothing to compute from, so the model gets no extra
    help and reasons from the raw finding alone, same as any other finding
    shape.
    """
    match = _EXPECTED_ACTUAL_DETAIL_PATTERN.search(detail)
    if not match:
        return None

    expected, actual = match.group("expected"), match.group("actual")
    return (
        f"the traffic this statement is about is currently {actual}, which "
        f"is the device's own configuration doing it -- the policy actually "
        f"requires {expected}. The device configuration is what disagrees "
        f"with the requirement, not the requirement itself."
    )


# ------------------------------------------------------------------------------
# 1d. Deterministic remediation text (#221)
#
# A DIFFERENT QUESTION FROM SECTIONS 1a-1c ABOVE
#     Those three compute what a finding MEANS, to correct the model's
#     wording before it speaks. This computes what would FIX it, and never
#     goes near the model at all -- ai/Modelfile rule 6 explicitly forbids
#     recommending a fix "unless the evidence itself states what would
#     resolve it," and that is exactly the boundary kept here: every string
#     below is built only from a regex-captured piece of evidence.detail
#     that the check itself already produced, never invented or inferred.
#
# WHY THIS IS A SEPARATE FUNCTION FAMILY, NOT MORE ARGUMENTS TO explain()
#     Remediation and explanation are different claims ("here is what is
#     wrong" vs. "here is what to change") and #109/#236 already established
#     that this project keeps different claims honestly separate rather than
#     blending them under one byline. See web/main.py's _attach_remediation()
#     and web/static/app.js's remediation render branch for the other two
#     places this same separation is kept.
#
# COVERAGE, MEASURED NOT ASSUMED
#     Checked against this project's own fixtures before writing this:
#
#         rtr-us5-insecure: 4/5 found-status findings match a known shape
#         rtr-us5-messy:    5/6 found-status findings match a known shape
#
#     The misses are informative, not a gap to force-fix. A GUARANTEES/
#     searchFilters proof (access_control's "Example permitted flow: ...")
#     has no single "decided by" line to name -- it proves a property over a
#     whole space of traffic, not one flow's fate. An undefined-reference
#     finding ("the structure 'acl_guest_in' is never defined") needs a
#     different kind of guidance entirely ("define the missing structure",
#     not "change this rule"). Both correctly return None below rather than
#     stretching a shape to cover them.
# ------------------------------------------------------------------------------

# Deliberately a SEPARATE pattern from _POLICY_DETAIL_PATTERN above, rather
# than adding a capturing group to it. That pattern is already relied on by
# _compute_policy_outcome() and its own tests; giving remediation its own
# pattern means neither function's correctness depends on the other's shape
# staying exactly as it is today.
#
# Captures the deciding line up to whichever comes first: a trailing
# "(N example flows matched)" note (policy_compliance.py appends this when
# more than one flow matches the same line) or a "[Rules checked: ...]"
# provenance note (added when a user policy is supplied), or end of string.
# Verified against real evidence.detail carrying both suffixes separately --
# without this, a two-flow finding named the rule as
# "permit ip any any (2 example flows matched)", folding a flow COUNT into
# what is supposed to be a copyable RULE.
_POLICY_REMEDIATION_PATTERN = re.compile(
    r"is (?P<wrong>permitted|denied) but policy requires it to be "
    r"(?P<required>DENIED|PERMITTED)\. Decided by: (?P<deciding>.+?)"
    r"(?:\s*\(\d+ example flows? matched\)|\s*\[|$)"
)

# Same reasoning: a separate pattern from _EXPECTED_ACTUAL_DETAIL_PATTERN,
# capturing the deciding line this shape's own function does not need.
_EXPECTED_ACTUAL_REMEDIATION_PATTERN = re.compile(
    r"Expected (?P<expected>PERMIT|DENY) but got (?P<actual>PERMIT|DENY), "
    r"decided by: (?P<deciding>.+?)(?:\s*\[|$)"
)


def _remediate_dead_rule(detail: str) -> Optional[str]:
    """Which line to change, for a dead-ACL-rule finding, or None.

    Reuses _DEAD_RULE_DETAIL_PATTERN exactly -- same match, same ambiguity
    guard (multiple disagreeing blocking lines means "do not name one",
    same as _compute_dead_rule_outcome()) -- because the "blocking" group it
    already captures is exactly the line remediation needs to name. Two
    functions reading one pattern is not duplication; writing a second,
    subtly different pattern for the same text would be.
    """
    match = _DEAD_RULE_DETAIL_PATTERN.search(detail)
    if not match:
        return None

    blocking_lines = [line.strip() for line in match.group("blocking").split(",")]
    if len(blocking_lines) != 1:
        # Same guard as _compute_dead_rule_outcome(): more than one blocking
        # line means there is no single line to point at as THE fix.
        return None

    return (
        f"Reorder or remove the rule that shadows it: `{blocking_lines[0]}` is "
        f"evaluated first and decides this traffic instead. Moving the "
        f"unreachable line above it, or removing the shadowing rule if it is "
        f"no longer needed, would let the unreachable line's own action "
        f"take effect."
    )


def _remediate_policy_mismatch(detail: str) -> Optional[str]:
    """Which side to change, for a policy_compliance finding, or None."""
    match = _POLICY_REMEDIATION_PATTERN.search(detail)
    if not match:
        return None

    required = match.group("required")
    deciding = match.group("deciding").strip()
    return (
        f"Change the device's configuration, not the policy: the rule "
        f"`{deciding}` is what is deciding this traffic today, and the "
        f"written policy already says it should be {required}. Adjusting or "
        f"removing that rule so the device agrees with the policy is the fix "
        f"-- the policy is not what needs to change here."
    )


def _remediate_expected_actual(detail: str) -> Optional[str]:
    """Which line to change, for an access_control policy-statement
    finding, or None."""
    match = _EXPECTED_ACTUAL_REMEDIATION_PATTERN.search(detail)
    if not match:
        return None

    expected = match.group("expected")
    deciding = match.group("deciding").strip()
    return (
        f"The rule `{deciding}` is what decides this today. Changing it so "
        f"the outcome is {expected} instead -- reordering it relative to "
        f"other rules, or editing its action -- is what this statement "
        f"needs to hold."
    )


def remediate_with_source(finding: Dict[str, Any]) -> Optional["tuple[str, str]"]:
    """(text, "deterministic") if a known evidence shape matched, else None.

    DELIBERATELY None, NOT A FALLBACK STRING
        explain() always has something to say -- worst case, the finding's
        own summary and detail, restated (_fallback_plain_restatement()).
        There is no equivalent honest fallback for remediation: "we do not
        know what to tell you to change" is not useful prose, and inventing
        one would be a guess dressed as guidance. So the three shapes below
        either match exactly or this returns None, and the caller (see
        web/main.py's _attach_remediation()) shows a plain "no mechanical
        remediation available" state rather than manufacturing text.

    "deterministic" AS THE SOURCE LABEL, NOT "model"/"fallback"
        Those two values describe explain()'s two paths -- a model spoke, or
        a template did when it could not. Neither describes this: no model
        is ever consulted here, by design (see the section-1d banner
        comment above), so the label says so plainly rather than reusing a
        vocabulary built for a different distinction.

    Never raises. Each of the three shape-functions below either matches an
    exact regex or returns None; there is no code path that can throw on a
    malformed `finding`, same guarantee `_evidence_detail()` already gives
    the rest of this module.
    """
    detail = _evidence_detail(finding)
    if not detail:
        return None

    text = (
        _remediate_dead_rule(detail)
        or _remediate_policy_mismatch(detail)
        or _remediate_expected_actual(detail)
    )
    if text is None:
        return None
    return (text, "deterministic")


# ------------------------------------------------------------------------------
# 2. Post-generation validation
# ------------------------------------------------------------------------------

# Words that only belong in a response CONFIRMING something about the
# network. Per ai/Modelfile rule 4, an "error" finding earns neither a
# positive nor a negative claim about the network -- so none of these
# should appear anywhere in an error explanation. Checked ONLY for
# status="error"; a "found" explanation legitimately needs words like
# "blocked" or "reach" to describe the confirmed fact.
_RESULT_CLAIM_WORDS = (
    "reach",
    "reachable",
    "blocked",
    "works",
    "working",
    "vulnerable",
    "safe",
    "secure",
    "clear",
    "issues",
)
_RESULT_CLAIM_PATTERN = re.compile(
    r"\b(" + "|".join(_RESULT_CLAIM_WORDS) + r")\w*\b", re.IGNORECASE
)

# Hedge words that let an invented consequence sneak past a plain "do not
# invent" rule -- measured directly: "...which could potentially cause
# issues" passed a first round of prompt tuning by hedging instead of
# asserting outright. Checked for EVERY status, not just "error": an
# invented consequence is CLAUDE.md constraint 2's concern regardless of
# what the finding's status is.
_SPECULATION_PATTERN = re.compile(
    r"\b(may|might|could|potentially|possibly)\b", re.IGNORECASE
)
_LEAD_TO_PATTERN = re.compile(r"\bcan\s+lead\s+to\b", re.IGNORECASE)


def _looks_like_a_result_claim(text: str) -> bool:
    """True if `text` uses language that asserts something about the
    network. Used only for status="error" responses -- see the module
    docstring for why. Errs toward flagging too much rather than too
    little: a false positive costs one retry or a safe fallback sentence;
    a false negative lets a wrong claim through to whoever reads it.
    """
    return bool(_RESULT_CLAIM_PATTERN.search(text))


def _looks_like_speculation(text: str) -> bool:
    """True if `text` hedges toward an unconfirmed consequence rather than
    stating a plain fact. Checked for every status -- see the module
    docstring's "wording mistakes" section.
    """
    return bool(_SPECULATION_PATTERN.search(text) or _LEAD_TO_PATTERN.search(text))


def _evidence_detail(finding: Dict[str, Any]) -> str:
    """The finding's evidence.detail as a string. Never raises, whatever
    shape `finding` is in -- returns "" for anything that isn't a usable
    string.

    WHY THIS EXISTS
        `finding.get("evidence", {}).get("detail")` and
        `(finding.get("evidence") or {}).get("detail", "")` both look like
        they default safely, but a dict's `.get(key, default)` only falls
        back to `default` when `key` is ABSENT -- not when it is present
        with value `None`. `findings.make_finding()` does not reject
        `evidence={"detail": None}`, or `evidence=None` outright, so a
        finding shaped that way is not hypothetical, it is one bug away in
        any check.

        Confirmed directly, three call sites, all crashing before this fix:
        `_build_prompt()` (via `_compute_dead_rule_outcome()`'s regex,
        `TypeError`), `_fallback_plain_restatement()` (`.strip()` on `None`,
        `AttributeError`), and `_fallback_error_explanation()` -- the
        deterministic last resort for status="error", the one place that
        must not be able to fail -- crashing on `evidence=None` outright,
        not just `detail=None`.

        A malformed finding from a future check with a bug should degrade
        explain() the same way an unreachable Ollama does, not take down
        the whole explanation layer, including its own fallback.

    A non-string, non-None `detail` (e.g. an int, if a future check ever
    got that wrong) is also treated as "", not str()-coerced -- this
    function's job is to hand back usable prose text, and a stringified
    int is not that.
    """
    evidence = finding.get("evidence")
    detail = evidence.get("detail") if isinstance(evidence, dict) else None
    return detail if isinstance(detail, str) else ""


def _fallback_error_explanation(finding: Dict[str, Any]) -> str:
    """The deterministic last resort for status="error", used only if the
    model fails validation twice in a row.

    Always correct, because it is not generated -- it states only the two
    facts actually known: the check did not complete, and (if given) the
    technical reason why. No model call, so nothing here can hallucinate.
    """
    detail = _evidence_detail(finding) or "an unknown error"
    return (
        "This check could not be completed, so nothing is confirmed about "
        f"the network either way. The underlying reason: {detail}"
    )


def _fallback_plain_restatement(finding: Dict[str, Any]) -> str:
    """The deterministic last resort for status="found"/"none", used only
    if the model fails validation twice in a row.

    Not polished plain English -- it is the check's own summary and
    evidence, stated together with no elaboration. Guaranteed grounded,
    because nothing here is generated: a plain but honest answer beats a
    fluent one that might still be speculating.
    """
    summary = (finding.get("summary") or "").strip()
    detail = _evidence_detail(finding).strip()
    if detail:
        return f"{summary}. Technical detail: {detail}"
    return summary or "No explanation is available for this finding."


def _build_prompt(finding: Dict[str, Any]) -> str:
    """Wrap the finding for the model, adding two things beyond the raw F-1
    fields:

    1. An instruction not to reuse the worked examples baked into
       ai/Modelfile's system prompt. WHY: measured directly while building
       the prompt -- without this, the model sometimes reproduced a worked
       example's answer almost verbatim for an unrelated finding, rather
       than reasoning about the finding it was actually given.

    2. If one of the three deterministic outcome functions can compute the
       real answer from evidence.detail -- _compute_dead_rule_outcome() for
       a dead-ACL-rule finding, _compute_policy_outcome() for a
       policy_compliance finding (#145), or _compute_expected_actual_outcome()
       for an access_control policy-statement finding -- that computed fact,
       labelled as already-verified. See each function's docstring for why
       it exists and how confident it has to be before it says anything at
       all. The three never more than one matches at once: each check
       produces its own exact evidence.detail shape, so trying the next one
       only when an earlier one returns None does not risk masking one with
       another.
    """
    parts = [
        "Explain ONLY the finding below. Do not reuse any wording from the "
        "worked examples in your instructions above -- those show STYLE "
        "only, never content to repeat. This finding is a different, "
        "unrelated case; read its actual fields before answering."
    ]

    detail = _evidence_detail(finding)
    computed_outcome = (
        _compute_dead_rule_outcome(detail)
        or _compute_policy_outcome(detail)
        or _compute_expected_actual_outcome(detail)
    )
    if computed_outcome is not None:
        # Deliberately NOT a distinctive, quotable label like "IMPORTANT
        # FACT:" -- measured directly that the model would echo a label
        # like that verbatim as its own paragraph instead of folding the
        # fact into its prose. Phrased as a passing instruction instead, and
        # told explicitly not to output any heading of its own.
        parts.append(
            "One more thing, already verified by code and certain, not "
            "something to re-derive, hedge, or contradict: "
            + computed_outcome
            + " Work this into your explanation using your own words, as "
            "part of the same flowing sentences as everything else -- do "
            "not quote it, label it, or set it apart as its own paragraph. "
            "You also do not need to interpret the raw 'Reason:' code in "
            "evidence.detail yourself (e.g. 'BLOCKING_LINES' is an internal "
            "code naming why the line is unreachable, not a rule or a "
            "device) -- the fact above already accounts for it."
        )

    parts.append("Finding to explain:\n" + json.dumps(finding, indent=2))
    return "\n\n".join(parts)


def _generate(finding: Dict[str, Any]) -> str:
    """One call to the model. No validation here -- explain() decides
    whether the result is acceptable."""
    # A second, independent enforcement point. `explain_with_source()` calls
    # the reachability guard first, but this protects a future direct caller
    # from accidentally bypassing the local boundary.
    if not _model_use_is_permitted():
        raise RuntimeError("remote Ollama host refused by Netwise local-model safety")
    response = ollama.generate(model=MODEL_NAME, prompt=_build_prompt(finding))
    return response["response"].strip()


def _try_generate(finding: Dict[str, Any]) -> Optional[str]:
    """One attempt to call the model, or None if the model could not be
    reached or could not answer.

    WHY THIS EXISTS
        analyse() already reports an unreachable Batfish as a status="error"
        finding rather than raising -- the web layer never has to handle an
        exception for it. Before this wrapper, explain() did not follow the
        same convention: `ollama.generate()` raises when the request cannot
        be served, and nothing here caught it. Confirmed directly, two ways:

            Ollama not running at all    -> builtin ConnectionError
            Ollama running, model not
            built (`ollama create ...`
            never run)                   -> ollama.ResponseError, HTTP 404

        The second is at least as likely as the first in practice -- it is
        exactly the state of a fresh clone before anyone has followed
        ai/explain.py's own PREREQUISITE section -- and was missed by the
        first pass at this fix, which only caught ConnectionError. Also
        catches ollama.RequestError (a malformed request, e.g. a model name
        the client rejects before sending), the third member of the same
        "the model could not be reached or could not answer" family; not
        reproduced live, included on the same reasoning as the other two
        rather than waiting for it to be found the hard way.

        Same failure class -- a dependency the check does not control is
        down or misconfigured -- handled two different ways. Wiring
        explanations into the dashboard (#31) on top of the old behaviour
        would mean a machine without Ollama running, or with the wrong
        model built, gets a broken findings view instead of findings
        without explanations.

    Returns None rather than raising so explain() can fall back the same way
    it already does when generation fails validation twice, instead of
    needing a separate failure path per exception type.
    """
    try:
        return _generate(finding)
    except (ConnectionError, ollama.ResponseError, ollama.RequestError):
        return None


def _is_unacceptable(text: str, *, is_error: bool) -> bool:
    """One check, used for every status. status="error" additionally
    rejects any claimed result about the network; every status rejects
    hedged speculation. See the module docstring's two-failure-modes
    section for why these are checked separately from each other."""
    if is_error and _looks_like_a_result_claim(text):
        return True
    return _looks_like_speculation(text)


#: Ollama's default port. The client honours OLLAMA_HOST, so the probe does
#: too -- probing 127.0.0.1 while the client talks to another machine would
#: skip generation on a working setup, which is the one way this can be worse
#: than no probe at all.
OLLAMA_DEFAULT_PORT = 11434

#: Explicitly opting out of Netwise's local-only model boundary. This is an
# environment variable rather than a dashboard control: a browser user must
# not be able to send configuration-derived evidence away by clicking through
# a convenient-looking prompt.
REMOTE_OLLAMA_OPT_IN = "NETWISE_ALLOW_REMOTE_OLLAMA"

#: How long a reachability answer is trusted, in seconds.
#:
#: SHORT ON PURPOSE, AND THE SHORTNESS IS THE SAFETY ARGUMENT.
#:     Caching "Ollama is down" for the process lifetime would mean somebody
#:     starting it mid-session never gets a model explanation until they
#:     restart the app. Five seconds is long enough to collapse one page's
#:     worth of findings into a single probe, and short enough that a model
#:     started during the demo is picked up on the next page load.
#:
#:     NOTE WHAT IS **NOT** CACHED: the fallback TEXT. `web/main.py` refuses
#:     to store that on purpose, so that a later-started model produces fresh
#:     output rather than a stale string. This changes only how long we spend
#:     discovering the model is absent.
OLLAMA_PROBE_TTL_SECONDS = 5.0

#: Answer plus the monotonic time it was taken. `None` means never probed.
_reachability: Dict[str, Any] = {"up": None, "at": 0.0}


def _ollama_endpoint() -> "tuple[str, int]":
    """The (host, port) the ollama client will actually talk to.

    Honours OLLAMA_HOST in the forms the client accepts: `host`,
    `host:port`, and `http://host:port`.
    """
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return ("127.0.0.1", OLLAMA_DEFAULT_PORT)

    without_scheme = raw.split("://", 1)[-1].rstrip("/")
    host, _, port = without_scheme.partition(":")
    try:
        return (host or "127.0.0.1", int(port) if port else OLLAMA_DEFAULT_PORT)
    except ValueError:
        return (host or "127.0.0.1", OLLAMA_DEFAULT_PORT)


def _is_loopback_host(host: str) -> bool:
    """Whether `host` unambiguously names this machine.

    Do not resolve arbitrary hostnames here. DNS resolution is network activity
    and a hostname that resolves to loopback today can resolve somewhere else
    tomorrow. Only the literal localhost name and literal loopback IP addresses
    satisfy Netwise's local-only promise.
    """
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _remote_ollama_is_explicitly_allowed() -> bool:
    """Whether the operator made the deliberate remote opt-in."""
    return os.environ.get(REMOTE_OLLAMA_OPT_IN) == "1"


def _model_use_is_permitted() -> bool:
    """Enforce Netwise's local-only model boundary before any model call.

    `OLLAMA_HOST` is useful for choosing a non-default local port, but it must
    not silently turn an offline product into one that transfers
    configuration-derived evidence to another machine. A remote model is only
    permitted after an operator explicitly sets `NETWISE_ALLOW_REMOTE_OLLAMA=1`.
    """
    host, _port = _ollama_endpoint()
    return _is_loopback_host(host) or _remote_ollama_is_explicitly_allowed()


def local_model_boundary_notice() -> Optional[str]:
    """Explain to a user why the safe deterministic path was selected."""
    if _model_use_is_permitted():
        return None
    return (
        "Local-model safety: Netwise did not send config-derived evidence to "
        "the non-local OLLAMA_HOST. It used a deterministic plain-English "
        "summary instead. Remote inference requires the explicit operator "
        "opt-in NETWISE_ALLOW_REMOTE_OLLAMA=1."
    )


def reset_reachability_cache() -> None:
    """Forget the last probe. Exported for tests, and for a caller that knows
    the world just changed."""
    _reachability["up"] = None
    _reachability["at"] = 0.0


def _ollama_is_reachable() -> bool:
    """Is anything listening where the model should be? (#225)

    WHY THIS EXISTS
        Measured on a machine with no Ollama, five findings on one page:

            call 1: 13.80s | 5 explain calls costing 10.15s | all fallback
            call 2: 10.13s | 5 explain calls costing 10.12s | all fallback
            call 3: 10.17s | 5 explain calls costing 10.16s | all fallback

        The analysis cache was working perfectly -- `analyse()` ran once. Every
        second of that was findings queueing up to discover, separately, that
        a service is absent. Ten seconds of blank screen reads as broken.

        `analysis/pipeline.connect()` already solves exactly this for Batfish,
        for exactly this reason, and records the same kind of measurement.
        This is that idea applied to the other dependency.

    WHY A PORT PROBE AND NOT A REAL REQUEST
        A probe is allowed to be cheap and approximate because it can only
        ever SKIP work, never fabricate an answer. An open port is not proof
        Ollama is healthy -- the model may not be built, which raises
        `ResponseError` -- so `_try_generate()` still handles every failure it
        handled before. This short-circuits the negative case only.

    FAILING TOWARDS ATTEMPTING
        Any unexpected error here returns True, so generation is attempted.
        A broken probe must never be able to silently downgrade a working
        installation to deterministic text -- that would trade a slow page
        for a false byline, which is a far worse bargain.
    """
    # This is an enforcement point, not merely a speed optimisation. Do this
    # before the socket call so an unapproved remote hostname is neither
    # resolved nor contacted.
    if not _model_use_is_permitted():
        return False

    now = time.monotonic()
    if (_reachability["up"] is not None
            and now - _reachability["at"] < OLLAMA_PROBE_TTL_SECONDS):
        return bool(_reachability["up"])

    host, port = _ollama_endpoint()
    try:
        with socket.create_connection((host, port), timeout=0.4):
            up = True
    except OSError:
        up = False
    except Exception:          # noqa: BLE001 -- see FAILING TOWARDS ATTEMPTING
        up = True

    _reachability["up"] = up
    _reachability["at"] = now
    return up


def explain_with_source(finding: Dict[str, Any]) -> "tuple[str, str]":
    """Same computation as explain(), but also says which path produced the
    text: (text, source), source is "model" or "fallback".

    Added for #109. The dashboard labels every explanation "AI explanation"
    unconditionally, including when Ollama is absent and the text is
    `_fallback_plain_restatement()`, deterministic string concatenation of
    the finding's own fields -- correct and deliberate (#52), but no AI
    wrote it, and explain()'s bare `str` return gave nothing downstream a
    way to tell the two apart. This function reports the one extra fact
    needed to fix that at the source, rather than having a caller guess
    from the text's shape.

    explain() itself is UNCHANGED below -- same signature, same behaviour,
    every existing caller and test keeps working exactly as before. This
    is the same decision with one more fact reported alongside it, not a
    second one.
    """
    is_error = finding.get("status") == "error"

    # `and _ollama_is_reachable()` is the whole of #225. The evidence check
    # comes FIRST and is unchanged: a finding with no real evidence never
    # reaches the model regardless, and that ordering is a grounding rule
    # rather than a performance one.
    if _evidence_detail(finding) and _ollama_is_reachable():
        for _ in range(2):
            explanation = _try_generate(finding)
            if explanation is None:
                break
            if not _is_unacceptable(explanation, is_error=is_error):
                return explanation, "model"

    if is_error:
        return _fallback_error_explanation(finding), "fallback"
    return _fallback_plain_restatement(finding), "fallback"


def explain(finding: Dict[str, Any]) -> str:
    """Return a plain-English explanation of ONE F-1 finding.

    Grounded strictly in `finding` -- CLAUDE.md constraint 2. This function
    never receives, and the model never sees, anything beyond the single
    finding passed in: no other findings, no wider network context.

    Generates, validates, and retries once if the first attempt is
    unacceptable; falls back to a fixed, non-generated sentence if the
    second attempt is unacceptable too, rather than ever showing an
    unvalidated response. If Ollama cannot be reached at all, this degrades
    straight to the same fallback -- it does not raise, and it does not
    waste a second attempt against a host that is already known to be
    unreachable.

    If the finding carries no real evidence.detail, generation is skipped
    entirely and this returns the deterministic fallback straight away.

    WHY: found in a senior-level adversarial QA pass. Neither safety-net
    check catches an unhedged, invented claim, because
    _looks_like_a_result_claim() only ever runs for status="error" (a
    "found" explanation legitimately needs words like "blocked" or "reach"
    to describe the confirmed fact -- banning them would break the normal
    case, not fix this one), and _looks_like_speculation() only catches
    HEDGED claims, not confident ones. Reproduced live, 3/3, temperature
    0.2: explain({"id": "AC-101", "status": "found", "summary": "A
    finding"}) -- no evidence field at all -- returned "The device has a
    rule that allows all traffic through with no restriction," a specific,
    confident, entirely invented technical claim. This is exactly what
    CLAUDE.md constraint 2 calls "a critical failure, not a bug": the model
    is only ever supposed to rephrase real Batfish output, and with no
    evidence.detail there is no real output to rephrase.

    Skipping generation rather than trying to prompt or validate the
    hallucination away, for the same reason _compute_dead_rule_outcome()
    refuses rather than guesses when it is not confident: a rule that says
    "do not say more than you know" is only real if it is enforced before
    generation, not policed after it. The fallback restates only the
    fields that are actually known (summary, and detail if present), which
    is strictly less than what was already being shown for a validation
    failure -- this is not a new code path, it is the existing one taken
    one step earlier.

    Delegates to explain_with_source() and discards which path produced
    the text. Callers that need that fact -- currently just the dashboard,
    for the AI-byline provenance question in #109 -- use that function
    directly instead.
    """
    return explain_with_source(finding)[0]


if __name__ == "__main__":
    from analysis.pipeline import analyse

    results = analyse("tests/fixtures/rtr-us5-insecure", check_names=["access_control"])
    finding = results[0]

    print("Finding:")
    print(json.dumps(finding, indent=2))
    print()
    print("Explanation:")
    print(explain(finding))
