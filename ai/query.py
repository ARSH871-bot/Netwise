"""
Netwise -- Layer 2, turning a plain-English question into a grounded answer
(US-11).

WHAT THIS DOES
    answer_question(question: str, bf: Session) -> dict
    Takes ONE plain-English question and returns:

        {"question_understood": str | None,
         "answer": str,
         "grounded": bool}

    `ai/explain.py` already does the other direction, finding -> English.
    This module does English -> finding: before anything can be explained,
    something has to decide which Batfish question to run and with what
    parameters. That decision is this module's whole job.

THE SHAPE: A (constrained selection) + C (show the question back)
    Per docs/design/query-grounding-problem.md (issue #64): every safety
    mechanism this project has built sits downstream of the query being the
    right one. `explain()` only ever rephrases a finding that already
    exists; nothing upstream of it decides what to ask. US-11 needed
    something upstream, and #64's worked example is why that is dangerous
    on its own: a mistranslated question can produce a real, evidenced,
    confidently wrong answer that passes every existing guard, because
    every existing guard checks whether the ANSWER is grounded in the
    query, not whether the QUERY was the right one.

    So this module never lets a question become an arbitrary Batfish call.
    It classifies the question's intent against a small, closed set of
    templates, resolves any named device/address against what the snapshot
    actually contains, and REFUSES rather than guesses the moment either
    step is not confident. Shape C is `question_understood`: whatever the
    answer, the caller can always show back what was actually run, so a
    wrong translation is visible to the person best placed to notice it,
    the one who asked.

WHY NEITHER STEP CALLS THE MODEL, ON PURPOSE
    Two places an LLM could plausibly sit: understanding the question, and
    writing the answer. Neither is used here, in this first version.

    Using a model to CLASSIFY the question would mean guessing at intent,
    exactly the move this project has refused everywhere else it faced the
    choice: `_compute_dead_rule_outcome()` refuses rather than infers when
    blocking lines disagree; `pfsense_convert.py` refuses rather than
    approximates an unsupported construct; explain() itself now refuses to
    generate at all when a finding carries no real evidence (#52). A
    closed set of three intents, matched against a fixed vocabulary, is
    fully testable without Ollama and cannot invent an intent nobody typed.

    The ANSWER text is built directly from Batfish's own disposition and
    path, the same "state the observed effect" discipline
    `analysis/checks/routing.py` already uses for its own findings, rather
    than paraphrased by a model that could reintroduce the exact wording
    risk explain()'s safety net exists to catch. Revisit if this proves too
    rigid, widening is safe, the reverse is not (#64's own argument,
    applied here too).

SCOPE (see docs/ankeet/US11-NATURAL-LANGUAGE.md for the full reasoning and
the live verification behind it, not committed to this repo)
    Three intents only:

        reachability          -> traceroute
        dead ACL rules        -> filterLineReachability
        undefined references  -> undefinedReferences

    testFilters/searchFilters are deliberately unreachable from here, both
    require a filter name upfront, which no natural-language question
    supplies, and traceroute already answers "can X reach Y" completely,
    ACLs included, without ever needing one.

    A reachability question's SOURCE must resolve to a known device name
    (see analysis.snapshot.device_names()); this is not a simplification,
    it is a hard Batfish requirement -- traceroute's `startLocation` is
    mandatory and must be a device/interface reference, confirmed live: a
    raw IP there raises BatfishException, not a validation error. The
    DESTINATION must be a literal IP address or CIDR. No source IP is
    supplied to `headers`; Batfish selects a representative one for the
    starting device, confirmed live to work.

    A CIDR destination is resolved to one real host address ourselves,
    rather than handed to Batfish as-is (#70). Left alone, Batfish resolves
    a network destination to its own network address, which is never a
    live host -- confirmed live on `routing-secure`: every actual host in
    10.20.20.0/24 answers "Yes", but the network itself answered "No",
    silently, with `grounded: true`, because the trace was well-formed and
    genuinely ended in EXITS_NETWORK. Nothing hallucinated and no guard
    failed; the query was simply not the one the user meant. This module
    picks the host itself now (see `_representative_host`) and names it in
    both `question_understood` and the answer text, so the substitution is
    visible rather than silent -- shape C doing the job it exists for.

    This is narrower than CLAUDE.md's own example question ("the guest
    network reach the finance server", both sides named, neither a raw
    IP). Stated plainly rather than glossed over: resolving a destination
    from a plain-English name needs interface/IP enumeration this project
    does not have yet (checked directly: the real Cisco fixtures carry no
    interface description text to match a name against). A real,
    incremental step, not the whole client ask.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Optional

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

from analysis import findings, snapshot

# ------------------------------------------------------------------------------
# 1. Intent classification -- a closed set of three, nothing else
# ------------------------------------------------------------------------------

# Deliberately narrow phrase sets, not a general parser. A question that
# matches none of these is refused, not guessed at -- see answer_question().
_REACH_KEYWORDS = re.compile(
    r"\b(?:reach|access|connect to|get to|talk to)\b", re.IGNORECASE
)
_DEAD_RULE_KEYWORDS = re.compile(
    r"\b(?:dead|unreachable|shadow(?:ed)?|never\s+(?:take|takes)\s+effect)\b"
    r".*\b(?:rules?|lines?|acls?)\b"
    r"|\b(?:rules?|lines?|acls?)\b.*\b(?:dead|unreachable|shadow(?:ed)?|"
    r"never\s+(?:take|takes)\s+effect)\b",
    re.IGNORECASE,
)
_UNDEFINED_REF_KEYWORDS = re.compile(
    r"\bundefined\b|\bnot\s+defined\b|\bbroken\s+references?\b|"
    r"\bmissing\s+(?:acls?|objects?|route-?maps?)\b",
    re.IGNORECASE,
)

_IP_OR_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")


def _is_valid_ip_or_cidr(text: str) -> bool:
    """True if `text` parses as a real IPv4 address or network -- not just
    four dot-separated numbers. "999.1.1.1" matches _IP_OR_CIDR's regex
    shape but is not a real address; this is the second check that catches
    it, the same "validate, don't just pattern-match" discipline
    pfsense_convert.py already uses for <address>/<ipaddr>."""
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def _find_device(text: str, known_devices: "set[str]") -> Optional[str]:
    """The first known device name mentioned in `text`, matched whole-word
    so "rtr-us5" does not spuriously match inside a longer token. Returns
    None if no known device is mentioned -- callers must not guess."""
    for device in known_devices:
        if re.search(rf"\b{re.escape(device)}\b", text, re.IGNORECASE):
            return device
    return None


def _find_ip_or_cidr(text: str) -> Optional[str]:
    """The first valid IPv4 address or CIDR mentioned in `text`, or None."""
    for match in _IP_OR_CIDR.finditer(text):
        if _is_valid_ip_or_cidr(match.group(1)):
            return match.group(1)
    return None


def _representative_host(network: "ipaddress.IPv4Network") -> str:
    """One concrete host address inside `network`, picked deterministically.

    Only called for a network wider than a single address -- see
    _resolve_destination(). `hosts()` excludes the network and broadcast
    addresses, which is exactly what a "real host" should mean, and is
    empty for /31 and /32, where those addresses are the only ones there
    are; the network address is a reasonable, disclosed fallback for that
    edge case rather than a case this project's fixtures actually exercise.
    """
    first_host = next(network.hosts(), None)
    return str(first_host) if first_host is not None else str(network.network_address)


def _resolve_destination(destination_text: str) -> Optional["tuple[str, str]"]:
    """The literal address to query Batfish with, and how to name it in
    question_understood / the answer text. For a single host these are the
    same string. For a network (#70), Batfish would otherwise silently
    resolve the CIDR to its own network address -- never a live host -- so
    this module picks a real host itself and says exactly which one, rather
    than letting a wrong answer happen quietly. Returns None if nothing
    valid is found."""
    matched = _find_ip_or_cidr(destination_text)
    if matched is None:
        return None

    network = ipaddress.ip_network(matched, strict=False)
    if network.num_addresses == 1:
        address = str(network.network_address)
        return address, address

    host = _representative_host(network)
    return host, f"a host in {matched} (checked {host})"


def _split_on_reach_keyword(question: str) -> Optional[tuple]:
    """Split a reachability question into (source_text, destination_text)
    around the first reach-style keyword. "Can rtr-us5 reach 10.20.0.5"
    splits into ("Can rtr-us5 ", " 10.20.0.5"). Returns None if no
    reach-style keyword is present at all."""
    match = _REACH_KEYWORDS.search(question)
    if not match:
        return None
    return question[: match.start()], question[match.end() :]


# ------------------------------------------------------------------------------
# 2. The public entry point
# ------------------------------------------------------------------------------


def answer_question(question: str, bf: Session) -> Dict[str, Any]:
    """Answer ONE plain-English question, grounded strictly in a real
    Batfish result -- see the module docstring for the shape and why
    neither step here calls a model.

    ALWAYS returns the same three keys:
        question_understood -- what was actually run, in plain English, or
                                None if nothing was understood well enough
                                to run anything (shape C)
        answer               -- the plain-English answer, or a refusal
        grounded              -- False on any refusal; lets a caller style
                                a refusal the way a status="error" card
                                already is, not as a normal answer

    Never raises. A malformed question, an unresolvable name, or a Batfish
    failure are all refusals, not exceptions -- the same convention
    analyse() already holds for an unreachable Batfish, and explain() now
    holds for an unreachable Ollama.
    """
    question = (question or "").strip()
    if not question:
        return _refuse("The question was empty.")

    if _DEAD_RULE_KEYWORDS.search(question):
        return _answer_whole_snapshot_question(
            bf,
            batfish_question="filterLineReachability",
            question_understood="Are there any ACL lines that can never take effect?",
        )

    if _UNDEFINED_REF_KEYWORDS.search(question):
        return _answer_whole_snapshot_question(
            bf,
            batfish_question="undefinedReferences",
            question_understood="Does anything reference a structure that is never defined?",
        )

    split = _split_on_reach_keyword(question)
    if split is not None:
        return _answer_reachability_question(split, bf)

    return _refuse(
        "This does not match a question I can answer yet: whether one "
        "device can reach an address, whether any ACL rule never takes "
        "effect, or whether anything references something undefined."
    )


def _refuse(reason: str) -> Dict[str, Any]:
    return {"question_understood": None, "answer": reason, "grounded": False}


# ------------------------------------------------------------------------------
# 3. Reachability -- traceroute
# ------------------------------------------------------------------------------


def _answer_reachability_question(split: tuple, bf: Session) -> Dict[str, Any]:
    source_text, destination_text = split

    present = snapshot.device_names(bf)
    if present is None:
        return _refuse(
            "The devices in this snapshot could not be determined, so I "
            "cannot tell whether the device you named is even in it."
        )

    source_device = _find_device(source_text, present)
    if source_device is None:
        return _refuse(
            "I could not find a known device name on the source side of "
            f"the question ({source_text.strip()!r}). I can only start a "
            "reachability check from a device that is actually in this "
            "snapshot, not a description of one."
        )

    resolved = _resolve_destination(destination_text)
    if resolved is None:
        return _refuse(
            "I could not find a valid IP address or network on the "
            f"destination side of the question ({destination_text.strip()!r}). "
            "For now I can only check reachability to a literal address, "
            "not a name like \"the finance server\"."
        )
    destination_ip, destination_display = resolved

    question_understood = (
        f"Can {source_device} reach {destination_display}?"
    )

    try:
        frame = (
            bf.q.traceroute(
                startLocation=source_device,
                headers=HeaderConstraints(dstIps=destination_ip),
            )
            .answer()
            .frame()
        )
    except Exception as error:
        return {
            "question_understood": question_understood,
            "answer": (
                "I could not run this check. The underlying reason: "
                + findings.describe_error(error)
            ),
            "grounded": False,
        }

    if frame.empty:
        return {
            "question_understood": question_understood,
            "answer": (
                f"Batfish returned no result starting from {source_device!r}. "
                "Does it exist in this snapshot the way I expect?"
            ),
            "grounded": False,
        }

    traces = frame.iloc[0]["Traces"]
    return {
        "question_understood": question_understood,
        "answer": _describe_traces(source_device, destination_display, traces),
        "grounded": True,
    }


# Same set analysis/checks/routing.py uses, and for the same reason,
# repeated here rather than imported so ai/ does not depend on a specific
# check module for a general Batfish-interpretation fact. pybatfish's own
# tooling also treats EXITS_NETWORK as success for colouring a trace
# diagram green; this project measured directly that a missing device
# reports EXITS_NETWORK too, which would read a genuinely absent
# destination as a working route. Excluded on purpose -- see
# routing.py's module docstring for the full account.
_SUCCESS_DISPOSITIONS = {"ACCEPTED", "DELIVERED_TO_SUBNET"}


def _describe_traces(source_device: str, destination_display: str, traces: Any) -> str:
    """Plain English, built directly from Batfish's own disposition and
    path -- never paraphrased by a model. States the observed effect, not
    an assumed cause, same discipline routing.py's own summaries hold.

    `destination_display` is whatever _resolve_destination() decided to
    call the destination -- a literal address, or (#70) "a host in
    <network> (checked <address>)" -- so the answer names the same thing
    question_understood does, rather than the answer being silently more
    specific than what the person was told was checked."""
    successes = [t for t in traces if t.disposition in _SUCCESS_DISPOSITIONS]
    failures = [t for t in traces if t.disposition not in _SUCCESS_DISPOSITIONS]

    if successes and not failures:
        return f"Yes. Traffic from {source_device} reaches {destination_display}."

    if failures and not successes:
        bad = failures[0]
        hops = " -> ".join(hop.node for hop in bad.hops) or source_device
        return (
            f"No. Traffic from {source_device} to {destination_display} ends in "
            f"{bad.disposition}. Path: {hops}."
        )

    # Both -- multiple traced paths disagree (e.g. equal-cost routes with
    # different outcomes). Reported plainly rather than picking one side,
    # the same "do not guess which one decides" discipline
    # _compute_dead_rule_outcome() already holds for ambiguous evidence.
    return (
        f"Mixed result: {len(successes)} of {len(traces)} traced paths from "
        f"{source_device} to {destination_display} succeed, {len(failures)} do not. "
        "The paths disagree, so there is no single yes/no answer here."
    )


# ------------------------------------------------------------------------------
# 4. Whole-snapshot questions -- no parameters, nothing to resolve
# ------------------------------------------------------------------------------


def _answer_whole_snapshot_question(
    bf: Session, *, batfish_question: str, question_understood: str
) -> Dict[str, Any]:
    try:
        frame = getattr(bf.q, batfish_question)().answer().frame()
    except Exception as error:
        return {
            "question_understood": question_understood,
            "answer": (
                "I could not run this check. The underlying reason: "
                + findings.describe_error(error)
            ),
            "grounded": False,
        }

    if frame.empty:
        return {
            "question_understood": question_understood,
            "answer": "No, checked the whole snapshot and found none.",
            "grounded": True,
        }

    return {
        "question_understood": question_understood,
        "answer": (
            f"Yes, found {len(frame)}. See the dashboard's findings list for "
            "the specific lines, this question only confirms whether any exist."
        ),
        "grounded": True,
    }
