"""
Netwise -- Layer 2, turning a plain-English question into a grounded answer
(US-11), and letting a reachability follow-up reuse what the last one
already resolved (US-25, #318).

WHAT THIS DOES
    answer_question(question: str, bf: Session, previous: dict | None = None) -> dict
    Takes ONE plain-English question and returns:

        {"question_understood": str | None,
         "answer": str,
         "grounded": bool,
         "resolved_entities": dict | None}

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

    The source resolves to `@enter(device)`, not the bare device name (#108).
    A bare device name is a NODE location -- traffic ORIGINATING at the
    device -- which never traverses an inbound ACL, so a config that blocks
    the traffic and one that permits everything answered identically,
    `grounded: true` on both. Measured live: `analysis/change_impact.py` hit
    the same trap the same week, from the same cause -- see its module
    docstring for the general shape. `@enter(device)` with no interface
    covers every interface the device has, which is what "can X reach Y"
    means to whoever asks it; the narrower "can this device itself originate
    reachable traffic" reading is not offered as a separate question here.

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

FOLLOW-UPS: ENTITIES CARRIED FORWARD, NEVER INTENT (#318)
    #240 named the unscoped version of this as "multi-step deterministic
    reasoning" -- a planner decomposing a compound question into an ordered
    sequence of sub-queries. #240 itself says not to start that off the back
    of the direction doc alone. #318 is the scoped piece that actually has
    acceptance criteria, and it is much narrower: a REACHABILITY question
    may omit its source device or its destination, and the missing side is
    filled from the previous turn's resolved entities -- passed in via
    `previous`, a dict shaped `{"source_device", "destination_ip",
    "destination_display"}`, the same three values this module already
    produces internally for every successful reachability resolution.

    WHAT THIS DELIBERATELY DOES NOT DO
        It does not relax intent CLASSIFICATION. A follow-up still needs a
        reach-style keyword to be recognised as a reachability question at
        all -- "does it reach 10.20.20.5" works, a bare "what about
        rtr-branch" with no reach keyword does not, and refuses exactly as
        before. The three-way classifier above is untouched. Only ENTITY
        RESOLUTION, inside the reachability path specifically, gains a
        fallback. CLAUDE.md 7c is explicit that this module's narrow scope
        is what makes it safe rather than merely limited; widening the
        classifier is a materially bigger decision than extending one
        already-existing fallback inside one already-existing path, and
        #318's own acceptance criteria say "entities", not "intents".

    THE FALLBACK FIRES ON A BACK-REFERENCE, NEVER ON RESOLUTION FAILURE
        ALONE (found by review, @ARSH871-bot). The first version fell back
        whenever a side failed to resolve, which does not distinguish "the
        question left this side out" from "the question named something
        that does not resolve" -- a typo, a plain-English name, a malformed
        address. Every one of the second kind used to refuse, and the SCOPE
        section above says it must keep refusing: "Can the guest network
        reach the finance server" is CLAUDE.md's own must-refuse example.
        Measured with the old version: that exact question, a typo'd device
        name, and a malformed IP all came back "Yes", `grounded: True`,
        quietly using the PREVIOUS turn's entity -- the worst shape a
        query-layer mistake can take, evidenced and confident and
        reproducible.

        So `_is_source_back_reference()`/`_is_destination_back_reference()`
        recognise a back-reference from a CLOSED SET ("it", "that device",
        ...; never anything containing a digit on the destination side),
        the same discipline `_REACH_KEYWORDS` already applies to intent. A
        segment that names something and fails to resolve it is refused,
        never guessed at as a reference to the last turn.

    WHY THE CARRIED-FORWARD DEVICE IS RE-VALIDATED, NOT TRUSTED
        `previous["source_device"]` is checked against THIS call's own
        `snapshot.device_names(bf)` before being used, exactly like a
        device named directly in the question text. A device from a
        different, earlier upload must not silently survive into this one
        just because the name happens to still exist -- reused state is
        still state, and this module already refuses rather than trusts
        everywhere else it can.

    WHY EXPLICIT TEXT ALWAYS WINS, WITH NO SEPARATE OVERRIDE LOGIC
        The fallback is only ever consulted when the question's own text
        fails to resolve a side AND that side is a recognised back-reference.
        If the current question names a device or address directly, that is
        what gets used, `previous` is never looked at for that side. This is
        a property of the order operations happen in, not a rule enforced
        separately -- see tests/test_query_translation.py for the test
        proving it holds.

    WHAT resolved_entities MEANS ON THE WAY OUT
        Populated whenever a reachability question's source AND destination
        both resolved -- fresh, carried forward, or one of each -- so the
        NEXT turn has something to reuse, independent of whether the
        Batfish call itself then succeeded (resolution and querying are
        different steps; a Batfish failure downstream does not undo a
        genuine resolution). None for a refused question and for both
        whole-snapshot intents, which have no per-question entity to carry.
        A caller (see web/main.py's /api/ask) is expected to persist this
        keyed by session and feed it back in as next turn's `previous` --
        this module holds no state of its own between calls.
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
# 1b. Back-references -- a closed set, exactly like everything else here
# ------------------------------------------------------------------------------
#
# FOUND BY REVIEW (@ARSH871-bot, #318), FIXED HERE.
#     The first version of the follow-up fallback fired whenever a side
#     failed to resolve, for ANY reason -- which does not distinguish "the
#     question left this side out" (the feature) from "the question named
#     something that does not resolve" (a typo, a plain-English name, a
#     malformed address). Before this, every one of the second kind
#     REFUSED, and the module docstring's own SCOPE section says they must:
#     "Can the guest network reach the finance server" is refused on
#     purpose, and widening it is future work that must keep the refusal
#     path intact. Measured live: with a previous turn resolved, that exact
#     question -- and a typo'd device name, and a malformed IP -- all came
#     back "Yes", `grounded: True`, using the PREVIOUS turn's entity. That
#     is the worst shape a query-layer mistake can take: evidenced,
#     confident, and reproducible, answering a question nobody asked.
#
#     So the fallback now fires on a BACK-REFERENCE, recognised positively
#     from a closed set, exactly the same discipline `_REACH_KEYWORDS` and
#     friends already use -- never on resolution failure alone. A segment
#     that names something and fails still refuses.

_SOURCE_BACK_REFERENCE_LEAD = re.compile(
    r"^\s*(?:can|does|is|could|would|will|do)\b\s*", re.IGNORECASE
)
#: Stripped from EITHER end after the lead, so "does it also reach" and
#: "does it reach too" both still match "it" -- filler, not content, and
#: still a closed set rather than a general parser. Adding a word here
#: never widens what counts as a REFERENCE, only how much filler around one
#: is tolerated.
_LEADING_FILLER = re.compile(r"^(?:also|still|too|even)\s+", re.IGNORECASE)
_TRAILING_FILLER = re.compile(r"\s+(?:also|still|too|even)$", re.IGNORECASE)
_SOURCE_BACK_REFERENCES = {
    "it", "that", "this", "that device", "this device", "the same device",
}
_DESTINATION_BACK_REFERENCES = {
    "it", "that", "there", "that address", "the same address",
}


def _strip_back_reference_filler(text: str) -> str:
    """Remove AT MOST ONE filler word, from either end -- "does it also
    still reach" is two filler words, and this project's own discipline is
    to refuse the unusual rather than parse harder to accept it, so only
    one substitution is ever attempted, tried leading first."""
    stripped = _LEADING_FILLER.sub("", text, count=1)
    if stripped == text:
        stripped = _TRAILING_FILLER.sub("", text, count=1)
    return stripped.strip()


def _is_source_back_reference(source_text: str) -> bool:
    """True only for a closed set of literal back-references ("it", "that
    device", ...), never for text that merely failed to name a real device.
    "rtr-brnch" (a typo) and "the guest network" (CLAUDE.md's own
    must-refuse example) are both real text that named something -- neither
    is in the set, so neither is treated as a reference to the last turn."""
    stripped = _SOURCE_BACK_REFERENCE_LEAD.sub("", source_text).strip().lower()
    stripped = _strip_back_reference_filler(stripped)
    return stripped in _SOURCE_BACK_REFERENCES


def _is_destination_back_reference(destination_text: str) -> bool:
    """Same discipline, destination side. ANY digit disqualifies it on
    purpose -- something IP-shaped that failed to parse (a typo'd address,
    an out-of-range octet) is a malformed address, not a reference to the
    last turn's destination, and must still refuse rather than silently
    substitute a different address than the one the user typed."""
    stripped = destination_text.strip().rstrip("?.!").strip().lower()
    if any(ch.isdigit() for ch in stripped):
        return False
    stripped = _strip_back_reference_filler(stripped)
    return stripped in _DESTINATION_BACK_REFERENCES


# ------------------------------------------------------------------------------
# 2. The public entry point
# ------------------------------------------------------------------------------


def answer_question(
    question: str, bf: Session, previous: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Answer ONE plain-English question, grounded strictly in a real
    Batfish result -- see the module docstring for the shape and why
    neither step here calls a model.

    ALWAYS returns the same four keys:
        question_understood -- what was actually run, in plain English, or
                                None if nothing was understood well enough
                                to run anything (shape C)
        answer               -- the plain-English answer, or a refusal
        grounded              -- False on any refusal; lets a caller style
                                a refusal the way a status="error" card
                                already is, not as a normal answer
        resolved_entities     -- dict or None; see the module docstring's
                                "FOLLOW-UPS" section for exactly when this
                                is populated and what a caller does with it

    `previous`, if given, is that same resolved_entities dict from an
    earlier call -- see "FOLLOW-UPS" in the module docstring. Omitted or
    None, this behaves exactly as it always has; passing it never widens
    which questions are UNDERSTOOD, only which reachability questions can
    leave a side unresolved and still run.

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
        return _answer_reachability_question(split, bf, previous)

    return _refuse(
        "This does not match a question I can answer yet: whether one "
        "device can reach an address, whether any ACL rule never takes "
        "effect, or whether anything references something undefined."
    )


def _refuse(reason: str) -> Dict[str, Any]:
    return {
        "question_understood": None,
        "answer": reason,
        "grounded": False,
        "resolved_entities": None,
    }


# ------------------------------------------------------------------------------
# 3. Reachability -- traceroute
# ------------------------------------------------------------------------------


def _answer_reachability_question(
    split: tuple, bf: Session, previous: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    source_text, destination_text = split

    present = snapshot.device_names(bf)
    if present is None:
        return _refuse(
            "The devices in this snapshot could not be determined, so I "
            "cannot tell whether the device you named is even in it."
        )

    source_device = _find_device(source_text, present)
    if (source_device is None and previous is not None
            and _is_source_back_reference(source_text)):
        # The source side is a literal back-reference ("it", "that
        # device", ...), not merely unresolved text -- see "1b." above for
        # why the distinction is load-bearing. Fall back to what the LAST
        # question resolved -- but re-validate it against THIS snapshot,
        # exactly like a name typed directly: a device from a different,
        # earlier upload must not survive into this one just because the
        # name happens to still exist. See the module docstring.
        candidate = previous.get("source_device")
        if candidate and candidate in present:
            source_device = candidate
    if source_device is None:
        return _refuse(
            "I could not find a known device name on the source side of "
            f"the question ({source_text.strip()!r}). I can only start a "
            "reachability check from a device that is actually in this "
            "snapshot, not a description of one."
        )

    resolved = _resolve_destination(destination_text)
    if (resolved is None and previous is not None
            and _is_destination_back_reference(destination_text)):
        # Same fallback, destination side, same "back-reference, not just
        # unresolved" gate. Already-validated by the call that originally
        # resolved it, so no re-validation needed here -- unlike a device
        # name, a literal IP carries no snapshot-specific meaning to go
        # stale.
        candidate_ip = previous.get("destination_ip")
        candidate_display = previous.get("destination_display")
        if candidate_ip and candidate_display:
            resolved = (candidate_ip, candidate_display)
    if resolved is None:
        return _refuse(
            "I could not find a valid IP address or network on the "
            f"destination side of the question ({destination_text.strip()!r}). "
            "For now I can only check reachability to a literal address, "
            "not a name like \"the finance server\"."
        )
    destination_ip, destination_display = resolved

    # Both sides resolved -- fresh, carried forward, or one of each -- so
    # this is what the NEXT turn can reuse, independent of whether the
    # Batfish call below then succeeds. See "FOLLOW-UPS" in the module
    # docstring for why resolution and querying are tracked separately.
    resolved_entities = {
        "source_device": source_device,
        "destination_ip": destination_ip,
        "destination_display": destination_display,
    }

    question_understood = (
        f"Can {source_device} reach {destination_display}?"
    )

    try:
        frame = (
            bf.q.traceroute(
                # @enter(), not the bare device name -- see #108. A node
                # location only sees traffic ORIGINATING at the device, so
                # an inbound ACL is never crossed and this returned the same
                # answer for a config that blocked the traffic and one that
                # permitted everything, both "grounded: true". @enter(device)
                # with no interface picks up every interface the device has,
                # which is what "can X reach Y" means to whoever asks it.
                startLocation=f"@enter({source_device})",
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
            "resolved_entities": resolved_entities,
        }

    if frame.empty:
        return {
            "question_understood": question_understood,
            "answer": (
                f"Batfish returned no result starting from {source_device!r}. "
                "Does it exist in this snapshot the way I expect?"
            ),
            "grounded": False,
            "resolved_entities": resolved_entities,
        }

    traces = frame.iloc[0]["Traces"]
    return {
        "question_understood": question_understood,
        "answer": _describe_traces(source_device, destination_display, traces),
        "grounded": True,
        "resolved_entities": resolved_entities,
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
            "resolved_entities": None,
        }

    if frame.empty:
        return {
            "question_understood": question_understood,
            "answer": "No, checked the whole snapshot and found none.",
            "grounded": True,
            "resolved_entities": None,
        }

    return {
        "question_understood": question_understood,
        "answer": (
            f"Yes, found {len(frame)}. See the dashboard's findings list for "
            "the specific lines, this question only confirms whether any exist."
        ),
        "grounded": True,
        "resolved_entities": None,
    }
