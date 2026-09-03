"""
Netwise -- propose a config change from plain English, and simulate its
effect before showing it (US-13, US-14).

WHAT THIS DOES
    propose_change(request: str, before_dir, host="localhost") -> dict
    Takes ONE plain-English request ("block 10.10.10.5 to 10.20.0.5 on
    tcp/443") and returns:

        {"request_understood": str | None,
         "proposed_change": {"device": str, "filter": str, "line": str,
                              "before_lines": list[str], "after_lines": list[str],
                              "after_config_text": str} | None,
         "impact": list[dict],   # F-1 findings from change_impact, [] if none
         "verified": bool,
         "warning": bool,
         "grounded": bool,
         "answer": str}

SCOPE, PER docs/design/config-change-and-pushback.md
    This is shape A from that document, and nothing wider. A request is
    accepted only if it reduces to a closed template this module can
    resolve without guessing: <block|allow> <source> to <destination> on
    <protocol>[/<port>], where source and destination must be a literal IP,
    a CIDR, or the word "any" -- never a service name. "Block YouTube" is
    REFUSED, with a reason, the same way ai/query.py refuses "can the guest
    network reach the finance server" today (US-11). Nothing here maps a
    name to an address; CLAUDE.md section 4 already names that as the
    ceiling, not a gap this module tries to close.

    Neither step calls a model, for the same reason ai/query.py's do not:
    classifying the request would be guessing at intent, and this project
    refuses rather than guesses everywhere else it has faced that choice
    (`pfsense_convert.py`, `_compute_dead_rule_outcome()`, `answer_question()`
    itself). Parsing is a closed set of regular expressions against a fixed
    vocabulary, fully testable without Ollama running.

NEVER APPLIED TO A LIVE DEVICE
    CLAUDE.md's non-negotiable constraint 4: "Netwise GENERATES and
    SIMULATES config changes. It must never push changes to a live device."
    The generated line is written only into a throwaway copy of the
    snapshot, in a temporary directory that is deleted before this function
    returns. `before_dir` itself is never written to.

HOW #14 FALLS OUT OF #13, PER THE SAME DOCUMENT
    "Insecure" is not a judgement this module makes. The generated line is
    applied to a scratch copy of the snapshot and compared against the
    original with `analysis/change_impact.analyse_change()` -- the same
    compareFilters/differentialReachability comparison Shubham's feature
    (#30) already runs for a given before/after pair. That module already
    grades severity by direction: a change that newly OPENS traffic is
    `high` (silent -- nothing breaks, so nobody looks), a change that
    CLOSES traffic is `medium` (loud -- someone notices). `warning=True`
    here means exactly "a high-severity finding is present in that diff" --
    running the tool the project already trusts, twice, and reading its
    answer. No new judgement is introduced.

    This module does NOT audit the proposed state the way change_impact's
    own docstring flags as unbuilt ("it will not tell you that the after
    config violates POL-2, only that it changed"). Running the producer
    checks over the after snapshot too is open question 2 on
    docs/design/pipeline-feature-shapes.md and is not this module's call to
    make alone -- see #182, filed for the related question of how a check
    would even receive a Policy today.

WHY EVERY GENERATED LINE GOES AT THE TOP OF THE FILTER
    A Cisco ACL is first-match-wins, top to bottom (see
    `analysis/pfsense_convert.py`'s own module docstring for the long
    version of why that matters). A line appended at the END of an existing
    filter can be silently shadowed by an earlier catch-all `deny ip any
    any` -- generating a rule that reads as the requested change and does
    nothing is exactly the "confidently wrong" failure this project refuses
    everywhere else. Inserting at the TOP is the one position whose effect
    is knowable without modelling the rest of the filter's shadow
    structure: the new line is always evaluated first, so it is never
    shadowed by anything already there.

WHY A DEVICE WITH MORE THAN ONE INBOUND-BOUND FILTER IS REFUSED
    If two DIFFERENT filter names are each bound `... in` on some interface
    of the target device, which one the client means is not stated by the
    request and is not guessable -- refused, the same "refuse rather than
    guess" discipline `pfsense_convert.py`'s own multi-interface handling
    uses. The same filter name bound to two different interfaces is NOT
    ambiguous: it is one shared filter, and the new line applies to both
    identically, which is exactly what was asked.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from analysis import change_impact, findings, snapshot
from analysis.pipeline import connect, find_parse_problems, load_snapshot

NETWORK_NAME = "netwise-propose"
SNAPSHOT_NAME = "current"

# ------------------------------------------------------------------------------
# 1. Parsing -- a closed template, nothing else. Pure functions, no Batfish.
# ------------------------------------------------------------------------------

_ACTION_KEYWORDS = re.compile(
    r"\b(block|deny|stop|allow|permit|let)\b", re.IGNORECASE
)
_ACTION_TO_CISCO = {
    "block": "deny", "deny": "deny", "stop": "deny",
    "allow": "permit", "permit": "permit", "let": "permit",
}

_TO_KEYWORD = re.compile(r"\bto\b", re.IGNORECASE)

# Same shape as ai/query.py's _IP_OR_CIDR -- duplicated deliberately rather
# than imported, the same call change_impact.py already made for its own
# SUCCESS_DISPOSITIONS: a five-line regex is cheaper to keep in sync by hand
# than to introduce a shared module for.
_IP_OR_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
_ANY_KEYWORD = re.compile(r"\bany\b", re.IGNORECASE)

# Anchored on the literal word "on" -- the template's own grammar is
# "<action> <source> to <destination> on <protocol>[/<port>]", so the token
# introduced by "on" is unambiguously the protocol. Found in review (#183):
# an unanchored version matched the word "any" wherever it first appeared in
# the whole request, including as a SOURCE or DESTINATION endpoint (both of
# which are also allowed to be "any") -- silently reading "allow any to
# 10.20.0.5 on tcp/80" as protocol "any" (-> "ip") instead of "tcp", four of
# nine template-legal requests tested. Requiring "on" immediately before the
# protocol word is not a positional guess; it is exactly what the closed
# template already promises, so a request that is genuinely ambiguous about
# where its protocol clause is has already failed to match the template at
# all, rather than being resolved by which match happened to come first.
_PROTOCOL_KEYWORDS = re.compile(
    r"\bon\s+(tcp|udp|icmp|ip|any)\b(?:\s*(?:/|port\s+)\s*(\d{1,5}))?",
    re.IGNORECASE,
)
_PROTOCOL_TO_CISCO = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "ip": "ip", "any": "ip"}

_HOSTNAME_LINE = re.compile(r"^hostname\s+(\S+)\s*$", re.MULTILINE)
_ACL_GROUP_IN = re.compile(r"^\s*ip access-group (\S+) in\s*$", re.MULTILINE)


def _is_valid_ip_or_cidr(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def _find_action(text: str) -> Optional["tuple[str, str]"]:
    """(cisco_action, remainder_after_the_action_word), or None."""
    match = _ACTION_KEYWORDS.search(text)
    if match is None:
        return None
    return _ACTION_TO_CISCO[match.group(1).lower()], text[match.end():]


def _split_source_destination(text: str) -> Optional["tuple[str, str]"]:
    """(source_text, destination_text), split on the first standalone "to"."""
    match = _TO_KEYWORD.search(text)
    if match is None:
        return None
    return text[: match.start()], text[match.end():]


def _find_endpoint(text: str) -> Optional[str]:
    """A literal IP, CIDR, or "any" found in `text` -- never a name."""
    for candidate_match in _IP_OR_CIDR.finditer(text):
        candidate = candidate_match.group(1)
        if _is_valid_ip_or_cidr(candidate):
            return candidate
    if _ANY_KEYWORD.search(text):
        return "any"
    return None


def _find_protocol_and_port(text: str) -> Optional["tuple[str, Optional[int]]"]:
    """(cisco_protocol, port_or_None), or None if no protocol keyword is
    present, or the port present is not a valid single port number."""
    match = _PROTOCOL_KEYWORDS.search(text)
    if match is None:
        return None
    protocol = _PROTOCOL_TO_CISCO[match.group(1).lower()]
    port_text = match.group(2)
    if port_text is None:
        return protocol, None
    port = int(port_text)
    if not (0 < port <= 65535):
        return None
    return protocol, port


def _cisco_endpoint(matched: str) -> str:
    """The Cisco extended-ACL token for an already-validated endpoint --
    "any", "host X", or "NETWORK WILDCARD". Same grammar
    `analysis/pfsense_convert.py`'s `_resolve_endpoint()` already emits, so
    Batfish is known to parse it -- this project's own pipeline already
    proves that grammar cleanly."""
    if matched == "any":
        return "any"
    network = ipaddress.ip_network(matched, strict=False)
    if network.num_addresses == 1:
        return f"host {network.network_address}"
    return f"{network.network_address} {network.hostmask}"


def _device_config_path(configs_dir: Path, device: str) -> Optional[Path]:
    """The .cfg file whose <hostname> line names `device`, not just a
    filename guess -- the same "read the declared identity, do not assume
    the filename matches it" discipline `analysis/checks/access_control.py`
    already applies when mapping a file back to a device."""
    for cfg_path in sorted(configs_dir.glob("*.cfg")):
        text = cfg_path.read_text(encoding="utf-8")
        match = _HOSTNAME_LINE.search(text)
        if match is not None and match.group(1) == device:
            return cfg_path
    return None


def _bound_inbound_acls(cfg_text: str) -> List[str]:
    """Distinct filter names bound `... in` on any interface, in this
    device's config text. See the module docstring for why more than one
    DISTINCT name is refused and the same name bound twice is not."""
    return sorted(set(_ACL_GROUP_IN.findall(cfg_text)))


def _insert_rule_at_top(cfg_text: str, acl_name: str, rule_line: str) -> Optional[str]:
    """`cfg_text` with `rule_line` inserted as the first rule in the named
    filter block, or None if that block's header could not be found."""
    header = f"ip access-list extended {acl_name}"
    lines = cfg_text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() == header:
            insertion = f" {rule_line}\n"
            return "".join(lines[: index + 1] + [insertion] + lines[index + 1 :])
    return None


def _acl_body_lines(cfg_text: str, acl_name: str) -> List[str]:
    """The rule lines of one named filter block, stripped, in order --
    everything between its header and the closing `!` that ends every block
    in this project's Cisco IOS output (the same convention
    `analysis/pfsense_convert.py` emits and every fixture in tests/fixtures/
    already follows). Returns [] if the header is not found, rather than
    raising -- a proposal that cannot show its own diff should still show
    the line it generated, not crash.

    NOT A GENERAL CISCO PARSER. This reads the exact block shape Netwise's
    own generator and converter both produce, the same narrow-grammar
    discipline `_cisco_endpoint()` above already applies. A config this
    project did not generate is exactly what feeds `before_lines` too, so a
    hand-written file with unconventional spacing could produce a shorter
    list than the real block -- the diff would then be incomplete rather
    than wrong, which is why this stays a display aid and never a fact
    `impact` or `verified` depends on.
    """
    header = f"ip access-list extended {acl_name}"
    lines = cfg_text.splitlines()
    body: List[str] = []
    in_block = False
    for line in lines:
        if line.strip() == header:
            in_block = True
            continue
        if not in_block:
            continue
        if line.strip() == "!":
            break
        body.append(line.strip())
    return body


def _with_safety_banner(device: str, cfg_text: str) -> str:
    """`cfg_text` with a comment banner identifying it as generated,
    unapplied, and for review only.

    Downloaded config text has a life outside this session -- saved to a
    laptop, emailed, opened a week later with no memory of where it came
    from. A file with no marking is indistinguishable from a real device
    backup once it leaves the dashboard, which is exactly the ambiguity
    CLAUDE.md's non-negotiable constraint 4 exists to prevent (Netwise
    GENERATES and SIMULATES, and must never be mistaken for something that
    was pushed). The banner is Cisco `!` comment syntax, so it stays inert
    if the file is ever fed back through a parser rather than just read.
    """
    banner = (
        f"! GENERATED BY NETWISE -- PROPOSED CHANGE, NOT APPLIED\n"
        f"! Device: {device}\n"
        f"! This file was never written to a live device. It is a simulated\n"
        f"! copy, for review only -- see the dashboard for the impact this\n"
        f"! change was shown to have before deciding whether to use it.\n"
        f"!\n"
    )
    return banner + cfg_text


# ------------------------------------------------------------------------------
# 2. The public entry point
# ------------------------------------------------------------------------------


def _refuse(reason: str) -> Dict[str, Any]:
    return {
        "request_understood": None,
        "proposed_change": None,
        "impact": [],
        "verified": False,
        "warning": False,
        "grounded": False,
        "answer": reason,
    }


def propose_change(
    request: str, before_dir: "str | Path", host: str = "localhost"
) -> Dict[str, Any]:
    """Propose ONE config change from plain English, and simulate it against
    a scratch copy of `before_dir` -- see the module docstring for the shape,
    the scope limit, and why neither step here calls a model.

    Never raises. Every failure -- an unparseable request, an unknown
    device, an unreachable Batfish -- is a refusal, not an exception, the
    same convention `ai/query.py`'s `answer_question()` and
    `analysis/change_impact.py`'s `analyse_change()` already hold.
    """
    request = (request or "").strip()
    if not request:
        return _refuse("The request was empty.")

    before_dir = Path(before_dir)

    found_action = _find_action(request)
    if found_action is None:
        return _refuse(
            "I could not find an action in the request. Say \"block\"/"
            "\"deny\" to add a restriction, or \"allow\"/\"permit\" to add "
            "one."
        )
    action, remainder = found_action

    split = _split_source_destination(remainder)
    if split is None:
        return _refuse(
            "I could not find the word \"to\" separating a source from a "
            "destination in the request, e.g. \"block 10.10.10.5 to "
            "10.20.0.5 on tcp/443\"."
        )
    source_text, destination_text = split

    source_raw = _find_endpoint(source_text)
    if source_raw is None:
        return _refuse(
            "I could not find a literal IP address, CIDR, or \"any\" on the "
            f"source side of the request ({source_text.strip()!r}). I can "
            "only propose a change against an address that is already "
            "written down, not a name like \"YouTube\"."
        )

    destination_raw = _find_endpoint(destination_text)
    if destination_raw is None:
        return _refuse(
            "I could not find a literal IP address, CIDR, or \"any\" on the "
            f"destination side of the request ({destination_text.strip()!r}). "
            "I can only propose a change against an address that is "
            "already written down, not a name like \"YouTube\"."
        )

    proto_port = _find_protocol_and_port(request)
    if proto_port is None:
        return _refuse(
            "I could not find a protocol (tcp, udp, icmp, or any) in the "
            "request, or the port given was not a single valid port number."
        )
    protocol, port = proto_port

    try:
        bf = connect(host)
    except Exception as error:
        return _refuse(
            f"Batfish is not answering at {host}. Start it with: "
            "docker start batfish. "
            f"Underlying error: {findings.describe_error(error)}"
        )

    try:
        load_snapshot(bf, before_dir, NETWORK_NAME, SNAPSHOT_NAME)
    except Exception as error:
        return _refuse(
            f"The current config could not be loaded: {findings.describe_error(error)}"
        )

    try:
        problems = find_parse_problems(bf)
    except Exception as error:
        return _refuse(
            f"Parse status could not be read: {findings.describe_error(error)}"
        )
    if problems:
        return _refuse(
            "The current config did not fully parse, so I cannot safely "
            "propose a change against it: " + "; ".join(problems)
        )

    present = snapshot.device_names(bf)
    if present is None:
        return _refuse(
            "The devices in this snapshot could not be determined, so I "
            "cannot tell whether the device you named is even in it."
        )

    device = _find_device(request, present)
    if device is None:
        return _refuse(
            "I could not find a known device name in the request. I can "
            "only propose a change against a device that is actually in "
            "this snapshot."
        )

    configs_dir = before_dir / "configs"
    cfg_path = _device_config_path(configs_dir, device)
    if cfg_path is None:
        return _refuse(f"Could not find {device}'s configuration file to modify.")
    cfg_text = cfg_path.read_text(encoding="utf-8")

    acls = _bound_inbound_acls(cfg_text)
    if len(acls) != 1:
        return _refuse(
            f"{device} has {len(acls)} distinct inbound-bound filter(s) "
            f"({acls}); I can only propose a change when there is exactly "
            "one, to avoid guessing which the client means."
        )
    acl_name = acls[0]

    port_clause = f" eq {port}" if port is not None and protocol in ("tcp", "udp") else ""
    rule_line = (
        f"{action} {protocol} {_cisco_endpoint(source_raw)} "
        f"{_cisco_endpoint(destination_raw)}{port_clause}"
    )

    new_cfg_text = _insert_rule_at_top(cfg_text, acl_name, rule_line)
    if new_cfg_text is None:
        return _refuse(
            f"Could not find the {acl_name!r} filter block in {device}'s "
            "config to insert into."
        )

    request_understood = f"On {device}, add to {acl_name!r} (at the top): {rule_line}"

    with tempfile.TemporaryDirectory(prefix="netwise-proposal-") as tmp:
        after_dir = Path(tmp) / "after"
        shutil.copytree(before_dir, after_dir)
        (after_dir / "configs" / cfg_path.name).write_text(new_cfg_text, encoding="utf-8")
        impact = change_impact.analyse_change(before_dir, after_dir, host=host)

    # Shown on the dashboard as a before/after diff of the affected filter,
    # not just the one generated line -- a line in isolation does not say
    # where it lands or what it sits beside. Read straight back out of
    # `cfg_text`/`new_cfg_text` rather than assembled by hand, so the diff
    # can never disagree with the text that was actually simulated above.
    before_lines = _acl_body_lines(cfg_text, acl_name)
    after_lines = _acl_body_lines(new_cfg_text, acl_name)

    # Offered as a download so a reviewer can inspect the full file, not
    # just the affected block -- see _with_safety_banner()'s own docstring
    # for why the banner is not optional.
    after_config_text = _with_safety_banner(device, new_cfg_text)

    proposed_change = {
        "device": device,
        "filter": acl_name,
        "line": rule_line,
        "before_lines": before_lines,
        "after_lines": after_lines,
        "after_config_text": after_config_text,
    }
    # verified and warning are two DIFFERENT facts and must never be ANDed
    # into one boolean (#183, found by Shubham). A proved high-severity
    # opening must be reported as a warning even when something ELSE in the
    # same impact list failed to run -- change_impact.py's own
    # differentialReachability failure path is built to preserve exactly
    # that pair (a proven finding beside an error), the same reasoning
    # policy_compliance's #22 fix already established: a proven violation
    # outranks an unrelated query failing, and replacing it with "we don't
    # know" reads as LESS alarming than the truth. Gating warning on
    # verified silently swallowed the proof in that direction.
    verified = all(f["status"] != "error" for f in impact)
    warning = any(
        f["status"] == "found" and f["severity"] == "high" for f in impact
    )

    if warning:
        answer = (
            f"Generated: {rule_line}, on {device}'s {acl_name!r} filter. "
            "Warning: simulating this change shows it newly opens access "
            "that was previously blocked -- see the impact list."
        )
        if not verified:
            answer += (
                " Some of the impact analysis also could not run, so this "
                "may not be the whole picture."
            )
    elif not verified:
        answer = (
            f"Generated: {rule_line}, on {device}'s {acl_name!r} filter. Its "
            "impact could not be fully verified -- see the impact list for "
            "what went wrong. This is NOT a claim that the change is safe."
        )
    elif any(f["status"] == "found" for f in impact):
        answer = (
            f"Generated: {rule_line}, on {device}'s {acl_name!r} filter. "
            "Simulating this change shows it narrows access; it does not "
            "appear to newly open anything -- see the impact list."
        )
    else:
        answer = (
            f"Generated: {rule_line}, on {device}'s {acl_name!r} filter. "
            "Simulating this change shows no detected effect on filter "
            "lines or reachability."
        )

    return {
        "request_understood": request_understood,
        "proposed_change": proposed_change,
        "impact": impact,
        "verified": verified,
        "warning": warning,
        "grounded": True,
        "answer": answer,
    }


# A network of its own, distinct from every other Batfish network this
# project uses -- default analyse() ("netwise"), change_impact.py
# ("netwise-change"), and propose_change()'s own validation load above
# ("netwise-propose"). A full scan run under any of those names could
# overwrite a snapshot a concurrent real scan is mid-read of; a name used
# nowhere else cannot collide with anything.
FULL_SCAN_NETWORK_NAME = "netwise-propose-scan"
FULL_SCAN_SNAPSHOT_NAME = "full"


def propose_and_scan(
    request: str, before_dir: "str | Path", host: str = "localhost", policy: Any = None
) -> Dict[str, Any]:
    """Like propose_change(), but runs the FULL analysis pipeline against the
    proposed config instead of only change_impact's narrow before/after diff.

    WHY THIS EXISTS
        propose_change()'s own "impact" list proves one thing:
        differentialReachability/compareFilters, i.e. what moved. It never
        runs access_control or policy_compliance against the result, so a
        change that newly VIOLATES a written policy, or opens a rule
        filterLineReachability would flag as dead, is invisible to it.

        Measured directly: proposing "allow 10.10.10.5 to 10.20.0.5 on
        tcp/80" against the secure demo fixture, propose_change()'s impact
        list shows one change_impact finding. Downloading the resulting
        config and uploading it as a fresh scan surfaces two MORE real
        findings -- access_control and policy_compliance both catch it --
        that the narrow diff never mentioned. This function is that
        second, more thorough step, without the manual download-and-reupload
        round trip.

    Returns:
        {"proposed_change": dict | None,  # same shape propose_change() returns
         "findings": list[dict],          # F-1 findings from the FULL pipeline
         "grounded": bool,
         "answer": str}

    A refusal (parsing failed, ACL not found, etc.) passes through with
    "findings": [] and "grounded": False -- there is nothing to scan when
    there was nothing to propose.
    """
    base = propose_change(request, before_dir, host=host)
    change = base["proposed_change"]
    if change is None:
        return {
            "proposed_change": None,
            "findings": [],
            "grounded": False,
            "answer": base["answer"],
        }

    # Local import: analysis.pipeline is the whole-product entry point and
    # importing it at module load time would make ai/propose.py depend on
    # everything every check depends on, for a function most callers of this
    # module never use. See the same reasoning at the top of this file for
    # why change_impact is imported at module scope but this is not --
    # change_impact is used by EVERY call to propose_change(); the full
    # pipeline is used only by this one, optional, heavier path.
    from analysis import pipeline as analysis_pipeline

    with tempfile.TemporaryDirectory(prefix="netwise-fullscan-") as tmp:
        scan_dir = Path(tmp) / "scan"
        shutil.copytree(before_dir, scan_dir)
        cfg_path = _device_config_path(scan_dir / "configs", change["device"])
        if cfg_path is None:
            # Cannot happen if propose_change() just found this device in
            # before_dir and scan_dir is an exact copy of it -- guarded
            # anyway rather than assumed, the same defence-in-depth this
            # project applies at every boundary with an external engine.
            return {
                "proposed_change": change,
                "findings": [],
                "grounded": False,
                "answer": (
                    f"Generated the change, but could not re-locate {change['device']}'s "
                    "config in the scratch copy to run a full scan against it."
                ),
            }
        cfg_path.write_text(change["after_config_text"], encoding="utf-8")
        scan_findings = analysis_pipeline.analyse(
            scan_dir,
            host=host,
            network_name=FULL_SCAN_NETWORK_NAME,
            snapshot_name=FULL_SCAN_SNAPSHOT_NAME,
            policy=policy,
        )

    return {
        "proposed_change": change,
        "findings": scan_findings,
        "grounded": True,
        "answer": (
            f"Full scan of the proposed config for {change['device']}: "
            f"{len(scan_findings)} result(s) across every check, not just "
            "the simulated change_impact diff above."
        ),
    }


def _find_device(text: str, known_devices: "set[str]") -> Optional[str]:
    """The first known device name mentioned in `text`, matched whole-word.
    Same shape as `ai/query.py`'s own `_find_device()` -- duplicated rather
    than imported, see the regex block comment above for why."""
    for device in known_devices:
        if re.search(rf"\b{re.escape(device)}\b", text, re.IGNORECASE):
            return device
    return None
