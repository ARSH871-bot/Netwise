"""
Netwise -- convert a PF Sense config.xml export into Cisco IOS config text
that Batfish can read natively (US-6).

WHY THIS EXISTS
    The client's real firewall is PF Sense, which exports a declarative XML
    tree (config.xml): interfaces, filter rules, NAT, aliases, DHCP, VPN.
    Batfish has no parser for that format at all -- it understands Cisco IOS,
    Juniper, Arista and a handful of others, never PF Sense. Every check this
    project has built (access_control, policy_compliance, routing) already
    assumes a Cisco-style node with named ACLs bound to interfaces.

    So the shape of the fix is: parse the one input format Batfish cannot
    read, emit the one output format everything else in this project already
    understands, and change nothing else. A converted config re-enters the
    pipeline through the exact same analyse() every other config uses.

SCOPE -- TIMEBOXED ON PURPOSE, PER CLAUDE.md SECTION 7
    IN SCOPE: interfaces (name, IP, subnet) and filter rules (source,
    destination, protocol, port, pass/block). That is what issue #6's
    acceptance criterion actually requires: "a converted config loads and
    analyses without error."

    OUT OF SCOPE, stated here rather than silently dropped: NAT, aliases with
    ranges or CIDR groups, DHCP, VPN, traffic shaping, IPv6, and combined
    "tcp/udp" rules. None of that is attempted. Where the input needs one of
    these to convert correctly, this module raises PfSenseConversionError
    rather than producing something that looks plausible and is wrong -- the
    same "refuse rather than guess" discipline analysis/checks/routing.py's
    _compute_dead_rule_outcome() and ai/Modelfile both already commit to.

    Rules split across more than one interface WERE out of scope until #78:
    the client's real export uses four, and a converter that cannot read its
    only real firewall is not finished. Each interface with rules gets its
    own ACL; an interface with an address but no rules of its own gets an
    explicit deny-all, matching PF Sense's real fail-closed default rather
    than leaving it unbound. See convert() and _acl_name().

    A RULE NAMING AN INTERFACE THIS MODULE CANNOT MODEL is refused with one
    of two distinct reasons, not one blanket message (#78, re-measured
    against the real export after item 1 landed): a role declared under
    <interfaces> but lacking a static address (DHCP or unconfigured) genuinely
    has no address to bind a Cisco ACL to; a role never declared under
    <interfaces> at all is most likely VPN/tunnel policy (OpenVPN, WireGuard),
    which this module does not parse and is out of scope regardless of
    addressing. See _declared_interface_roles() for why conflating the two
    was actively wrong about the second kind, not just imprecise.

RULE ORDER: MODELLED WHERE IT CAN BE, REFUSED WHERE IT CANNOT (issues #47, #78)
    PF Sense's real rule evaluation is "last matching rule wins" unless a
    rule is marked "quick", in which case evaluation stops there and that
    rule's action is final. A Cisco ACL is always first-match-wins, top to
    bottom -- the two models only coincide on their own when there happens
    to be nothing for them to disagree about.

    THREE CASES, per interface's rule list, not per rule pair:

    1. NO rule is quick (issue #78 item 2). "Stop immediately" never fires,
       so the final decision for any flow is simply the action of the LAST
       rule (top to bottom) that matches it -- which is exactly what
       evaluating the SAME rules first-match-wins, REVERSED, produces: the
       first rule to match in the reversed list is, by construction, the
       last to match in the original one. Not an approximation, the same
       decision for every flow. This module reverses and converts rather
       than checking for disagreement, because there is none left to find.
       The client's real export measures zero of seven rules marked quick
       -- this is his whole rule set, not a corner case.

    2. EVERY rule is quick. Already exactly modelled by first-match-wins in
       ORIGINAL order: a quick rule stops evaluation the instant it matches,
       which is what first-match already does for every rule. Converts as
       written, no reordering needed.

    3. SOME rules are quick, some are not, in no particular pattern. This is
       where the two models can still genuinely disagree, and where general
       reordering does not reduce to a single case the way 1 and 2 do. For
       two overlapping rules A (earlier) and B (later): if A and B have the
       SAME action, there is nothing to disagree about regardless of which
       "wins"; if A is quick, both models stop at A and agree; otherwise
       (actions differ, A not quick) the models can disagree, and this
       module refuses rather than guesses -- see
       `_check_rule_order_is_unambiguous()`, called once per interface for
       exactly this case, not the other two.

    Demonstrated, not hypothetical (issue #47's probe): a deny-then-permit
    pair on the same host, neither marked "quick", converted cleanly under
    the ORIGINAL (pre-#47) version of this module and reported the permit
    line as "unreachable, shadowed by the deny" -- while the real firewall,
    evaluating last-match, lets that exact traffic through. Confidently
    wrong is worse than refusing, which is what led to case 3's refusal
    existing at all; #78 item 2 is what taught this module cases 1 and 2
    do not need it.

    tests/fixtures/pfsense-source/config.xml's two "pass" rules are both
    marked `<quick/>` (case 3, mixed), and it is load-bearing, not
    decoration. The file's final rule is a catch-all deny, which by
    definition overlaps every specific rule before it -- without `<quick/>`
    on the two passes this fixture falls into case 1 instead (no quick
    rules at all) and correctly CONVERTS, reversed, denying the traffic the
    quick-marked version permits -- see
    `test_the_real_fixture_without_quick_now_converts_correctly_instead_of_refusing`,
    verified live against Batfish before being written as an assertion.

WHY INTERFACE NAMES ARE REWRITTEN, NOT COPIED
    PF Sense identifies interfaces with FreeBSD device names (em0, em1, igb0).
    Cisco IOS config syntax requires an interface name matching a known Cisco
    interface type (GigabitEthernet0/0, and similar), because Batfish's Cisco
    grammar parses against that vocabulary specifically -- em0 is not valid
    Cisco IOS syntax and would fail to parse, which would violate the one
    acceptance criterion this story has. So each PF Sense interface role is
    assigned a synthetic GigabitEthernet0/N name, in the order it appears in
    the XML; the original PF Sense identifier and description are kept as a
    comment for traceability, not thrown away.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Union

# The ACL name every other fixture in this project already uses for a single
# inbound filter. Reusing it, rather than inventing a new name, is what lets
# tests/fixtures/pfsense-source/config.xml's converted output be compared
# directly against tests/fixtures/rtr-us5-secure's hand-written one.
#
# Still used when there is exactly one interface with rules (#78 item 1 added
# support for more than one) -- the single-interface case converts identically
# to before, byte for byte, rather than gaining a role suffix nobody asked
# for. See _acl_name() for what a second or later ACL is called.
ACL_NAME = "acl_in"

_PFSENSE_TO_CISCO_ACTION = {"pass": "permit", "block": "deny", "reject": "deny"}
_PFSENSE_TO_CISCO_PROTOCOL = {"tcp": "tcp", "udp": "udp", "icmp": "icmp", "any": "ip"}


class PfSenseConversionError(Exception):
    """Raised when the input needs something this converter deliberately does
    not attempt -- see the module docstring's SCOPE section. Always raised
    with a message naming the specific unsupported construct, never silently
    swallowed or approximated."""


def _text(el: Optional[ET.Element], tag: str, default: Optional[str] = None) -> Optional[str]:
    """Return the text of `el`'s first `tag` child, or `default` if absent.

    PF Sense's XML uses an empty element (e.g. `<any/>`) to mean "this option
    is set" rather than storing a value in text -- callers that need to
    detect presence rather than read text use `el.find(tag) is not None`
    directly instead of this helper.
    """
    if el is None:
        return default
    child = el.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


# A literal newline inside an XML text node is valid XML (`<descr>a&#10;b</descr>`
# parses fine and `.text` comes back as "a\nb"), but every free-text field this
# module emits verbatim into the generated Cisco config text -- <hostname>,
# interface <descr>, interface <if> -- assumes it is ONE line. Cisco IOS parses
# config line by line, so a newline inside one of these fields is not cosmetic:
# it lets the field's content be read as additional config statements.
#
# Found in a senior-level adversarial QA pass, confirmed with:
#   <hostname>probe&#10;ip access-list extended acl_in&#10; permit ip any any</hostname>
# Cisco IOS treats a REPEATED "ip access-list extended NAME" block as
# APPENDING to the existing ACL of that name, not replacing it -- so the
# injected "permit ip any any" became a real line in the same acl_in ACL as
# the legitimate rules, evaluated BEFORE the real deny. An actual policy
# bypass in the converted config, not just corrupted-looking output.
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")


def _reject_control_characters(text: str, *, field: str) -> str:
    """Refuse `text` if it contains a newline or other control character,
    rather than emit it into the generated config where it could be read as
    additional config lines. See the module-level comment above this
    function for the confirmed exploit this closes.

    Applied to free-text fields only (interface <descr>, <if>) -- fields
    already validated to a strict character set (see
    `_sanitised_hostname()`) do not need this separately, a stricter check
    already implies it.
    """
    if _CONTROL_CHAR_PATTERN.search(text):
        raise PfSenseConversionError(
            f"{field} contains a newline or other control character "
            f"({text!r}) -- refusing to emit it into the generated config "
            "rather than risk it being read as additional config lines"
        )
    return text


# Real PF Sense hostnames are DNS hostname syntax: letters, digits, hyphen,
# dot -- this is deliberately closer to "what a hostname actually is" than
# "reject the specific characters found exploitable so far", the same
# refuse-rather-than-guess discipline as everywhere else in this module.
_HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def _sanitised_hostname(text: str) -> str:
    """Validate <hostname> is safe to use both inside the generated Cisco
    config text and as a filesystem path component.

    WHY THIS EXISTS
        Found in the same QA pass as `_reject_control_characters()`, a
        second consequence of the same unsanitised field:
        `write_snapshot()` builds its output path directly from this text
        (`configs_dir / f"{hostname_text}.cfg"`). A crafted hostname like
        "../../../../evil" walks the write outside the intended snapshot
        directory -- confirmed directly, landed four directories above the
        target, outside `snapshot_dir` entirely.

        A conservative hostname-shaped allowlist closes both the
        config-injection risk this field shares with <descr>/<if> AND the
        path-traversal risk in one check, rather than a control-character
        blocklist for one and a separate path check for the other -- an
        allowlist cannot be bypassed by a character nobody thought to ban.
    """
    if not _HOSTNAME_PATTERN.match(text):
        raise PfSenseConversionError(
            f"<hostname> is {text!r}, not a plain hostname -- refusing to "
            "use it in the generated config or as a filename"
        )
    return text


def _parse_interfaces(root: ET.Element) -> Dict[str, Dict[str, str]]:
    """Return {role: {"if": ..., "ipaddr": ..., "subnet": ..., "descr": ...}}
    for every interface PF Sense defines, in document order.

    `role` is PF Sense's own key ("wan", "lan", "opt1", ...) -- it is also
    the value a filter rule's <interface> and a network reference's
    <network> use to point back at one of these, so it is kept as the dict
    key rather than translated at this stage.
    """
    interfaces_el = root.find("interfaces")
    if interfaces_el is None:
        raise PfSenseConversionError("no <interfaces> section in this export")

    interfaces: Dict[str, Dict[str, str]] = {}
    for iface_el in interfaces_el:
        role = iface_el.tag
        ipaddr = _text(iface_el, "ipaddr")
        subnet = _text(iface_el, "subnet")
        if not ipaddr or not subnet:
            # DHCP-assigned or unconfigured interfaces have no static ipaddr.
            # Nothing to model for such an interface -- skip it rather than
            # emit a Cisco stanza with no address, which would itself fail
            # to parse meaningfully.
            continue

        # WHY VALIDATED HERE, NOT LEFT TO ipaddress.IPv4Network() DOWNSTREAM
        #   Found in a senior-level adversarial QA pass: an invalid <subnet>
        #   (e.g. "-1") or an IPv6-shaped <ipaddr> was not rejected here, so
        #   it reached ipaddress.IPv4Network() unvalidated in _resolve_endpoint()
        #   and again in convert()'s interface-emission loop, raising a raw
        #   ipaddress.NetmaskValueError / AddressValueError instead of
        #   PfSenseConversionError. Same class of gap PR #34 already fixed
        #   once for <address>/<port> inside filter rules -- recurring one
        #   layer up, for interface addressing, and fixed the same way:
        #   validated at the layer that knows what went wrong (which
        #   interface, which field), rather than left for a caller several
        #   frames away to catch a exception type it was not expecting.
        try:
            ipaddress.IPv4Network(f"{ipaddr}/{subnet}", strict=False)
        except ValueError as error:
            raise PfSenseConversionError(
                f"interface {role!r} has <ipaddr>{ipaddr!r}</ipaddr> and "
                f"<subnet>{subnet!r}</subnet>, not a valid IPv4 address and "
                f"prefix length -- {error}"
            ) from None

        interfaces[role] = {
            "if": _reject_control_characters(
                _text(iface_el, "if", default=role), field="<if>"
            ),
            "ipaddr": ipaddr,
            "subnet": subnet,
            "descr": _reject_control_characters(
                _text(iface_el, "descr", default=role.upper()), field="<descr>"
            ),
        }
    return interfaces


def _assign_cisco_interface_names(interfaces: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Map each PF Sense role to a synthetic Cisco interface name, in the
    order interfaces were defined. See the module docstring for why this
    rewrite is necessary rather than optional."""
    return {role: f"GigabitEthernet0/{i}" for i, role in enumerate(interfaces)}


def _is_quick(rule_el: ET.Element) -> bool:
    """True if `rule_el` carries PF Sense's <quick/> marker.

    Pulled out on its own (#78 item 2) because it is now read from two
    places that must agree with each other: _check_rule_order_is_unambiguous()
    already used this exact test inline, and convert() needs the same
    question answered once per interface, before generating any ACL line,
    to decide whether that interface's rules can be modelled exactly rather
    than checked for disagreement. One implementation, not two copies that
    could drift.
    """
    return rule_el.find("quick") is not None


def _rule_interface(rule_el: ET.Element) -> Optional[str]:
    """The role a rule's <interface> names, or None if it does not name one.

    Found by adversarial QA on #78 item 2: `_text(rule_el, "interface")`
    already strips whitespace, so a genuinely missing <interface> and a
    present-but-whitespace-only one, `<interface> </interface>`, both end
    up here -- but three call sites in convert() used to read `_text(...)`
    directly and only one of them (the unassigned-rule refusal) checked for
    `None`, not for "falsy after stripping". A whitespace-only tag slipped
    past that refusal as `""`, then landed in `unknown_roles` instead,
    which still correctly refused overall -- fail-closed, not a bypass --
    but with a misleading message blaming "no static address configured"
    for what was actually a malformed tag.

    One normalisation, used everywhere a rule's interface is read, so
    "not specified" means the same thing at every call site rather than
    depending on which one happens to check for it.
    """
    role = _text(rule_el, "interface")
    return role or None


def _declared_interface_roles(root: ET.Element) -> "set[str]":
    """Every role named directly under <interfaces>, regardless of whether
    it has a static address -- unlike _parse_interfaces(), which silently
    drops a role with no <ipaddr>/<subnet>.

    Exists so convert() can tell apart the two ways a rule's <interface> can
    fail to resolve to anything modellable (#78):

      - declared, but skipped by _parse_interfaces() for lacking a static
        address (DHCP or unconfigured) -- the role IS a real interface, it
        just cannot be written as a Cisco ACL binding without an address
      - never declared at all -- PF Sense lets a filter rule's <interface>
        name something that is not a LAN interface in this section at all,
        most often a VPN/tunnel role (OpenVPN, WireGuard) that appears
        elsewhere in the export, if anywhere. Nothing here parses those
        sections; the role is simply absent.

    Both used to collapse into one message, "no static address configured",
    which is only true of the first kind and actively misleading about the
    second -- a WireGuard role does not become convertible by giving it an
    address, because tunnel policy is not LAN filtering.

    Assumes root.find("interfaces") is not None -- convert() calls
    _parse_interfaces(root) first, which already raises otherwise.
    """
    return {el.tag for el in root.find("interfaces")}


def _acl_name(role: str, *, rule_bearing_roles: "set[str]") -> str:
    """The Cisco ACL name bound to one interface's inbound filter (#78 item 1).

    The one case that must convert exactly as it did before multi-interface
    support existed: a single interface with rules and nothing else needing a
    name. That ACL stays `acl_in`, matching every existing fixture and the
    hand-written tests/fixtures/rtr-us5-secure config this module is
    deliberately verified against -- see ACL_NAME above.

    Any other ACL -- a second or later rule-bearing interface, or a
    synthesised deny-all for an interface with an address but no rules of its
    own (see convert()) -- gets its own name built from PF Sense's own role,
    the same convention _assign_cisco_interface_names() already uses for
    interface names, rather than a second naming scheme.

    `role` is an XML tag name (see _parse_interfaces()), not free text pulled
    from an element's content the way <descr> or <hostname> are, so it is
    already constrained by XML's own tag-name grammar and does not need the
    separate validation those fields do.
    """
    if role in rule_bearing_roles and len(rule_bearing_roles) == 1:
        return ACL_NAME
    return f"acl_{role}_in"


def _resolve_endpoint(el: ET.Element, interfaces: Dict[str, Dict[str, str]]) -> str:
    """Convert a PF Sense <source> or <destination> element into a Cisco ACL
    address clause: "any", "host 1.2.3.4", or "NETWORK WILDCARD-MASK".

    Handles exactly the three forms tests/fixtures/pfsense-source/config.xml
    uses: <any/>, <network>ROLE</network> (that interface's own subnet), and
    <address>IP</address> (a single host). PF Sense also supports network
    aliases like "lanip" (the interface's own address, not its subnet) and
    named address-group aliases -- neither is handled; both raise rather
    than silently picking the nearest matching behaviour.

    WHY <address> IS VALIDATED AS AN IP, NOT TRUSTED AS ONE
        Found in review, not anticipated up front: PF Sense's <address> can
        itself hold a named alias (e.g. "TRUSTED_HOSTS") rather than a literal
        IP -- the same "named alias" case this docstring already calls out
        for <network>, just reachable through a different element. Without
        the check below, that alias name was passed straight through into
        "host TRUSTED_HOSTS", which is not valid Cisco syntax.

        Measured what Batfish actually does with that line: it does NOT
        reject the file outright. fileParseStatus reports
        PARTIALLY_UNRECOGNIZED, and Batfish silently drops the one bad line
        while modelling everything else. Today, analysis.pipeline's
        find_parse_problems() treats any non-PASSED status as fatal, so this
        still surfaces as status="error" rather than a wrong answer -- but
        that strictness is an open decision under active proposal to relax
        for real-world configs (CLAUDE.md section 11). Relying on ANOTHER
        module's current policy, one already flagged as likely to change, as
        the only thing standing between this and a silently wrong model of a
        client firewall is not good enough. Validated here instead, at the
        layer that actually knows what went wrong.
    """
    if el.find("any") is not None:
        return "any"

    network = _text(el, "network")
    if network is not None:
        if network not in interfaces:
            raise PfSenseConversionError(
                f"rule references network {network!r}, which is not a "
                "configured interface with a static address (or is an "
                "alias form like 'lanip' that this converter does not "
                "resolve)"
            )
        iface = interfaces[network]
        net = ipaddress.IPv4Network(f"{iface['ipaddr']}/{iface['subnet']}", strict=False)
        return f"{net.network_address} {net.hostmask}"

    address = _text(el, "address")
    if address is not None:
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            raise PfSenseConversionError(
                f"<address> is {address!r}, not an IP address -- likely a "
                "named alias, which this converter does not resolve"
            ) from None
        return f"host {address}"

    raise PfSenseConversionError(
        "a <source> or <destination> element matched none of any/network/"
        "address -- likely a named alias group, which is out of scope"
    )


def _endpoint_network(el: ET.Element, interfaces: Dict[str, Dict[str, str]]) -> ipaddress.IPv4Network:
    """The address space a <source>/<destination> element actually matches,
    as an IPv4Network, for OVERLAP DETECTION only -- see
    _check_rule_order_is_unambiguous(). The ACL line itself is still built
    by _resolve_endpoint(), which keeps emitting the literal "any"/"host"/
    network syntax Cisco expects; this exists only to answer "do these two
    address spaces intersect", which a formatted string cannot answer
    without being re-parsed.

    "any" becomes 0.0.0.0/0 -- the actual universal set, not a special case,
    so it overlaps everything through the same .overlaps() call as every
    other shape. A single host becomes a /32.

    Handles exactly the same three forms _resolve_endpoint() does, and is
    always called after _resolve_endpoint() has already succeeded for the
    same element (see convert()), so the validation _resolve_endpoint()
    already performs -- unresolvable network references, non-IP <address>
    aliases -- does not need repeating here.
    """
    if el.find("any") is not None:
        return ipaddress.IPv4Network("0.0.0.0/0")

    network = _text(el, "network")
    if network is not None:
        iface = interfaces[network]
        return ipaddress.IPv4Network(f"{iface['ipaddr']}/{iface['subnet']}", strict=False)

    address = _text(el, "address")
    return ipaddress.IPv4Network(f"{address}/32")


def _protocols_might_overlap(a: str, b: str) -> bool:
    """PF Sense protocol strings ("tcp", "udp", "icmp", "any"). "any" is a
    superset of every other protocol, so it overlaps all of them; two
    specific protocols overlap only if they are the same one."""
    return a == "any" or b == "any" or a == b


def _ports_might_overlap(a: Optional[int], b: Optional[int]) -> bool:
    """None means "no <port> element", i.e. every port -- a superset of any
    specific port, same reasoning as "any" for protocols above."""
    return a is None or b is None or a == b


def _check_rule_order_is_unambiguous(
    rule_els: List[ET.Element], interfaces: Dict[str, Dict[str, str]], acl_lines: List[str]
) -> None:
    """Refuse to convert if two rules could disagree about a flow that
    matches both of them -- see the module docstring's issue #47 section
    for the two evaluation models this reconciles.

    THE EXACT CONDITION, derived rather than approximated
        For two rules A (earlier in the file) and B (later), whose traffic
        spaces overlap:

        - If A and B have the SAME action, it does not matter which one
          "wins" for the overlapping traffic -- the outcome is identical
          either way, so there is nothing to disagree about even though
          the two models might pick a different rule to credit it to.

        - If A is "quick": PF Sense stops evaluating at A the instant a
          flow matches it, so A's action is final. Cisco's first-match
          semantics ALSO stop at A, being earlier. The two models agree on
          A's action for every such flow, regardless of what B is or
          whether B is also quick.

        - Otherwise (actions differ, A is not quick): Cisco still stops at
          A (first-match always does), but PF Sense keeps evaluating past
          A and lets B's action override it (whether because B is quick
          and matches next, or because B is simply the last matching rule
          in a run with no quick rules at all). The two models can produce
          different actions for the same flow. Genuinely ambiguous.

        B's own "quick" flag never enters this decision -- only A's does,
        because A is the one either model might stop at first. This is
        narrower than "flag unless both rules are quick" would be: a
        specific, quick, early rule followed by a broad, non-quick,
        catch-all rule is NOT ambiguous, and the check does not spuriously
        refuse it.

    Called from convert() AFTER every rule has already been through
    _rule_to_acl_line() successfully, passed in as `acl_lines` (same order
    as `rule_els`) rather than rebuilt here -- so every field read here is
    already known to be a shape this module understands, and no rule is
    converted to an ACL line twice. This function only ever adds a refusal
    on top of a config that would otherwise have converted, it never turns
    an already-invalid rule into a different error.

    O(n^2) in the rule count. Called once per interface's own rule list, not
    once for the whole file (#78 item 1) -- n is one ACL's rule count, not the
    file's. PF Sense rule sets in scope for this converter are small (no
    aliases, no ranges -- see the module's own SCOPE section), so this is not
    a performance concern; correctness is what matters here, not asymptotic
    elegance.
    """
    parsed = []
    # strict=True enforces the precondition this function's docstring states:
    # acl_lines is the SAME ORDER and the SAME LENGTH as rule_els, because
    # convert() builds it from that exact list. Nothing checked it.
    #
    # Without strict, a future change that filters one list and not the other
    # -- skipping disabled rules when building ACL lines, say -- makes zip()
    # truncate to the shorter one, and this guard silently stops checking the
    # tail of the rule set. It would still return, still find nothing wrong,
    # and still let the file convert. That is the shape of failure this whole
    # module exists to refuse: a check that quietly covers less than it claims.
    for rule_el, line in zip(rule_els, acl_lines, strict=True):
        pf_type = _text(rule_el, "type") or ""
        pf_protocol = _text(rule_el, "protocol", default="any") or "any"
        destination_el = rule_el.find("destination")
        port_text = _text(destination_el, "port") if pf_protocol in ("tcp", "udp") else None
        parsed.append(
            {
                # The CISCO action, not the raw PF Sense <type> -- "block"
                # and "reject" both become "deny", and a block/reject pair
                # is exactly as same-action-safe as a block/block pair.
                "action": _PFSENSE_TO_CISCO_ACTION.get(pf_type),
                "quick": _is_quick(rule_el),
                "protocol": pf_protocol,
                "source": _endpoint_network(rule_el.find("source"), interfaces),
                "destination": _endpoint_network(destination_el, interfaces),
                "port": int(port_text) if port_text is not None else None,
                "line": line,
            }
        )

    for i, a in enumerate(parsed):
        for b in parsed[i + 1 :]:
            if a["action"] == b["action"]:
                continue
            if a["quick"]:
                continue
            if not _protocols_might_overlap(a["protocol"], b["protocol"]):
                continue
            if not a["source"].overlaps(b["source"]):
                continue
            if not a["destination"].overlaps(b["destination"]):
                continue
            if not _ports_might_overlap(a["port"], b["port"]):
                continue
            raise PfSenseConversionError(
                "rule order is ambiguous: these two rules' traffic spaces "
                "overlap, their actions differ, and the earlier one is not "
                "marked quick, so PF Sense's real last-match-wins "
                "evaluation and this converter's first-match-wins model "
                f"can disagree about which one decides -- {a['line']!r} "
                f"(earlier) and {b['line']!r} (later)"
            )


def _rule_to_acl_line(rule_el: ET.Element, interfaces: Dict[str, Dict[str, str]]) -> str:
    """Convert one PF Sense <rule> element into one Cisco extended-ACL line."""
    pf_type = _text(rule_el, "type")
    action = _PFSENSE_TO_CISCO_ACTION.get(pf_type or "")
    if action is None:
        raise PfSenseConversionError(f"unsupported rule <type>: {pf_type!r}")

    pf_protocol = _text(rule_el, "protocol", default="any")
    cisco_protocol = _PFSENSE_TO_CISCO_PROTOCOL.get(pf_protocol or "")
    if cisco_protocol is None:
        raise PfSenseConversionError(
            f"unsupported <protocol>: {pf_protocol!r} -- combined forms "
            "like 'tcp/udp' need two Cisco ACL lines and are not handled"
        )

    source_el = rule_el.find("source")
    destination_el = rule_el.find("destination")
    if source_el is None or destination_el is None:
        raise PfSenseConversionError("rule is missing <source> or <destination>")

    src = _resolve_endpoint(source_el, interfaces)
    dst = _resolve_endpoint(destination_el, interfaces)

    port_clause = ""
    if cisco_protocol in ("tcp", "udp"):
        port = _text(destination_el, "port")
        if port is not None:
            # Same class of gap the review found in <address>: PF Sense's
            # <port> can hold a named alias (e.g. "HTTPS_ALT") instead of a
            # number. Checked for the identical reason, not just because the
            # other one was found -- an unvalidated port would produce
            # "eq HTTPS_ALT", equally invalid Cisco syntax, equally liable to
            # be silently dropped by Batfish's partial-recognition parsing.
            if not port.isdigit() or not (0 < int(port) <= 65535):
                raise PfSenseConversionError(
                    f"<port> is {port!r}, not a single numeric port -- "
                    "named aliases and ranges are out of scope"
                )
            port_clause = f" eq {port}"

    return f"{action} {cisco_protocol} {src} {dst}{port_clause}"


def convert(xml_path: Union[str, Path]) -> str:
    """Parse a PF Sense config.xml export and return equivalent Cisco IOS
    config text. Raises PfSenseConversionError for anything out of scope --
    see the module docstring. Never returns a partial or best-guess result.
    """
    root = ET.parse(xml_path).getroot()

    hostname = _sanitised_hostname(_text(root.find("system"), "hostname", default="pfsense"))
    interfaces = _parse_interfaces(root)
    if not interfaces:
        raise PfSenseConversionError("no interface has both an address and a subnet")
    cisco_names = _assign_cisco_interface_names(interfaces)

    filter_el = root.find("filter")
    rule_els = filter_el.findall("rule") if filter_el is not None else []

    # WHY AN EMPTY RULE SET IS REFUSED, NOT CONVERTED AS "NO ACL"
    #   Found in a senior-level adversarial QA pass. PF Sense fails CLOSED
    #   with no rules configured on an interface -- it blocks everything.
    #   Cisco fails OPEN with no ACL bound to an interface -- it permits
    #   everything. Converting zero rules into zero rules would silently
    #   invert the source firewall's actual security posture: the client's
    #   most restrictive interface would become the analysis's least
    #   restrictive one. Nothing here can pick which interface(s) should
    #   get an implicit "deny all" either -- an empty <filter> gives no
    #   signal about that -- so the correct move is to refuse rather than
    #   guess, same discipline as everywhere else in this module.
    if not rule_els:
        raise PfSenseConversionError(
            "no filter rules at all -- PF Sense fails closed with no rules "
            "(blocks everything), Cisco fails open with no ACL bound "
            "(permits everything); converting this would silently invert "
            "the source firewall's actual security posture"
        )

    # Rules may now span more than one interface role (#78 item 1) -- each
    # gets its own ACL, built and checked independently below. Batfish/Cisco
    # still applies one ACL per interface direction; what changed is that
    # this module now builds several instead of refusing past one.
    # _rule_interface(), not _text(r, "interface") directly -- see that
    # function's docstring. A whitespace-only <interface> tag used to read
    # as "" here, not None, so it never counted as "no interface at all" and
    # instead surfaced later as a bogus unknown-role refusal blaming "no
    # static address configured" for what was really a malformed tag.
    rule_roles = {_rule_interface(r) for r in rule_els}
    rule_roles.discard(None)

    # WHY A RULE SET WITH NO <interface> AT ALL IS REFUSED
    #   Found in a senior-level adversarial QA pass. rule_roles is empty here
    #   in exactly one case: every rule is missing <interface>. Before this
    #   check, such a config still emitted ACL deny/permit lines -- present in
    #   the file, bound to nothing. A config that looks like it has a filter
    #   and silently enforces none of it.
    if not rule_roles:
        raise PfSenseConversionError(
            "no filter rule names an <interface> -- the resulting ACL would "
            "be written but never bound to anything, and would silently "
            "enforce nothing"
        )

    # A rule with NO <interface> at all, alongside others that DO name one, is
    # ambiguous about which ACL it belongs to. Under the old single-interface
    # restriction this could only ever mean one thing; with several ACLs now
    # possible it genuinely is not knowable. Refuse rather than guess, same
    # discipline as everywhere else in this module.
    unassigned = [r for r in rule_els if _rule_interface(r) is None]
    if unassigned:
        raise PfSenseConversionError(
            f"{len(unassigned)} filter rule(s) name no <interface> while "
            f"{len(rule_els) - len(unassigned)} other(s) do "
            f"({sorted(rule_roles)}) -- which ACL they belong to is not "
            "knowable, refusing rather than guessing"
        )

    # Split rather than one blanket message (#78): a role that is genuinely
    # declared under <interfaces> just lacks an address (DHCP or
    # unconfigured); a role that is not declared there at all is most likely
    # VPN/tunnel policy (OpenVPN, WireGuard), which this module does not
    # parse and is out of scope regardless of addressing. Conflating the two
    # under "no static address configured" is wrong about the second kind --
    # see _declared_interface_roles().
    unknown_roles = rule_roles - set(interfaces)
    if unknown_roles:
        declared = _declared_interface_roles(root)
        no_static_address = sorted(unknown_roles & declared)
        not_declared_at_all = sorted(unknown_roles - declared)

        reasons = []
        if no_static_address:
            reasons.append(
                f"{no_static_address} have no static address configured "
                "(DHCP or unconfigured) -- a Cisco ACL needs an address to "
                "bind rules to"
            )
        if not_declared_at_all:
            reasons.append(
                f"{not_declared_at_all} are not declared under <interfaces> "
                "at all -- most likely VPN/tunnel policy (e.g. OpenVPN, "
                "WireGuard), which this module does not parse and is out of "
                "scope, not LAN filtering"
            )

        raise PfSenseConversionError(
            "filter rules apply to interface(s) that cannot be modelled: "
            + "; ".join(reasons)
        )

    # One bucket of rules per interface, in document order within each --
    # rule ORDER only matters relative to other rules on the same ACL, never
    # across interfaces, since no real firewall ever compares them that way.
    rules_by_role: Dict[str, List[ET.Element]] = {role: [] for role in rule_roles}
    for r in rule_els:
        rules_by_role[_rule_interface(r)].append(r)

    # Each interface's rule-order ambiguity is checked against only ITS OWN
    # rules (#47/#58's guard, now run once per ACL instead of once globally).
    # A rule on "lan" cannot be ambiguous against a rule on "wan" -- they are
    # never evaluated against the same traffic by any real firewall.
    #
    # WHY AN INTERFACE WITH NO QUICK RULES AT ALL IS REVERSED, NOT CHECKED
    # (#78 item 2)
    #   PF Sense's real rule is: evaluate top to bottom, remember the action
    #   of the last matching rule, and stop immediately if that rule is
    #   quick. With NO quick rules anywhere in the list, "stop immediately"
    #   never fires, so the final decision for any flow is simply the action
    #   of the LAST rule (top to bottom) that matches it.
    #
    #   That is exactly what a Cisco ACL produces if the SAME rules are
    #   evaluated first-match-wins in REVERSED order: the first rule to match
    #   in the reversed list is, by construction, the last rule to match in
    #   the original one. This is not an approximation of last-match-wins,
    #   it is the same decision, for every possible flow -- so there is
    #   nothing left for _check_rule_order_is_unambiguous() to be uncertain
    #   about, and calling it here would spuriously refuse configs this
    #   module can now convert exactly. Skipped for this case, not weakened.
    #
    #   The client's real export measures zero of seven rules marked quick
    #   (#78) -- this is not a hypothetical case, it is his whole rule set.
    #
    #   Any OTHER rule set -- some rules quick, or every rule quick -- keeps
    #   the existing original-order-plus-refusal behaviour. An all-quick list
    #   is already exactly modelled by first-match-wins in original order (a
    #   quick rule stops evaluation the instant it matches, which is what
    #   first-match already does), and a genuinely mixed list is where this
    #   module still refuses rather than guesses, because the general case
    #   -- some rules quick, some not, in no particular pattern -- does not
    #   reduce to a single reordering the way the all-or-nothing cases do.
    acl_lines_by_role: Dict[str, List[str]] = {}
    for role, rules in rules_by_role.items():
        if not any(_is_quick(r) for r in rules):
            rules = list(reversed(rules))
            acl_lines_by_role[role] = [_rule_to_acl_line(r, interfaces) for r in rules]
            continue
        lines_for_role = [_rule_to_acl_line(r, interfaces) for r in rules]
        _check_rule_order_is_unambiguous(rules, interfaces, lines_for_role)
        acl_lines_by_role[role] = lines_for_role

    lines: List[str] = [f"hostname {hostname}", "!"]
    for role, info in interfaces.items():
        cisco_name = cisco_names[role]
        net = ipaddress.IPv4Network(f"{info['ipaddr']}/{info['subnet']}", strict=False)
        lines.append(f"interface {cisco_name}")
        lines.append(f" description {info['descr']} (PF Sense: {info['if']})")
        lines.append(f" ip address {info['ipaddr']} {net.netmask}")
        # WHY EVERY INTERFACE GETS A BOUND ACL, NOT JUST THE ONES WITH RULES
        #   PF Sense fails CLOSED with no rules configured on an interface --
        #   the same reasoning the empty-<filter> refusal above applies to the
        #   whole file, just reachable per-interface now that more than one
        #   is possible. Left unbound, an address-only interface with no
        #   rules of its own would read to Cisco/Batfish as unfiltered, fail
        #   OPEN -- the exact inversion that refusal exists to prevent.
        lines.append(f" ip access-group {_acl_name(role, rule_bearing_roles=rule_roles)} in")
        lines.append("!")

    for role in interfaces:
        acl_name = _acl_name(role, rule_bearing_roles=rule_roles)
        lines.append(f"ip access-list extended {acl_name}")
        if role in acl_lines_by_role:
            lines.extend(f" {line}" for line in acl_lines_by_role[role])
        else:
            lines.append(" deny ip any any")
        lines.append("!")

    return "\n".join(lines) + "\n"


def write_snapshot(xml_path: Union[str, Path], snapshot_dir: Union[str, Path]) -> Path:
    """Convert `xml_path` and write it as a Batfish-ready snapshot at
    `snapshot_dir` (device files land in `snapshot_dir/configs/`, matching
    what analysis.pipeline.load_snapshot expects). Returns the file written.

    WHY THE OUTPUT PATH IS VALIDATED TWICE
        `_sanitised_hostname()` already rejects anything but a plain
        hostname-shaped string, which structurally cannot contain a path
        separator or "..", so the second check below can never actually
        fire today. It stays as a cheap, explicit assertion rather than a
        trust that a regex will always be the only thing standing between
        untrusted XML text and a filesystem write -- found in a senior-
        level adversarial QA pass, confirmed live before this fix:
        `<hostname>../../../../evil</hostname>` wrote a file four
        directories above the intended `snapshot_dir` entirely.
    """
    text = convert(xml_path)
    hostname = ET.parse(xml_path).getroot().find("system")
    hostname_text = _sanitised_hostname(_text(hostname, "hostname", default="pfsense"))

    configs_dir = Path(snapshot_dir) / "configs"
    configs_dir.mkdir(parents=True, exist_ok=True)
    out_path = (configs_dir / f"{hostname_text}.cfg").resolve()
    if configs_dir.resolve() not in out_path.parents:
        raise PfSenseConversionError(
            f"<hostname> {hostname_text!r} would write outside the snapshot "
            "directory -- refusing"
        )
    out_path.write_text(text)
    return out_path


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(
            "usage: python -m analysis.pfsense_convert <config.xml> <snapshot-dir>\n"
            "example: python -m analysis.pfsense_convert "
            "tests/fixtures/pfsense-source/config.xml /tmp/pfsense-converted"
        )
    written = write_snapshot(sys.argv[1], sys.argv[2])
    print(f"Wrote {written}")
    print()
    print(written.read_text())
