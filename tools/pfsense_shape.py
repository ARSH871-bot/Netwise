"""Describe the SHAPE of a PF Sense config.xml without revealing its contents.

WHY THIS EXISTS
    CLAUDE.md constraint 1: no config data goes to any cloud AI service. That
    rule does not stop us reasoning about a client's export -- it stops us
    moving it. This prints structure only: which elements are present, how
    many, and which of them analysis/pfsense_convert.py can handle.

    It NEVER prints a value. No hostnames, no addresses, no descriptions, no
    interface names. Only tag names, counts, and yes/no answers. The output is
    safe to paste into a chat, an email, or a report.

RUN
    python tools/pfsense_shape.py path/to/config.xml

WHAT TO DO WITH THE OUTPUT
    Paste it. It is enough to say whether the converter will work on this
    file, what it would refuse on, and what would need building -- without
    anyone outside the machine seeing a single line of the network.
"""
from __future__ import annotations

import collections
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# Constructs analysis/pfsense_convert.py understands today. Anything outside
# this list is not a bug -- it is a documented refusal (CLAUDE.md section 7).
SUPPORTED_RULE_FIELDS = {
    "type", "interface", "ipprotocol", "protocol", "source",
    "destination", "descr", "tracker", "quick",
}
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp", "any"}
SUPPORTED_TYPES = {"pass", "block", "reject"}

#: PF Sense's own addressing keywords. An <ipaddr> matching one of these is a
#: KEYWORD, not an address, so it is safe to print. Anything else is treated as
#: a real address and redacted -- the safe default, since an unrecognised token
#: is exactly the case where guessing would leak.
DYNAMIC_ADDRESSING = {"dhcp", "ppp", "pppoe", "pptp", "l2tp", "dhcp6", "slaac", "6rd", "6to4", "track6"}

#: PF Sense's own reserved interface roles. These are the product's vocabulary,
#: not user-chosen text, so printing one reveals nothing about the network.
#: `optN` is matched by pattern below. ANY other role -- an interface group or
#: a renamed interface, which users do name freely -- is redacted.
KNOWN_ROLES = {
    "wan", "lan", "openvpn", "ipsec", "wireguard", "l2tp", "pppoe", "enc0", "lo0",
}


def _safe_role(role: str) -> str:
    """A role name, or a redaction marker if it is not PF Sense vocabulary.

    Same discipline as the type/protocol printing below, and for the same
    reason Ankeet gave on #74: this file's docstring promises it never prints
    a value, and a rule's <interface> is element CONTENT, not a tag name. Roles
    like "wan" or "openvpn" are PF Sense's own reserved words; an interface
    GROUP or a renamed interface is user-chosen text and could be anything.
    """
    low = role.lower()
    if low in KNOWN_ROLES or re.fullmatch(r"opt\d+", low):
        return role
    return "<role outside PF Sense vocabulary, redacted>"


def _tag_census(root: ET.Element) -> collections.Counter:
    return collections.Counter(el.tag for el in root.iter())


def main(path: str) -> None:
    root = ET.parse(path).getroot()
    census = _tag_census(root)

    print("PF Sense config.xml -- STRUCTURE ONLY, no values")
    print("=" * 56)

    rules = root.findall("./filter/rule")
    quick = [r for r in rules if r.find("quick") is not None]
    print(f"\nfilter rules              : {len(rules)}")
    print(f"  marked <quick/>         : {len(quick)}")
    print(f"  NOT marked quick        : {len(rules) - len(quick)}")

    # THE question. See CLAUDE.md section 7 and issue #47.
    if not rules:
        verdict = "no rules found -- the converter refuses an empty rule set"
    elif len(quick) == len(rules):
        verdict = "ALL rules are quick -> first-match-wins is equivalent. Safe to convert."
    elif not quick:
        verdict = "NO rules are quick -> last-match-wins applies. Converter will refuse overlapping pairs."
    else:
        verdict = "MIXED -> safe only where the EARLIER rule of an overlapping pair is quick."
    print(f"  => {verdict}")

    print(f"\ninterfaces                : {len(root.findall('./interfaces/*'))}")

    # WHY THIS SECTION EXISTS
    #   analysis/pfsense_convert.py SKIPS any interface with no static
    #   <ipaddr>/<subnet> -- DHCP, PPPoE, or unconfigured. A filter rule naming
    #   a skipped interface then hits the "no static address configured"
    #   refusal. A DHCP WAN is the normal case for a small-site firewall, so
    #   this decides whether multi-interface support (#78 item 1) is enough to
    #   read a given export, or whether it still refuses for a second reason.
    #
    #   Reported STRUCTURALLY. An <ipaddr> is only ever printed when it is one
    #   of PF Sense's own addressing KEYWORDS -- never when it is an address.
    #   That ordering matters: this tool previously printed field values before
    #   checking them against a known vocabulary, which Ankeet caught on #74.
    #   Validate, then print.
    print("\ninterface addressing (keywords only, never an address):")
    rule_roles = {
        (r.findtext("interface") or "").strip()
        for r in rules
        if (r.findtext("interface") or "").strip()
    }
    for iface_el in root.findall("./interfaces/*"):
        role = iface_el.tag
        ipaddr = (iface_el.findtext("ipaddr") or "").strip()
        subnet = (iface_el.findtext("subnet") or "").strip()

        if not ipaddr:
            addressing = "<absent>"
        elif ipaddr.lower() in DYNAMIC_ADDRESSING:
            addressing = ipaddr.lower()
        else:
            addressing = "<static address present, redacted>"

        convertible = bool(ipaddr) and ipaddr.lower() not in DYNAMIC_ADDRESSING and bool(subnet)
        has_rules = role in rule_roles

        note = ""
        if has_rules and not convertible:
            note = "  <-- HAS RULES BUT WILL BE SKIPPED: converter refuses"
        elif not convertible:
            note = "  <-- skipped by converter (no static address)"
        elif not has_rules:
            note = "  <-- converted, no rules of its own -> deny-all ACL"

        print(f"  {_safe_role(role):<10} addressing={addressing:<38} rules={'yes' if has_rules else 'no ':<3}{note}")

    blocked = [
        el.tag for el in root.findall("./interfaces/*")
        if el.tag in rule_roles
        and (
            not (el.findtext("ipaddr") or "").strip()
            or (el.findtext("ipaddr") or "").strip().lower() in DYNAMIC_ADDRESSING
            or not (el.findtext("subnet") or "").strip()
        )
    ]
    orphan_roles = sorted(rule_roles - {el.tag for el in root.findall("./interfaces/*")})
    if blocked or orphan_roles:
        print(
            f"  => STILL REFUSES after #78 item 1. Rules name "
            f"{[_safe_role(r) for r in sorted(blocked) + orphan_roles]}, "
            "which the converter cannot model."
        )
    else:
        print("  => every rule-bearing interface has a static address the converter can model.")
    print("\nrule field usage (tag names only):")
    field_use = collections.Counter(
        child.tag for rule in rules for child in rule
    )
    for tag, n in sorted(field_use.items(), key=lambda kv: -kv[1]):
        mark = " " if tag in SUPPORTED_RULE_FIELDS else " <-- NOT SUPPORTED"
        print(f"  {tag:<24}{n:>4}{mark}")

    print("\nvalues we must recognise (vocabulary only, never addresses):")
    for field, allowed in (("type", SUPPORTED_TYPES), ("protocol", SUPPORTED_PROTOCOLS)):
        seen = collections.Counter(
            (r.findtext(field) or "").strip() for r in rules if r.find(field) is not None
        )
        for value, n in sorted(seen.items()):
            # Print a value ONLY if it is in the expected vocabulary; count and
            # redact anything else. Found by Ankeet on #74: the first version
            # printed whatever text was in the element and then annotated it,
            # so a crafted <type>internal-hostname.corp.local</type> printed
            # that hostname directly above this tool's own closing line,
            # "Nothing above contains an address, hostname, or description" --
            # false in that run.
            #
            # These two fields are dropdown-constrained in a real PF Sense GUI
            # export, so it would not trigger there. That is not the point: the
            # docstring states "It NEVER prints a value" as a guarantee, and a
            # guarantee that holds only for well-behaved input is not one.
            if value in allowed:
                print(f"  {field}={value!r:<18}{n:>4}")
            else:
                print(
                    f"  {field}=<present, outside expected vocabulary, redacted>"
                    f"{n:>4} <-- NOT SUPPORTED"
                )

    print("\nsections present at the top level:")
    out_of_scope = {"nat", "dhcpd", "openvpn", "ipsec", "aliases", "shaper"}
    for tag in sorted({el.tag for el in root}):
        mark = " <-- out of scope, converter ignores or refuses" if tag in out_of_scope else ""
        print(f"  {tag}{mark}")

    print(f"\ntotal elements in file    : {sum(census.values())}")
    print("\nNothing above contains an address, hostname, or description.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tools/pfsense_shape.py path/to/config.xml")
    if not Path(sys.argv[1]).is_file():
        sys.exit(f"not a file: {sys.argv[1]}")
    main(sys.argv[1])
