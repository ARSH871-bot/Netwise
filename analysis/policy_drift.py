"""Has an edit made my policy weaker? (#418)

WHY THIS EXISTS
    A policy is edited many times. Each edit looks reasonable on its own, and
    nothing compares it with the version before. A prohibition narrowed from
    a /24 to a /25 has quietly stopped protecting half a subnet; the file
    still loads, every rule still "holds", and the gap only shows up as a
    breach nobody was told to look for.

    This compares two versions of one policy and reports every place the new
    one protects LESS than the old.

WHAT COUNTS AS WEAKER
    rule removed               whatever it protected is no longer checked
    prohibition narrowed       some traffic it forbade is no longer forbidden
    requirement widened        some traffic it did not require must now be
                               allowed
    kind changed               a prohibition became a requirement, or back
    moved                      the rule is about a different device or filter

    Added rules, a prohibition widened, and a requirement narrowed make a
    policy stricter, and are not reported as drift.

CONTAINMENT, NOT OVERLAP
    analysis/policy_conflicts asks whether two traffic descriptions OVERLAP.
    This needs a stricter question: is the old rule's traffic entirely INSIDE
    the new one's? A /24 and a /25 overlap, and the /25 still loses half the
    /24 -- overlap alone cannot see that.

    For one query against another the answer is exact, field by field: each
    field of the old must sit inside the same field of the new. Addresses use
    ipaddress.collapse_addresses, so two /25s together do contain their /24.
    For a rule with several queries (a union), the old query is inside the
    new rule when one new query holds it, and provably outside when it shares
    no traffic with any of them. Between those -- covered only by several new
    queries together -- the answer is UNDECIDABLE, and is reported, never
    called unchanged. Same three answers as #322, for the same reason.

PAIRING
    Rules are paired across versions by `number`. A rule that changed number
    is reported as removed plus added, never silently paired with something
    else. If either file relies on numbers the loader ASSIGNED, pairing by
    position is fragile -- inserting one rule shifts every number after it --
    and the command line says so.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Sequence, Tuple

from analysis.policy_conflicts import (
    ANY, KNOWN_FIELDS, _Undecidable, _parse, _ref, overlap,
)

_FULL = {
    "srcIps": [ipaddress.ip_network("0.0.0.0/0")],
    "dstIps": [ipaddress.ip_network("0.0.0.0/0")],
    "srcPorts": [(0, 65535)],
    "dstPorts": [(0, 65535)],
}


def _merge(ranges: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    out: List[Tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _field_inside(field: str, inner: Any, outer: Any) -> bool:
    """Is every value `inner` allows also allowed by `outer`? Exact."""
    if outer is ANY:
        return True
    if inner is ANY:
        # Only a constraint that is in fact everything contains "any".
        inner = _FULL.get(field)
        if inner is None:
            return False          # protocols: the closed list is not every protocol
    if field in ("srcIps", "dstIps"):
        collapsed = list(ipaddress.collapse_addresses(outer))
        return all(any(n.subnet_of(c) for c in collapsed) for n in inner)
    if field in ("srcPorts", "dstPorts"):
        merged = _merge(outer)
        return all(any(lo >= mlo and hi <= mhi for mlo, mhi in merged) for lo, hi in inner)
    return set(inner) <= set(outer)


def _query_inside(inner: Any, outer: Any) -> Tuple[Optional[bool], str]:
    """Is all of one query's traffic inside another query's? (True/False/None)"""
    try:
        a, ra = _parse(inner)
        b, rb = _parse(outer)
    except _Undecidable as exc:
        return None, str(exc)
    if ra or rb:
        return None, (ra + rb)[0]
    for field in KNOWN_FIELDS:
        if not _field_inside(field, a[field], b[field]):
            return False, field
    return True, ""


def _inside_union(query: Any, union: Sequence[Any]) -> Tuple[Optional[bool], str]:
    """Is all of `query` inside the union of `union`'s queries?

    Exact in three cases, undecidable in the rest:
      * one of them holds it                        -> True
      * it shares no traffic with any of them       -> False
      * exactly ONE of them shares traffic with it  -> whatever that one says,
        because the others cannot cover any of it
    Otherwise several might cover it together, and this does not compute
    unions of multi-field boxes, so it says so instead of guessing.
    """
    reasons = []
    touching = []
    for other in union:
        verdict, why = _query_inside(query, other)
        if verdict is True:
            return True, ""
        if verdict is None:
            reasons.append(why)
        meets, why_meet = overlap(query, other)
        if meets is not False:
            touching.append(other)
            if meets is None:
                reasons.append(why_meet)
    if not touching:
        return False, ""
    if len(touching) == 1:
        verdict, why = _query_inside(query, touching[0])
        return verdict, why
    return None, reasons[0] if reasons else "covered, if at all, only by several queries together"


def _covers(old_queries: Sequence[Any], new_queries: Sequence[Any]) -> Tuple[Optional[bool], Any, str]:
    """Is all of the old rule's traffic inside the new rule's?

    Returns (verdict, the old query that escapes or is undecidable, reason).
    """
    undecided = None
    for q in old_queries or []:
        verdict, why = _inside_union(q, new_queries or [])
        if verdict is False:
            return False, q, ""
        if verdict is None and undecided is None:
            undecided = (q, why)
    if undecided:
        return None, undecided[0], undecided[1]
    return True, None, ""


def _show(query: Any) -> str:
    return ", ".join(f"{k} {v}" for k, v in query.items()) if isinstance(query, dict) else repr(query)


def drift(old: Sequence[Dict[str, Any]], new: Sequence[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """Every way `new` protects less than `old`.

    Returns (weakenings, undecidable), both lists of sentences naming the
    rule. The second must not be read as "no drift" -- see the docstring.
    """
    old_by = {r.get("number"): r for r in old if isinstance(r, dict)}
    new_by = {r.get("number"): r for r in new if isinstance(r, dict)}
    weaker: List[str] = []
    unknown: List[str] = []

    for number in sorted(old_by, key=lambda n: (n is None, n)):
        was = old_by[number]
        now = new_by.get(number)
        if now is None:
            weaker.append(f"{_ref(was)} was removed, so nothing checks what it covered any more")
            continue
        if was.get("kind") != now.get("kind"):
            weaker.append(f"{_ref(was)} changed from a {was.get('kind')} to a {now.get('kind')}")
            continue
        if (was.get("node"), was.get("filter")) != (now.get("node"), now.get("filter")):
            weaker.append(
                f"{_ref(was)} moved from {was.get('node')} filter {was.get('filter')} to "
                f"{now.get('node')} filter {now.get('filter')}, so the old place is no longer checked"
            )
            continue

        if was.get("kind") == "prohibition":
            # Weaker if some traffic it used to forbid is no longer forbidden.
            verdict, escaped, why = _covers(was.get("queries"), now.get("queries"))
            if verdict is False:
                weaker.append(f"{_ref(was)} now forbids less: {_show(escaped)} is no longer fully forbidden")
            elif verdict is None:
                unknown.append(f"{_ref(was)}: could not tell whether it got narrower ({why})")
        elif was.get("kind") == "requirement":
            # Weaker if it now requires traffic it did not require before.
            verdict, escaped, why = _covers(now.get("queries"), was.get("queries"))
            if verdict is False:
                weaker.append(f"{_ref(was)} now requires more to be allowed: {_show(escaped)} was not required before")
            elif verdict is None:
                unknown.append(f"{_ref(was)}: could not tell whether it got wider ({why})")
    return weaker, unknown


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`python -m analysis.policy_drift old.json new.json` -- exit 1 if weaker."""
    import sys

    from analysis.policy import PolicyError, load_policy_file

    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: python -m analysis.policy_drift <old-policy.json> <new-policy.json>")
        return 2
    loaded = []
    for path in args:
        try:
            loaded.append(load_policy_file(path))
        except PolicyError as error:
            print(f"{path}: not loaded -- {error}")
            return 2
    for path, pol in zip(args, loaded):
        if pol.assigned:
            print(f"warning: {path} relies on rule numbers the loader assigned; rules are paired "
                  "by number, so inserting or reordering a rule pairs the wrong ones. Give every "
                  "rule an explicit `number`.")
    weaker, unknown = drift(loaded[0].entries_for("policy_compliance"),
                            loaded[1].entries_for("policy_compliance"))
    for line in weaker:
        print(f"WEAKER: {line}")
    for line in unknown:
        print(f"warning: {line}")
    if not weaker:
        print("Not weaker: every rule in the old policy is still in force, at least as wide."
              + (f" {len(unknown)} rule(s) could not be compared, above." if unknown else ""))
    return 1 if weaker else 0


if __name__ == "__main__":
    raise SystemExit(main())
