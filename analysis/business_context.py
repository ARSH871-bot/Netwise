"""Load and validate a user-supplied business context (#87, risk side).

WHAT THIS IS FOR
    `analysis/checks/risk.py` re-rates every finding using rules R-1..R-4,
    and all of them look only at the finding itself -- what kind of problem
    it is, and what the evidence says. None of them know what the affected
    device is FOR. A blanket permit on a lab switch and the same blanket
    permit on the payroll server score identically today, which is the one
    judgement a network owner can make and Netwise cannot.

    This module is the input side of fixing that: a place for the user to
    say which of their assets matter, so `risk` can weigh a finding by what
    it actually endangers rather than only by its shape.

WHY IT MIRRORS analysis/policy.py RATHER THAN INVENTING A SECOND STYLE
    `policy.py` already solved "take a file the user wrote and refuse it
    clearly", and its rules were argued out on #159. Re-deriving them here
    would mean re-deriving the mistakes too, so the same properties hold
    and for the same reasons:

      - a dedicated loader, validating by hand and failing loudly (D5)
      - JSON only, from the standard library -- no new runtime dependency
        for a security tool on one person's say-so
      - an UNKNOWN KEY is an error, never ignored. Silently dropping a key
        the user set is how someone believes an asset is protected when
        nothing reads it: F-4 arriving through the input rather than the
        output
      - errors NAME THE ENTRY, quoting its description, because "unknown
        key" alone is a scavenger hunt through a long file
      - an EMPTY context is VALID (D4's analogue): it asserts nothing, and
        the caller's obligation is to keep scoring exactly as it does today

    It never half-loads. One bad entry refuses the whole file, for the same
    reason a check that half-runs is worse than one that does not run.

THE SHAPE, AND THE THREE THINGS IT REFUSES
    A JSON list of entries. Each entry identifies ONE asset -- by `device`
    or by `subnet`, never both -- and gives it a tier:

        [
          {"device": "rtr-us5", "tier": "critical",
           "description": "Edge router, all site traffic"},
          {"subnet": "10.10.10.0/24", "tier": "important",
           "description": "Finance VLAN"}
        ]

    Refused, rather than guessed at:

      1. An entry with both `device` and `subnet`, or neither. Which one
         identifies the asset would be a guess, and a guess here silently
         mis-scores a real finding.
      2. A `subnet` that is not a literal IP or CIDR. The same limit
         `ai/query.py` already enforces on a destination, for the same
         reason -- resolving a name needs interface enumeration this
         project does not have.
      3. Two entries naming the same asset. Which tier wins is undefined,
         and picking one would make a scoring decision the user did not.

WHAT THIS MODULE IS NOT
    Not scoring. It loads and validates; it does not decide what a tier is
    worth, and it does not import `risk`. How a tier changes a severity is
    a separate step with its own ruleset, and mixing the two would put a
    scoring decision inside a parser, where nobody reviewing severities
    would think to look for it.

    **The format is not yet team-agreed.** `docs/finding-format.md` (F-1)
    is untouched by this -- no finding gains a field -- so it needs no
    amendment. But the vocabulary below is one person's proposal until the
    team says otherwise, exactly as the policy format was before #159.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: The criticality tiers, worst first. Three, not five, and not a free
#: number: a tier the user has to think hard about is a tier they will get
#: wrong, and a number invites arithmetic nobody agreed to. Ordered, so a
#: caller can compare positions without hardcoding the names.
TIERS = ("critical", "important", "standard")

#: Exactly one of these identifies the asset an entry is about.
_IDENTIFIER_KEYS = ("device", "subnet")

#: Every key an entry may carry. Anything else is an error, never ignored.
_ALLOWED_KEYS = frozenset({"description", "device", "subnet", "tier"})

#: Required in every entry, once the identifier rule has passed.
#: `description` is NOT required: it is the user's file, and demanding
#: prose for every asset is how a format goes unused. It is used in error
#: messages whenever it is there.
_REQUIRED_KEYS = ("tier",)


class BusinessContextError(ValueError):
    """A business context that cannot be loaded, naming the entry at fault.

    A ValueError for the same reason `PolicyError` is one: callers that
    already catch bad input keep working, and `analysis/pipeline.py` turns
    anything raised inside a check into a `status="error"` finding, which
    is the right outcome for a file the user got wrong.
    """


class BusinessContext:
    """A validated business context: which assets matter, and how much.

    `entries` is the normalised list, in file order. Order is preserved
    rather than sorted, so an error message and a later report both point
    at the same entry number the user sees in their own file.
    """

    def __init__(self, entries: Optional[List[Dict[str, Any]]] = None) -> None:
        self.entries = entries or []

    @property
    def is_empty(self) -> bool:
        """True when the context says nothing about any asset.

        A VALID state, not an error. The caller's obligation is to keep
        behaving exactly as it does with no context at all -- an empty file
        must never be read as "nothing here is important".
        """
        return not self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        counts = ", ".join(
            f"{tier}={sum(1 for e in self.entries if e['tier'] == tier)}"
            for tier in TIERS
        )
        return f"<BusinessContext {counts}{' EMPTY' if self.is_empty else ''}>"


def _describe_entry(index: int, entry: Mapping[str, Any]) -> str:
    """Name an entry the way a person would look for it in their own file.

    Quoting the description is what makes the error fixable. Where there is
    no description, the identifier is the next best handle -- and only then
    does the reader fall back to counting entries.
    """
    if isinstance(entry, Mapping):
        description = entry.get("description")
        if isinstance(description, str) and description.strip():
            shortened = description.strip()
            if len(shortened) > 60:
                shortened = shortened[:57] + "..."
            return f"entry {index} ({shortened!r})"
        for key in _IDENTIFIER_KEYS:
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return f"entry {index} ({key} {value.strip()!r})"
    return f"entry {index}"


def _suggest_tier(given: Any) -> str:
    """A did-you-mean, but only for a difference we can actually see.

    No fuzzy matching: a wrong guess in an error message is worse than no
    guess, because it sends the reader to change the wrong thing. Case is the
    one difference worth naming -- "Critical" is a plausible thing to write
    and an unhelpful thing to be silently corrected on.

    This one EARNS its place, which is not automatic. `policy._suggest()` was
    the same idea and was deleted in #185 because its condition was identical
    to the accepting branch above it, so it could never fire. The test here is
    whether a suggestion can say something the accepting path does not already
    handle. A case difference is not silently corrected, so this one can.
    """
    if isinstance(given, str) and given.strip().lower() in TIERS:
        return f" -- did you mean {given.strip().lower()!r}? (tiers are lower-case)"
    return ""


def _validate_subnet(where: str, value: Any) -> str:
    """A subnet must be a literal IP or CIDR, never a name.

    The same limit `ai/query.py` enforces on a destination, and for the
    same reason: resolving "the finance VLAN" to an address needs interface
    enumeration this project does not have. Refusing is correct today.
    """
    if not isinstance(value, str):
        raise BusinessContextError(
            f"{where}: 'subnet' must be an IP address or CIDR written out, "
            f"got {type(value).__name__}"
        )

    text = value.strip()
    try:
        # strict=False so "10.10.10.5/24" is accepted as the network it
        # names, rather than refused over a set host bit.
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError as error:
        raise BusinessContextError(
            f"{where}: 'subnet' must be a literal IP address or CIDR, got "
            f"{text!r} ({error}). A name cannot be resolved to an address "
            f"offline, so it is refused rather than guessed at"
        ) from error


def _validate_entry(index: int, entry: Any) -> Tuple[Dict[str, Any], str]:
    """Validate and normalise one entry.

    Returns the entry and the key it is identified by, so the caller can
    detect duplicates without re-deriving which field was used. Raises
    BusinessContextError, naming the entry.
    """
    where = _describe_entry(index, entry if isinstance(entry, Mapping) else {})

    if not isinstance(entry, Mapping):
        raise BusinessContextError(
            f"{where}: expected a mapping of keys to values, got "
            f"{type(entry).__name__}"
        )

    unknown = [key for key in entry if key not in _ALLOWED_KEYS]
    if unknown:
        raise BusinessContextError(
            f"{where}: unknown key(s): {', '.join(sorted(unknown))}. "
            f"Allowed: {', '.join(sorted(_ALLOWED_KEYS))}"
        )

    # Exactly one identifier. Both is ambiguous, neither is unusable, and
    # either way choosing for the user silently mis-scores a real finding.
    present = [key for key in _IDENTIFIER_KEYS if entry.get(key) is not None]
    if len(present) > 1:
        raise BusinessContextError(
            f"{where}: an entry names both "
            f"{' and '.join(repr(k) for k in present)}. One entry describes "
            f"one asset -- split it into two entries"
        )
    if not present:
        raise BusinessContextError(
            f"{where}: an entry must identify one asset, by "
            f"{' or '.join(repr(k) for k in _IDENTIFIER_KEYS)}"
        )

    missing = [key for key in _REQUIRED_KEYS if entry.get(key) is None]
    if missing:
        raise BusinessContextError(
            f"{where}: missing required key(s): {', '.join(missing)}. "
            f"Tiers are: {', '.join(TIERS)}"
        )

    tier = entry["tier"]
    if tier not in TIERS:
        raise BusinessContextError(
            f"{where}: unknown tier {tier!r}{_suggest_tier(tier)}. "
            f"Allowed: {', '.join(TIERS)}"
        )

    identifier = present[0]
    normalised: Dict[str, Any] = {"tier": tier}

    if identifier == "subnet":
        normalised["subnet"] = _validate_subnet(where, entry["subnet"])
    else:
        device = entry["device"]
        if not isinstance(device, str) or not device.strip():
            raise BusinessContextError(
                f"{where}: 'device' must be a non-empty device name, got "
                f"{device!r}"
            )
        normalised["device"] = device.strip()

    description = entry.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise BusinessContextError(
                f"{where}: 'description' must be text, got "
                f"{type(description).__name__}"
            )
        normalised["description"] = description

    return normalised, identifier


def load_business_context(data: Any) -> BusinessContext:
    """Validate and normalise an already-parsed business context.

    Format-agnostic, for `load_policy`'s reason: the decision-heavy part is
    validation, and it should not care where the data came from. Raises
    BusinessContextError naming the entry for anything it will not accept,
    and never half-loads.
    """
    if data is None:
        # A file that parsed to nothing says nothing about any asset, which
        # is valid. It must never be read as "nothing here is important".
        return BusinessContext()

    if not isinstance(data, list):
        raise BusinessContextError(
            f"a business context must be a list of entries at the top level, "
            f"got {type(data).__name__}"
        )

    entries: List[Dict[str, Any]] = []
    #: identifier value -> the entry number that claimed it first.
    seen: Dict[str, int] = {}

    for index, entry in enumerate(data, start=1):
        validated, identifier = _validate_entry(index, entry)

        # Two entries for one asset leave the tier undefined. Picking one
        # would be a scoring decision made in a parser, by nobody.
        key = f"{identifier}:{validated[identifier]}"
        if key in seen:
            raise BusinessContextError(
                f"{_describe_entry(index, entry)}: {identifier} "
                f"{validated[identifier]!r} is already described by entry "
                f"{seen[key]}. One asset gets one tier -- remove the "
                f"duplicate rather than leaving which one wins to chance"
            )
        seen[key] = index

        entries.append(validated)

    return BusinessContext(entries)


def load_business_context_file(path: Any) -> BusinessContext:
    """Load a business context from a JSON file.

    JSON only, from the standard library. That is `policy.py`'s limit and
    it is deliberate: adding YAML would add a runtime dependency to a
    security tool, and this format has not been through the team yet.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise BusinessContextError(f"no business context file at {file_path}")

    text = file_path.read_text(encoding="utf-8").strip()
    if not text:
        # An empty FILE is an empty CONTEXT, which is valid.
        return BusinessContext()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise BusinessContextError(
            f"{file_path} is not valid JSON: line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error

    return load_business_context(parsed)
