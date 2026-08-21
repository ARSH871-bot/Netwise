"""Load and validate a user-supplied security policy (#87).

WHAT THIS IS FOR
    Netwise's biggest gap: every policy assertion is hardcoded to this
    project's own fixtures. Measured across every readable fixture with
    `tools/stranger_config.py`, on configs identical but for the device name:

        ours      12 found /  3 none /  7 error
        stranger   3 found /  0 none / 15 error

    Twelve detections become three, and the three survivors are the two
    analyses that need no policy at all. On a network that is not ours,
    Netwise finds dead ACL rules and undefined references, and everything
    else honestly says "could not check".

    This module is the input side of closing that.

THE FIVE DECISIONS THIS IMPLEMENTS, AND WHO AGREED THEM
    `docs/design/user-policy-format.md` states them; #159 collected the
    answers. All three teammates answered 1A 2A 3A 4A 5A:

    D1  One vocabulary, normalised, rather than four dialects.
    D2  Device named per entry, with an optional top-level default.
    D3  A policy naming an absent device is reported once per check as
        status="error" -- ALREADY DECIDED by #29/#45/#50, and already
        implemented in the checks. Not this module's job.
    D4  An empty policy is VALID, but loud.
    D5  Validate by hand, failing loudly, rather than with a schema.

    Two additions came with those answers and are implemented here:

      - @shubhamkataria2005, on D4: an empty policy must let each
        policy-driven check emit status="none" -- NOT return nothing.
        Verified against the pipeline: a check returning [] produces
        `PC-000 status=error "The policy compliance check returned no
        findings"`, which reports the check as broken when in fact it ran
        fine and had nothing to assert. Wrong status and wrong message.
      - @shubhamkataria2005 and @SamikaPerera, on D5: name the ENTRY, not
        just the field, and treat an UNKNOWN KEY as an error rather than
        ignoring it. Silently dropping a key the user actually set is how
        someone believes a rule is enforced when nothing reads it -- F-4
        arriving through the input rather than the output.

WHAT IS DELIBERATELY NOT DECIDED HERE
    **The file format.** `user-policy-format.md` says "YAML or JSON" and
    never chooses, and PyYAML is not in requirements.txt -- so picking YAML
    would add a runtime dependency to a security tool on one person's say-so.

    So the decision-heavy part, validation and normalisation, takes an
    already-parsed mapping and does not care where it came from.
    `load_policy_file()` handles JSON today, from the standard library. YAML
    becomes a few lines and one requirements entry the moment the team
    agrees to the dependency.

WHAT THIS MODULE MUST NOT BECOME
    From the same document: no policy DSL, no expressions, no silent
    defaults. "A policy that half-loads is worse than one that will not
    load, for the same reason a check that half-runs is."
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

#: The checks a policy file may configure. `risk` and `change_impact` are
#: absent on purpose: one is a post-processor and the other compares two
#: snapshots, and neither asserts anything a user would write down.
POLICY_SECTIONS = ("access_control", "policy_compliance", "routing")

#: Keys every entry may carry, whichever section it is in.
#:
#: `node` and `violation_severity` are the NORMALISED names (D1). Before
#: this, `routing` used `start_node` and `policy_compliance` used
#: `severity` -- three structures, two disagreements, and a user writing
#: `node:` under a route would have got silence. @patelankeet2 and
#: @shubhamkataria2005 each accepted the rename in their own check on #159.
_COMMON_KEYS = frozenset({"description", "node", "violation_severity", "violation_summary"})

#: Keys specific to one section, derived from what each check actually reads.
_SECTION_KEYS: Dict[str, frozenset] = {
    "access_control": frozenset({"filter", "headers", "expected"}),
    "policy_compliance": frozenset({"filter", "kind", "queries", "number"}),
    "routing": frozenset({"src_ip", "dst_ip", "expected", "number"}),
}

#: Required in every entry. Deliberately short: a policy is the user's, and
#: demanding fields they cannot know is how a format goes unused. `node` is
#: required only AFTER the top-level default is applied (D2).
_REQUIRED_KEYS = ("description", "node")

#: Renames we accept and correct rather than reject, because these are the
#: names our own code used until #159 and a user copying from our docs or
#: from a check would write them. Accepting silently would defeat D1, so
#: they are corrected AND reported -- see `Policy.renamed`.
_LEGACY_KEYS = {
    "start_node": "node",
    "severity": "violation_severity",
}


class PolicyError(ValueError):
    """A policy that cannot be loaded, with a message naming the entry.

    Deliberately a ValueError: callers that already catch bad input keep
    working, and `analysis/pipeline.py` turns anything raised inside a check
    into a `status="error"` finding, which is the right outcome for a policy
    the user got wrong.
    """


class Policy:
    """A validated, normalised policy.

    `sections` maps a check name to its list of entries. A check with no
    entries is present with an empty list rather than absent, so a caller
    can tell "the user supplied nothing for this check" from "this check is
    not policy-driven at all".
    """

    def __init__(
        self,
        sections: Dict[str, List[Dict[str, Any]]],
        renamed: Optional[List[str]] = None,
    ) -> None:
        self.sections = sections
        #: Legacy key names that were corrected, as human-readable notes.
        #: Reported rather than silent, because a user who wrote
        #: `start_node:` should learn the name changed.
        self.renamed = renamed or []

    @property
    def is_empty(self) -> bool:
        """True when the policy asserts nothing at all.

        This is a VALID state (D4), and the caller's obligation is to be
        loud about it: emit `status="none"` per policy-driven check saying
        how many rules were not evaluated, never silence. A check that
        returns nothing is reported by the pipeline as broken.
        """
        return not any(self.sections.values())

    def entries_for(self, check: str) -> List[Dict[str, Any]]:
        return self.sections.get(check, [])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        counts = ", ".join(f"{k}={len(v)}" for k, v in sorted(self.sections.items()))
        return f"<Policy {counts}{' EMPTY' if self.is_empty else ''}>"


def _describe_entry(section: str, index: int, entry: Mapping[str, Any]) -> str:
    """Name an entry the way a person would look for it.

    A message saying only "unknown key" sends the reader on a scavenger
    hunt through ten entries with seven keys each. Quoting the description
    is what makes the error fixable, so it is used whenever present.
    """
    description = entry.get("description") if isinstance(entry, Mapping) else None
    if isinstance(description, str) and description.strip():
        shortened = description.strip()
        if len(shortened) > 60:
            shortened = shortened[:57] + "..."
        return f"{section} entry {index} ({shortened!r})"
    return f"{section} entry {index}"


def _suggest(unknown: str, allowed: frozenset) -> str:
    """A did-you-mean, but only when it is a rename we actually know about.

    No fuzzy matching. A wrong guess in an error message is worse than no
    guess, because it sends the reader to change the wrong thing.
    """
    if unknown in _LEGACY_KEYS and _LEGACY_KEYS[unknown] in allowed:
        return f" -- did you mean {_LEGACY_KEYS[unknown]!r}? (renamed in #159)"
    return ""


def _validate_entry(
    section: str, index: int, entry: Any, default_node: Optional[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """Validate and normalise one entry. Raises PolicyError, naming it."""
    where = _describe_entry(section, index, entry if isinstance(entry, Mapping) else {})

    if not isinstance(entry, Mapping):
        raise PolicyError(
            f"{where}: expected a mapping of keys to values, got "
            f"{type(entry).__name__}"
        )

    allowed = _COMMON_KEYS | _SECTION_KEYS[section]
    normalised: Dict[str, Any] = {}
    renamed: List[str] = []

    for key, value in entry.items():
        if key in _LEGACY_KEYS and _LEGACY_KEYS[key] in allowed:
            canonical = _LEGACY_KEYS[key]
            renamed.append(f"{where}: {key!r} was renamed to {canonical!r} in #159")
            normalised[canonical] = value
            continue
        if key not in allowed:
            raise PolicyError(
                f"{where}: unknown key {key!r}{_suggest(key, allowed)}. "
                f"Allowed here: {', '.join(sorted(allowed))}"
            )
        normalised[key] = value

    if "node" not in normalised and default_node is not None:
        normalised["node"] = default_node

    missing = [k for k in _REQUIRED_KEYS if k not in normalised]
    if missing:
        raise PolicyError(
            f"{where}: missing required key(s): {', '.join(missing)}"
            + (
                ". A top-level 'device:' would supply 'node' for every entry"
                if "node" in missing
                else ""
            )
        )

    return normalised, renamed


def load_policy(data: Any) -> Policy:
    """Validate and normalise an already-parsed policy mapping.

    Format-agnostic on purpose -- see the module docstring. Raises
    PolicyError naming the entry for anything it will not accept, and never
    half-loads.
    """
    if data is None:
        # A file that parsed to nothing is an EMPTY policy, not a broken
        # one. D4: valid, and the caller must be loud about it.
        return Policy({section: [] for section in POLICY_SECTIONS})

    if not isinstance(data, Mapping):
        raise PolicyError(
            f"a policy must be a mapping at the top level, got {type(data).__name__}"
        )

    default_node = data.get("device")
    if default_node is not None and not isinstance(default_node, str):
        raise PolicyError(
            f"top-level 'device' must be a device name, got "
            f"{type(default_node).__name__}"
        )

    unknown_sections = [
        key for key in data if key != "device" and key not in POLICY_SECTIONS
    ]
    if unknown_sections:
        raise PolicyError(
            f"unknown section(s): {', '.join(sorted(unknown_sections))}. "
            f"A policy may configure: {', '.join(POLICY_SECTIONS)}"
        )

    sections: Dict[str, List[Dict[str, Any]]] = {s: [] for s in POLICY_SECTIONS}
    renamed: List[str] = []

    for section in POLICY_SECTIONS:
        raw = data.get(section)
        if raw is None:
            continue
        if not isinstance(raw, list):
            raise PolicyError(
                f"section {section!r} must be a list of entries, got "
                f"{type(raw).__name__}"
            )
        for index, entry in enumerate(raw, start=1):
            validated, entry_renamed = _validate_entry(
                section, index, entry, default_node
            )
            sections[section].append(validated)
            renamed.extend(entry_renamed)

    return Policy(sections, renamed)


def load_policy_file(path: Any) -> Policy:
    """Load a policy from a JSON file.

    JSON only, from the standard library, and that is a deliberate limit
    rather than a preference -- see the module docstring. The team agreed
    the file's CONTENT on #159 and did not choose between YAML and JSON.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise PolicyError(f"no policy file at {file_path}")

    text = file_path.read_text(encoding="utf-8").strip()
    if not text:
        # An empty FILE is an empty POLICY, which is valid and loud (D4).
        return Policy({section: [] for section in POLICY_SECTIONS})

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise PolicyError(
            f"{file_path} is not valid JSON: line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error

    return load_policy(parsed)


# ------------------------------------------------------------------------------
# Delivering a loaded policy to a check (#87, the vertical slice)
# ------------------------------------------------------------------------------
#
# THE PROBLEM THIS SOLVES, AND WHY IT LOOKS LIKE THIS
#     Everything above was written, tested and merged in #173 -- and wired to
#     NOTHING. Measured before this change: no module under `analysis/checks/`,
#     `analysis/pipeline.py`, `web/` or `ai/` imported it. A loader nobody calls
#     closes no gap at all.
#
#     The obvious wiring is to pass the policy in as an argument. That is
#     blocked, and correctly so: F-3 fixes a check's signature at
#     `run(bf: Session) -> list[dict]`, and `docs/design/pipeline-feature-shapes.md`
#     was ADOPTED by all four signatures. Widening it is a contract change
#     needing the whole team, not something to slip inside a feature branch.
#
#     So the policy is set here, before the pipeline runs, and checks read it.
#     Module-level state, which is a real cost and is stated rather than
#     hidden -- see below.
#
# WHY MODULE-LEVEL STATE IS ACCEPTABLE HERE, AND WHERE IT STOPS BEING SO
#     Netwise is a single-user local tool. `web/main.py` already keeps
#     `_uploaded` this way and says the same thing: "Module-level state is only
#     defensible because this is a single-user local tool... If Netwise ever
#     serves more than one user, this becomes per-session state." The same
#     sentence applies here, for the same reason, and the same day it stops
#     being true it stops being true for both.
#
#     It is deliberately NOT a convenience. The alternative -- checks reaching
#     for a file path themselves -- would put policy loading, and therefore
#     policy ERRORS, inside three different checks with three different
#     failure behaviours.
#
# THE SAFETY PROPERTY THAT MATTERS MORE THAN THE PLUMBING
#     A finding produced from the user's policy and a finding produced from
#     our built-in example policy look identical on screen. That is exactly
#     the confusion #87 is about: the user believing their rules are enforced
#     when ours are. So `active_policy()` returning None is a MEANINGFUL
#     answer, and the check is obliged to say which policy it used rather than
#     quietly defaulting. See policy_compliance.run().

#: The policy in force for this process, or None when the user supplied none.
#: None is not "empty" -- an empty policy is a real, valid, deliberate state
#: (D4) and is a Policy object with empty sections. Conflating the two would
#: be F-4 in the policy layer: "the user asserted nothing" and "the user
#: supplied nothing" are different claims.
_active_policy: Optional[Policy] = None


def set_active_policy(policy: Optional[Policy]) -> None:
    """Install the policy the checks should read, or None to use none.

    Raises TypeError rather than accepting a raw dict: a caller that has not
    been through `load_policy()` has not been validated, and letting one
    through would put unvalidated user input in front of a check -- the
    failure the whole module exists to prevent.
    """
    global _active_policy
    if policy is not None and not isinstance(policy, Policy):
        raise TypeError(
            "set_active_policy() takes a Policy from load_policy() or "
            f"load_policy_file(), not {type(policy).__name__}. Passing a raw "
            "mapping would hand a check unvalidated user input."
        )
    _active_policy = policy


def active_policy() -> Optional[Policy]:
    """The policy in force, or None if the user supplied none."""
    return _active_policy


def clear_active_policy() -> None:
    """Forget the active policy. Called on upload, and between tests."""
    global _active_policy
    _active_policy = None
