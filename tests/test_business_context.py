"""Tests for the business-context loader (#87, risk side).

FAILURE PATHS FIRST, FOR THE REASON test_policy_loader.py GIVES
    "A policy that half-loads is worse than one that will not load, for the
    same reason a check that half-runs is." The same is true of a business
    context, and arguably more so: a policy that half-loads makes Netwise
    miss a finding, while a context that half-loads makes it RE-RATE one --
    it changes a severity the user reads and acts on. So the cases that
    must REFUSE are written first and tested hardest; the happy path is the
    easy half.

THE THREE REFUSALS THAT ARE SPECIFIC TO THIS FORMAT
    Beyond the discipline inherited from `policy.py`:

      - both `device` and `subnet`, or neither -- which identifies the
        asset would be a guess
      - a `subnet` that is not a literal IP or CIDR -- the limit
        `ai/query.py` already enforces on a destination
      - two entries naming one asset -- which tier wins is undefined

    Each of these has a mutation test alongside it, because a guard nobody
    has watched fail is a guard nobody knows works.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import json

import pytest

from analysis.business_context import (
    TIERS,
    BusinessContext,
    BusinessContextError,
    load_business_context,
    load_business_context_file,
)


def _entry(**overrides):
    base = {
        "device": "rtr-us5",
        "tier": "critical",
        "description": "Edge router, carries all site traffic",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# The refusals
# ---------------------------------------------------------------------------


def test_an_unknown_key_is_an_error_and_names_the_entry():
    """Inherited from the policy loader, and for its exact reason.

    Ignoring an unrecognised key is how a user ends up believing an asset
    is protected when nothing reads it. The message has to name the entry,
    because "unknown key" alone is a scavenger hunt through a long file.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(owner="finance-team")])

    message = str(raised.value)
    assert "unknown key" in message
    assert "owner" in message
    assert "entry 1" in message
    assert "Edge router" in message, "the message must quote the description"


def test_an_unknown_tier_is_rejected_and_lists_the_real_ones():
    """The tier vocabulary is closed, exactly as the intent set in query.py is.

    "high" is the plausible wrong answer here -- it is F-1's severity
    vocabulary, and someone who has read the rest of this project will
    reach for it. Accepting it would quietly conflate how bad a finding is
    with how much the asset matters, which are the two things this feature
    exists to keep apart.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(tier="high")])

    message = str(raised.value)
    assert "unknown tier" in message
    assert "'high'" in message
    for tier in TIERS:
        assert tier in message, "the message must list the tiers that do work"


def test_a_miscased_tier_gets_a_did_you_mean_but_is_still_refused():
    """Corrected silently would be a silent default; refused blankly is unkind.

    So it is refused AND named, the same trade `policy._suggest` makes.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(tier="Critical")])

    message = str(raised.value)
    assert "did you mean 'critical'" in message


def test_no_did_you_mean_is_offered_for_a_tier_we_cannot_actually_see():
    """A wrong guess in an error message sends the reader to change the wrong
    thing, so the hint fires only on a difference we can prove is a
    difference. "vital" is a synonym, not a typo we can detect."""
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(tier="vital")])

    assert "did you mean" not in str(raised.value)


def test_an_entry_naming_both_device_and_subnet_is_refused():
    """One entry describes one asset.

    Guessing which field identifies it would silently mis-score every
    finding about the one that lost.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(subnet="10.10.10.0/24")])

    message = str(raised.value)
    assert "'device'" in message and "'subnet'" in message
    assert "split it into two entries" in message


def test_an_entry_identifying_nothing_is_refused():
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([{"tier": "standard", "description": "something"}])

    assert "must identify one asset" in str(raised.value)


def test_a_missing_tier_names_the_entry_and_the_key():
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([{"device": "rtr-us5", "description": "Edge"}])

    message = str(raised.value)
    assert "tier" in message
    assert "entry 1" in message


@pytest.mark.parametrize(
    "bad_subnet",
    ["finance-vlan", "10.10.10.999/24", "10.10.10.0/33", ""],
)
def test_a_subnet_that_is_not_a_literal_address_is_refused(bad_subnet):
    """`ai/query.py`'s limit, restated here.

    Resolving "the finance VLAN" to an address needs interface enumeration
    this project does not have, so a name is refused rather than guessed
    at. That refusal is the feature, not a gap in it.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([{"subnet": bad_subnet, "tier": "important"}])

    assert "literal IP address or CIDR" in str(raised.value)


def test_two_entries_naming_the_same_device_are_refused():
    """Which tier wins is undefined, and a parser must not decide it."""
    with pytest.raises(BusinessContextError) as raised:
        load_business_context(
            [_entry(tier="critical"), _entry(tier="standard", description="again")]
        )

    message = str(raised.value)
    assert "already described by entry 1" in message
    assert "rtr-us5" in message


def test_two_entries_naming_the_same_subnet_are_refused_after_normalisation():
    """The duplicate check runs on the NORMALISED value, not the raw text.

    "10.10.10.0/24" and "10.10.10.5/24" are the same network written two
    ways. Comparing the strings the user typed would let that pair through
    and leave the tier undefined -- the exact thing the check exists to
    prevent.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context(
            [
                {"subnet": "10.10.10.0/24", "tier": "critical"},
                {"subnet": "10.10.10.5/24", "tier": "standard"},
            ]
        )

    assert "already described by entry 1" in str(raised.value)


def test_the_same_name_used_as_a_device_and_a_subnet_is_not_a_duplicate():
    """The opposite direction: the duplicate check must not over-reach.

    A device and a network are different kinds of thing, so they cannot
    collide even if they somehow read alike.
    """
    context = load_business_context(
        [
            {"device": "10.10.10.0/24", "tier": "critical"},
            {"subnet": "10.10.10.0/24", "tier": "standard"},
        ]
    )

    assert len(context) == 2


@pytest.mark.parametrize("bad", [{"device": "rtr-us5"}, "a string", 42, True])
def test_a_context_that_is_not_a_list_is_refused(bad):
    """Deliberately including a MAPPING.

    `policy.py`'s top level is a mapping, so someone moving between the two
    files will write one here. The message says what shape this one wants
    rather than only that the shape is wrong.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context(bad)

    assert "list of entries" in str(raised.value)


@pytest.mark.parametrize("bad_entry", ["rtr-hq", 42, None, ["rtr-hq", "critical"]])
def test_an_entry_that_is_not_a_mapping_is_refused_by_position(bad_entry):
    """Asserts the MESSAGE, not merely that something was raised.

    Written that weaker way first, and a mutation caught it: with the
    `isinstance(entry, Mapping)` guard deleted, a string entry still
    raised -- iterating "rtr-hq" yields characters, which fail the
    unknown-key check instead. Same exception, useless message, and a test
    that only looked for "entry 2" could not tell the two apart. A bare
    `42` does not even reach that far: it raises TypeError, which the
    pipeline reports as a crash rather than a file the user can fix.
    """
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(), bad_entry])

    message = str(raised.value)
    assert "entry 2" in message
    assert "expected a mapping" in message


@pytest.mark.parametrize("bad_device", ["", "   ", 10, None])
def test_a_device_that_is_not_a_usable_name_is_refused(bad_device):
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([{"device": bad_device, "tier": "standard"}])

    # `None` fails the identifier rule; the rest fail the name rule. Both
    # are refusals, which is what this asserts -- not which message won.
    assert str(raised.value)


def test_a_non_string_description_is_refused():
    with pytest.raises(BusinessContextError) as raised:
        load_business_context([_entry(description=["Edge", "router"])])

    assert "'description' must be text" in str(raised.value)


def test_one_bad_entry_refuses_the_whole_context():
    """Never half-loads.

    A context that loaded three of four entries would re-rate three
    findings and leave the fourth silently at its default -- indistinguish-
    able, on screen, from a context that said nothing about it.
    """
    with pytest.raises(BusinessContextError):
        load_business_context(
            [_entry(), _entry(device="rtr-hq", tier="nonsense", description="HQ")]
        )


def test_the_error_names_the_second_entry_not_the_first():
    with pytest.raises(BusinessContextError) as raised:
        load_business_context(
            [_entry(), _entry(device="rtr-hq", tier="nonsense", description="HQ core")]
        )

    message = str(raised.value)
    assert "entry 2" in message
    assert "HQ core" in message


# ---------------------------------------------------------------------------
# An empty context is valid
# ---------------------------------------------------------------------------


def test_an_empty_context_is_valid_not_an_error():
    """D4's analogue: asserting nothing is a thing a user may legitimately do.

    The obligation this creates is on the caller, not here -- scoring must
    carry on exactly as it does with no file at all. An empty context must
    never be read as "nothing here is important".
    """
    context = load_business_context([])

    assert context.is_empty
    assert context.entries == []


def test_a_context_that_parsed_to_nothing_is_empty_not_broken():
    assert load_business_context(None).is_empty


def test_a_context_with_entries_is_not_empty():
    assert not load_business_context([_entry()]).is_empty


def test_an_empty_file_is_an_empty_context_not_a_parse_error(tmp_path):
    path = tmp_path / "business-context.json"
    path.write_text("   \n", encoding="utf-8")

    assert load_business_context_file(path).is_empty


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_valid_context_loads_every_entry_in_file_order():
    context = load_business_context(
        [
            _entry(device="rtr-us5", tier="critical"),
            {"subnet": "10.10.10.0/24", "tier": "important", "description": "Finance"},
            {"device": "sw-lab-1", "tier": "standard"},
        ]
    )

    assert len(context) == 3
    assert [e["tier"] for e in context.entries] == ["critical", "important", "standard"]
    assert context.entries[0]["device"] == "rtr-us5"
    assert context.entries[1]["subnet"] == "10.10.10.0/24"
    assert "description" not in context.entries[2], (
        "an absent optional key must stay absent rather than become None"
    )


@pytest.mark.parametrize("tier", TIERS)
def test_every_declared_tier_is_accepted(tier):
    """Pins the vocabulary itself, so removing a tier from TIERS without
    deciding to breaks a test rather than a user's file."""
    assert load_business_context([_entry(tier=tier)]).entries[0]["tier"] == tier


def test_a_bare_host_address_is_accepted_as_a_subnet():
    """A single important server is the likeliest first entry anyone writes."""
    context = load_business_context([{"subnet": "10.20.0.5", "tier": "critical"}])

    assert context.entries[0]["subnet"] == "10.20.0.5/32"


def test_a_device_name_is_stripped_of_surrounding_whitespace():
    assert load_business_context(
        [{"device": "  rtr-us5  ", "tier": "standard"}]
    ).entries[0]["device"] == "rtr-us5"


# ---------------------------------------------------------------------------
# The file loader
# ---------------------------------------------------------------------------


def test_a_missing_file_is_refused_by_name(tmp_path):
    missing = tmp_path / "nope.json"

    with pytest.raises(BusinessContextError) as raised:
        load_business_context_file(missing)

    assert "nope.json" in str(raised.value)


def test_malformed_json_names_the_line_and_column(tmp_path):
    path = tmp_path / "business-context.json"
    path.write_text('[{"device": "rtr-us5",}]', encoding="utf-8")

    with pytest.raises(BusinessContextError) as raised:
        load_business_context_file(path)

    message = str(raised.value)
    assert "not valid JSON" in message
    assert "line" in message and "column" in message


def test_a_real_file_round_trips(tmp_path):
    path = tmp_path / "business-context.json"
    path.write_text(
        json.dumps(
            [
                {"device": "rtr-us5", "tier": "critical", "description": "Edge"},
                {"subnet": "10.10.10.0/24", "tier": "important"},
            ]
        ),
        encoding="utf-8",
    )

    context = load_business_context_file(path)

    assert len(context) == 2
    assert context.entries[0]["device"] == "rtr-us5"


def test_context_is_constructible_directly_for_callers_that_need_a_stub():
    """`Policy` allows this and the risk tests will need the same thing."""
    assert BusinessContext().is_empty
    assert not BusinessContext([{"device": "rtr-us5", "tier": "critical"}]).is_empty
