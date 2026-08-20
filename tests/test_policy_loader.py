"""Tests for the user-supplied policy loader (#87).

FAILURE PATHS FIRST, AND THAT IS THE POINT
    `docs/design/user-policy-format.md` is explicit: "A policy that
    half-loads is worse than one that will not load, for the same reason a
    check that half-runs is." So the cases that must REFUSE are written
    first and tested hardest; the happy path is the easy half.

    Two of these encode additions the team made when answering #159, not
    the original five decisions:

      - an empty policy is VALID (D4) -- the caller has to be loud about it
      - an UNKNOWN KEY is an ERROR, never ignored, and the message names the
        entry rather than only the field

    The second is F-4 arriving through the input side: silently dropping a
    key the user actually set is how someone believes a rule is enforced
    when nothing reads it.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import json

import pytest

from analysis.policy import POLICY_SECTIONS, Policy, PolicyError, load_policy, load_policy_file


def _entry(**overrides):
    base = {
        "description": "DNS lookups to the approved server must be allowed",
        "node": "acme-edge-fw",
        "filter": "acl_in",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# The refusals
# ---------------------------------------------------------------------------


def test_an_unknown_key_is_an_error_and_names_the_entry():
    """The addition @shubhamkataria2005 and @SamikaPerera both asked for.

    Ignoring an unrecognised key is how a user ends up believing a rule is
    enforced when nothing reads it. The message has to name the entry,
    because "unknown key" alone is a scavenger hunt through ten entries.
    """
    with pytest.raises(PolicyError) as raised:
        load_policy({"access_control": [_entry(protocol="tcp")]})

    message = str(raised.value)
    assert "unknown key" in message
    assert "'protocol'" in message
    assert "access_control entry 1" in message
    assert "DNS lookups" in message, "the message must quote the description"


def test_a_legacy_key_is_corrected_and_reported_rather_than_silently_accepted():
    """`start_node` was routing's key until #159 renamed it to `node`.

    Accepting it silently would defeat D1 -- the user would keep writing the
    old name and never learn the vocabulary is now one. Rejecting it
    outright would punish someone who copied from our own check. So it is
    corrected AND reported.
    """
    policy = load_policy({"routing": [{"description": "hq reaches branch", "start_node": "rtr-hq"}]})

    entry = policy.entries_for("routing")[0]
    assert entry["node"] == "rtr-hq"
    assert "start_node" not in entry
    assert policy.renamed, "a corrected key must be reported, not silent"
    assert "start_node" in policy.renamed[0]


def test_no_did_you_mean_is_offered_for_a_key_we_do_not_actually_know():
    """A wrong did-you-mean is worse than none: it sends the reader to
    change the wrong thing. Suggestions come from the rename table only,
    with no fuzzy matching -- so a typo gets a plain refusal.

    Written the other way round first, asserting that `severity` under
    `access_control` would be REFUSED with a suggestion. That was wrong
    about our own code: `severity` is in the rename table, so it is
    corrected rather than refused, and the test was encoding a behaviour
    the module deliberately does not have. Corrected here rather than
    changing the module to match a mistaken test -- see the test below for
    what `severity` actually does.
    """
    with pytest.raises(PolicyError) as raised:
        load_policy({"access_control": [_entry(sevrity="high")]})
    message = str(raised.value)
    assert "unknown key" in message
    assert "did you mean" not in message, "no guessing at typos"


def test_a_legacy_key_from_another_section_is_still_corrected():
    """`severity` was `policy_compliance`'s name for what the other two
    called `violation_severity`. A user writing it under `access_control`
    is copying our own old vocabulary, so the rename table applies
    everywhere rather than per section -- one vocabulary is the whole point
    of D1."""
    policy = load_policy({"access_control": [_entry(severity="high")]})
    entry = policy.entries_for("access_control")[0]
    assert entry["violation_severity"] == "high"
    assert "severity" not in entry
    assert any("severity" in note for note in policy.renamed)


def test_a_missing_required_key_names_the_entry_and_the_key():
    with pytest.raises(PolicyError) as raised:
        load_policy({"access_control": [{"description": "no device named"}]})
    message = str(raised.value)
    assert "missing required key" in message
    assert "node" in message
    assert "device:" in message, "point at the top-level default that would fix it"


def test_an_unknown_section_is_refused():
    """`risk` and `change_impact` are not policy-driven, so naming one is a
    misunderstanding worth catching rather than ignoring."""
    with pytest.raises(PolicyError) as raised:
        load_policy({"risk": []})
    assert "unknown section" in str(raised.value)
    assert "risk" in str(raised.value)


@pytest.mark.parametrize("bad", ["a string", 42, ["a", "list"]])
def test_a_policy_that_is_not_a_mapping_is_refused(bad):
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_a_section_that_is_not_a_list_is_refused():
    with pytest.raises(PolicyError) as raised:
        load_policy({"routing": {"description": "not in a list"}})
    assert "must be a list" in str(raised.value)


def test_an_entry_that_is_not_a_mapping_is_refused_by_position():
    with pytest.raises(PolicyError) as raised:
        load_policy({"routing": ["just a string"]})
    assert "routing entry 1" in str(raised.value)


def test_a_non_string_top_level_device_is_refused():
    with pytest.raises(PolicyError):
        load_policy({"device": ["not", "a", "name"], "access_control": []})


# ---------------------------------------------------------------------------
# D4 -- an empty policy is valid, and the caller must be loud
# ---------------------------------------------------------------------------


def test_an_empty_policy_is_valid_not_an_error():
    """D4, agreed 3 of 3 on #159. It is the honest description of what
    Netwise does for a stranger today: run the two policy-free analyses and
    say clearly that everything else was not checked."""
    policy = load_policy({})
    assert policy.is_empty
    assert policy.entries_for("access_control") == []


def test_every_policy_driven_section_is_present_even_when_empty():
    """A caller must be able to tell "the user supplied nothing for this
    check" from "this check is not policy-driven". Absence cannot express
    the difference; an empty list can."""
    policy = load_policy({})
    assert set(policy.sections) == set(POLICY_SECTIONS)


def test_a_policy_with_entries_is_not_empty():
    policy = load_policy({"access_control": [_entry()]})
    assert not policy.is_empty


def test_an_empty_file_is_an_empty_policy_not_a_parse_error(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("   \n", encoding="utf-8")
    assert load_policy_file(path).is_empty


# ---------------------------------------------------------------------------
# D2 -- per entry, with an optional top-level default
# ---------------------------------------------------------------------------


def test_the_top_level_device_supplies_node_for_entries_that_omit_it():
    policy = load_policy(
        {"device": "acme-edge-fw", "access_control": [{"description": "d", "filter": "acl_in"}]}
    )
    assert policy.entries_for("access_control")[0]["node"] == "acme-edge-fw"


def test_a_per_entry_node_overrides_the_top_level_default():
    """D2 exists because `routing` already spans two devices. A default that
    could not be overridden would not express what we have today."""
    policy = load_policy(
        {
            "device": "acme-edge-fw",
            "routing": [
                {"description": "hq to branch", "node": "rtr-hq"},
                {"description": "branch to hq", "node": "rtr-branch"},
            ],
        }
    )
    nodes = [e["node"] for e in policy.entries_for("routing")]
    assert nodes == ["rtr-hq", "rtr-branch"]


# ---------------------------------------------------------------------------
# Nothing half-loads
# ---------------------------------------------------------------------------


def test_one_bad_entry_refuses_the_whole_policy():
    """"A policy that half-loads is worse than one that will not load."

    If entry 2 is wrong, entry 1 must not be quietly applied -- the user
    would be running a policy they did not write.
    """
    with pytest.raises(PolicyError):
        load_policy({"access_control": [_entry(), _entry(bogus=1)]})


def test_the_error_names_the_second_entry_not_the_first():
    with pytest.raises(PolicyError) as raised:
        load_policy({"access_control": [_entry(), _entry(bogus=1)]})
    assert "entry 2" in str(raised.value)


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------


def test_a_missing_file_is_refused_by_name(tmp_path):
    with pytest.raises(PolicyError) as raised:
        load_policy_file(tmp_path / "nope.json")
    assert "no policy file" in str(raised.value)


def test_malformed_json_names_the_line_and_column(tmp_path):
    """A parse error that says only "invalid" makes the user hunt. The
    standard library already knows where it failed; pass that on."""
    path = tmp_path / "policy.json"
    path.write_text('{"access_control": [', encoding="utf-8")
    with pytest.raises(PolicyError) as raised:
        load_policy_file(path)
    message = str(raised.value)
    assert "not valid JSON" in message
    assert "line" in message and "column" in message


def test_a_real_file_round_trips(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps({"device": "acme-edge-fw", "access_control": [{"description": "d", "filter": "acl_in"}]}),
        encoding="utf-8",
    )
    policy = load_policy_file(path)
    assert policy.entries_for("access_control")[0]["node"] == "acme-edge-fw"
    assert not policy.is_empty


def test_policy_is_constructible_directly_for_callers_that_need_a_stub():
    assert Policy({s: [] for s in POLICY_SECTIONS}).is_empty
