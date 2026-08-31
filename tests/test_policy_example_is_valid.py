"""Netwise -- the shipped example policy must actually be a valid policy (#195).

WHY THIS FILE EXISTS
    We shipped a validated format, an endpoint that accepts it, and a file
    picker that asks for it -- and nothing a user could copy. The only
    complete example anywhere was VALID_POLICY inside a test file, which #181
    then made invalid by requiring `queries` and `violation_summary`.

    So the first thing anyone tried would have been rejected by a validator
    that was right to reject it. That no user hit this is luck rather than
    design: there was nothing to copy, so nobody copied the wrong thing.

    #181 established the principle this file enforces:

        if our example policy is not a valid policy, the format is not one a
        user can copy from the thing we ship as the example

    An example that is not tested is a stale document waiting to happen --
    which is the failure family this project keeps finding, and #195's own
    finding 2 was exactly that in README.md.

WHY IT DOES NOT NEED BATFISH
    Loading and validating a policy is pure Python. Whether the rules FIND
    anything is a question about a config, and that belongs to the fixtures.
    This file asks only whether the document we hand a user is one the
    product accepts.

RUN
    pytest tests/ -v
"""

import json
from pathlib import Path

import pytest

from analysis import policy

EXAMPLE = Path(__file__).parent.parent / "docs" / "examples" / "policy.example.json"


def test_the_example_exists_where_the_docs_say_it_does():
    """A referenced file that is not there is worse than no reference."""
    assert EXAMPLE.is_file(), f"{EXAMPLE} is missing; README and the format doc point at it"


def test_the_example_loads_through_the_real_loader():
    """THE #195 REGRESSION.

    Not `json.load` -- `load_policy_file`, the function the product uses. A
    file that is valid JSON and an invalid policy is exactly the failure this
    exists to prevent.
    """
    loaded = policy.load_policy_file(EXAMPLE)
    entries = loaded.entries_for("policy_compliance")

    assert entries, "the example must contain at least one rule a check can run"


def test_every_entry_carries_every_key_the_check_dereferences():
    """The keys are not decoration -- `queries` becomes the Batfish question.

    Asserted against `_SECTION_REQUIRED` rather than a list typed here, so a
    key added to the schema fails this on the day it is added rather than
    whenever somebody next reads the example.
    """
    loaded = policy.load_policy_file(EXAMPLE)
    required = set(policy._REQUIRED_KEYS) | policy._SECTION_REQUIRED["policy_compliance"]

    for entry in loaded.entries_for("policy_compliance"):
        missing = required - set(entry)
        assert not missing, (
            f"rule {entry.get('number')} is missing {sorted(missing)} -- "
            "a user copying this would get a file the loader rejects"
        )


def test_it_shows_both_rule_kinds():
    """A user needs to see both, because the DIRECTION decides the question.

    An example containing only prohibitions teaches half the format, and the
    half it omits is the one where getting it backwards inverts the result
    (docs/policy-rules.md section 2).
    """
    kinds = {e["kind"] for e in policy.load_policy_file(EXAMPLE).entries_for("policy_compliance")}
    assert kinds == {"prohibition", "requirement"}, f"only shows {sorted(kinds)}"


def test_it_shows_a_multi_arm_rule():
    """"Everything except X" is written as separate queries, never invertSearch.

    That is the single most surprising thing about the format -- `invertSearch`
    looks like the natural way and produces false alarms on a CLEAN config
    (docs/policy-rules.md). An example that never shows a second arm leaves a
    user to discover the wrong way first.
    """
    entries = policy.load_policy_file(EXAMPLE).entries_for("policy_compliance")
    assert any(len(e["queries"]) > 1 for e in entries), (
        "no rule demonstrates the multi-arm shape"
    )


def test_changing_only_the_device_name_still_loads():
    """The claim the docs make about this file, tested rather than asserted.

    "Download it, change the device name, and it loads" is the whole promise.
    If a rename breaks it, the example is a demo rather than a starting point.
    """
    data = json.loads(EXAMPLE.read_text())
    data["device"] = "rtr-somebody-elses-router"

    loaded = policy.load_policy(data)

    assert loaded.entries_for("policy_compliance")
    for entry in loaded.entries_for("policy_compliance"):
        assert entry["node"] == "rtr-somebody-elses-router", (
            "the top-level device must reach every entry, or a rename is not one edit"
        )


@pytest.mark.parametrize("key", ["queries", "violation_summary", "kind"])
def test_removing_a_required_key_is_caught_by_the_loader(key):
    """Proves the loader is what is validating, not this test file.

    Without this, every assertion above could pass against a loader that
    accepts anything.
    """
    data = json.loads(EXAMPLE.read_text())
    del data["policy_compliance"][0][key]

    with pytest.raises(policy.PolicyError) as exc:
        policy.load_policy(data)

    assert key in str(exc.value), f"the error should name {key}: {exc.value}"
