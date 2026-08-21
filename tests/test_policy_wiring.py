"""The policy loader reaching a check (#87, the vertical slice).

WHY THIS FILE EXISTS
    `analysis/policy.py` was written, validated, tested and merged in #173 --
    and read by nothing. Measured before this change: no module under
    `analysis/checks/`, `analysis/pipeline.py`, `web/` or `ai/` imported it.
    A loader nobody calls closes no gap.

    #87's gap, measured with `tools/stranger_config.py`: rename every device
    in a fixture and the same config goes from 12 found to 3, because our
    policy names our devices.

    Measured again after this change, on a real run against real Batfish --
    `rtr-us5-insecure` with every `rtr-us5` renamed to `rtr-acme-edge`:

        with OUR policy    found=0  none=0  error=1
        with THEIR policy  found=3  none=0  error=0

    That is the gap moving, on a network that is not ours.

THE THREE STATES, WHICH ARE NOT TWO
    no policy supplied      -> our built-in rules, LABELLED as ours
    policy with entries     -> the user's rules
    policy with NO entries  -> the user's (empty) policy, NOT ours

    The third is the one worth getting right, and it has its own tests below.
    An empty policy is a valid, deliberate state (D4) meaning "I assert
    nothing" -- a different claim from "I did not give you a policy". Falling
    back to our rules there would enforce assertions the user explicitly
    chose not to make, and present them as theirs.

WHY EVERY FINDING CARRIES ITS PROVENANCE
    A finding from the user's policy and one from our built-in example look
    identical on screen. That is #87 in one sentence: the user believes their
    rules are enforced when ours are.

These need neither Batfish nor Ollama.

RUN
    pytest tests/ -v
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from analysis import pipeline, policy
from analysis.checks import policy_compliance


@pytest.fixture(autouse=True)
def _no_policy():
    """No test may inherit another's policy.

    Module-level state again, and the same reasoning as the web caches: a
    policy surviving a test would let one test's rules answer another test's
    check, and the failure would look like a bug in the second test.
    """
    policy.clear_active_policy()
    yield
    policy.clear_active_policy()


def _rule(node: str = "rtr-us5", number: int = 1) -> Dict[str, Any]:
    return {
        "number": number,
        "description": "A rule",
        "kind": "prohibition",
        "node": node,
        "filter": "acl_in",
        "violation_severity": "high",
        "violation_summary": "Something forbidden is allowed",
        "queries": [{"srcIps": "10.0.0.0/8"}],
    }


# --- The vocabulary had to agree before anything could be wired ---------------


def test_the_builtin_rules_use_the_loader_vocabulary():
    """The blocker that had to be cleared first.

    Measured before the fix: a built-in rule and a loaded entry differed in
    exactly one key -- `severity` against `violation_severity` -- so handing
    a loaded policy to the check raised KeyError. @shubhamkataria2005
    flagged it on #173. This asserts the two vocabularies now match, using
    the loader's OWN key sets rather than a copy of them.
    """
    allowed = policy._COMMON_KEYS | policy._SECTION_KEYS["policy_compliance"]
    for rule in policy_compliance.POLICY_RULES:
        extra = set(rule) - allowed
        assert not extra, (
            f"built-in rule {rule['number']} has key(s) the loader would "
            f"reject: {sorted(extra)}"
        )


def test_the_builtin_rules_round_trip_through_the_loader():
    """Stronger than the key check: our own policy must be a VALID policy.

    If our example rules cannot be loaded by our own loader, the format is
    not one a user could copy from the thing we ship as the example.
    """
    loaded = policy.load_policy(
        {"policy_compliance": policy_compliance.POLICY_RULES})
    entries = loaded.entries_for("policy_compliance")

    assert len(entries) == len(policy_compliance.POLICY_RULES)
    assert not loaded.renamed, (
        f"our own rules trip the legacy-name path: {loaded.renamed}"
    )
    for original, entry in zip(policy_compliance.POLICY_RULES, entries):
        assert entry["node"] == original["node"]
        assert entry["violation_severity"] == original["violation_severity"]


# --- The three states ---------------------------------------------------------


def test_with_no_policy_the_builtin_rules_are_used_and_labelled():
    rules, label, user_supplied = policy_compliance.rules_in_use()

    assert rules is policy_compliance.POLICY_RULES
    assert user_supplied is False
    assert label == policy_compliance.BUILTIN_POLICY_LABEL
    assert "no policy file was supplied" in label


def test_with_a_policy_the_users_rules_are_used_and_labelled():
    policy.set_active_policy(
        policy.load_policy({"policy_compliance": [_rule(node="rtr-acme")]}))

    rules, label, user_supplied = policy_compliance.rules_in_use()

    assert user_supplied is True
    assert [r["node"] for r in rules] == ["rtr-acme"]
    assert label == policy_compliance.USER_POLICY_LABEL


def test_an_empty_policy_does_not_fall_back_to_our_rules():
    """THE ONE THAT MATTERS.

    "I assert nothing" and "I gave you no policy" are different claims.
    Falling back here would enforce assertions the user explicitly chose not
    to make, and the finding would say they were theirs.
    """
    policy.set_active_policy(policy.load_policy({"policy_compliance": []}))

    rules, label, user_supplied = policy_compliance.rules_in_use()

    assert rules == [], "an empty policy fell back to Netwise's own rules"
    assert user_supplied is True
    assert label == policy_compliance.USER_POLICY_LABEL


def test_an_empty_policy_reports_none_not_nothing(monkeypatch):
    """D4, and @shubhamkataria2005's addition to it on #159.

    A check returning [] is reported by the pipeline as `PC-000 status=error
    "the policy compliance check returned no findings"` -- the wrong status
    and the wrong message for a check that ran fine and had nothing to
    assert. Verified against the real pipeline helper rather than asserted.
    """
    policy.set_active_policy(policy.load_policy({"policy_compliance": []}))

    results = policy_compliance.run(bf=None)

    assert len(results) == 1
    assert results[0]["status"] == "none", (
        "an empty policy must report 'checked nothing', never an error and "
        "never silence"
    )
    assert "no policy_compliance entries" in results[0]["evidence"]["detail"]

    # And the pipeline must not then re-report it as a broken check.
    from analysis.pipeline import duplicate_id_findings
    assert duplicate_id_findings(results) == []


# --- The rules actually reach the check ---------------------------------------


def test_the_users_rules_are_the_ones_queried(monkeypatch):
    """Not just 'selected' -- actually asked of Batfish.

    A wiring that chose the right rules and then queried the built-in ones
    would pass every test above while changing nothing.
    """
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-acme"})

    asked: List[str] = []

    def fake_search(bf, node, filter_name, action, headers):
        asked.append(node)
        return []

    monkeypatch.setattr(policy_compliance, "_search", fake_search)
    policy.set_active_policy(
        policy.load_policy({"policy_compliance": [_rule(node="rtr-acme")]}))

    policy_compliance.run(bf=None)

    assert asked == ["rtr-acme"], (
        f"the check queried {asked}, not the device the user's policy names"
    )


def test_without_a_policy_our_own_device_is_queried(monkeypatch):
    """The other direction, so the test above cannot pass by accident."""
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    asked: List[str] = []
    monkeypatch.setattr(
        policy_compliance, "_search",
        lambda bf, node, f, a, h: (asked.append(node), [])[1])

    policy_compliance.run(bf=None)

    assert set(asked) == {"rtr-us5"}


# --- Provenance ---------------------------------------------------------------


@pytest.mark.parametrize("supplied", [False, True])
def test_every_finding_says_which_policy_it_came_from(monkeypatch, supplied):
    """Both directions, parametrised, because "the user's findings are
    labelled" is only half the guarantee -- ours must be labelled too, or a
    reader cannot tell an unlabelled card apart from a user-supplied one."""
    node = "rtr-acme" if supplied else "rtr-us5"
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {node})
    monkeypatch.setattr(
        policy_compliance, "_search",
        lambda bf, n, f, a, h: [{"Flow": "a flow", "Line_Content": "permit ip any any"}])

    if supplied:
        policy.set_active_policy(
            policy.load_policy({"policy_compliance": [_rule(node=node)]}))

    results = policy_compliance.run(bf=None)

    assert results, "nothing was produced"
    for finding in results:
        assert "Rules checked:" in finding["evidence"]["detail"], (
            f"{finding['id']} does not say whose policy produced it"
        )
    expected = ("the policy file you supplied" if supplied
                else "built-in example policy")
    assert expected in results[0]["evidence"]["detail"]


def test_the_provenance_does_not_break_the_145_inversion_guard(monkeypatch):
    """#145's deterministic fix reads `evidence.detail` with a narrow regex.

    Appending the provenance must leave that match intact -- otherwise the
    AI layer silently loses the guard that stops it inverting which side of
    a policy finding does what. Tested against the real function, not a
    copy of its pattern.
    """
    import ai.explain as explain

    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    monkeypatch.setattr(
        policy_compliance, "_search",
        lambda bf, n, f, a, h: [{"Flow": "10.10.10.1 -> 8.8.8.8",
                                 "Line_Content": "permit ip any any"}])

    results = policy_compliance.run(bf=None)
    found = [f for f in results if f["status"] == "found"]
    assert found, "no violation was produced"

    for finding in found:
        computed = explain._compute_policy_outcome(finding["evidence"]["detail"])
        assert computed is not None, (
            "the provenance suffix broke #145's policy-inversion guard: "
            f"{finding['evidence']['detail']!r}"
        )


# --- set_active_policy refuses unvalidated input ------------------------------


def test_a_raw_dict_is_refused():
    """The loader exists to validate. Accepting a bare mapping would route
    unvalidated user input straight to a check, which is the failure the
    whole module was written to prevent."""
    with pytest.raises(TypeError) as caught:
        policy.set_active_policy({"policy_compliance": []})

    assert "load_policy" in str(caught.value)
    assert policy.active_policy() is None


def test_none_clears_it():
    policy.set_active_policy(policy.load_policy({"policy_compliance": []}))
    assert policy.active_policy() is not None
    policy.set_active_policy(None)
    assert policy.active_policy() is None


# --- analyse() installs and always clears -------------------------------------


def test_analyse_installs_the_policy_for_the_duration(monkeypatch):
    seen = {}

    def fake_analyse(*a, **k):
        seen["active"] = policy.active_policy()
        return []

    monkeypatch.setattr(pipeline, "_analyse", fake_analyse)
    loaded = policy.load_policy({"policy_compliance": [_rule()]})

    pipeline.analyse("anywhere", policy=loaded)

    assert seen["active"] is loaded


def test_analyse_clears_the_policy_afterwards(monkeypatch):
    monkeypatch.setattr(pipeline, "_analyse", lambda *a, **k: [])
    pipeline.analyse("anywhere",
                     policy=policy.load_policy({"policy_compliance": [_rule()]}))

    assert policy.active_policy() is None, (
        "a policy outlived its analyse() call and would apply to the next "
        "config analysed in this process"
    )


def test_the_policy_is_cleared_even_when_a_check_raises(monkeypatch):
    """try/finally, and it matters: analyse() is called repeatedly in one
    process, so a leaked policy would silently assert one user's rules
    against another user's config."""
    def explodes(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(pipeline, "_analyse", explodes)

    with pytest.raises(RuntimeError):
        pipeline.analyse(
            "anywhere",
            policy=policy.load_policy({"policy_compliance": [_rule()]}))

    assert policy.active_policy() is None


def test_analyse_refuses_a_raw_dict():
    with pytest.raises(TypeError) as caught:
        pipeline.analyse("anywhere", policy={"policy_compliance": []})
    assert "load_policy" in str(caught.value)


def test_analyse_without_a_policy_leaves_none_active(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        pipeline, "_analyse",
        lambda *a, **k: (seen.update(active=policy.active_policy()), [])[1])

    pipeline.analyse("anywhere")

    assert seen["active"] is None, (
        "no policy was supplied, so the check must see None and use our "
        "built-in rules -- labelled as ours"
    )
