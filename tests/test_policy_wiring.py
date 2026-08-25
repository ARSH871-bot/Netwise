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

import json
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


# --- A user's first policy file fails at the LOADER, not inside the check -----
#
# @patelankeet2 wrote one by hand on #181 -- the exact thing `--policy` exists
# for -- and got `KeyError: 'number'` from inside the check, four calls after
# load_policy() had accepted it clean. D5 promised the opposite: "validate by
# hand, failing loudly, naming the offending entry".
#
# Measured after his report, the gap was wider AND worse than one key:
#
#     missing key          no violation found   violation found
#     filter               KeyError             KeyError
#     kind                 KeyError             KeyError
#     queries              KeyError             KeyError
#     number               none                 KeyError   <--
#     violation_severity   none                 KeyError   <--
#     violation_summary    none                 KeyError   <--
#
# The last three are the dangerous class: a policy missing any of them reports
# "checked, all clear" on every run and fails the first day it catches
# something real. A green tick that becomes an error exactly when there is a
# problem to report is F-4's worst shape, reached through the input.


def _complete(**overrides) -> Dict[str, Any]:
    entry = {
        "description": "DNS to the approved resolver must be allowed",
        "node": "rtr-us5",
        "kind": "requirement",
        "filter": "acl_in",
        "violation_severity": "medium",
        "violation_summary": "DNS lookups are blocked",
        "queries": [{"dstIps": "218.8.104.58"}],
    }
    entry.update(overrides)
    return entry


@pytest.mark.parametrize(
    "key",
    sorted(policy._SECTION_REQUIRED["policy_compliance"]),
)
def test_a_missing_key_the_check_dereferences_is_refused_by_the_loader(key):
    """Parametrised over the declared set, not a list I typed twice.

    So a key added to `_SECTION_REQUIRED` is covered the day it is added,
    and one removed stops being asserted -- rather than the two lists
    drifting, which is the defect this whole project keeps finding.
    """
    entry = {k: v for k, v in _complete().items() if k != key}

    with pytest.raises(policy.PolicyError) as caught:
        policy.load_policy({"policy_compliance": [entry]})

    message = str(caught.value)
    assert key in message, f"the error does not name the missing key {key!r}"
    assert "DNS to the approved resolver" in message, (
        "the error does not name the entry, which is what D5 promised"
    )


def test_every_missing_key_is_reported_at_once():
    """A user fixing their first policy file should learn everything wrong
    with an entry in one go, not discover a second missing field after
    correcting the first."""
    with pytest.raises(policy.PolicyError) as caught:
        policy.load_policy(
            {"policy_compliance": [{"description": "d", "node": "rtr-us5"}]})

    message = str(caught.value)
    for key in policy._SECTION_REQUIRED["policy_compliance"]:
        assert key in message, f"{key!r} missing from a one-shot error"


def test_the_declared_required_keys_match_what_the_check_dereferences():
    """The drift guard for `_SECTION_REQUIRED`.

    It cannot be derived at import time -- `analysis.policy` importing
    `analysis.checks` would be a cycle -- so it is declared by hand and
    checked here against the check's real source. Without this, the list
    and the code are one fact in two places.

    `number` is excluded because the loader ASSIGNS it rather than
    requiring it; see _assign_missing_numbers().
    """
    import re
    from pathlib import Path

    source = (Path(policy_compliance.__file__)).read_text(encoding="utf-8")
    dereferenced = set(re.findall(r'rule\["(\w+)"\]', source))

    declared = set(policy._SECTION_REQUIRED["policy_compliance"])
    universal = set(policy._REQUIRED_KEYS)
    assigned = {"number"}

    should_be_declared = dereferenced - universal - assigned
    assert declared == should_be_declared, (
        f"_SECTION_REQUIRED['policy_compliance'] is {sorted(declared)} but "
        f"the check dereferences {sorted(should_be_declared)}. A key the "
        f"check reads and the loader does not require becomes a KeyError "
        f"inside the check instead of a named policy error."
    )


def test_a_complete_entry_loads_and_runs(monkeypatch):
    """The other direction, so the tests above cannot pass by refusing
    everything."""
    monkeypatch.setattr(policy_compliance.snapshot, "device_names",
                        lambda bf: {"rtr-us5"})
    monkeypatch.setattr(
        policy_compliance, "_search",
        lambda *a, **k: [{"Flow": "f", "Line_Content": "deny ip any any"}])

    policy.set_active_policy(
        policy.load_policy({"policy_compliance": [_complete()]}))
    results = policy_compliance.run(bf=None)

    assert any(f["status"] == "found" for f in results)


# --- `number` is assigned, not demanded, and never silently ------------------


def test_number_is_assigned_when_absent():
    """It is OUR id-numbering concern, not the user's. docs/policy-rules.md
    only ever discusses it as our built-in rules' internal numbering."""
    loaded = policy.load_policy(
        {"policy_compliance": [_complete(description="one"),
                               _complete(description="two")]})
    entries = loaded.entries_for("policy_compliance")

    assert [e["number"] for e in entries] == [1, 2]


def test_an_assigned_number_is_reported_not_silent():
    """This module's docstring forbids SILENT defaults, not defaults."""
    loaded = policy.load_policy({"policy_compliance": [_complete()]})

    assert loaded.assigned, "a number was invented and nothing said so"
    assert "number" in loaded.assigned[0]
    assert "file order" in loaded.assigned[0]


def test_an_explicit_number_is_never_overwritten():
    loaded = policy.load_policy(
        {"policy_compliance": [_complete(number=7)]})

    assert loaded.entries_for("policy_compliance")[0]["number"] == 7
    assert not loaded.assigned, "nothing was assigned, so nothing to report"


def test_mixing_explicit_and_absent_numbers_is_refused():
    """The case that would silently collide: an explicit 2 and a positional
    2 are the same finding id, and `duplicate_id_findings()` would report a
    broken contract the user's file caused and our numbering hid."""
    with pytest.raises(policy.PolicyError) as caught:
        policy.load_policy(
            {"policy_compliance": [_complete(description="a", number=2),
                                   _complete(description="b")]})

    assert "same finding id" in str(caught.value)


def test_assigned_numbers_are_stable_across_loads():
    """A finding id is only comparable between runs if it is deterministic."""
    data = {"policy_compliance": [_complete(description="a"),
                                  _complete(description="b"),
                                  _complete(description="c")]}
    first = policy.load_policy(json.loads(json.dumps(data)))
    second = policy.load_policy(json.loads(json.dumps(data)))

    assert ([e["number"] for e in first.entries_for("policy_compliance")]
            == [e["number"] for e in second.entries_for("policy_compliance")])


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


# ---------------------------------------------------------------------------
# Concurrency -- @SamikaPerera's finding on #182
# ---------------------------------------------------------------------------


def _one_entry_policy(tag: str):
    """A policy identifiable by the summary its single entry carries."""
    return policy.load_policy({
        "device": tag,
        "policy_compliance": [{
            "description": "d", "kind": "must_deny", "filter": "acl_in",
            "node": tag, "queries": [{"dstIps": "10.0.0.1"}],
            "violation_severity": "high", "violation_summary": tag,
        }],
    })


def _tag_of(pol):
    if pol is None:
        return None
    entries = pol.entries_for("policy_compliance")
    return entries[0]["violation_summary"] if entries else "<empty>"


def test_two_concurrent_analyses_do_not_read_each_others_policy(monkeypatch):
    """Each request's checks must read the policy THAT request installed.

    WHY THIS IS A REAL CASE AND NOT A THEORETICAL ONE
        `/api/findings` is a SYNC FastAPI endpoint, so it runs in the
        threadpool and two overlapping requests genuinely execute in
        parallel. One browser with two tabs, or a double-clicked Scan Now,
        is enough. Each calls `analyse()`, which installs a policy and
        clears it in a `finally`.

        @SamikaPerera raised this on #182 and framed it as worth a sentence
        in a docstring. Measured against the real code, it was worse:

            router-A installed its own policy, its check saw 'router-B'
            router-B installed its own policy, its check saw None

            2 of 2 concurrent analyses read the WRONG policy

        Both wrong, in the two worst available ways -- one check asserting a
        DIFFERENT user's rules, the other silently falling back to our
        built-in examples, which is #87's exact confusion arriving through
        the mechanism built to fix it.

        The fix is `threading.local()` in `analysis/policy.py`. Reverting it
        to a plain module-level global makes this test fail.
    """
    import threading
    import time

    seen: Dict[str, Any] = {}

    def slow_analyse(*_args, **_kwargs):
        # Stand in for a check reading the policy partway through a run,
        # which is what makes the overlap observable at all.
        time.sleep(0.30)
        seen[threading.current_thread().name] = _tag_of(policy.active_policy())
        return []

    monkeypatch.setattr(pipeline, "_analyse", slow_analyse)

    def run(pol):
        pipeline.analyse("anywhere", policy=pol)

    threads = [
        threading.Thread(target=run, args=(_one_entry_policy(tag),), name=tag)
        for tag in ("router-A", "router-B")
    ]
    threads[0].start()
    time.sleep(0.05)          # guarantee the two runs actually overlap
    threads[1].start()
    for thread in threads:
        thread.join()

    assert seen == {"router-A": "router-A", "router-B": "router-B"}, (
        f"a concurrent analysis read another request's policy: {seen}. A "
        f"check asserting the wrong user's rules, or silently falling back "
        f"to ours, is exactly what #87 exists to prevent"
    )
