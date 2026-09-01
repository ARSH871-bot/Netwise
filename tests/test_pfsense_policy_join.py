"""A converted PF Sense export must be analysable against the USER's policy.

WHY THIS FILE EXISTS (#216)
    #216 is a P0 whose stated criterion is a sentence about the client:

        "a converted PF Sense export analyses and reports three 'could not
        check' findings and ZERO findings, because our policy names
        `rtr-us5` and the converted device is `pfsense-us5`. The client's
        own firewall produces nothing until this lands."

    Both of its dependencies landed -- #181 wired a user policy to a check,
    #261 made the other two checks say when they ignored one. Measured
    afterwards, end to end through the real endpoints against real Batfish:

        PF Sense, no policy of the user's    3 could-not-check, 0 findings
        PF Sense, THEIR policy               2 could-not-check, 1 finding

        PC-001  found  high  The LAN can reach the internal server
                device  pfsense-us5
                detail  Flow start=pfsense-us5 [10.10.10.0:49152->
                        10.20.0.5:443 TCP (SYN)] is permitted but policy
                        requires it to be DENIED.

    That capability is the whole point of #216, and NOTHING IN THE SUITE
    PROTECTED IT. Measured before this file: of the six test modules
    mentioning PF Sense, zero mention a policy; of the policy modules, zero
    mention PF Sense. Both halves were tested and the join between them was
    not, which is the shape this project keeps finding.

WHAT THE JOIN ACTUALLY IS, AND WHY IT USED TO BREAK
    The converter names the device from `<hostname>`, so an export becomes
    `pfsense-us5`. Our built-in rules name `rtr-us5`. Those never meet, which
    is exactly why the client's firewall produced nothing: not because the
    conversion failed -- it succeeds -- but because every rule asked about a
    device that is not in the snapshot.

    So the join is: THE DEVICE NAME THE CONVERTER EMITS MUST BE THE NAME A
    USER'S POLICY CAN ADDRESS. These tests pin both ends of that.

NO BATFISH, NO OLLAMA
    Same technique as tests/test_web_policy_applied.py, and for the same
    reason. `pipeline._analyse` is the only thing that touches Batfish, so it
    is stubbed -- and the REAL `policy_compliance.rules_in_use()` is called
    from inside the stub, at the moment a real check would call it. What is
    asserted is what a check would actually see, not that a call was made.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from analysis import pipeline, policy
from analysis.checks import policy_compliance
from web import main

client = TestClient(main.app)

#: The PF Sense export we ship. Its `<hostname>` is what the converter emits.
PFSENSE_XML = Path(__file__).parent / "fixtures" / "pfsense-source" / "config.xml"

#: The device name the converter produces from that fixture. Asserted rather
#: than assumed by `test_the_converter_emits_the_device_name_a_policy_addresses`
#: -- if the fixture's hostname ever changes, that test fails first and names
#: the reason, instead of these two failing for a reason that reads as unrelated.
CONVERTED_DEVICE = "pfsense-us5"

#: A policy about the CONVERTED device. Deliberately not about `rtr-us5`: the
#: point is that a user can address the device their own firewall became.
THEIR_POLICY = {
    "device": CONVERTED_DEVICE,
    "policy_compliance": [
        {
            "description": "the LAN must not reach the internal server",
            "kind": "prohibition",
            "filter": "acl_in",
            "node": CONVERTED_DEVICE,
            "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "10.20.0.5"}],
            "violation_severity": "high",
            "violation_summary": "The LAN can reach the internal server",
        }
    ],
}


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    """Isolate the staged config and policy, and never leak an active policy.

    An installed policy outliving a test would silently apply to the next --
    the same failure `analyse()` guards against with its `finally`.
    """
    snapshot = tmp_path / "current"
    (snapshot / "configs").mkdir(parents=True)
    # Patch the FUNCTIONS, not the old module constants. Since #242 storage
    # is per session, so `configs_dir()` resolves through a ContextVar --
    # setting a module attribute shadows the compatibility shim and the
    # redirect silently does nothing, which is a fixture that appears to
    # isolate and does not.
    monkeypatch.setattr(main, "snapshot_dir", lambda session_id=None: snapshot)
    monkeypatch.setattr(
        main, "configs_dir", lambda session_id=None: snapshot / "configs"
    )
    monkeypatch.setattr(
        main, "policy_path", lambda session_id=None: snapshot / "policy.json"
    )
    monkeypatch.setattr(main, "_uploaded", False)
    if hasattr(main, "_forget_analysis"):
        main._forget_analysis()
    policy.clear_active_policy()
    yield
    policy.clear_active_policy()


def _upload_pfsense():
    return client.post(
        "/api/upload",
        files={"file": ("config.xml", PFSENSE_XML.read_bytes(), "text/plain")},
    )


def _upload_policy(body):
    return client.post(
        "/api/policy",
        files={"file": ("policy.json", json.dumps(body).encode(),
                        "application/json")},
    )


def _staged_config_text() -> str:
    """Whatever the upload actually left for Batfish to read."""
    files = sorted(main.CONFIGS_DIR.glob("*"))
    assert files, "the upload staged nothing at all"
    return "\n".join(f.read_text(encoding="utf-8") for f in files if f.is_file())


# ---------------------------------------------------------------------------
# The join itself
# ---------------------------------------------------------------------------


def test_the_converter_emits_the_device_name_a_policy_addresses():
    """Uploading a PF Sense export stages a config named for ITS hostname.

    This is the fact the whole join rests on, and it is asserted first so
    that a fixture rename fails here -- with a message about the fixture --
    rather than making the two tests below fail for a reason that looks
    unrelated to their names.
    """
    response = _upload_pfsense()
    assert response.status_code == 200, response.text

    staged = _staged_config_text()
    assert f"hostname {CONVERTED_DEVICE}" in staged, (
        "the converted config does not carry the device name this module's "
        f"policies address. Staged config begins:\n{staged[:200]}"
    )


def test_our_built_in_rules_do_not_name_the_converted_device():
    """The 'before' of #216, pinned so the test below cannot go vacuous.

    Our example rules are about `rtr-us5`. A converted export is
    `pfsense-us5`. Those never meet, which is precisely why the client's
    firewall reported three 'could not check' findings and nothing else.

    If someone ever renames a built-in rule's node to the converted device,
    `test_a_user_policy_about_the_converted_device_reaches_the_check` would
    still pass while proving nothing -- our rules would be doing the work.
    This test is what stops that being silent.
    """
    built_in_nodes = {rule["node"] for rule in policy_compliance.POLICY_RULES}

    assert built_in_nodes, "there are no built-in rules to compare against"
    assert CONVERTED_DEVICE not in built_in_nodes, (
        f"a built-in rule now names {CONVERTED_DEVICE!r}, so a passing "
        "user-policy test would no longer prove the user's rules were used. "
        f"Built-in nodes: {sorted(built_in_nodes)}"
    )


def test_a_user_policy_about_the_converted_device_reaches_the_check():
    """The capability #216 exists to deliver, asserted where a check sees it.

    Not "analyse() was called with a policy" -- that would pass against a
    build where `rules_in_use()` ignored its argument entirely. The real
    function is called from inside the stub, and what it returns is what a
    real check would really get.
    """
    assert _upload_pfsense().status_code == 200
    assert _upload_policy(THEIR_POLICY).status_code == 200

    seen: dict = {}

    def _capture(*args, **kwargs):
        rules, label, from_user = policy_compliance.rules_in_use()
        seen["rules"] = rules
        seen["label"] = label
        seen["from_user"] = from_user
        seen["staged"] = _staged_config_text()
        return []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(pipeline, "_analyse", _capture)
        assert client.get("/api/findings").status_code == 200

    assert seen, "the analysis never ran, so nothing was proved"
    assert seen["from_user"] is True, (
        f"the check fell back to our built-in rules (label {seen['label']!r})"
    )

    nodes = {rule["node"] for rule in seen["rules"]}
    assert nodes == {CONVERTED_DEVICE}, (
        f"the check would assert about {sorted(nodes)}, not the converted "
        f"device {CONVERTED_DEVICE!r}"
    )

    # ...and the device those rules name is genuinely in the snapshot the
    # check is about. Both ends, in one assertion: a policy addressing a
    # device that is not there would be the original bug wearing new names.
    assert f"hostname {CONVERTED_DEVICE}" in seen["staged"], (
        "the user's rules name a device the staged config does not contain"
    )


def test_a_policy_naming_some_other_device_is_still_the_users():
    """The fallback is keyed on `active_policy() is None`, not on matching.

    A user whose rules happen to name nothing in this snapshot must NOT
    silently get ours instead -- they would be shown assertions they never
    made, attributed to them by omission. #261 is what tells them their
    rules went unread; this pins that they were still THEIR rules.
    """
    assert _upload_pfsense().status_code == 200
    elsewhere = json.loads(json.dumps(THEIR_POLICY))
    elsewhere["device"] = "some-other-firewall"
    elsewhere["policy_compliance"][0]["node"] = "some-other-firewall"
    assert _upload_policy(elsewhere).status_code == 200

    seen: dict = {}

    def _capture(*args, **kwargs):
        rules, label, from_user = policy_compliance.rules_in_use()
        seen.update(rules=rules, label=label, from_user=from_user)
        return []

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(pipeline, "_analyse", _capture)
        assert client.get("/api/findings").status_code == 200

    assert seen["from_user"] is True, (
        "a policy that matches nothing fell back to our rules, which would "
        "present our assertions as the user's"
    )
    assert {r["node"] for r in seen["rules"]} == {"some-other-firewall"}
