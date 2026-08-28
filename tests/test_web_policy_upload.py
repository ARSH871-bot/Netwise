"""Netwise -- tests for the policy upload endpoint (#87, POST /api/policy).

WHAT THIS PROTECTS
    A policy file is the user's own security rules. Two things about it are
    safety-critical, and neither is obvious from reading the endpoint:

    1. A REJECTED POLICY MUST NEVER BE STAGED.
       If validation fails and the file lands anyway, the user sees an error
       and still has a broken policy sitting in the staging location. **Since
       #181 landed this is no longer hypothetical** -- the next analysis DOES
       run against whatever is staged, so a rejected file that reached
       POLICY_PATH would silently become the rules in force. The endpoint
       validates into a temp file and copies to POLICY_PATH only after
       `load_policy_file()` returns, and `test_a_rejected_policy_is_never_
       staged` is the guard on that order.

    2. A POLICY MUST NEVER LAND IN configs/.
       Batfish reads every file under `configs/`. A policy there is handed
       to the parser as a device, which either fails and blames the user's
       network or produces a snapshot that analyses cleanly while containing
       a file that is not a config.

WHAT IS DELIBERATELY NOT TESTED HERE
    That an uploaded policy CHANGES THE FINDINGS. It does, since #181 --
    `tests/test_web_policy_applied.py` is where that lives, because it needs
    the pipeline and this file deliberately needs nothing but the endpoint.

    THIS PARAGRAPH USED TO SAY THE POLICY WAS NOT APPLIED AT ALL: "It is not,
    and the endpoint says so." Both halves stopped being true when #181
    landed, and the endpoint's message went on saying it for a day because a
    test below was asserting it. Corrected together, and recorded here because
    a docstring is where a reader checks what a file is FOR -- a stale one
    sends them looking for a behaviour that moved.

    What this file still tests is the UPLOAD path only: accepted, rejected,
    staged, never staged, and what the response says about it.

NO BATFISH, NO OLLAMA, NO NETWORK. The endpoint validates with
`analysis.policy.load_policy_file()`, which is pure standard library.
"""

import json

import pytest
from fastapi.testclient import TestClient

from web import main

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _post_policy(body, filename="policy.json"):
    """POST a policy. `body` may be a dict (encoded) or raw bytes."""
    if isinstance(body, (bytes, bytearray)):
        payload = bytes(body)
    else:
        payload = json.dumps(body).encode("utf-8")
    return client.post(
        "/api/policy",
        files={"file": (filename, payload, "application/json")},
    )


def _post_config(text=b"hostname rtr-us5\n", filename="device.cfg"):
    return client.post(
        "/api/upload",
        files={"file": (filename, text, "text/plain")},
    )


# COMPLETED IN #181, AND THE REASON IS WORTH READING.
#
#     This fixture was named VALID_POLICY and was not a valid policy. It
#     loaded cleanly, and then died the moment anything read it. Measured on
#     `main`, feeding the loaded entry to the check it is written for:
#
#         loader accepted: ['description', 'filter', 'kind', 'node',
#                           'violation_severity']
#         run() RAISED KeyError: 'queries'
#
#     `queries` is the traffic space a rule asserts about -- without it there
#     is nothing to ask Batfish. `violation_summary` is the finding's summary
#     and `number` becomes its id. The check dereferences all three.
#
#     So the upload tests demonstrated an unusable policy as an acceptable
#     one, in the feature whose entire job is accepting a user's policy file.
#     A user copying this shape would have been told "accepted and staged"
#     and then seen the check fail -- or, for the three keys that are only
#     read when a violation is found, seen "all clear" every run until the
#     day it caught something.
#
#     #181 makes the loader require what the check dereferences, which is
#     what turned this fixture red. The fixture is completed rather than the
#     validation relaxed: these tests are about the UPLOAD path, and they
#     test it just as well with a policy that would actually work.
VALID_POLICY = {
    "device": "rtr-us5",
    "policy_compliance": [
        {
            "description": "The internal network must not reach the internet",
            "filter": "acl_in",
            "kind": "prohibition",
            "violation_severity": "high",
            "violation_summary": "The internal network can reach the internet",
            "queries": [
                {
                    "srcIps": "10.10.10.0/24",
                    "dstIps": "0.0.0.0/0 \\ (218.8.104.58, 10.20.0.5)",
                }
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def clean_staging():
    """Leave no staged policy behind, in either direction.

    Module-level paths survive a test, so a policy staged by one test would
    otherwise be visible to the next -- which is exactly the stale-state
    confusion these tests are about.
    """
    main._discard_staged_policy()
    yield
    main._discard_staged_policy()


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_valid_policy_is_accepted_and_staged():
    response = _post_policy(VALID_POLICY)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] is True
    assert body["rule_count"] == 1
    assert body["is_empty"] is False
    assert main.POLICY_PATH.exists()

    # Staged verbatim: the bytes we accepted are the bytes on disk, so what
    # the loader validated and what a later run would read cannot differ.
    assert json.loads(main.POLICY_PATH.read_text(encoding="utf-8")) == VALID_POLICY


def test_the_message_says_staged_and_which_checks_read_it():
    """#82's honest-staging pattern, applied to the policy.

    THIS TEST USED TO ASSERT "not yet applied", AND KEPT PASSING AFTER #181
    MADE THAT FALSE. That is the sharper half of what went wrong: the string
    was not merely stale, it was pinned in place by a test, so the one
    mechanism that should have objected was instead enforcing it.

    Both directions are wrong and the message has to avoid both:

        understating   "not yet applied" while a scan uses the policy
        overstating    "your policy is in force" while two checks ignore it

    So the assertions below name what must be present AND what must not, and
    the negative one is the one that would have caught the original bug.
    """
    body = _post_policy(VALID_POLICY).json()
    message = body["message"].lower()

    assert "staged" in message
    assert "applied" in message
    # The check that actually reads a policy is named, so the user knows the
    # scope rather than inferring it.
    assert "policy compliance" in message
    # ...and the two that do not are named too, with the issue that tracks it.
    assert "access control" in message
    assert "routing" in message
    assert "#87" in body["message"]

    # The regression itself. If someone reintroduces the old sentence, or
    # writes a new one that denies the policy is used, this fails.
    assert "not yet applied" not in message
    assert "not applied" not in message


def test_a_policy_is_never_staged_inside_configs():
    """Batfish reads everything under configs/. A policy there is a device."""
    _post_policy(VALID_POLICY)

    assert main.POLICY_PATH.exists()
    assert main.CONFIGS_DIR not in main.POLICY_PATH.parents
    if main.CONFIGS_DIR.exists():
        staged = [p.name for p in main.CONFIGS_DIR.rglob("*") if p.is_file()]
        assert "policy.json" not in staged


def test_an_empty_policy_is_valid_but_reported_as_asserting_nothing():
    """D4: an empty policy is a real, deliberate state -- not an error.

    "I assert nothing" and "I supplied nothing" are different claims, and
    the response must not flatten them.
    """
    response = _post_policy({"policy_compliance": []})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["is_empty"] is True
    assert body["rule_count"] == 0
    assert "asserts nothing" in body["message"].lower()


def test_a_legacy_key_is_corrected_and_reported():
    """D1: `severity` became `violation_severity` in #159.

    Accepted rather than rejected, because a user copying from our own docs
    would write it -- but REPORTED, because accepting silently is how one
    vocabulary splits back into the dialects D1 removed.
    """
    # `queries` and `violation_summary` completed in #181, same reason as
    # VALID_POLICY above: the loader now requires what the check
    # dereferences. What this test is ABOUT is untouched -- `severity` is
    # still the legacy spelling, and the assertions below still pin that it
    # is corrected AND reported rather than swallowed.
    legacy = {
        "device": "rtr-us5",
        "policy_compliance": [
            {
                "description": "Legacy key spelling",
                "filter": "acl_in",
                "kind": "prohibition",
                "severity": "high",
                "violation_summary": "The internal network can reach the internet",
                "queries": [{"srcIps": "10.10.10.0/24", "dstIps": "0.0.0.0/0"}],
            }
        ],
    }
    body = _post_policy(legacy).json()

    assert body["accepted"] is True
    assert body["renamed"], "a corrected key must be reported, not swallowed"
    assert any("violation_severity" in note for note in body["renamed"])


# ---------------------------------------------------------------------------
# Rejections -- and the safety property underneath them
# ---------------------------------------------------------------------------


def test_an_unknown_key_is_rejected_and_the_entry_is_named():
    """D5, and @shubhamkataria2005's addition to it on #159.

    The endpoint must pass PolicyError's own message through unchanged: it
    names the ENTRY, not just the field, which is the difference between a
    fixable error and a scavenger hunt.

    NOT asserted here: a did-you-mean suggestion. `analysis/policy.py` has
    `_suggest()` for exactly that, and it is currently UNREACHABLE -- it
    fires only when a legacy key's canonical name is allowed in that section,
    which is the same condition the rename branch above it already handles,
    so every input that would earn a suggestion is accepted-and-renamed
    instead. Measured across all three sections and both legacy keys: no
    input produces one. Asserting it here would be a test for behaviour that
    does not exist; raised as #185 against `analysis/policy.py` instead,
    where the fault is.
    """
    typo = {
        "device": "rtr-us5",
        "policy_compliance": [
            {
                "description": "Typo in a key",
                "nodes": "rtr-us5",
                "filter": "acl_in",
                "kind": "prohibition",
            }
        ],
    }
    response = _post_policy(typo)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "nodes" in detail, detail
    # The entry, by its description -- so the user can find it in their file.
    assert "entry 1" in detail, detail
    assert "Typo in a key" in detail, detail
    # And what WOULD have been valid there.
    assert "node" in detail, detail


def test_invalid_json_is_rejected_with_the_position():
    response = _post_policy(b'{"device": "rtr-us5",}')

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "not valid json" in detail.lower(), detail
    assert "line" in detail.lower() and "column" in detail.lower(), detail


def test_a_non_json_extension_is_rejected():
    response = _post_policy(VALID_POLICY, filename="policy.yaml")

    assert response.status_code == 400
    assert ".json" in response.json()["detail"]


def test_an_empty_upload_is_rejected_rather_than_read_as_asserting_nothing():
    """A zero-byte FILE is a mistake; an empty POLICY is a choice.

    `load_policy_file()` treats an empty file as a policy asserting nothing,
    which is right for the CLI. Through an upload it is far more likely to be
    the wrong file, and staging "I assert nothing" on someone's behalf is a
    claim they did not make.
    """
    response = _post_policy(b"")

    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
    assert not main.POLICY_PATH.exists()


@pytest.mark.parametrize(
    "bad_body, why",
    [
        (b'{"device": "rtr-us5",}', "trailing comma, not valid JSON"),
        (b'["not", "a", "mapping"]', "a policy must be a mapping"),
        ({"unknown_section": []}, "unknown top-level section"),
        (
            {"policy_compliance": [{"filter": "acl_in"}]},
            "missing the required description/node",
        ),
    ],
)
def test_a_rejected_policy_is_never_staged(bad_body, why):
    """THE SAFETY PROPERTY. Validation happens BEFORE anything is staged.

    A user who sees an error must not be left with a broken policy staged.
    Every rejection shape is checked, not just one, because the ordering
    bug this guards against would be invisible on whichever case was tested
    and present on the rest.
    """
    assert not main.POLICY_PATH.exists()

    response = _post_policy(bad_body)

    assert response.status_code == 400, f"{why}: expected a rejection"
    assert not main.POLICY_PATH.exists(), (
        f"{why}: the policy was REJECTED but staged anyway -- the next "
        "analysis would run against a file nobody accepted"
    )


def test_a_rejection_leaves_an_earlier_good_policy_alone():
    """A bad upload must not destroy the policy already staged.

    Clearing on a rejection would be a different flavour of the same fault:
    the user is told their new file failed, and silently loses the working
    one they had.
    """
    _post_policy(VALID_POLICY)
    staged_before = main.POLICY_PATH.read_bytes()

    _post_policy(b'{"device": "rtr-us5",}')

    assert main.POLICY_PATH.exists()
    assert main.POLICY_PATH.read_bytes() == staged_before


# ---------------------------------------------------------------------------
# Bidirectional clearing (#82's discipline, both ways)
# ---------------------------------------------------------------------------


def test_uploading_a_config_discards_a_staged_policy():
    """A new network must not be checked against the old network's rules.

    A policy names devices, so one written for the previous upload asserts
    nothing true about this one.
    """
    _post_policy(VALID_POLICY)
    assert main.POLICY_PATH.exists()

    response = _post_config()

    assert response.status_code == 200, response.text
    assert not main.POLICY_PATH.exists()


def test_the_config_upload_reports_that_it_cleared_the_policy():
    """Reported, not silent.

    A user who staged a policy and then a config would otherwise discover it
    by wondering why their rules stopped appearing.
    """
    _post_policy(VALID_POLICY)
    body = _post_config().json()
    assert body["policy_cleared"] is True


def test_a_config_upload_with_no_staged_policy_says_so():
    """The flag is a fact about what happened, not a constant."""
    body = _post_config().json()
    assert body["policy_cleared"] is False
