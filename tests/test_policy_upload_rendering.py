"""The dashboard must clear stale findings when a policy changes (#87, #82).

WHAT THIS PROTECTS
    Findings on screen describe a config checked against a policy. #82
    established that a new CONFIG makes them stale. A new POLICY makes them
    exactly as stale, for the same reason one step sideways: they were
    computed against rules that are no longer the ones staged.

    Nothing in the Python suite can catch this. `/api/findings` recomputes on
    every request -- there is no server-side results cache on `main` -- so the
    clearing lives entirely in `web/static/app.js`. If the policy handler
    stops calling `clearStaleResults()`, the server tests all still pass and
    the dashboard shows one policy's findings under another policy's success
    message.

WHAT IT ALSO PINS
    A REJECTED policy must NOT clear the findings. Nothing changed, so
    nothing on screen became stale -- and throwing away a working analysis
    because a new file failed to parse would punish the user for the error
    they were just told about.

HOW
    A Node harness loads the REAL web/static/app.js into a small DOM shim and
    drives the change handler against a scripted server. No jsdom, no npm, no
    browser -- see tests/js/policy_upload_harness.js. Skips if Node is
    genuinely absent rather than failing.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).parent / "js" / "policy_upload_harness.js"

STAGED_NOTICE = "notice staged"

needs_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="Node is not installed; the policy upload harness needs it",
)


@pytest.fixture(scope="module")
def rendered():
    """Drive every case through the real handler once, and share it."""
    result = subprocess.run(
        ["node", str(HARNESS)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, (
        f"harness failed (exit {result.returncode}):\n{result.stderr}"
    )
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# The clearing -- the point of the file
# ---------------------------------------------------------------------------


@needs_node
def test_an_accepted_policy_clears_the_previous_findings(rendered):
    """Two findings and a summary tile were on screen; none may survive."""
    case = rendered["accepted"]

    assert case["summaryCount"] == 0, (
        "the summary tiles survived a policy change -- three stale counts are "
        "the same false claim in smaller type"
    )
    assert case["findingsCount"] == 1, (
        "the previous policy's findings are still on screen under the new "
        "policy's success message"
    )
    assert case["noticeClass"] == STAGED_NOTICE


@needs_node
def test_the_replacement_is_neutral_and_says_why(rendered):
    """Not a loading state: nothing is running.

    And it must say the findings went because the RULES changed, not leave
    the user guessing why their results vanished.
    """
    text = rendered["accepted"]["noticeText"].lower()

    assert "policy staged" in text
    assert "old rules" in text
    assert "scan now" in text
    assert "analysing" not in text, "nothing is running; a loading state lies"


@needs_node
def test_a_rejected_policy_leaves_the_findings_alone(rendered):
    """Nothing changed, so nothing became stale.

    The opposite behaviour would throw away a valid analysis because a new
    file failed to parse -- punishing the user for the error they were just
    told about.
    """
    case = rendered["rejected"]

    assert case["findingsCount"] == 2, "a rejected policy cleared the findings"
    assert case["summaryCount"] == 1


# ---------------------------------------------------------------------------
# What the pane says
# ---------------------------------------------------------------------------


@needs_node
def test_the_servers_own_rejection_message_is_shown_verbatim(rendered):
    """PolicyError names the entry. Rewording it here would lose that."""
    message = rendered["rejected"]["policyMessage"]

    assert "entry 1" in message
    assert "unknown key 'nodes'" in message


@needs_node
def test_the_success_message_is_the_servers_own(rendered):
    """One place can say "staged, not applied", and it is the server.

    Summarising it here would give that sentence a second author, free to
    drift into claiming the policy is in force.
    """
    assert "not yet applied" in rendered["accepted"]["policyMessage"].lower()


# ---------------------------------------------------------------------------
# Tone -- "nothing failed, but something was discarded" is its own colour
# ---------------------------------------------------------------------------


@needs_node
def test_a_discarded_policy_is_reported_in_amber(rendered):
    case = rendered["configClearedPolicy"]

    assert "warn" in case["policyMessageClass"], case["policyMessageClass"]
    assert "ok" not in case["policyMessageClass"].split(), (
        "a discarded policy is being reported as a plain success"
    )
    assert "cleared" in case["policyMessage"].lower()


@needs_node
def test_a_config_upload_with_no_staged_policy_says_nothing(rendered):
    """The message is a fact about what happened, not a constant.

    Reporting a clearing that did not occur would be its own small false
    claim, and it is exactly what a harness carrying state between cases
    would hide -- which it briefly did while this was being written.
    """
    case = rendered["configNoPolicy"]

    assert case["policyMessage"] == ""
    assert case["policyMessageClass"] == ""


@needs_node
def test_accepted_and_rejected_keep_their_own_tones(rendered):
    assert "ok" in rendered["accepted"]["policyMessageClass"].split()
    assert "bad" in rendered["rejected"]["policyMessageClass"].split()
    assert "warn" not in rendered["accepted"]["policyMessageClass"]


@needs_node
def test_corrected_legacy_key_names_are_surfaced(rendered):
    """A rename accepted silently is how D1's one vocabulary splits again.

    Counted as nodes rather than read from the string: they are appended with
    createTextNode, never innerHTML, because these strings quote the user's
    own file back at them.
    """
    assert rendered["renamed"]["renameNoteNodes"] > 0, (
        "the loader corrected a legacy key and the user was never told"
    )
    assert rendered["accepted"]["renameNoteNodes"] == 0, (
        "a policy with nothing renamed must not grow a note"
    )
    # Its own class, so CSS can make it read as a heads-up rather than as
    # another sentence of the success message.
    assert rendered["renamed"]["renameNoteClasses"] == ["rename-note"], (
        "the rename note has no class of its own, so it renders as plain "
        "success text and disappears into the sentence above it"
    )


# ---------------------------------------------------------------------------
# The courtesy check, and its limits
# ---------------------------------------------------------------------------


@needs_node
def test_a_non_json_file_never_reaches_the_server(rendered):
    """Client-side validation is UX, not the control -- but it should work.

    The server enforces the same rule (tests/test_web_policy_upload.py); this
    only spares a round trip, and must not clear anything on the way.
    """
    case = rendered["wrongExtension"]

    assert rendered["wrongExtensionPosted"] == 0, "it was uploaded anyway"
    assert ".json" in case["policyMessage"]
    assert case["findingsCount"] == 2, "a locally-rejected file cleared results"
