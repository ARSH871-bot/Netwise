"""
Netwise -- what ai/explain.py's output check lets through when a model
says "all clear" about a finding that is not.

WHY THIS FILE EXISTS
    explain_with_source() asks the model for an explanation and then runs
    _is_unacceptable() on the answer. If the answer passes, it reaches the
    user labelled as model-written. If it fails twice, the user gets the
    deterministic fallback instead.

    The check that stops a claim about the network runs only for
    status="error" (`is_error = finding.get("status") == "error"`), and it
    is a word list: reach, reachable, blocked, works, working, vulnerable,
    safe, secure, clear, issues. Measured with no model on 3 November, by
    stubbing the generator, this lets through:

      - for status="error", "There are no problems with this rule.",
        "This is fine and nothing needs fixing.", "Everything looks
        clean." and "This check passed." None of them uses a listed word.
      - for status="found", every clean-sounding sentence tried, including
        "No issues found." and "...the rule is safe.", because the check
        does not run for "found" at all.

    The first is F-4's failure (CLAUDE.md section 7a): a check that COULD
    NOT RUN described to the user as if it had run and found nothing. The
    second is a confirmed problem described as no problem. web/main.py
    explains only status="found" findings, so the second is on the path the
    dashboard actually uses.

    The tests marked as gaps below are RED ON PURPOSE. They pin what the
    check should refuse, so the gap is visible in the suite rather than only
    in a note. They are not marked xfail, because an expected failure is
    easy to stop seeing.

HOW THE CHECK IS DRIVEN
    Through explain_with_source(), with the generator stubbed to return a
    chosen sentence and the Ollama probe stubbed to say it is reachable --
    the same arrangement tests/test_explain_safety_net.py uses. No model,
    no network, no Batfish. A sentence is "accepted" when it comes back
    unchanged with source "model".

    Findings are built with the real constructors in analysis/findings.py,
    so each one has exactly the shape a check would produce.

RUN
    pytest tests/test_explain_output_check_gap.py -v
"""

import pytest

from ai import explain as explain_module
from analysis.findings import error_finding, make_finding, no_issues_finding


def _finding(status: str) -> dict:
    """One finding of the given status, built the way a check builds it."""
    if status == "found":
        return make_finding(
            check="access_control", severity="high", device="rtr-us5",
            summary="A filter permits traffic the policy requires to be denied",
            detail=("Expected DENY but got PERMIT for 10.10.10.0/24 -> "
                    "10.20.0.5 TCP/23, decided by: permit ip any any"),
            source="rtr-us5.cfg:42", status="found", number=1)
    if status == "none":
        return no_issues_finding(
            check="access_control", device="rtr-us5",
            summary="No issues found by access control",
            detail="1 policy statement(s) hold, 1 guarantee(s) proven",
            source="analysis/checks/access_control.py")
    if status == "error":
        return error_finding(
            check="access_control", device="rtr-us5",
            summary="Could not check the access-control policy",
            detail="BatfishException: Work terminated abnormally",
            source="analysis/checks/access_control.py")
    raise ValueError(f"unknown status {status!r}")


def _accepted(monkeypatch, status: str, text: str) -> bool:
    """True if the explainer would show `text` to the user as model output.

    Stubs the generator to return `text` on every attempt, so a rejection
    can only come from the output check, and the probe to say the model is
    reachable, so the check is actually reached.
    """
    monkeypatch.setattr(explain_module, "_generate", lambda finding: text)
    monkeypatch.setattr(explain_module, "_ollama_is_reachable", lambda: True)
    shown, source = explain_module.explain_with_source(_finding(status))
    return source == "model" and shown == text


# --- The control: a faithful explanation still gets through -------------------
#
# Without this, a fix that rejected everything would make every gap test
# below pass. Each sentence repeats only what its finding says.

_FAITHFUL = {
    "found": ("The filter on rtr-us5 lets telnet from 10.10.10.0/24 to "
              "10.20.0.5 through, because the line permit ip any any decides "
              "it, although the policy says that traffic should be denied."),
    "none": ("The access-control check ran on rtr-us5 and every policy "
             "statement it was given held."),
    "error": ("The access-control check did not run on rtr-us5, so nothing is "
              "confirmed either way. The underlying reason: BatfishException: "
              "Work terminated abnormally."),
}


@pytest.mark.parametrize("status", ["found", "none", "error"])
def test_a_faithful_explanation_is_still_accepted(monkeypatch, status):
    assert _accepted(monkeypatch, status, _FAITHFUL[status]), (
        f"a faithful explanation of a status={status!r} finding was rejected: "
        f"{_FAITHFUL[status]!r}. The output check must still let an accurate "
        f"answer through, or every test in this file passes for the wrong reason."
    )
