"""The model is not asked when it is not there (#225).

WHAT THIS FIXES
    Measured on a machine with no Ollama, five findings on one page:

        call 1: 13.80s | 5 explain calls costing 10.15s | all fallback
        call 2: 10.13s | 5 explain calls costing 10.12s | all fallback
        call 3: 10.17s | 5 explain calls costing 10.16s | all fallback

    The analysis cache was working perfectly -- `analyse()` ran once across
    all three. Every second of that was five findings queueing up to
    discover, separately, that a service is absent.

WHAT IT MUST NOT BREAK, WHICH IS THE HARDER HALF
    `web/main.py` deliberately does not cache fallback text, so that
    somebody starting Ollama mid-session gets fresh model output rather than
    a stale string. A probe answer cached for the process lifetime would
    reintroduce exactly that staleness one layer down: the text would not be
    cached, but the DECISION not to generate would be.

    So the probe's TTL is short, and `test_a_model_started_later_is_picked_up`
    below is the test that matters most in this file.

NO NETWORK
    Every test stubs the socket call. None of them opens a real connection.
"""

from __future__ import annotations

import socket

import pytest

from ai import explain as explain_module


@pytest.fixture(autouse=True)
def _clean_probe_cache():
    """A probe answer surviving into the next test is how one test starts
    passing for a reason belonging to another one."""
    explain_module.reset_reachability_cache()
    yield
    explain_module.reset_reachability_cache()


class _Socket:
    """Stands in for the connection `socket.create_connection` returns."""

    def __enter__(self): return self

    def __exit__(self, *exc): return False


def _connections(monkeypatch, *, up):
    """Stub the probe's socket. Returns a list that records each attempt."""
    attempts = []

    def fake(address, timeout=None):
        attempts.append(address)
        if not up:
            raise OSError("connection refused")
        return _Socket()

    monkeypatch.setattr(socket, "create_connection", fake)
    return attempts


# ---------------------------------------------------------------------------
# The probe itself
# ---------------------------------------------------------------------------


def test_an_open_port_means_reachable(monkeypatch):
    _connections(monkeypatch, up=True)
    assert explain_module._ollama_is_reachable() is True


def test_a_refused_port_means_unreachable(monkeypatch):
    _connections(monkeypatch, up=False)
    assert explain_module._ollama_is_reachable() is False


def test_one_page_of_findings_costs_one_probe(monkeypatch):
    """The whole point: five findings, one probe, not five timeouts."""
    attempts = _connections(monkeypatch, up=False)

    for _ in range(5):
        explain_module._ollama_is_reachable()

    assert len(attempts) == 1, (
        f"each call probed again ({len(attempts)} attempts) -- the TTL is "
        f"not being honoured, and the 10s page load is back"
    )


def test_a_model_started_later_is_picked_up(monkeypatch):
    """THE TEST THAT MATTERS MOST HERE.

    Caching "Ollama is down" for the process lifetime would mean somebody
    starting it mid-session never gets a model explanation until the app is
    restarted -- and on a demo machine that is exactly when it would happen.

    `web/main.py` refuses to cache fallback TEXT for the same reason. A
    permanently cached probe answer would defeat that from one layer down:
    the text would not be stale, but the decision not to generate would be.
    """
    state = {"up": False}

    def fake(address, timeout=None):
        if not state["up"]:
            raise OSError("connection refused")
        return _Socket()

    monkeypatch.setattr(socket, "create_connection", fake)

    assert explain_module._ollama_is_reachable() is False

    # Somebody runs `ollama serve` during the demo.
    state["up"] = True
    explain_module.reset_reachability_cache()   # stands in for the TTL expiring

    assert explain_module._ollama_is_reachable() is True, (
        "a model started after the first probe must be found again -- "
        "otherwise the app has to be restarted to notice it"
    )


def test_the_ttl_is_short_enough_to_be_worth_calling_short():
    """A number, asserted, so "short" cannot drift into "for ever".

    Five seconds collapses one page's findings into one probe and still
    notices a model started during a meeting.
    """
    assert 0 < explain_module.OLLAMA_PROBE_TTL_SECONDS <= 30, (
        "a long TTL turns this from a speed fix into a staleness bug"
    )


def test_an_unexpected_probe_error_still_attempts_generation(monkeypatch):
    """Fail TOWARDS asking the model.

    A broken probe must never be able to silently downgrade a working
    installation to deterministic text. That would trade a slow page for a
    false byline, which is a far worse bargain -- and #109 exists because
    the byline was wrong once already.
    """
    def exploding(address, timeout=None):
        raise RuntimeError("something nobody predicted")

    monkeypatch.setattr(socket, "create_connection", exploding)

    assert explain_module._ollama_is_reachable() is True


# ---------------------------------------------------------------------------
# Where the probe is honoured -- both ends of the join
# ---------------------------------------------------------------------------


REAL_FINDING = {
    "id": "AC-001",
    "check": "access_control",
    "severity": "high",
    "device": "rtr-us5",
    "status": "found",
    "summary": "Unencrypted web traffic is allowed out",
    "evidence": {"detail": "Expected DENY but got PERMIT, decided by: permit ip any any",
                 "source": "rtr-us5:acl_in"},
}


def test_an_unreachable_model_is_never_called(monkeypatch):
    """The saving. Without this the probe exists and changes nothing."""
    _connections(monkeypatch, up=False)
    called = []
    monkeypatch.setattr(explain_module, "_generate",
                        lambda finding: called.append(finding) or "text")

    text, source = explain_module.explain_with_source(REAL_FINDING)

    assert called == [], (
        "the model was called even though nothing is listening -- this is "
        "the timeout the whole change exists to avoid"
    )
    assert source == "fallback"
    assert text, "a fallback explanation is still produced"


def test_a_reachable_model_is_still_called(monkeypatch):
    """The other end. Without this, 'never call the model' would also pass."""
    _connections(monkeypatch, up=True)
    called = []

    def stub(finding):
        called.append(finding)
        return "One machine cannot reach the DNS server because a rule blocks it."

    monkeypatch.setattr(explain_module, "_generate", stub)

    text, source = explain_module.explain_with_source(REAL_FINDING)

    assert len(called) == 1, (
        "the probe said reachable and the model was still not called -- the "
        "probe has become a blanket ban on generation"
    )
    assert source == "model"
    assert "DNS" in text


def test_the_evidence_check_still_comes_first(monkeypatch):
    """A finding with no real evidence must not reach the model even when
    Ollama is up. That ordering is a GROUNDING rule, not a speed one, and
    #225 must not have quietly reordered it."""
    _connections(monkeypatch, up=True)
    called = []
    monkeypatch.setattr(explain_module, "_generate",
                        lambda finding: called.append(finding) or "text")

    bare = {"id": "AC-000", "status": "none", "summary": "nothing found"}
    _text, source = explain_module.explain_with_source(bare)

    assert called == [], "a finding with no evidence must never be generated from"
    assert source == "fallback"


# ---------------------------------------------------------------------------
# OLLAMA_HOST -- probing the wrong machine would be worse than no probe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("", ("127.0.0.1", 11434)),
    ("otherbox", ("otherbox", 11434)),
    ("otherbox:1234", ("otherbox", 1234)),
    ("http://otherbox:1234", ("otherbox", 1234)),
    ("http://otherbox:1234/", ("otherbox", 1234)),
    ("otherbox:notaport", ("otherbox", 11434)),
])
def test_the_probe_follows_ollama_host(monkeypatch, value, expected):
    """The client honours OLLAMA_HOST, so the probe must too.

    Probing 127.0.0.1 while the client talks to another machine would report
    "unreachable" on a working installation and silently stop generating --
    the one way this change could be worse than not making it.
    """
    monkeypatch.setenv("OLLAMA_HOST", value)
    assert explain_module._ollama_endpoint() == expected
