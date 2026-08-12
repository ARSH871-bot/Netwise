"""Tests for what happens when Batfish is not running.

THE PROBLEM THESE COVER
    The container was OOM-killed twice in one working day (`Exited (137)`).
    That is not an exotic failure -- it is the normal state of a laptop that
    has been asleep, and it is what a demo opens on. Two things were wrong
    with how the product handled it, and neither was the F-4 handling, which
    was already correct:

    1. It took a long time to say so. pybatfish retries internally, so the
       dashboard just spun. Measured 12 August:

           stopped container (port refuses)    21.0s
           wrong host (packets dropped)        88.9s

    2. When it finally spoke, the one sentence a user can act on was last,
       behind ~200 characters of truncated urllib3 ("Max retries exceeded with
       url: /v2/question_templates ... NewConnectionError('<urllib3.connection
       .HTTPConnection"). Everything before it is noise to the person who just
       needs to start a container.

    So these tests care about two things: that the probe short-circuits before
    the slow path, and that the fix is the first thing in the message. The
    second is the one that would rot silently -- a later edit reordering that
    string breaks nothing that any other test notices.

WHAT THESE DO NOT COVER
    Whether Batfish is *healthy*. An open port is not a working service, which
    is exactly why the probe only ever short-circuits the failure case and
    still lets pybatfish do the real check.

These need neither Batfish nor Docker.
"""

import socket

import pytest

from analysis import pipeline


def _closed_port() -> int:
    """Bind a port, learn its number, release it. Nothing listens there after."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# --------------------------------------------------------------------------
# The probe itself
# --------------------------------------------------------------------------


def test_probe_passes_when_something_is_listening():
    """The negative case is the interesting one, so pin the positive first.

    If this ever fails, the probe rejects a WORKING Batfish, which is far worse
    than being slow -- it is the one way this change could take down a healthy
    setup.
    """
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = int(server.getsockname()[1])

        pipeline._require_port_open("127.0.0.1", port, timeout=2.0)


def test_probe_raises_connection_error_when_nothing_listens():
    with pytest.raises(ConnectionError) as caught:
        pipeline._require_port_open("127.0.0.1", _closed_port(), timeout=1.0)

    # ConnectionError specifically, not OSError: analyse() and any human
    # reading a traceback should not have to tell the probe apart from the
    # real connection attempt.
    assert isinstance(caught.value, ConnectionError)


def test_probe_error_names_the_port_it_tried():
    """A wrong port and a stopped container look identical without this."""
    port = _closed_port()

    with pytest.raises(ConnectionError) as caught:
        pipeline._require_port_open("127.0.0.1", port, timeout=1.0)

    assert str(port) in str(caught.value)
    assert "127.0.0.1" in str(caught.value)


# --------------------------------------------------------------------------
# That connect() actually uses it to skip the slow path
# --------------------------------------------------------------------------


def test_connect_fails_before_building_a_session(monkeypatch):
    """The whole point of the probe: never reach the 21-second path.

    Without this test the probe could be deleted, or moved below the Session
    construction, and every other test would still pass -- the outcome is the
    same ConnectionError either way. Only the *timing* changes, and timing is
    what this change exists for. So assert on order, not duration: a duration
    assertion would be flaky on a loaded machine and would still not say what
    went wrong.
    """
    def _explode(*args, **kwargs):
        raise AssertionError("Session was constructed despite a failed probe")

    monkeypatch.setattr(pipeline, "Session", _explode)

    with pytest.raises(ConnectionError):
        pipeline.connect(host="127.0.0.1", probe_port=_closed_port(), probe_timeout=1.0)


def test_probe_can_be_skipped(monkeypatch):
    """Batfish on a non-default port must stay usable.

    The probe is the one part of this change that can wrongly fail a working
    setup, so the escape hatch is tested rather than merely documented.
    """
    built = []

    class _FakeSession:
        def __init__(self, host="localhost"):
            built.append(host)

        def get_component_versions(self):
            return {"Batfish": "test"}

    monkeypatch.setattr(pipeline, "Session", _FakeSession)

    # A closed port, which the probe would reject -- but the probe is off.
    pipeline.connect(host="127.0.0.1", probe_port=_closed_port(), probe_timeout=0)

    assert built == ["127.0.0.1"]


# --------------------------------------------------------------------------
# What the user actually reads
# --------------------------------------------------------------------------


def _findings_with_batfish_down(monkeypatch):
    def _refuse(*args, **kwargs):
        raise ConnectionError(
            "HTTPConnectionPool(host='localhost', port=9996): Max retries "
            "exceeded with url: /v2/question_templates?verbose=False (Caused by "
            "NewConnectionError('<urllib3.connection.HTTPConnection object at "
            "0x0000017>: Failed to establish a new connection: [WinError 10061] "
            "No connection could be made because the target machine actively "
            "refused it'))"
        )

    monkeypatch.setattr(pipeline, "connect", _refuse)
    return pipeline.analyse("tests/fixtures/rtr-us5-messy")


def test_every_check_reports_error_not_clean(monkeypatch):
    """F-4. This was already correct; it is pinned so it stays correct."""
    results = _findings_with_batfish_down(monkeypatch)

    assert results, "an unreachable Batfish must still produce findings"
    assert {f["status"] for f in results} == {"error"}
    assert not any(f["status"] == "none" for f in results), (
        "a green tick when nobody could look is the failure F-4 exists to prevent"
    )


def test_the_fix_comes_before_the_stack_trace(monkeypatch):
    """The actual regression this change fixes.

    Asserting "the message mentions docker" would pass with the instruction
    buried at the end, which is the exact bug. So assert on ORDER.
    """
    detail = _findings_with_batfish_down(monkeypatch)[0]["evidence"]["detail"]

    assert "docker start batfish" in detail

    fix_at = detail.index("docker start batfish")
    noise_at = detail.index("Max retries exceeded")
    assert fix_at < noise_at, (
        "the actionable instruction must come before the urllib3 detail -- "
        f"got fix at {fix_at}, noise at {noise_at}"
    )


def test_the_raw_error_is_still_there(monkeypatch):
    """Kept deliberately: it is what separates a stopped container from a
    wrong host. Moving it later must not become dropping it."""
    detail = _findings_with_batfish_down(monkeypatch)[0]["evidence"]["detail"]

    assert "Max retries exceeded" in detail
