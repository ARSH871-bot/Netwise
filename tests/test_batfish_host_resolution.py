"""`NETWISE_BATFISH_HOST` decides where Batfish is, and an argument overrides it.

WHY THIS EXISTS
    `web/main.py` calls `analysis.pipeline.analyse()` with no host, so before
    US-41 (#333) every deployment looked for Batfish on its own loopback. In a
    container that is the container itself, and `docker compose up` could not
    work no matter how the compose file was written. This is the code change
    that makes one-command install possible.

THE PROPERTY THAT MATTERS MOST
    An explicitly passed host is honoured EXACTLY, including the literal
    string "localhost". The tempting shortcut -- "if host == 'localhost', use
    the environment instead" -- would mean a caller that deliberately named
    loopback silently got a different machine. A parameter that can be
    overridden by configuration is not a parameter, it is a suggestion, and
    the one place this must not happen is the host holding a network model
    built from somebody's real configuration.

    `None` is the sentinel, and it means "nobody chose".

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import pytest

from analysis import pipeline


class TestNobodyChose:
    """`None` -- the default -- consults the environment."""

    def test_falls_back_to_loopback_when_unset(self, monkeypatch):
        monkeypatch.delenv(pipeline.BATFISH_HOST_ENV, raising=False)
        assert pipeline.resolve_batfish_host(None) == "localhost"

    def test_uses_the_environment_when_set(self, monkeypatch):
        monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, "batfish")
        assert pipeline.resolve_batfish_host(None) == "batfish"

    def test_blank_and_whitespace_are_not_a_host(self, monkeypatch):
        """An empty variable is an unset one, not a hostname of ''.

        `docker compose` writes an empty string for a variable that is
        declared and not given a value, which is a very easy way to end up
        asking for a Session on host "".
        """
        for blank in ("", "   ", "\t"):
            monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, blank)
            assert pipeline.resolve_batfish_host(None) == "localhost"


class TestSomebodyChose:
    """An explicit argument wins, always."""

    def test_explicit_host_beats_the_environment(self, monkeypatch):
        monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, "batfish")
        assert pipeline.resolve_batfish_host("10.0.0.9") == "10.0.0.9"

    def test_explicit_localhost_is_not_reinterpreted(self, monkeypatch):
        """The whole point of the sentinel.

        Somebody debugging against a local Batfish while the environment
        points at a container must get the local one.
        """
        monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, "batfish")
        assert pipeline.resolve_batfish_host("localhost") == "localhost"


class TestConnectUsesTheResolution:
    """The resolution has to reach the Session, not merely exist."""

    def test_connect_passes_the_resolved_host_onward(self, monkeypatch):
        seen: dict = {}

        monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, "batfish")
        monkeypatch.setattr(pipeline, "_require_port_open",
                            lambda host, port, timeout: seen.update(probe=host))

        class FakeSession:
            def __init__(self, host):
                seen["session"] = host

            def get_component_versions(self):
                return {}

        monkeypatch.setattr(pipeline, "Session", FakeSession)

        pipeline.connect()
        assert seen["session"] == "batfish", "Session got the wrong host"
        assert seen["probe"] == "batfish", (
            "the reachability probe checked a different host than the Session "
            "connected to -- that would fail a working setup, or pass a "
            "broken one"
        )

    def test_the_probe_and_the_session_cannot_disagree(self, monkeypatch):
        """Mutation guard for the line above.

        `connect()` resolves once and uses the result twice. If it ever
        resolved separately for the probe and the Session, a working setup
        could be reported unreachable -- which is exactly the failure
        `_require_port_open` was added to avoid.
        """
        seen: dict = {}
        monkeypatch.setenv(pipeline.BATFISH_HOST_ENV, "somewhere-else")
        monkeypatch.setattr(pipeline, "_require_port_open",
                            lambda host, port, timeout: seen.update(probe=host))

        class FakeSession:
            def __init__(self, host):
                seen["session"] = host

            def get_component_versions(self):
                return {}

        monkeypatch.setattr(pipeline, "Session", FakeSession)
        pipeline.connect(host="explicit-host")
        assert seen["probe"] == seen["session"] == "explicit-host"


class TestTheSignaturesActuallyChanged:
    """The three entry points must all take the sentinel, not just one.

    #172 fixed a `sys.path` bug in one tool and left it live in another "for
    as long as it had been fixed in the first". `analyse`, `analyse_change`
    and `propose_change` are the same shape of risk: three doors onto the
    same room.
    """

    @pytest.mark.parametrize("func_path", [
        ("analysis.pipeline", "analyse"),
        ("analysis.pipeline", "connect"),
        ("analysis.change_impact", "analyse_change"),
        ("ai.propose", "propose_change"),
    ])
    def test_host_defaults_to_none(self, func_path):
        import importlib
        import inspect

        module_name, func_name = func_path
        module = importlib.import_module(module_name)
        signature = inspect.signature(getattr(module, func_name))
        assert "host" in signature.parameters, f"{func_name} has no host"
        default = signature.parameters["host"].default
        assert default is None, (
            f"{module_name}.{func_name} still defaults host to {default!r}. "
            "A hardcoded 'localhost' here means this entry point ignores "
            "NETWISE_BATFISH_HOST and cannot run in a container."
        )
