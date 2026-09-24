"""Netwise refuses to talk to anything but Batfish and the local model.

WHY THIS FILE EXISTS
    Constraint N-1 is the product's main commercial differentiator and, until
    US-40 (#332), the only claim in this project supported by reading the
    source rather than by measurement. `analysis/egress.py` makes it
    checkable; this makes the check itself checkable.

THE TEST THAT MATTERS MOST
    `test_a_planted_outbound_call_is_refused` plants a connection to a public
    address inside a check and proves the guard stops it. Without that, a
    guard that never fires and a guard that cannot fire look identical -- and
    this project has already shipped two tests that asserted a false wording
    and held it in place.

THE TEST THAT ALMOST DID NOT EXIST
    `TestAConfiguredHostIsNotAlwaysLoopback` covers a real bug found by
    running `python -m tools.egress_audit` rather than by reasoning. The
    allowlist held the hostname; `socket.connect` is handed the resolved
    ADDRESS. On this machine that never showed, because Batfish is loopback
    and the loopback rule permitted it anyway. Under `docker compose`,
    NETWISE_BATFISH_HOST=batfish resolves to a private bridge address that is
    neither the literal string nor loopback, and the guard would have refused
    the product's own analysis engine.

    So these tests never use loopback to check the allowlist. A rule that is
    only ever exercised where a second rule would also pass is not tested.

These need neither Batfish nor Ollama.
"""

from __future__ import annotations

import socket

import pytest

from analysis import egress


@pytest.fixture(autouse=True)
def clean_guard(monkeypatch):
    """Every test starts with no guard, no record, and no cached lookups."""
    monkeypatch.delenv(egress.GUARD_ENV, raising=False)
    egress.uninstall()
    egress.reset()
    yield
    egress.uninstall()
    egress.reset()


def _connect(host: str, port: int) -> None:
    """Attempt a connection, ignoring whether it would have succeeded.

    The guard raises before the real connect, so a refusal surfaces as
    EgressRefused. An allowed destination that is simply not listening
    surfaces as an ordinary OSError, which is not what any of these
    assertions are about.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.05)
    try:
        sock.connect((host, port))
    except egress.EgressRefused:
        raise
    except OSError:
        pass
    finally:
        sock.close()


class TestTheGuardRefuses:
    def test_a_public_address_is_refused(self):
        egress.install()
        with pytest.raises(egress.EgressRefused) as refused:
            _connect("93.184.216.34", 443)
        assert "93.184.216.34:443" in str(refused.value)

    def test_the_refusal_says_where_to_make_it_legitimate(self):
        """A refusal that does not say what to do produces a bad workaround."""
        egress.install()
        with pytest.raises(egress.EgressRefused) as refused:
            _connect("1.1.1.1", 53)
        assert "analysis/egress.py" in str(refused.value)

    def test_a_refusal_is_recorded_as_well_as_raised(self):
        egress.install()
        with pytest.raises(egress.EgressRefused):
            _connect("8.8.8.8", 443)
        recorded = egress.attempts()
        assert len(recorded) == 1
        assert recorded[0].allowed is False
        assert recorded[0].host == "8.8.8.8"

    def test_an_oserror_subclass_so_callers_degrade_rather_than_crash(self):
        assert issubclass(egress.EgressRefused, OSError)


class TestTheGuardPermitsWhatNetwiseNeeds:
    def test_loopback_is_allowed(self):
        egress.install()
        _connect("127.0.0.1", 9996)
        assert egress.attempts()[0].allowed is True

    def test_batfish_ports_are_named_in_the_reason(self, monkeypatch):
        monkeypatch.setenv("NETWISE_BATFISH_HOST", "127.0.0.1")
        egress.install()
        _connect("127.0.0.1", 9997)
        assert "Batfish" in egress.attempts()[0].reason

    def test_batfishs_jupyter_port_is_not_allowed_by_association(self):
        """8888 belongs to Batfish's image and to nothing Netwise uses.

        Permitting it because it is "part of Batfish" is how an allowlist
        becomes a category rather than a list.
        """
        egress.install()
        with pytest.raises(egress.EgressRefused):
            _connect("93.184.216.34", 8888)


class TestAConfiguredHostIsNotAlwaysLoopback:
    """The container case, which is where the original bug would have bitten.

    Uses this machine's own hostname because it resolves to a real, non-
    loopback address without any network being available -- the same shape as
    `batfish` resolving to a bridge address under compose.
    """

    @staticmethod
    def _non_loopback_endpoint():
        name = socket.gethostname()
        try:
            addresses = {
                info[4][0] for info in socket.getaddrinfo(name, None)
                if not egress._is_loopback(info[4][0])
            }
        except OSError:                              # pragma: no cover
            addresses = set()
        if not addresses:                            # pragma: no cover
            pytest.skip("this machine's hostname resolves only to loopback")
        return name, sorted(addresses)[0]

    def test_a_configured_hostname_is_allowed_at_its_resolved_address(
            self, monkeypatch):
        name, address = self._non_loopback_endpoint()
        monkeypatch.setenv("NETWISE_BATFISH_HOST", name)
        egress.reset()
        egress.install()
        _connect(address, 9996)
        attempt = egress.attempts()[0]
        assert attempt.allowed is True, (
            f"{address} is where {name} resolves, and {name} is the "
            "configured Batfish host. Refusing it would refuse the product's "
            "own analysis engine under docker compose."
        )
        assert "reached as" in attempt.reason

    def test_the_same_address_on_another_port_is_still_refused(
            self, monkeypatch):
        """Resolution widens the allowlist by HOST, never by port."""
        name, address = self._non_loopback_endpoint()
        monkeypatch.setenv("NETWISE_BATFISH_HOST", name)
        egress.reset()
        egress.install()
        with pytest.raises(egress.EgressRefused):
            _connect(address, 443)

    def test_a_hostname_that_does_not_resolve_does_not_widen_anything(
            self, monkeypatch):
        monkeypatch.setenv("NETWISE_BATFISH_HOST",
                           "batfish.invalid-host-that-does-not-exist")
        egress.reset()
        egress.install()
        with pytest.raises(egress.EgressRefused):
            _connect("93.184.216.34", 9996)


class TestAPlantedOutboundCall:
    """The acceptance criterion: plant one in a check and prove it is stopped."""

    def test_a_planted_outbound_call_is_refused(self, monkeypatch):
        """Simulates a check that has been made to phone home.

        This is the failure the guard exists for -- not a mistake anyone on
        this team would make deliberately, but exactly what a compromised
        dependency or a careless copy-paste would introduce, and precisely
        what a buyer's security review is asking about.
        """
        from analysis.checks import access_control

        def leaking_run(bf):
            _connect("93.184.216.34", 443)          # evidence leaving
            return []

        monkeypatch.setattr(access_control, "run", leaking_run)
        egress.install()

        with pytest.raises(egress.EgressRefused):
            access_control.run(bf=None)

        report = egress.describe()
        assert report["refused"] == 1
        assert report["allowed"] == 0

    def test_the_record_names_the_file_that_tried(self):
        egress.install()
        with pytest.raises(egress.EgressRefused):
            _connect("93.184.216.34", 443)
        component = egress.attempts()[0].component
        assert "test_egress_guard.py" in component, (
            f"attributed to {component!r}; a record that cannot say which "
            "code tried is not evidence"
        )


class TestTheGuardCanBeSwitchedOff:
    def test_off_means_off_and_says_so(self, monkeypatch):
        monkeypatch.setenv(egress.GUARD_ENV, "0")
        assert egress.install() is False
        assert egress.describe()["guard_active"] is False

    def test_off_is_not_the_same_as_clean(self, monkeypatch):
        """Nothing recorded because nothing was watched.

        `refused: 0` with the guard off must never read as a clean result.
        This is F-4 -- "checked and found nothing" versus "could not check"
        -- arriving in the safety evidence rather than in a finding.
        """
        monkeypatch.setenv(egress.GUARD_ENV, "0")
        egress.install()
        _connect("93.184.216.34", 443)
        report = egress.describe()
        assert report["attempts"] == []
        assert report["guard_active"] is False


class TestTheReportStatesItsOwnLimits:
    def test_limits_are_always_present(self):
        egress.install()
        limits = egress.describe()["limits"]
        assert len(limits) >= 3
        joined = " ".join(limits).lower()
        assert "subprocess" in joined
        assert "sandbox" in joined

    def test_install_is_idempotent(self):
        """Installing twice must not stack wrappers.

        A doubled wrapper would record every attempt twice, and a count that
        is wrong in the safe direction is still a wrong count.
        """
        egress.install()
        egress.install()
        _connect("127.0.0.1", 9996)
        assert len(egress.attempts()) == 1

    def test_uninstall_restores_the_original(self):
        before = socket.socket.connect
        egress.install()
        assert socket.socket.connect is not before
        egress.uninstall()
        assert socket.socket.connect is before
