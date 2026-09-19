"""Prove that nothing left this machine. US-40 (#332).

WHY THIS EXISTS
    Constraint N-1 -- "no config data to any cloud AI service", CLAUDE.md
    section 5 -- is the single thing that most distinguishes Netwise from
    every hosted analyser it competes with. It is also the only claim in this
    project with no measurement behind it.

    Everything else here is evidenced. The PF Sense rule-order model was
    verified against Batfish. The query layer's entry-location bug was proved
    with two configs differing in one ACL. The `risk` post-processor's two
    limits are enforced in `run_post_processors()` rather than trusted. N-1,
    by contrast, rests on four people having read the source carefully.

    That is a reasonable basis for trusting your own code. It is not
    something you can hand to somebody else's security team, and "we read it
    carefully" is what every breached vendor said first.

WHAT THIS DOES
    Wraps the one place data can actually leave a process -- `socket.connect`
    -- and, for every attempt, records the host, the port, and the code that
    made it. An attempt outside the allowlist is REFUSED, not merely noted.

    Recording without refusing would be the same mistake as `status="none"`
    versus `status="error"`: a log nobody reads is indistinguishable from a
    guarantee nobody kept.

WHAT THE ALLOWLIST IS, AND WHY IT IS NOT JUST "LOOPBACK"
    Netwise talks to exactly two things: Batfish and Ollama. Where those are
    is a deployment decision. Under `docker compose` Batfish is a sibling
    container on a private network, so a loopback-only rule would refuse the
    product's own analysis engine.

    So the allowlist is DERIVED from the same configuration the product uses
    -- `resolve_batfish_host()` and `OLLAMA_HOST` -- and `describe()` states
    what the boundary actually is in this deployment rather than implying a
    stronger one. A guard that quietly permits more than it claims is worse
    than no guard.

WHAT THIS DOES NOT PROVE, STATED PLAINLY
    - It observes THIS process. A subprocess gets its own interpreter and is
      not covered. `tools/egress_audit.py` says so in its output.
    - It guards `connect`, which is where bytes flow. A DNS lookup for a
      hostname is recorded when it precedes a connect, but a name resolution
      on its own is not intercepted.
    - Python-level patching stops Python-level sockets. It is evidence, not a
      sandbox. A real containment boundary is the container's own network
      policy, and `docker-compose.yml` is where that belongs.

    These limits are written here rather than discovered later, because the
    failure mode this whole module exists to prevent is a claim that sounds
    broader than what was measured.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import threading
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from analysis.pipeline import resolve_batfish_host

#: Ports Batfish serves. 9997 is the coordinator, 9996 is the v2 API
#: `pybatfish` actually talks to. 8888 is Batfish's own Jupyter, which Netwise
#: never uses -- it is deliberately NOT here, so an accidental connection to
#: it is refused rather than silently permitted for being "part of Batfish".
BATFISH_PORTS = (9996, 9997)

#: Ollama's default port. The real one comes from OLLAMA_HOST when set.
OLLAMA_DEFAULT_PORT = 11434

#: Set to "0" to run without the guard. Named so that turning it off is a
#: visible act in a compose file or a shell, rather than a default nobody
#: notices.
GUARD_ENV = "NETWISE_EGRESS_GUARD"


class EgressRefused(OSError):
    """Raised instead of connecting to a destination outside the allowlist.

    An OSError subclass on purpose: callers that already handle a network
    failure will handle this too, and degrade the way they degrade for an
    unreachable service, rather than crashing in a new way.
    """


@dataclass(frozen=True)
class Attempt:
    """One outbound connection attempt, allowed or refused."""

    host: str
    port: int
    allowed: bool
    reason: str
    component: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "allowed": self.allowed,
            "reason": self.reason,
            "component": self.component,
        }


@dataclass
class _State:
    installed: bool = False
    original: Optional[Any] = None
    attempts: List[Attempt] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


_state = _State()


# --------------------------------------------------------------------------
# What is allowed
# --------------------------------------------------------------------------
def _is_loopback(host: str) -> bool:
    """Literal loopback only -- never a resolved name.

    Deliberately the same rule `ai/explain.py:_is_loopback_host()` applies,
    and for the same reason its docstring gives: resolving a hostname is
    itself network activity, and a name that resolves to loopback today can
    resolve somewhere else tomorrow.
    """
    if host.lower() in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _ollama_host_port() -> Tuple[str, int]:
    """Where OLLAMA_HOST points, in the forms the ollama client accepts."""
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return ("127.0.0.1", OLLAMA_DEFAULT_PORT)
    without_scheme = raw.split("://", 1)[-1].rstrip("/")
    host, _, port = without_scheme.partition(":")
    try:
        return (host or "127.0.0.1", int(port) if port else OLLAMA_DEFAULT_PORT)
    except ValueError:
        return (host or "127.0.0.1", OLLAMA_DEFAULT_PORT)


def allowlist() -> Dict[str, Set[int]]:
    """The destinations this deployment legitimately needs, host -> ports.

    Read fresh every time rather than cached at import: the environment can
    change between a test setting it and the guard consulting it, and a
    cached allowlist would answer for a configuration that is no longer in
    force.
    """
    entries: Dict[str, Set[int]] = {}
    batfish = resolve_batfish_host(None)
    entries.setdefault(batfish, set()).update(BATFISH_PORTS)
    ollama_host, ollama_port = _ollama_host_port()
    entries.setdefault(ollama_host, set()).add(ollama_port)
    return entries


#: Resolved configured endpoints, so one lookup is not repeated per finding.
#: Keyed by hostname. Cleared by `reset()`, so a test that changes the
#: environment is not answered from a previous configuration.
_resolved: Dict[str, Set[str]] = {}


def _addresses_of(hostname: str) -> Set[str]:
    """Every address a CONFIGURED endpoint resolves to.

    Deliberately different from `_is_loopback()`, which refuses to resolve
    anything. That function asks "is this host local?", where resolving would
    let a name that points elsewhere claim locality. This asks "is this the
    endpoint the operator configured?" -- the name is our own configuration,
    we are about to connect to it regardless, and resolving is the only way
    to compare it with the address `connect()` was actually handed.

    A name that does not resolve yields just itself, so a misconfigured host
    is refused rather than silently widening the allowlist.
    """
    if hostname in _resolved:
        return _resolved[hostname]
    found = {hostname}
    try:
        for info in socket.getaddrinfo(hostname, None):
            address = info[4][0]
            if isinstance(address, str):
                found.add(address)
    except OSError:
        pass
    _resolved[hostname] = found
    return found


def _verdict(host: str, port: int) -> Tuple[bool, str]:
    """Whether this destination is permitted, and the reason either way."""
    entries = allowlist()

    for allowed_host, ports in entries.items():
        if port not in ports:
            continue
        if host == allowed_host or host in _addresses_of(allowed_host):
            role = "Batfish" if port in BATFISH_PORTS else "the local model"
            via = "" if host == allowed_host else f", reached as {host}"
            return True, f"{role} for this deployment ({allowed_host}:{port}{via})"

    if _is_loopback(host):
        # Loopback is this machine talking to itself, which cannot be
        # exfiltration. It is allowed and RECORDED, because "we only talk to
        # ourselves" is exactly the claim somebody will want the evidence for.
        return True, "loopback -- this machine, not the network"

    return False, (
        "not Batfish, not the local model, and not this machine. Netwise "
        "does not send configuration-derived data anywhere else"
    )


# --------------------------------------------------------------------------
# Who tried
# --------------------------------------------------------------------------
#: Frames belonging to the guard itself and to the standard library's socket
#: plumbing. Naming the caller is the point of the record; naming `socket.py`
#: would make every row identical and useless.
_UNINTERESTING = ("analysis/egress.py", "analysis\\egress.py",
                  "socket.py", "ssl.py", "threading.py")


def _component() -> str:
    """The Netwise file that asked for the connection.

    Walks outward from the guard to the first frame that is not this module
    or socket plumbing. Best effort, and labelled as such: an attribution
    that is wrong is worse than one that says it does not know.
    """
    for frame in reversed(traceback.extract_stack()[:-2]):
        name = frame.filename.replace("\\", "/")
        if any(u.replace("\\", "/") in name for u in _UNINTERESTING):
            continue
        for layer in ("analysis/", "ai/", "web/", "tools/"):
            if layer in name:
                short = name.split(layer, 1)[-1]
                return f"{layer}{short}:{frame.lineno}"
        return f"{name.rsplit('/', 1)[-1]}:{frame.lineno}"
    return "unattributed"


def _record(host: str, port: int, allowed: bool, reason: str) -> Attempt:
    attempt = Attempt(host=host, port=port, allowed=allowed, reason=reason,
                      component=_component())
    with _state.lock:
        _state.attempts.append(attempt)
    return attempt


# --------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------
def _address(target: Any) -> Optional[Tuple[str, int]]:
    """The (host, port) of a connect target, or None if it is not IP.

    A unix socket target is a path, not a host and port. It cannot leave the
    machine, so it is not this module's business -- but it must not be
    mistaken for one either, which is what returning None prevents.
    """
    if isinstance(target, tuple) and len(target) >= 2:
        host, port = target[0], target[1]
        if isinstance(port, int):
            return (str(host), port)
    return None


def install() -> bool:
    """Start guarding outbound connections. Idempotent.

    Returns whether the guard is now active. `NETWISE_EGRESS_GUARD=0` turns
    it off, and that is reported rather than silently obeyed -- see
    `describe()`.
    """
    if os.environ.get(GUARD_ENV, "").strip() == "0":
        return False
    if _state.installed:
        return True

    original = socket.socket.connect

    def guarded(self, target, *args, **kwargs):        # type: ignore[no-untyped-def]
        address = _address(target)
        if address is None:
            return original(self, target, *args, **kwargs)
        host, port = address
        allowed, reason = _verdict(host, port)
        _record(host, port, allowed, reason)
        if not allowed:
            raise EgressRefused(
                f"Netwise refused an outbound connection to {host}:{port} -- "
                f"{reason}. If this is a legitimate destination it belongs in "
                f"analysis/egress.py:allowlist(), as a deliberate change."
            )
        return original(self, target, *args, **kwargs)

    _state.original = original
    socket.socket.connect = guarded                    # type: ignore[assignment]
    _state.installed = True
    return True


def uninstall() -> None:
    """Restore the unguarded socket. For tests, and for symmetry."""
    if not _state.installed:
        return
    socket.socket.connect = _state.original            # type: ignore[assignment]
    _state.installed = False
    _state.original = None


def reset() -> None:
    """Forget every recorded attempt and every cached resolution.

    The resolution cache is cleared too, because a test that points
    NETWISE_BATFISH_HOST somewhere new must not be answered from the
    previous deployment's addresses.
    """
    with _state.lock:
        _state.attempts.clear()
        _resolved.clear()


def attempts() -> List[Attempt]:
    with _state.lock:
        return list(_state.attempts)


def describe() -> Dict[str, Any]:
    """Everything a reviewer needs, including what was NOT proved.

    The `limits` key is not decoration. A reader who takes `refused: 0` as
    "nothing left this machine" would be over-reading it in three specific
    ways, and they are named here so the number cannot be quoted without
    them.
    """
    recorded = attempts()
    return {
        "guard_active": _state.installed,
        "allowlist": {host: sorted(ports) for host, ports in allowlist().items()},
        "attempts": [a.as_dict() for a in recorded],
        "allowed": sum(1 for a in recorded if a.allowed),
        "refused": sum(1 for a in recorded if not a.allowed),
        "limits": [
            "Observes this process only; a subprocess is not covered.",
            "Guards connect(), where bytes flow; a bare DNS lookup is not "
            "intercepted.",
            "Python-level patching stops Python-level sockets. This is "
            "evidence, not a sandbox.",
        ],
    }
