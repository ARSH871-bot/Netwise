"""Check this machine can actually run Netwise, and say what to fix if not.

WHY THIS EXISTS
    US-16 is "as a user, I can run the finished tool from clear setup
    instructions". The README has five steps, and today you find out whether
    step 1 worked when step 3 fails -- with an error from pybatfish, or an
    empty dashboard, or a finding that says the analysis could not run.

    That is not hypothetical. During one week of development the Batfish
    container was OOM-killed four times (`Exited (137)`), Docker Desktop itself
    was down once, and on that occasion two verification runs LOOKED like
    clean passes:

        containment test  ->  findings=3, explanations=0   "degraded cleanly"
        /api/ask          ->  4 questions, all grounded=False

    Both were meaningless -- `findings=3` is the one-error-per-check signature
    of Batfish being unreachable. A dead environment produced results that read
    as good news, which is this project's recurring failure family arriving
    through the setup rather than through a check.

    This answers "is my environment right?" in one command, before any of that.

THE RULE THIS FOLLOWS (the same one F-4 follows)
    REQUIRED and OPTIONAL are never conflated, and neither is silently
    tolerated. Ollama being absent is not a broken install -- it means the
    explanation layer will degrade to deterministic text, which is a designed
    behaviour, not a fault. Reporting that as a failure would train people to
    ignore this tool; reporting it as nothing would hide a real surprise later.

    So there are three outcomes per check, deliberately mirroring F-4:

        OK       checked, working
        MISSING  checked, not there -- and what that costs you
        BROKEN   checked, there, and not working -- with the fix

RUN
    python -m tools.preflight

EXIT CODE
    0 if everything REQUIRED is working, 1 otherwise. Optional problems never
    change the exit code -- so this is safe to put in front of a demo script.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from typing import List, Tuple

#: (label, status, detail). status is one of OK / MISSING / BROKEN.
Result = Tuple[str, str, str]

OK, MISSING, BROKEN = "OK", "MISSING", "BROKEN"

BATFISH_HOST = "localhost"
BATFISH_PORT = 9996
OLLAMA_PORT = 11434


# ---------------------------------------------------------------------------
# Individual checks. Each returns (status, detail) and never raises.
# ---------------------------------------------------------------------------


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_python() -> Result:
    major, minor = sys.version_info[:2]
    version = f"{major}.{minor}"
    # 3.12 and 3.13 are what CI runs. Others may work and are untested, which
    # is not the same thing -- the README says so too.
    if (major, minor) in {(3, 12), (3, 13)}:
        return ("Python", OK, f"{version} (a version CI tests)")
    return (
        "Python",
        MISSING,
        f"{version}. CI tests 3.12 and 3.13; others may work and are untested.",
    )


def check_dependencies() -> Result:
    """Import what the product actually needs, not what a file lists.

    A requirements.txt that installs cleanly is not proof the imports work --
    that is the same "proxy for the thing" mistake this project keeps finding.
    """
    missing = []
    for module in ("pybatfish", "pandas", "fastapi", "uvicorn", "multipart", "ollama"):
        try:
            __import__(module)
        except ImportError:
            missing.append(module)

    if not missing:
        return ("Python packages", OK, "all importable")
    return (
        "Python packages",
        MISSING,
        f"cannot import: {', '.join(missing)}. Run: "
        "pip install -r requirements.txt",
    )


def check_docker() -> Result:
    """Docker DAEMON, which is a different failure from the container.

    Separated deliberately. `docker start batfish` cannot fix a stopped
    daemon -- it fails with a socket error mentioning nothing about Batfish,
    which is exactly the dead end #89's message had to grow a clause for.
    """
    if shutil.which("docker") is None:
        return ("Docker", MISSING, "the `docker` command is not on PATH.")

    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as error:
        return ("Docker", BROKEN, f"could not run `docker info`: {error}")

    if result.returncode == 0:
        return ("Docker", OK, "daemon is running")
    return (
        "Docker",
        BROKEN,
        "the daemon is not running. Start Docker Desktop and wait for it to "
        "finish starting, then run this again.",
    )


def check_batfish_container() -> Result:
    if shutil.which("docker") is None:
        return ("Batfish container", MISSING, "cannot check without docker.")

    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=batfish",
             "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return ("Batfish container", BROKEN, f"could not query docker: {error}")

    status = result.stdout.strip()
    if not status:
        return (
            "Batfish container",
            MISSING,
            "no container named 'batfish'. Create it with: docker run --name "
            "batfish -d -p 9996:9996 -p 9997:9997 -p 8888:8888 batfish/allinone",
        )
    if status.startswith("Up"):
        return ("Batfish container", OK, status)

    # Exit 137 is SIGKILL. It is worth naming because it is what an
    # out-of-memory kill looks like, and that happened four times in one week
    # here -- but it is NOT proof of one.
    #
    # Measured while testing this tool: a plain `docker stop batfish` also
    # produces 137, because Batfish is a JVM that does not exit on SIGTERM
    # within Docker's grace period and gets SIGKILLed anyway. An earlier
    # version of this hint asserted 137 "means it was killed for running out
    # of memory", which would have sent someone to add RAM after they stopped
    # the container themselves. So it now offers the cause rather than
    # asserting it.
    hint = "Run: docker start batfish"
    if "(137)" in status:
        hint += (
            "   -- exit 137 is SIGKILL. If you did not stop it yourself, the "
            "usual cause is Docker running out of memory; give it more RAM if "
            "this keeps happening."
        )
    return ("Batfish container", BROKEN, f"{status}. {hint}")


def check_batfish_service() -> Result:
    """An open port is not a healthy service, so ask it a real question."""
    if not _port_open(BATFISH_HOST, BATFISH_PORT):
        return (
            "Batfish service",
            BROKEN,
            f"nothing is listening on {BATFISH_HOST}:{BATFISH_PORT}. If the "
            "container has just started, it takes a few seconds to come up.",
        )

    try:
        from analysis.pipeline import connect

        connect(BATFISH_HOST)
    except Exception as error:  # noqa: BLE001 -- report anything, never raise
        return (
            "Batfish service",
            BROKEN,
            f"port is open but the service did not answer: "
            f"{type(error).__name__}: {str(error)[:120]}",
        )
    return ("Batfish service", OK, "answering")


def check_ollama() -> Result:
    """OPTIONAL. Absent means degraded explanations, not a broken install."""
    if not _port_open("localhost", OLLAMA_PORT, timeout=2.0):
        return (
            "Ollama (optional)",
            MISSING,
            "not running. Everything still works: explanations fall back to "
            "deterministic text, and the whole test suite passes without it.",
        )
    return ("Ollama (optional)", OK, "running")


def check_node() -> Result:
    """OPTIONAL, and the reason it is listed at all is worth stating.

    Two test files drive the real web/static/app.js through a Node DOM shim.
    Without Node they SKIP -- and a skipped test is indistinguishable from a
    passing one in pytest's summary line. That is the same reason
    .github/workflows/tests.yml installs Node explicitly rather than relying
    on the runner image happening to ship it.
    """
    if shutil.which("node") is None:
        return (
            "Node (optional)",
            MISSING,
            "not installed. The two frontend test files will SKIP rather than "
            "fail, so the suite will look green while not checking the "
            "dashboard's rendering rules.",
        )
    return ("Node (optional)", OK, "installed")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

REQUIRED = [check_python, check_dependencies, check_docker,
            check_batfish_container, check_batfish_service]
OPTIONAL = [check_ollama, check_node]

_SYMBOL = {OK: "  OK   ", MISSING: " MISSING", BROKEN: " BROKEN "}


def run() -> int:
    results: List[Tuple[Result, bool]] = []
    for check in REQUIRED:
        results.append((check(), True))
    for check in OPTIONAL:
        results.append((check(), False))

    print("Netwise preflight")
    print("=" * 72)
    for (label, status, detail), required in results:
        print(f"[{_SYMBOL[status]}] {label}")
        if status != OK:
            print(f"           {detail}")
        else:
            print(f"           {detail}")
    print("=" * 72)

    broken_required = [
        label for (label, status, _), required in results
        if required and status != OK
    ]
    if broken_required:
        print(f"NOT READY -- {len(broken_required)} required check(s) failed: "
              f"{', '.join(broken_required)}")
        print("Fix the lines above, then run this again.")
        return 1

    degraded = [
        label for (label, status, _), required in results
        if not required and status != OK
    ]
    if degraded:
        # Deliberately not an error. Saying "ready" while staying explicit
        # about what is reduced is the whole point of separating these.
        print(f"READY -- with {len(degraded)} optional item(s) absent: "
              f"{', '.join(degraded)}")
        print("Everything required works. See the notes above for what that costs.")
    else:
        print("READY -- everything, including the optional pieces.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
