"""Check this machine can actually run Netwise, and say what to fix if not.

WHY THIS EXISTS
    US-16 is "as a user, I can run the finished tool from clear setup
    instructions". The README has eight steps, and without this you find out
    whether Batfish started when the analysis step fails -- with an error
    from pybatfish, or an empty dashboard, or a finding that says the
    analysis could not run.

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
    python -m tools.preflight        (the form the README gives)
    python tools/preflight.py        (also works -- see the sys.path note below)

EXIT CODE
    0 if everything REQUIRED is working, 1 otherwise. Optional problems never
    change the exit code -- so this is safe to put in front of a demo script.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

# RUN AS A SCRIPT, NOT ONLY AS A MODULE.
#     `python -m tools.preflight` puts the repository root on sys.path;
#     `python tools/preflight.py` puts tools/ there instead, so `import
#     analysis` fails and check_batfish_service() cannot reach the thing it
#     is meant to test. Both forms are documented -- the README gives the
#     module form and refers to the file by path -- so both must work.
#
#     This is the first half of the fix. The second is in
#     check_batfish_service(), which no longer reports an import failure as a
#     Batfish failure. Either half alone would hide the other, which is why
#     both are here: one makes the command work, one makes it honest when
#     something else breaks the import.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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


def check_dependency_versions() -> Result:
    """Do the installed versions satisfy requirements.txt?

    WHY THIS IS SEPARATE FROM check_dependencies()
        Because "it imports" and "it is the version we declare" are different
        claims, and the first was standing in for the second.

        Measured on the author's machine, 17 August, while every run of the
        suite was being reported as evidence:

            pandas            installed 2.3.3    declared >=3.0.5
            fastapi           installed 0.128.0  declared >=0.141.1
            uvicorn           installed 0.40.0   declared >=0.52.1
            python-multipart  installed 0.0.21   declared >=0.0.32
            pytest            installed 9.0.2    declared >=9.1.1

        Five of seven, and `check_dependencies()` reported "all importable"
        throughout, because every one of them imports perfectly well.

        This is not cosmetic. CI runs `pip install -r requirements.txt` on a
        clean machine, so CI was testing pandas 3.x while the same suite
        locally was testing pandas 2.x -- both green, and not the same test.
        #131 raised that floor deliberately and #132 exists precisely because
        a major pandas bump cannot be validated on a CI tick. A local run on
        the old major answers a question nobody asked.

        It is also the same shape as the missing-packages incident that put a
        wrong test count into a status update: an environment quietly unlike
        the declared one, reported as fine.

    WHY IT CAN ITSELF REPORT "COULD NOT CHECK"
        Parsing a requirement specifier properly needs `packaging`, which is
        not in requirements.txt. Rather than hand-rolling version comparison
        -- which gets 0.9 vs 0.10 wrong -- this reports BROKEN with the reason
        when it cannot do the comparison. Saying "I could not check" beats
        both a wrong answer and a silent pass, which is F-4 applied to the
        preflight tool itself.
    """
    requirements = Path(__file__).resolve().parent.parent / "requirements.txt"
    if not requirements.exists():
        return ("Package versions", BROKEN, "requirements.txt not found")

    try:
        from importlib.metadata import PackageNotFoundError, version
        from packaging.requirements import Requirement
        from packaging.version import Version
    except ImportError as error:
        return (
            "Package versions",
            BROKEN,
            f"cannot compare versions: {error}. Install `packaging`, or treat "
            "this check as not run -- it is not a pass.",
        )

    wrong: List[str] = []
    absent: List[str] = []
    for raw in requirements.read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        try:
            requirement = Requirement(line)
        except Exception:  # noqa: BLE001 -- a line we cannot parse is not a failure
            continue
        try:
            installed = version(requirement.name)
        except PackageNotFoundError:
            absent.append(f"{requirement.name} (declared {requirement.specifier})")
            continue
        if requirement.specifier and not requirement.specifier.contains(
            Version(installed), prereleases=True
        ):
            wrong.append(
                f"{requirement.name} {installed}, declared {requirement.specifier}"
            )

    if not wrong and not absent:
        return ("Package versions", OK, "all satisfy requirements.txt")

    parts = []
    if wrong:
        parts.append("does not match requirements.txt: " + "; ".join(wrong))
    if absent:
        parts.append("not installed: " + "; ".join(absent))
    return (
        "Package versions",
        BROKEN,
        ". ".join(parts)
        + ". Run: pip install -r requirements.txt --upgrade   -- until then, a "
        "local test run is not testing what CI tests.",
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

    # AN IMPORT ERROR IS NOT A BATFISH ERROR.
    #     This used to sit inside the same `except Exception` as the call
    #     below, so a ModuleNotFoundError -- the repository root missing from
    #     sys.path -- was reported as "the service did not answer". Batfish
    #     was fine every time. The message sent the reader to restart Docker,
    #     which cannot fix an import, in the one tool whose whole purpose is
    #     saying which piece is broken rather than that something is.
    try:
        from analysis.pipeline import connect
    except ImportError as error:
        return (
            "Batfish service",
            BROKEN,
            f"could not check -- Netwise's own code did not import, so this "
            f"says NOTHING about Batfish: {type(error).__name__}: "
            f"{str(error)[:120]}. Run from the repository root, and install "
            f"the dependencies (README step 4).",
        )

    try:
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
    """OPTIONAL. Absent, or running without the model this product actually
    calls, both mean degraded explanations rather than a broken install --
    but they are two different states, and this used to report only the
    first one (#234).

    THE PORT BEING OPEN IS NOT THE SAME CLAIM AS "THE MODEL EXISTS"
        Measured: a machine with Ollama installed and running, but with no
        models built at all, passed this check --

            $ ollama list
            NAME    ID    SIZE    MODIFIED
                                          <- empty

            $ python -m tools.preflight
            [  OK   ] Ollama (optional)
                       running

        -- because the old check was a TCP connect and nothing more.
        Meanwhile ai/explain.py calls `ollama.generate(model="netwise-warden",
        ...)`, which raises `ollama.ResponseError` (HTTP 404) when that model
        was never built with `ollama create`. So preflight said the machine
        was ready while every explanation was silently falling back to
        deterministic text -- the same "the service answered" vs "the thing
        actually works" conflation F-4 exists to prevent elsewhere, arriving
        through the setup tool instead of a finding.

        Fixed the same way check_batfish_service() already treats an open
        port as insufficient: ask Ollama which models it actually has, not
        just whether something is listening.
    """
    if not _port_open("localhost", OLLAMA_PORT, timeout=2.0):
        return (
            "Ollama (optional)",
            MISSING,
            "not running. Everything still works: explanations fall back to "
            "deterministic text, and the whole test suite passes without it.",
        )

    # AN IMPORT ERROR IS NOT AN OLLAMA ERROR, THE SAME REASON
    # check_batfish_service() SEPARATES THE TWO.
    try:
        import ollama

        from ai.explain import MODEL_NAME
    except ImportError as error:
        return (
            "Ollama (optional)",
            BROKEN,
            f"could not check which models are built -- Netwise's own code "
            f"did not import, so this says NOTHING about Ollama: "
            f"{type(error).__name__}: {str(error)[:120]}. Run from the "
            f"repository root, and install the dependencies (README step 4).",
        )

    try:
        built = ollama.list().models
    except Exception as error:  # noqa: BLE001 -- report anything, never raise
        return (
            "Ollama (optional)",
            BROKEN,
            f"port is open but could not list its models: "
            f"{type(error).__name__}: {str(error)[:120]}",
        )

    # Ollama reports tagged names ("netwise-warden:latest"); MODEL_NAME is
    # untagged, the same form ollama.generate() itself accepts and resolves.
    # Compare on the part before the colon so a tag can never cause a false
    # MISSING here.
    names = {(model.model or "").split(":")[0] for model in built}
    if MODEL_NAME in names:
        return ("Ollama (optional)", OK, f"running, and '{MODEL_NAME}' is built")

    return (
        "Ollama (optional)",
        MISSING,
        f"running, but the model '{MODEL_NAME}' has not been built yet. "
        f"Everything still works: explanations fall back to deterministic "
        f"text. Build it with: ollama create {MODEL_NAME} -f ai/Modelfile",
    )


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

REQUIRED = [check_python, check_dependencies, check_dependency_versions,
            check_docker,
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
    for (label, status, detail), _required in results:
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
