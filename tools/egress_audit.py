"""Run a real scan with the egress guard on, and print what it saw. US-40 (#332).

    python -m tools.egress_audit                       # a bundled fixture
    python -m tools.egress_audit my-configs/           # your own

WHAT THIS IS FOR
    CLAUDE.md section 5 promises that no configuration data reaches any cloud
    service. Until now that promise was supported by reading the source. This
    runs the product for real and reports every outbound connection it
    attempted, so the promise can be checked instead of believed.

WHAT A CLEAN RESULT LOOKS LIKE
    Every attempt allowed, every allowed attempt either Batfish or the local
    model, and `refused: 0`. A refusal is not a crash -- it is this tool doing
    the job it exists for, and the row names the file that tried.

WHY IT PRINTS THE LIMITS EVERY TIME
    `refused: 0` is a narrower statement than "nothing left this machine",
    and the gap between those two sentences is exactly where a security claim
    goes wrong. The limits are printed with the result rather than kept in a
    docstring somebody may not read.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    # `python tools/egress_audit.py` puts tools/ on sys.path, not the
    # repository root, so the product package would not import. See
    # tests/test_tools_invocation.py, which holds every tool to this.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import egress                                   # noqa: E402
from analysis import pipeline                                 # noqa: E402

DEFAULT_SNAPSHOT = Path("tests/fixtures/rtr-us5-insecure")


def _rule() -> None:
    print("-" * 78)


def main() -> int:
    target = Path(sys.argv[1]) if sys.argv[1:] else DEFAULT_SNAPSHOT
    if not target.exists():
        print(f"No such config folder: {target}")
        return 2

    egress.reset()
    if not egress.install():
        print(f"The guard is switched off ({egress.GUARD_ENV}=0). Nothing to "
              f"report, and nothing was checked -- which is not the same as "
              f"a clean result.")
        return 2

    print(f"Netwise egress audit -- analysing {target}")
    _rule()
    allowed_now = egress.allowlist()
    print("Allowed for this deployment, derived from its own configuration:")
    for host, ports in sorted(allowed_now.items()):
        print(f"    {host:<24} {', '.join(str(p) for p in sorted(ports))}")
    print("    plus loopback, which is this machine talking to itself")
    _rule()

    failure = None
    try:
        results = pipeline.analyse(target)
        print(f"Scan completed: {len(results)} finding(s).")
    except egress.EgressRefused as refused:
        failure = str(refused)
        print("Scan STOPPED by the guard.")
        print(f"    {failure}")
    except Exception as error:                      # noqa: BLE001
        # Batfish being down is not an egress finding, and reporting it as
        # one would be the "could not check" versus "checked and clean"
        # confusion this project exists to avoid.
        print(f"Scan did not complete: {type(error).__name__}: {error}")
        print("    This is a scan failure, not an egress finding. The "
              "connection record below is still whatever was attempted.")

    _rule()
    report = egress.describe()
    if not report["attempts"]:
        print("No outbound connection was attempted at all.")
    else:
        print(f"{len(report['attempts'])} outbound connection attempt(s):")
        print()
        print(f"    {'VERDICT':<9} {'DESTINATION':<26} {'FROM':<34}")
        for attempt in report["attempts"]:
            verdict = "allowed" if attempt["allowed"] else "REFUSED"
            destination = f"{attempt['host']}:{attempt['port']}"
            print(f"    {verdict:<9} {destination:<26} {attempt['component']:<34}")
            if not attempt["allowed"]:
                print(f"              {attempt['reason']}")

    _rule()
    print(f"allowed: {report['allowed']}    refused: {report['refused']}")
    print()
    print("What this does NOT prove:")
    for limit in report["limits"]:
        print(f"  - {limit}")

    egress.uninstall()
    return 1 if report["refused"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
