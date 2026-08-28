"""Netwise -- build a multi-device snapshot, for scale work (#218).

WHY THIS EXISTS
    Every fixture in this repository was one or two devices. Real networks
    arrive as a folder of fifty, and nothing was known about behaviour at that
    size -- #218 recorded it as the one gap where we genuinely did not know how
    bad it was.

    The answer, measured with this tool, turned out to be reassuring about
    speed and alarming about coverage. See docs/scale.md.

WHY A GENERATOR AND A SMALL COMMITTED FIXTURE, RATHER THAN FIFTY FILES IN GIT
    tests/fixtures/multi-device-10/ is committed, because a fixture the suite
    cannot reach is not a fixture. Ten is enough to exercise every behaviour
    that only appears with more than one device -- coverage reporting, device
    scoping, the PC-049 card -- and small enough to read.

    Fifty identical configs would add 40 more files and no new behaviour. The
    larger sizes are generated on demand instead, which is also how the timing
    figures in docs/scale.md were taken.

    This follows tools/make_diagrams.py and tools/make_traceability.py: the
    generator is committed so the artefact can be rebuilt rather than trusted,
    and so a change to it is reviewable.

WHAT THIS IS HONEST ABOUT
    These are NOT a realistic network. Every device is the same router with a
    different name and LAN, there is no routing between them, and no device
    references another. What that buys is a real answer to "how does the
    pipeline behave with N devices in one snapshot". What it does NOT buy is
    anything about topology, convergence, or cross-device analysis -- a real
    fifty-device network is harder in ways this cannot show, and any figure
    taken from it should be read as a floor rather than an estimate.

RUN
    python -m tools.make_scale_fixture              # rebuild the committed 10
    python tools/make_scale_fixture.py              # same, script form
    python -m tools.make_scale_fixture --devices 50 --out /tmp/n50
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

if __package__ in (None, ""):                    # script form, see CLAUDE.md 8
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = REPO_ROOT / "tests" / "fixtures" / "rtr-us5-secure" / "configs" / "rtr-us5.cfg"
DEFAULT_OUT = REPO_ROOT / "tests" / "fixtures" / "multi-device-10"
DEFAULT_DEVICES = 10

#: The first device keeps the name our built-in rules assert about, so the
#: snapshot exercises the INTERESTING case: some devices covered by policy and
#: some not. A snapshot where nothing is covered only ever reaches the PC-050
#: path, which the single-device fixtures already test.
COVERED_DEVICE = "rtr-us5"

HEADER = """!
! Netwise test fixture -- SYNTHETIC, GENERATED. Not a real network.
!
! Built by tools/make_scale_fixture.py. Do not edit by hand: rebuild it.
!
! One of {total} devices in this snapshot. Every device is the same router
! with its own name and LAN. There is NO routing between them and no device
! references another, so this exercises snapshot SIZE and policy COVERAGE,
! and says nothing about topology.
!
! {role}
!
"""


def _device_config(index: int, total: int) -> "tuple[str, str]":
    """One device's name and config text.

    Device 0 is `rtr-us5`, which the built-in policy names. Every other device
    is `rtr-devNNN` on its own /24, which no rule mentions -- so the snapshot
    contains both a covered and an uncovered device, which is the state
    PC-049 exists to report (#228).
    """
    template = TEMPLATE.read_text()
    body = template.split("hostname", 1)[1]
    body = "hostname" + body

    if index == 0:
        name = COVERED_DEVICE
        role = "COVERED by the built-in policy -- rules assert about this one."
    else:
        name = "rtr-dev%03d" % index
        role = "NOT covered by any built-in rule -- PC-049 should name it."
        octet = 10 + index
        body = body.replace("hostname rtr-us5", "hostname " + name)
        body = body.replace("10.10.10.1 255.255.255.0", "10.%d.10.1 255.255.255.0" % octet)
        body = body.replace("10.10.10.0 0.0.0.255", "10.%d.10.0 0.0.0.255" % octet)

    return name, HEADER.format(total=total, role=role) + body


def build(devices: int, out: Path) -> Path:
    """Write a snapshot of `devices` routers into `out`, replacing what is there."""
    if devices < 1:
        raise ValueError("a snapshot needs at least one device, got %d" % devices)

    configs = out / "configs"
    if out.exists():
        shutil.rmtree(out)
    configs.mkdir(parents=True)

    for i in range(devices):
        name, text = _device_config(i, devices)
        (configs / (name + ".cfg")).write_text(text)

    return out


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--devices", type=int, default=DEFAULT_DEVICES,
                        help="how many routers (default: %d)" % DEFAULT_DEVICES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="snapshot directory to write (default: the committed fixture)")
    args = parser.parse_args(argv)

    out = build(args.devices, args.out)
    print("Wrote %d device(s) to %s" % (args.devices, out))
    print("  covered by the built-in policy : %s" % COVERED_DEVICE)
    print("  not covered by any rule        : %d" % (args.devices - 1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
