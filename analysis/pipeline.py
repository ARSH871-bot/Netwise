"""
Netwise -- the shared analysis pipeline (F-3).

This is the backbone every feature plugs into. It connects to Batfish, loads a
config folder, runs the checks, and returns ONE list of findings in the F-1
format (docs/finding-format.md). The AI layer and the dashboard consume that
list and nothing else.

===========================================================================
HOW TO ADD YOUR CHECK  --  Ankeet, Shubham, Samika: this is all you need
===========================================================================

    1. Create   analysis/checks/<your_feature>.py
    2. Put one function in it:

           def run(bf: Session) -> list[dict]

       It gets a live Batfish session with the snapshot already loaded.
       Return a list of findings built with analysis.findings helpers.

    3. Add ONE line to the CHECKS dictionary below.

    Copy analysis/checks/access_control.py -- it is written as the template.

    You do NOT handle connecting, loading snapshots, or catching your own
    crashes. The pipeline does all of that. If your check raises, the pipeline
    converts it into a status="error" finding, so a bug in one feature can
    never take down the other three.

===========================================================================

THE ONE RULE THIS FILE ENFORCES (F-4)
    A failure must never disappear. If Batfish is unreachable, if the config
    will not parse, if a check crashes -- the user still gets a finding, with
    status="error", saying so. We never return a short list that quietly omits
    the check that broke, because a missing check looks identical to a clean
    one, and that is how a security tool ends up lying.

RUN IT
    python -m analysis.pipeline tests/fixtures/rtr-us5-secure
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pybatfish.client.session import Session

from analysis import findings
from analysis.checks import access_control, policy_compliance

# --- The check registry -----------------------------------------------------
#
# Maps the check name (which is also the "check" field in every finding it
# produces) to the function that runs it. Add your check here; one line.
CHECKS = {
    "access_control": access_control.run,
    "policy_compliance": policy_compliance.run,
    # "routing":           routing.run,             # Ankeet
    # "risk":              risk.run,                # Samika
    #
    # change_impact is deliberately NOT here. It compares two snapshots, which
    # differentialReachability requires, and this registry hands a check exactly
    # one. It will be a separate entry point instead -- team decision, shape
    # still being agreed. Do not add it to CHECKS.
}


def connect(host: str = "localhost") -> Session:
    """Open a Batfish session. Raises if the service is not reachable."""
    session = Session(host=host)
    # Cheapest call that actually proves the connection works -- constructing a
    # Session on its own does not contact the server.
    session.get_component_versions()
    return session


def load_snapshot(
    bf: Session, config_dir: Path, network_name: str, snapshot_name: str
) -> None:
    """Upload a config folder and have Batfish build a model of it.

    `config_dir` is the snapshot ROOT. Batfish expects the device files one
    level down, in a `configs/` subfolder. Pointing at the inner folder is the
    most common way to get a silently empty snapshot, so we check for it here
    and fail with a message that says what is actually wrong.
    """
    if not config_dir.is_dir():
        raise FileNotFoundError(f"Config folder not found: {config_dir}")
    if not (config_dir / "configs").is_dir():
        raise FileNotFoundError(
            f"No 'configs' subfolder inside {config_dir}. "
            "Batfish looks for device files in <snapshot>/configs/."
        )

    bf.set_network(network_name)
    bf.init_snapshot(str(config_dir), name=snapshot_name, overwrite=True)


def find_parse_problems(bf: Session) -> List[str]:
    """Return a description of every file Batfish did not fully understand.

    Empty list means every file parsed cleanly.

    Why this is strict: a line Batfish never parsed is a rule we will never
    analyse. If we ran the checks anyway, a user could see a clean result for a
    config we only partly read -- which is exactly the lie F-4 exists to
    prevent.

    TEAM DECISION PENDING: right now ANY status other than PASSED stops the
    analysis, including PARTIALLY_UNRECOGNIZED. That is the safe choice while
    we are on small test configs. Real-world configs often have a few
    unrecognised lines, and refusing to analyse them at all may prove too
    strict. When we hit that, the fix is to let the checks run but attach a
    loud "results may be incomplete" finding -- NOT to quietly ignore it.
    """
    frame = bf.q.fileParseStatus().answer().frame()

    if frame.empty:
        return ["Batfish found no configuration files to read"]

    problems = []
    for _, row in frame.iterrows():
        if row["Status"] != "PASSED":
            problems.append(f"{row['File_Name']} ({row['Status']})")
    return problems


def run_check(bf: Session, name: str) -> List[Dict[str, Any]]:
    """Run one registered check, converting any crash into an error finding.

    This is the isolation boundary. A check written by one team member must
    not be able to break the run for everyone else, so every exception it
    raises is caught here and turned into a finding the user can see.
    """
    try:
        results = CHECKS[name](bf)
    except Exception as error:
        return [
            findings.error_finding(
                check=name,
                summary=f"The {name.replace('_', ' ')} check failed to run",
                detail=f"{type(error).__name__}: {error}",
                source="analysis/checks/" + name + ".py",
            )
        ]

    # A check that returns nothing is almost certainly a bug -- it should have
    # returned a status="none" finding to say "I ran and found nothing". We
    # refuse to let that silence through.
    if not results:
        return [
            findings.error_finding(
                check=name,
                summary=f"The {name.replace('_', ' ')} check returned no findings",
                detail=(
                    "A check must return at least one finding. If it found "
                    "nothing, it should return a status='none' finding."
                ),
                source="analysis/checks/" + name + ".py",
            )
        ]

    return results


def analyse(
    config_dir: str | Path,
    check_names: Optional[Sequence[str]] = None,
    host: str = "localhost",
    network_name: str = "netwise",
    snapshot_name: str = "current",
) -> List[Dict[str, Any]]:
    """Analyse a config folder and return findings in the F-1 format.

    This is the function the web layer will call. It does NOT raise for
    operational failures -- an unreachable Batfish, an unparseable config and a
    crashing check all come back as status="error" findings, because the user
    needs to be told, not handed a stack trace.

    Args:
        config_dir:  snapshot root (device files live in <config_dir>/configs/)
        check_names: which checks to run; None means all registered ones

    Raises:
        ValueError: if you ask for a check that is not registered. That is a
            programming mistake, not a runtime condition, so it fails loudly
            and immediately rather than being reported as a finding.
    """
    config_dir = Path(config_dir)
    names = list(check_names) if check_names is not None else list(CHECKS)

    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ValueError(
            f"Unknown check(s): {', '.join(unknown)}. "
            f"Registered checks are: {', '.join(CHECKS)}"
        )

    # --- Connect ------------------------------------------------------------
    try:
        bf = connect(host)
    except Exception as error:
        return _every_check_failed(
            names,
            summary="Analysis could not run: Batfish is not reachable",
            detail=(
                f"Could not connect to Batfish at {host}: "
                f"{findings.describe_error(error)}. "
                "Is Docker running, and the batfish container started?"
            ),
            source=str(config_dir),
        )

    # --- Load the config ----------------------------------------------------
    try:
        load_snapshot(bf, config_dir, network_name, snapshot_name)
    except Exception as error:
        return _every_check_failed(
            names,
            summary="Analysis could not run: the config could not be loaded",
            detail=findings.describe_error(error),
            source=str(config_dir),
        )

    # --- Confirm Batfish understood it --------------------------------------
    try:
        problems = find_parse_problems(bf)
    except Exception as error:
        return _every_check_failed(
            names,
            summary="Analysis could not run: parse status could not be read",
            detail=findings.describe_error(error),
            source=str(config_dir),
        )

    if problems:
        return _every_check_failed(
            names,
            summary="Analysis could not run: the config did not fully parse",
            detail=(
                "Batfish could not fully read: "
                + "; ".join(problems)
                + ". Any rule it did not parse is a rule we cannot analyse."
            ),
            source=str(config_dir),
        )

    # --- Run the checks -----------------------------------------------------
    results: List[Dict[str, Any]] = []
    for name in names:
        results.extend(run_check(bf, name))

    return _finalise(results)


def _finalise(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The ONE exit from analyse(). Every return path must go through here.

    Its whole job is to make sure the duplicate-id guard cannot be bypassed.

    This is not theoretical caution. The guard was originally applied only at
    the end of the happy path, and the four early returns above skipped it --
    which meant the ONE case it did not cover was "Batfish is down", by far the
    most common operational failure. Those paths emit one sentinel error per
    registered check, and two of our checks share the "PC" prefix:

        AC-000 access_control | RT-000 routing | PC-000 policy_compliance
        PC-000 change_impact  | RK-000 risk            ^^^^^^ collision

    A consumer keying by id would then show four checks instead of five, with
    change_impact simply absent -- not errored, not clean, gone. That is F-4 in
    its purest form on the likeliest failure path.

    So: if you add a return to analyse(), route it through this function.
    """
    return results + duplicate_id_findings(results)


def _every_check_failed(
    names: Sequence[str], *, summary: str, detail: str, source: str
) -> List[Dict[str, Any]]:
    """Nothing could run: report it once per requested check.

    One finding per check rather than one overall, so every feature shows as
    errored in the dashboard instead of silently missing. A check that is absent
    from the results looks identical to one that passed.
    """
    return _finalise(
        [
            findings.error_finding(
                check=name, summary=summary, detail=detail, source=source
            )
            for name in names
        ]
    )


def duplicate_id_findings(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Report any `id` used by more than one finding. Empty list means all unique.

    WHY THIS EXISTS
        docs/finding-format.md calls `id` a "unique identifier", and anything
        downstream is entitled to believe it -- a dashboard keying findings by
        id, the AI layer referring to one, a diff between two runs. Nothing
        currently enforces it, and it is genuinely easy to break: two checks can
        share an ID prefix (policy_compliance and change_impact both map to
        "PC"), and every check picks its own numbers.

        The failure is silent and it is the F-4 failure wearing a different hat.
        If a consumer keys by id, one of a colliding pair disappears -- and if
        the one that disappears is a status="error", the user reads "all clear"
        with no sign that a check never ran. Same lie, reached through `id`
        instead of through `status`.

    WHAT IT DOES NOT DO
        It does not renumber anything. Silently disambiguating would hide the
        defect, which is the behaviour we are trying to prevent. Both findings
        stay in the list exactly as their checks produced them, and this adds a
        loud error finding on top saying the contract was broken.

    Attribution: the finding is filed against the FIRST check involved in the
    collision -- an arbitrary but stable choice, since the fault is really the
    pipeline's to report and F-1 requires a real check name.
    """
    seen: Dict[str, List[str]] = {}
    for finding in results:
        seen.setdefault(finding["id"], []).append(finding["check"])

    collisions = {fid: checks for fid, checks in seen.items() if len(checks) > 1}
    if not collisions:
        return []

    described = "; ".join(
        f"{fid} used by {', '.join(checks)}" for fid, checks in sorted(collisions.items())
    )
    first_check = sorted(collisions.items())[0][1][0]
    return [
        findings.error_finding(
            check=first_check,
            summary="Internal error: two findings share an id",
            detail=(
                f"docs/finding-format.md requires ids to be unique. Duplicates: "
                f"{described}. Every finding is still listed below, but anything "
                "keying by id would silently drop one of each pair."
            ),
            source="analysis/pipeline.py",
            # 999 keeps this clear of the sentinels (000) and of any real
            # finding numbering, so the guard cannot collide with what it guards.
            number=999,
        )
    ]


# ---------------------------------------------------------------------------
# Command line entry point -- handy for trying the pipeline by hand.
# ---------------------------------------------------------------------------


def _print_summary(results: List[Dict[str, Any]]) -> None:
    """Print findings as JSON, then a one-line count per status."""
    print(json.dumps(results, indent=2))
    print()
    for status in ("found", "none", "error"):
        count = sum(1 for f in results if f["status"] == status)
        print(f"  {status:<6} {count}")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(
            "usage: python -m analysis.pipeline <config-folder> [check ...]\n"
            "example: python -m analysis.pipeline tests/fixtures/rtr-us5-secure"
        )
    config_dir = sys.argv[1]
    requested = sys.argv[2:] or None
    _print_summary(analyse(config_dir, check_names=requested))


if __name__ == "__main__":
    main()
