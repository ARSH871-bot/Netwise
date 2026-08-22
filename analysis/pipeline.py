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
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pybatfish.client.session import Session

from analysis import findings
from analysis import policy as policy_module
from analysis.checks import access_control, policy_compliance, risk, routing

# --- The check registry -----------------------------------------------------
#
# Maps the check name (which is also the "check" field in every finding it
# produces) to the function that runs it. Add your check here; one line.
CHECKS = {
    "access_control": access_control.run,
    "policy_compliance": policy_compliance.run,
    "routing": routing.run,
    # "risk":              risk.run,                # Samika
    #
    # change_impact is deliberately NOT here. It compares two snapshots, which
    # differentialReachability requires, and this registry hands a check exactly
    # one. It will be a separate entry point instead -- team decision, shape
    # still being agreed. Do not add it to CHECKS.
}


#: The port pybatfish's v2 API talks to. Only used for the reachability probe
#: below -- the Session works it out for itself.
BATFISH_V2_PORT = 9996


def connect(
    host: str = "localhost",
    probe_timeout: float = 2.0,
    probe_port: int = BATFISH_V2_PORT,
) -> Session:
    """Open a Batfish session. Raises if the service is not reachable.

    The probe exists for speed of *failure*, not for correctness. pybatfish
    retries before it gives up, so a stopped container makes the dashboard spin
    for a long time before saying anything. Measured 12 August:

        stopped container (port refuses)    21.0s  ->   4.0s
        wrong host (packets dropped)        88.9s  ->   2.0s

    If the probe succeeds we carry on and let pybatfish do the real check -- an
    open port is not proof that Batfish is healthy, so this only ever
    short-circuits the negative case.

    The 4.0s is not a bug: "localhost" resolves to both ::1 and 127.0.0.1, and
    `create_connection` gives each the full timeout in turn. Halving the timeout
    to make that number look better would also halve it for the single-address
    case, so it is left alone and written down instead.

    `probe_port` is a parameter rather than a constant because the probe is the
    one thing here that would wrongly fail a working setup: Batfish on a
    non-default port would be reachable to pybatfish and closed to the probe.
    Pass the real port, or `probe_timeout=0` to skip the probe entirely.
    """
    if probe_timeout > 0:
        _require_port_open(host, probe_port, probe_timeout)

    session = Session(host=host)
    # Cheapest call that actually proves the connection works -- constructing a
    # Session on its own does not contact the server.
    session.get_component_versions()
    return session


def _require_port_open(host: str, port: int, timeout: float) -> None:
    """Raise ConnectionError unless something accepts TCP on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as error:
        # Deliberately the same exception type pybatfish raises for an
        # unreachable server, so callers cannot tell the probe apart from the
        # real attempt and no caller needs to learn a new failure mode.
        raise ConnectionError(
            f"nothing is listening on {host}:{port} ({error})"
        ) from error


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
                detail=findings.describe_error(error),
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
    policy: Optional["policy_module.Policy"] = None,
) -> List[Dict[str, Any]]:
    """Analyse a config folder, optionally against the user's own policy (#87).

    `policy` is a validated `Policy` from `analysis.policy.load_policy()` or
    `load_policy_file()`. When given, policy-driven checks assert the USER's
    rules instead of Netwise's built-in example ones, and say so in every
    finding's evidence. When omitted, behaviour is exactly as before.

    Everything else about this function is unchanged; see `_analyse()` below,
    which is the original body. This wrapper exists only to install the policy
    and to guarantee it is cleared afterwards.
    """
    if policy is not None and not isinstance(policy, policy_module.Policy):
        raise TypeError(
            "analyse(policy=...) takes a Policy from load_policy() or "
            f"load_policy_file(), not {type(policy).__name__}. Passing a raw "
            "mapping would hand a check unvalidated user input."
        )

    # CLEARED IN A finally, AND THAT IS THE POINT.
    #     analyse() is called repeatedly in one process -- every /api/findings
    #     hit, every test. A policy that outlived its call would silently
    #     apply to the NEXT analysis of a different config: the #82 failure
    #     with a policy in place of a snapshot. A check raising must not be
    #     able to leave one installed either.
    policy_module.set_active_policy(policy)
    try:
        return _analyse(
            config_dir,
            check_names=check_names,
            host=host,
            network_name=network_name,
            snapshot_name=snapshot_name,
        )
    finally:
        policy_module.clear_active_policy()


def _analyse(
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
        ValueError: for either of two registration mistakes, both of which are
            programming errors rather than runtime conditions, so they fail
            loudly and immediately rather than being reported as findings:

            1. you asked for a check that is not registered in `CHECKS`;
            2. a key in `POST_PROCESSORS` is not a valid F-1 check name (#75).

            Both are checked before connecting, so neither depends on Batfish
            being reachable. The second is listed here because this docstring
            is how the rest of the team learned the contract, and a caller
            reading it would otherwise know only one of the two ways this
            function can raise -- noted by Shubham on #76.
    """
    # WHY THE POLICY IS INSTALLED BY THE CALLER ABOVE AND NOT PASSED IN HERE
    #     A check's signature is fixed by F-3 at `run(bf) -> list[dict]`, and
    #     `docs/design/pipeline-feature-shapes.md` was ADOPTED by all four
    #     signatures -- so a policy cannot travel as an argument without a
    #     contract change the whole team has to agree to. Installing it in
    #     `analyse()` keeps that contract untouched.
    #
    #     The alternative, each check loading a file itself, would put policy
    #     PARSING and therefore policy ERRORS inside three checks with three
    #     different failure behaviours. One place, one error path.
    config_dir = Path(config_dir)
    names = list(check_names) if check_names is not None else list(CHECKS)

    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        raise ValueError(
            f"Unknown check(s): {', '.join(unknown)}. "
            f"Registered checks are: {', '.join(CHECKS)}"
        )

    # Both registration mistakes are now caught in the same place, before any
    # work starts. run_post_processors() checks this too, for anyone calling it
    # directly -- but relying on that alone made the guarantee conditional on
    # Batfish being up, which is the opposite of what this docstring promised.
    #
    # Found by verifying the claim rather than reading it: with the container
    # OOM-killed, analyse() returned early via _every_check_failed() and an
    # invalid POST_PROCESSORS key was never detected at all. A registration bug
    # could therefore sit undiscovered on a machine where Batfish happened to
    # be down, and surface for the first time on someone else's.
    _check_registry_names()

    # --- Connect ------------------------------------------------------------
    try:
        bf = connect(host)
    except Exception as error:
        return _every_check_failed(
            names,
            summary="Analysis could not run: Batfish is not reachable",
            # The instruction comes FIRST and the raw error last. Measured: the
            # underlying ConnectionError is ~200 characters of urllib3 detail
            # ("Max retries exceeded with url: /v2/question_templates ...") and
            # putting it first pushed the one sentence a user can act on past
            # where anybody reads. The raw text is still here -- it is what
            # distinguishes a stopped container from a wrong host -- just after
            # the fix rather than in front of it.
            # The "if that reports..." clause is not padding. The first version
            # of this message asserted `docker start batfish` as THE fix.
            # Shubham hit the case it does not cover -- Docker Desktop itself
            # not running -- where that command fails with a daemon socket
            # error mentioning nothing about Batfish, having just been told
            # confidently that it was the answer. The old wording ("Is Docker
            # running, and the batfish container started?") covered it only by
            # being vague enough to send nobody anywhere; the gain in
            # directness lost that. One clause turns a dead end into a
            # sequence, and keeps the instruction first.
            detail=(
                f"Batfish is not answering at {host}. Start it with: "
                "docker start batfish   -- if that reports it cannot reach the "
                "Docker daemon, start Docker Desktop first, then run it again. "
                "(First time only: docker run --name batfish -d -p 9996:9996 "
                "-p 9997:9997 batfish/allinone.) "
                f"Underlying error: {findings.describe_error(error)}"
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

    # --- Then let the post-processors refine the combined list ---------------
    results = run_post_processors(results)

    return _finalise(results)


# ---------------------------------------------------------------------------
# The post-processor stage
#
# A post-processor is the second of the three shapes in
# docs/design/pipeline-feature-shapes.md (adopted, all four signatures). Unlike
# a check, it does not get a Batfish session -- it gets the COMBINED findings
# from every check that ran:
#
#     def refine(results: list[dict]) -> list[dict]
#
# `risk` is the reason this exists. Prioritisation has to see every finding to
# order them; as a registered check it would receive a Batfish session and be
# the one check unable to see what it is meant to prioritise.
#
# HOW TO ADD ONE (Samika: this is you)
#     1. Write   def refine(results: list[dict]) -> list[dict]   in your module
#     2. Add one line to POST_PROCESSORS below
#     3. Return the full list. Re-rate, re-order and annotate freely --
#        but read the two guarantees below before you do.
# ---------------------------------------------------------------------------

POST_PROCESSORS = {
    "risk": risk.refine,  # Samika -- ruleset in docs/severity-rules.md
}

# Ranked worst-first, so a HIGHER index is a LOWER severity.
_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}



def _check_registry_names() -> None:
    """Fail fast if a POST_PROCESSORS key is not a valid F-1 check name.

    See run_post_processors()'s docstring for why this matters (#75). Raised
    rather than reported, deliberately: this can only be wrong because someone
    registered a post-processor under a name F-1 does not know, which is a bug
    to fix at development time, not a condition to tell a user about.
    """
    unknown = sorted(set(POST_PROCESSORS) - set(findings.VALID_CHECKS))
    if unknown:
        raise ValueError(
            "POST_PROCESSORS keys must also be valid F-1 check names, because "
            "a violation is reported with check=<key>. Unknown: "
            f"{', '.join(unknown)}. Valid: {', '.join(sorted(findings.VALID_CHECKS))}."
        )


def run_post_processors(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run each post-processor over the combined findings, enforcing F-4.

    TWO GUARANTEES, ENFORCED HERE RATHER THAN DOCUMENTED
        A post-processor may re-rate, re-order and annotate. It may NOT:

        1. Downgrade a `status="error"` finding. An unrunnable check is a blind
           spot regardless of what any policy says about the device. Letting a
           scoring rule quietly file it below the fold re-creates the F-4
           failure by another route -- the user stops seeing that nobody
           looked.

        2. Drop a finding. Removing one is the same lie as never producing it:
           a missing check is indistinguishable from a clean one.

        Both were agreed as conditions of adopting this shape. They are checked
        here instead of trusted, because a rule that only exists in a document
        is a rule that holds until someone is in a hurry.

    A violation is not silently corrected. The original finding is restored AND
    an error finding is added saying what was attempted, because a
    post-processor trying to bury a blind spot is itself worth seeing.
    A REGISTRY KEY MUST ALSO BE A VALID F-1 CHECK NAME (#75)
        Both failure paths below report a misbehaving post-processor by
        building a finding with `check=name` -- the registry key. F-1 rejects
        any `check` outside `findings.VALID_CHECKS`, so the key is silently
        load-bearing.

        Found by Shubham while verifying the two guarantees before signing
        A-1. It is latent today, because `risk` is the only post-processor and
        happens to be a valid check name -- the invariant holds by coincidence
        of naming, which is not a guarantee.

        Left alone it fails in the worst possible place: the error paths.
        `_restore_protected_findings()` is called OUTSIDE the try, and
        `analyse()` does not wrap this function, so an unregistered key turns
        a contained, reportable fault into an uncaught ValueError out of the
        entry point the web layer calls -- breaking `analyse()`'s own promise
        that it never raises for an operational failure.

        So the names are checked ONCE, up front, before any post-processor
        runs. This is a programming error at registration, not a runtime
        condition, so it fails loudly and immediately rather than becoming a
        finding: turning it into a finding would hide a bug rather than
        surface one. The point is that it can no longer happen *while*
        reporting something else going wrong.
    """
    _check_registry_names()

    for name, refine in POST_PROCESSORS.items():
        before = {f["id"]: f for f in results}

        try:
            # Hand over copies. A post-processor that mutates in place cannot
            # then be compared against what it started with.
            refined = refine([dict(f) for f in results])
        except Exception as error:
            results = results + [
                findings.error_finding(
                    check=name,
                    summary=f"The {name.replace('_', ' ')} stage failed to run",
                    detail=findings.describe_error(error),
                    source=f"analysis/checks/{name}.py",
                )
            ]
            continue

        # Inside the try's blast radius by design (#75, second half — found by
        # Samika reviewing the first). A post-processor with a VALID name can
        # still return a malformed shape, and this call reads f["id"] on
        # whatever it returned. Left outside, a KeyError escaped
        # run_post_processors() and out of analyse() — the entry point the web
        # layer calls, and the one function documented never to raise for an
        # operational failure. Because `risk` runs in this stage, an escape
        # here does not spoil one finding, it takes down findings delivery for
        # the whole dashboard.
        try:
            results, complaints = _restore_protected_findings(name, before, refined)
        except Exception as error:
            results = results + [
                findings.error_finding(
                    check=name,
                    summary=f"The {name.replace('_', ' ')} stage returned something unusable",
                    detail=findings.describe_error(error),
                    source=f"analysis/checks/{name}.py",
                )
            ]
            continue
        results.extend(complaints)

    return results


def _restore_protected_findings(
    name: str,
    before: Dict[str, Dict[str, Any]],
    refined: List[Dict[str, Any]],
) -> tuple:
    """Undo anything a post-processor was not allowed to do, and report it."""
    kept = {f["id"]: f for f in refined}
    complaints: List[Dict[str, Any]] = []
    number = 800  # clear of check numbering and of the duplicate-id guard's 999

    for fid, original in before.items():
        current = kept.get(fid)

        if current is None:
            refined.append(original)
            number += 1
            complaints.append(
                findings.error_finding(
                    check=name,
                    device=original.get("device", "unknown"),
                    summary=f"The {name.replace('_', ' ')} stage dropped a finding",
                    detail=(
                        f"{fid} was removed and has been restored. A "
                        "post-processor may re-rate and re-order, never remove: "
                        "a missing finding is indistinguishable from one that "
                        "was never a problem."
                    ),
                    source="analysis/pipeline.py",
                    number=number,
                )
            )
            continue

        if original.get("status") != "error":
            continue

        was = _SEVERITY_RANK.get(original.get("severity", ""), 0)
        now = _SEVERITY_RANK.get(current.get("severity", ""), 0)
        if now > was:  # a higher rank index means it was downgraded
            current["severity"] = original["severity"]
            number += 1
            complaints.append(
                findings.error_finding(
                    check=name,
                    device=original.get("device", "unknown"),
                    summary=f"The {name.replace('_', ' ')} stage downgraded a blind spot",
                    detail=(
                        f"{fid} has status=error and its severity was lowered from "
                        f"{original['severity']} to {current.get('severity')}. "
                        "Restored. An unrunnable check is a blind spot whatever "
                        "the policy says about the device."
                    ),
                    source="analysis/pipeline.py",
                    number=number,
                )
            )

    return refined, complaints


def _finalise(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The ONE exit from analyse(). Every return path must go through here.

    Its whole job is to make sure the duplicate-id guard cannot be bypassed.

    This is not theoretical caution. The guard was originally applied only at
    the end of the happy path, and the four early returns above skipped it --
    which meant the ONE case it did not cover was "Batfish is down", by far the
    most common operational failure. Those paths emit one sentinel error per
    registered check, and until amendment A-2 two of them shared the "PC"
    prefix:

        AC-000 access_control | RT-000 routing | PC-000 policy_compliance
        PC-000 change_impact  | RK-000 risk            ^^^^^^ collision

    A-2 (#102) gave change_impact its own "CH-" prefix, so that particular
    pair can no longer occur. The guard stays, and this example is kept as
    history rather than deleted, for the reason Shubham gave when he raised
    the amendment: uniqueness across DIFFERENT checks is now structural, but
    uniqueness WITHIN one check is still only discipline. make_finding()
    takes `number` as a required argument and nothing stops a check passing
    the same one twice, and both sentinel helpers default to 0 -- so one
    check emitting a clean sentinel and an error sentinel in the same run
    still collides with itself. Defence in depth, not duplication.

    A consumer keying by id would then show four checks instead of five, with
    one of them simply absent -- not errored, not clean, gone. That is F-4 in
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
            "usage: python -m analysis.pipeline <config-folder> "
            "[--policy <file.json>] [check ...]\n"
            "example: python -m analysis.pipeline tests/fixtures/rtr-us5-secure\n"
            "example: python -m analysis.pipeline my-configs/ --policy my-policy.json"
        )
    argv = sys.argv[1:]

    # --policy is parsed by hand rather than with argparse, to keep this
    # consistent with the positional style the rest of the command already
    # uses and documented in CONTRIBUTING section 4.
    user_policy = None
    if "--policy" in argv:
        index = argv.index("--policy")
        if index + 1 >= len(argv):
            sys.exit("--policy needs a file path")
        path = argv[index + 1]
        del argv[index:index + 2]
        try:
            user_policy = policy_module.load_policy_file(path)
        except policy_module.PolicyError as error:
            # A policy the user got wrong is reported as a message, not a
            # traceback, and analysis does NOT proceed. Running with our
            # built-in rules after their file failed to load would silently
            # check assertions they did not make -- which is the #87
            # confusion arriving through the error path.
            sys.exit(f"Policy not loaded, so nothing was analysed.\n  {error}")
        # Both channels, not just renames. `assigned` reports values we
        # supplied because the user did not -- currently the rule numbers
        # that become finding ids. This module forbids SILENT defaults, and
        # printing only half of what we changed would be exactly that.
        for note in list(user_policy.renamed) + list(user_policy.assigned):
            print(f"note: {note}")

    config_dir = argv[0]
    requested = argv[1:] or None
    _print_summary(
        analyse(config_dir, check_names=requested, policy=user_policy)
    )


if __name__ == "__main__":
    main()
