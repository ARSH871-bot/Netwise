"""
Netwise -- CVE mapping check (Samika's feature, #239).

WHAT THIS CHECK DOES
    Reads the software version a device's config declares, looks that version
    up in the offline dataset that ships with the repository, and reports what
    the dataset says about it.

WHAT IT CANNOT DO, SAID FIRST BECAUSE EVERYTHING ELSE DEPENDS ON IT
    It cannot tell you a device is vulnerable.

    A running-config's `version` line carries the TRAIN -- "15.2" -- and never
    the build. The precise release, 15.2(4)M6, appears only in `show version`
    output, which is runtime state and is not in an exported config at all.
    Most of the advisories in the dataset additionally require a feature to be
    switched on: Smart Install running, the web UI reachable, IKEv1
    terminating on the device.

    So a match here means "this train appears in these advisories, and they
    are worth checking against this device". It does not mean "this device is
    affected". Every `found` finding this check produces says so in its own
    evidence, in words, because a reader who takes it as confirmation will act
    on a claim the check never made.

WHY SEVERITY IS CAPPED AT MEDIUM, ALWAYS
    The dataset records advisories rated `critical` with a CVSS of 10.0. This
    check still reports `medium`, and will not report `high` for any input.

    That is not a judgement about the CVE. It is a statement about THIS
    CHECK'S CONFIDENCE. Severity in this project drives a worst-first list
    that people read top-down, and `high` in that list means "act on this".
    A train-level match cannot support that instruction, because a human still
    has to confirm the exact build and the enabled feature set before it is
    known to apply at all. Rating it `high` would let the ordering claim a
    certainty the evidence does not have -- and it would push genuine,
    confirmed access-control failures below a finding that might turn out to
    be nothing.

    This is the same distinction `analysis/checks/risk.py` makes about what a
    rule is and is not claiming: R-3 rates a routing failure `medium` not
    because outages do not matter but because the check cannot tell an outage
    from a control doing its job. Same shape here -- the cap describes the
    limits of the evidence, not the seriousness of the advisory.

    The cap is enforced in TWO places on purpose, and they are not duplicates:
    here, so the check never emits `high`; and in `risk.apply_business_context()`
    as a ceiling, because business-context escalation would otherwise take a
    `medium` finding on a device the user marked `critical` up to `high` and
    quietly undo this reasoning through a different feature.

WHY IT READS RAW TEXT RATHER THAN BATFISH'S MODEL
    Measured, not assumed: `nodeProperties` returns 37 columns for a Cisco IOS
    snapshot and the closest any of them gets to a version is
    `Configuration_Format = CISCO_IOS`, which is the vendor and syntax family.
    The model does not carry a version. See `analysis/config_version.py`.

    The raw text is still reached THROUGH the session -- `fileParseStatus()`
    names the files, `get_snapshot_input_object_text()` returns each one -- so
    this check keeps F-3's `run(bf)` signature and needs no new argument.
    Verified against a live Batfish before the check was written, because if
    it had not worked this feature would have needed a contract change that
    takes all four of us.

REGISTRATION: NOT IN `CHECKS`, AND THE REASON IS NOT TECHNICAL
    This check fits `CHECKS` perfectly -- right signature, no extra inputs, it
    would work today. It is deliberately left out anyway, because running it
    requires "cve_mapping" in `findings.VALID_CHECKS`, and that file says:

        "Add to this ONLY by team agreement -- the dashboard and the AI layer
         both switch on these names."

    CLAUDE.md section 7a says the same about the field vocabulary. So wiring
    this into the pipeline would put an unratified vocabulary addition into
    every scan, which is precisely what `docs/finding-format.md` spends two
    paragraphs regretting about A-2: the code merged while the table was
    incomplete, and the regret then became someone else's status claim.

    The vocabulary entries exist so the check can be reviewed and tested; the
    registration does not, so nothing runs before the team agrees. `run(bf)`
    is callable directly and every test here does exactly that.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pybatfish.client.session import Session

from analysis import cve_data as cve_dataset
from analysis import findings
from analysis.config_version import find_version

CHECK_NAME = "cve_mapping"

#: THE CEILING. See the module docstring: this is about what the check can
#: claim, not about how bad the advisory is. `high` is never emitted.
MAX_SEVERITY = "medium"

#: Sentinel numbering. `000` is the clean sentinel (`no_issues_finding`'s
#: default). Errors are numbered from 050 so a run that produces both a clean
#: result for one device and an error for another cannot collide with itself
#: -- `make_finding` does not enforce uniqueness within a check, and
#: `pipeline.duplicate_id_findings()` is a backstop rather than a licence.
ERROR_NUMBER_BASE = 50


def _severity_for(advisories: List[Dict[str, Any]]) -> str:
    """Always MAX_SEVERITY. The advisories are not consulted, on purpose.

    Written as a function taking the advisories it then ignores, rather than
    as a constant, because the tempting change is to read `cisco_severity`
    here and map `critical` to `high`. This is where someone would make it,
    and this docstring is what they should read first: the cap is about the
    CHECK's confidence, not the CVE's seriousness, so a more severe advisory
    does not make a train-level guess more certain.

    If the check ever learns the exact build -- from `show version` output
    alongside the config, say -- then it can claim more, and this is the
    function to change. Not before.
    """
    return MAX_SEVERITY


def _device_configs(bf: Session) -> Tuple[List[Tuple[str, str, str]], Optional[str]]:
    """[(device, filename, config_text)], or ([], reason) if we could not look.

    Returns a reason rather than raising, so the caller can turn "we could not
    read the configs" into a `status="error"` finding instead of letting the
    pipeline's crash isolation report it as a broken check. Not being able to
    read a file and the check being broken are different things.
    """
    try:
        frame = bf.q.fileParseStatus().answer().frame()
    except Exception as error:  # noqa: BLE001 -- reported, not swallowed
        return [], findings.describe_error(error)

    out: List[Tuple[str, str, str]] = []
    for _, row in frame.iterrows():
        filename = str(row.get("File_Name", ""))
        nodes = list(row.get("Nodes") or [])
        if not filename or not nodes:
            continue
        try:
            text = bf.get_snapshot_input_object_text(filename)
        except Exception:  # noqa: BLE001
            # One unreadable file must not lose the others. The device is
            # still reported below, as "no version found", which is the
            # honest outcome: we did not read a version for it.
            text = ""
        for node in nodes:
            out.append((str(node), filename, text))
    return out, None


def run(bf: Session) -> List[Dict[str, Any]]:
    """Map each device's declared software version to known advisories.

    Four outcomes, one per acceptance criterion on #239, and the two `error`
    ones are the point of the check rather than its edge cases:

        no version line              -> error   "we could not find a version"
        version, not in the dataset  -> error   "we have no data for it"
        version, assessed, findings  -> found   "worth checking" (medium)
        version, assessed, nothing   -> none    "we looked, nothing recorded"

    An unmatched version NEVER produces `none`. That is AC-2, and it is the
    same claim F-4 makes about the difference between a check that ran and one
    that could not: "we have no data about your software" and "your software
    is fine" are different sentences, and only one of them is true here.
    """
    results: List[Dict[str, Any]] = []
    number = ERROR_NUMBER_BASE

    def next_error_number() -> int:
        nonlocal number
        number += 1
        return number

    # --- The dataset. If it will not load, nothing else is knowable. --------
    try:
        data = cve_dataset.load_cve_data()
    except Exception as error:  # noqa: BLE001
        return [
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="The CVE reference dataset could not be loaded",
                detail=(
                    "No software version could be checked against known "
                    "advisories, because the dataset itself did not load: "
                    f"{findings.describe_error(error)}. Nothing is claimed "
                    "about any device's software either way."
                ),
                source="analysis/data/cisco_ios_cves.json",
                number=ERROR_NUMBER_BASE,
            )
        ]

    provenance = data.provenance()

    configs, failure = _device_configs(bf)
    if failure is not None:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="Device configurations could not be read",
                detail=(
                    "The software version of each device is read from its "
                    f"configuration text, and that could not be retrieved: "
                    f"{failure}. Nothing is claimed about any device's "
                    f"software. [{provenance}]"
                ),
                source="analysis/checks/cve_mapping.py",
                number=ERROR_NUMBER_BASE,
            )
        ]

    if not configs:
        return [
            findings.error_finding(
                check=CHECK_NAME,
                device="unknown",
                summary="No device configurations were available to check",
                detail=(
                    "This snapshot reported no parsed configuration files, so "
                    "no software version could be read from it. Nothing is "
                    f"claimed about any device's software. [{provenance}]"
                ),
                source="analysis/checks/cve_mapping.py",
                number=ERROR_NUMBER_BASE,
            )
        ]

    for device, filename, text in configs:
        version = find_version(text)

        # --- AC-1: no version line ---------------------------------------
        if version is None:
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=device,
                    summary=f"No software version is declared in {device}'s config",
                    detail=(
                        "This configuration does not declare a software "
                        "version, so it could not be checked against known "
                        "advisories. This is NOT a statement that the "
                        "software is current -- nothing is known about it. "
                        "A Cisco IOS running-config declares its train on a "
                        f"top-level 'version' line. [{provenance}]"
                    ),
                    source=filename,
                    number=next_error_number(),
                )
            )
            continue

        # --- AC-2: a version we have no data for --------------------------
        #
        # ASKED BEFORE advisories_for(), AND THAT ORDER IS THE CRITERION.
        # An unassessed train and an assessed-with-nothing-recorded train
        # both return an empty advisory list. Reading the list first would
        # merge them and report a clean result for a version nobody looked
        # at, which is exactly what AC-2 forbids.
        if not data.is_assessed(version):
            results.append(
                findings.error_finding(
                    check=CHECK_NAME,
                    device=device,
                    summary=(
                        f"No CVE data available for {device}'s software "
                        f"version ({version})"
                    ),
                    detail=(
                        f"{device} declares version {version}, which this "
                        "dataset does not cover, so it could not be checked. "
                        "This is NOT a clean result: an unmatched version "
                        "means nobody looked, not that nothing was found. "
                        f"Versions this dataset covers: "
                        f"{', '.join(data.assessed_trains)}. [{provenance}]"
                    ),
                    source=filename,
                    number=next_error_number(),
                )
            )
            continue

        advisories = data.advisories_for(version)

        # --- AC-4 clean: assessed, nothing recorded -----------------------
        if not advisories:
            results.append(
                findings.no_issues_finding(
                    check=CHECK_NAME,
                    device=device,
                    summary=(
                        f"No known advisories for {device}'s software "
                        f"version ({version})"
                    ),
                    detail=(
                        f"{device} declares version {version}. This dataset "
                        "has assessed that train and recorded no advisories "
                        "against it. This is a checked result, not an "
                        f"absence of data. [{provenance}]"
                    ),
                    source=filename,
                )
            )
            continue

        # --- a genuine match: "worth checking", never "confirmed" ---------
        listed = ", ".join(a["id"] for a in advisories)
        conditions = "; ".join(
            f"{a['id']} requires {a['requires']}"
            for a in advisories
            if a.get("requires")
        )
        results.append(
            findings.make_finding(
                check=CHECK_NAME,
                severity=_severity_for(advisories),
                device=device,
                summary=(
                    f"{device} runs software ({version}) named in "
                    f"{len(advisories)} known advisor"
                    f"{'y' if len(advisories) == 1 else 'ies'} -- worth checking"
                ),
                detail=(
                    f"{device} declares version {version}, which appears in: "
                    f"{listed}. "
                    "THIS IS NOT CONFIRMATION THAT THE DEVICE IS AFFECTED. A "
                    "config declares a TRAIN, not the exact build -- the "
                    "precise release appears only in 'show version' output, "
                    "which is runtime state and not in an exported config. "
                    "Most of these also require a feature to be enabled"
                    f"{': ' + conditions if conditions else ''}. "
                    "Confirm the running build and feature set before "
                    f"treating this as urgent. [{provenance}]"
                ),
                source=filename,
                status="found",
                number=len(
                    [r for r in results if r.get("status") == "found"]
                ) + 1,
            )
        )

    return results
