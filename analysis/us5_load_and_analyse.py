"""
Netwise -- US-5: load a configuration file WE provide and analyse it.

WHY THIS EXISTS
    The Sprint 1 smoke test proved Batfish works, but it used Batfish's own
    bundled tutorial snapshot. That does not prove much about OUR tool -- of
    course the vendor's example works with the vendor's software.

    US-5 closes that gap. This script loads a config file we wrote ourselves,
    confirms Batfish actually understood it, and asks real questions about it.
    That is the thing a client cares about: "will it read MY config?"

WHAT IT DOES
    1. Connects to Batfish.
    2. Loads configs/my-snapshot as a snapshot.
    3. Runs fileParseStatus() and STOPS if the config did not parse.
    4. Runs testFilters for a DNS flow that the ACL should PERMIT.
    5. Runs testFilters for an HTTP flow that the ACL should DENY.

THE CONFIG UNDER TEST (configs/my-snapshot/configs/rtr-us5.cfg)
    Device rtr-us5 has ACL `acl_in` applied inbound on GigabitEthernet0/0:

        permit udp 10.10.10.0 0.0.0.255 host 218.8.104.58 eq domain
        permit tcp 10.10.10.0 0.0.0.255 host 10.20.0.5 eq 443
        deny   ip any any

    In plain English: this network may look up DNS names on one specific DNS
    server, and may reach one specific internal server over HTTPS. Everything
    else is blocked.

    The two flows below are chosen to land on opposite sides of that policy.
    The DENY test deliberately targets 10.20.0.5 -- the SAME server the ACL
    permits over HTTPS -- but over plain HTTP. So the contrast is not "allowed
    server vs blocked server", it is "secure traffic to this server is allowed,
    insecure traffic to the same server is not". That is a much sharper
    demonstration that Batfish reasons about the whole flow, not just addresses.

PREREQUISITES
    - Docker running, with the Batfish container up:
        docker start batfish
    - pip install -r requirements.txt

RUN
    python analysis/us5_load_and_analyse.py

NOTE ON SPEED: the first snapshot load after the container starts is slow
(often a few minutes) while Batfish's JVM warms up and parses the configs.
That is normal, not a hang.
"""

import logging
import sys
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints
from requests.exceptions import ConnectionError as RequestsConnectionError

# --- What we are analysing --------------------------------------------------

# The snapshot root. Batfish expects device files inside a `configs/`
# subfolder, which is why the path is nested: the ROOT we hand Batfish is
# configs/my-snapshot, and the device file lives at
# configs/my-snapshot/configs/rtr-us5.cfg. Pointing Batfish at the inner
# folder is the single most common way to get an empty snapshot.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_DIR = PROJECT_ROOT / "configs" / "my-snapshot"

# A Batfish "network" is a container for snapshots; a "snapshot" is one set of
# config files. Naming both explicitly keeps this run from colliding with the
# Sprint 1 smoke test's data.
NETWORK_NAME = "netwise-us5"
SNAPSHOT_NAME = "us5"

# The device and filter we interrogate. These names come from the config file
# itself -- `hostname rtr-us5` and `ip access-list extended acl_in`.
NODE = "rtr-us5"
FILTER = "acl_in"


def connect_to_batfish() -> Session:
    """Open a session against the Batfish container, or explain why we can't."""
    print("[1/5] Connecting to Batfish at localhost...")
    try:
        bf = Session(host="localhost")
        version = bf.get_component_versions().get("Batfish")
    except RequestsConnectionError:
        # This is the common case: Docker or the container is not running.
        sys.exit(
            "      CANNOT REACH BATFISH on localhost:9996/9997.\n"
            "      Batfish does the analysis, so nothing below can run without it.\n"
            "      Check, in this order:\n"
            "        1. Is Docker itself running?     docker ps\n"
            "        2. Is the container started?     docker start batfish\n"
            "      Note the container needs ~30s after starting before it answers."
        )
    print(f"      Connected. Batfish service version: {version}")
    return bf


def load_snapshot(bf: Session) -> None:
    """Upload our config folder and have Batfish build a model from it.

    init_snapshot is the step that does the real work: Batfish reads every
    file, parses it into a vendor-neutral model of the network, and keeps that
    model in memory for questions to run against. overwrite=True means "throw
    away any previous snapshot of this name", so repeated runs stay clean.
    """
    print(f"[2/5] Loading snapshot from {SNAPSHOT_DIR} ...")

    # Fail early with a readable message rather than letting Batfish return an
    # empty snapshot that produces confusing "node not found" errors later.
    if not SNAPSHOT_DIR.is_dir():
        sys.exit(f"      SNAPSHOT FOLDER NOT FOUND: {SNAPSHOT_DIR}")
    if not (SNAPSHOT_DIR / "configs").is_dir():
        sys.exit(
            f"      MISSING 'configs' SUBFOLDER inside {SNAPSHOT_DIR}.\n"
            "      Batfish looks for device files in <snapshot>/configs/."
        )

    bf.set_network(NETWORK_NAME)
    try:
        bf.init_snapshot(str(SNAPSHOT_DIR), name=SNAPSHOT_NAME, overwrite=True)
    except Exception as error:
        sys.exit(f"      SNAPSHOT FAILED TO LOAD: {error}")
    print("      Snapshot loaded.")


def check_parse_status(bf: Session) -> None:
    """Confirm Batfish actually UNDERSTOOD the config before we trust answers.

    This is the most important safety check in the script. Batfish will happily
    load a file it only partly understands, and then answer questions based on
    the parts it did understand -- silently ignoring the rest. For a security
    tool that is dangerous: a rule Batfish never parsed is a rule we will never
    report on, and the user would see a clean result that is actually blind.

    So: PASSED continues, anything else stops the run loudly.
    """
    print("[3/5] Checking the config parsed...")
    frame = bf.q.fileParseStatus().answer().frame()

    if frame.empty:
        sys.exit(
            "      NO FILES PARSED. Batfish found nothing to read.\n"
            f"      Check that device files exist in {SNAPSHOT_DIR / 'configs'}."
        )

    print()
    print(frame.to_string(index=False))
    print()

    # Status is PASSED / PARTIALLY_UNRECOGNIZED / FAILED per file.
    bad = frame[frame["Status"] != "PASSED"]
    if not bad.empty:
        sys.exit(
            "      CONFIG DID NOT FULLY PARSE -- stopping.\n"
            "      Any line Batfish could not read is a rule we cannot analyse,\n"
            "      so continuing would risk reporting a clean result on a config\n"
            "      we only partly understood.\n"
            f"      Problem files: {', '.join(bad['File_Name'].tolist())}"
        )
    print(f"      All {len(frame)} file(s) parsed cleanly.")


def test_one_flow(
    bf: Session,
    step: str,
    description: str,
    headers: HeaderConstraints,
    expected_action: str,
) -> bool:
    """Ask Batfish how `acl_in` treats ONE specific flow, and check the answer.

    testFilters is the "spot check" question: given one concrete packet, does
    this filter permit or deny it, and WHICH LINE decided? That last part is
    what makes Batfish explainable -- the Line_Content column is the evidence
    the AI layer will later rephrase into plain English. Without it we could
    only say "blocked"; with it we can say "blocked BY THIS RULE".

    Returns True if the result matched what we expected.
    """
    print(f"[{step}/5] {description}")
    answer = bf.q.testFilters(
        nodes=NODE,
        filters=FILTER,
        # startLocation tells Batfish where the packet enters the device. It
        # matters because a filter's behaviour can depend on the incoming
        # interface.
        startLocation=NODE,
        headers=headers,
    ).answer()

    # Batfish hands every answer back as a pandas DataFrame. Turning these
    # frames into structured data is exactly the problem the Sprint 2 pipeline
    # has to solve -- a printed table cannot ground an AI explanation.
    frame = answer.frame()
    if frame.empty:
        print("      NO RESULT -- check the node and filter names.")
        return False

    row = frame.iloc[0]
    action = row["Action"]
    print(f"      Action:       {action}")
    print(f"      Matched line: {row['Line_Content']}")

    if action == expected_action:
        print(f"      As expected ({expected_action}).")
        return True

    print(f"      UNEXPECTED -- expected {expected_action}, got {action}.")
    return False


def main() -> None:
    # pybatfish logs a lot at INFO level; quieten it so our output is readable.
    logging.getLogger("pybatfish").setLevel(logging.ERROR)

    bf = connect_to_batfish()
    load_snapshot(bf)
    check_parse_status(bf)

    results = []

    # --- Test 1: should be PERMITTED ---------------------------------------
    # A DNS lookup from the internal network to the one allowed DNS server.
    # This should match the first ACL line.
    #
    # `applications=["dns"]` is a named shorthand -- Batfish expands it to the
    # right protocol and port (UDP/53), which matches `eq domain` in the ACL.
    # Careful: only a fixed set of names is valid (dns, http, https, ssh, ...).
    # An unrecognised name makes the Batfish SERVER reject the question with an
    # HTTP 500, which surfaces in Python as a confusing "too many 500 error
    # responses". If that happens, either use a valid name or describe the flow
    # explicitly with ipProtocols=["udp"] and dstPorts="53".
    results.append(
        test_one_flow(
            bf,
            step="4",
            description="Testing a DNS lookup to the allowed DNS server (expect PERMIT)...",
            headers=HeaderConstraints(
                srcIps="10.10.10.0/24",
                dstIps="218.8.104.58",
                applications=["dns"],
            ),
            expected_action="PERMIT",
        )
    )

    print()

    # --- Test 2: should be DENIED ------------------------------------------
    # Plain HTTP to 10.20.0.5 -- the same server the ACL allows over HTTPS.
    # Nothing in the ACL permits port 80, so this falls through to `deny ip
    # any any`. Seeing a deny as well as a permit proves the ACL is actually
    # being evaluated, rather than everything being waved through.
    results.append(
        test_one_flow(
            bf,
            step="5",
            description="Testing plain HTTP to the HTTPS-only server (expect DENY)...",
            headers=HeaderConstraints(
                srcIps="10.10.10.0/24",
                dstIps="10.20.0.5",
                applications=["http"],
            ),
            expected_action="DENY",
        )
    )

    # --- Verdict ------------------------------------------------------------
    print()
    if all(results):
        print("US-5 PASSED")
        print("  Batfish loaded a config WE wrote, confirmed it parsed, and")
        print("  correctly permitted allowed traffic while denying the rest.")
    else:
        sys.exit("US-5 FAILED -- at least one flow did not behave as expected.")


if __name__ == "__main__":
    main()
