"""
Netwise -- Batfish connectivity smoke test.

PURPOSE: prove that host-side pybatfish can drive the Batfish container end to
end. This is a CONNECTIVITY PROOF, not the analysis pipeline. It does one of
each thing: connect once, load one snapshot, run one question.

The real pipeline (arbitrary config folders, all five questions, structured
output) comes later, once the team has agreed the output schema.

WHAT IT DOES
    1. Makes sure we have example Cisco configs on disk (copies them out of the
       Batfish container the first time -- see EXAMPLE_SOURCE below).
    2. Connects to Batfish with Session(host="localhost").
    3. Loads those configs as a snapshot.
    4. Runs ONE testFilters query and prints the result.

The query asks a deliberately checkable question of the example router
`rtr-with-acl`, which has an ACL named `acl_in` containing this line:

    80 permit tcp 11.36.216.170/32 11.36.216.169/32 eq bgp

So we send a TCP flow to port 179 (which is what `eq bgp` means) from
11.36.216.170 to 11.36.216.169, and expect Batfish to answer PERMIT and name
line 80 as the reason. If it does, every layer between our Python and the
container's analysis engine is working.

GOTCHA worth knowing before you write more queries: describe the flow with
`ipProtocols` + `dstPorts`, NOT with `applications=["bgp"]`. Batfish's
"application specifier" only accepts a short list of named applications (DNS,
SSH, HTTP and friends) -- `bgp` is not one of them. Passing it makes the
Batfish server reject the question with an HTTP 500, which surfaces in Python
as a confusing `RetryError: too many 500 error responses` that says nothing
about the real cause. If you ever see that, read the server's own log:

    docker logs batfish --tail 60

PREREQUISITES
    - Docker running, with the Batfish container up:
        docker run -d --name batfish -p 9997:9997 -p 9996:9996 -p 8888:8888 \
            batfish/allinone
    - pip install -r requirements.txt

RUN
    python analysis/smoke_test.py

NOTE ON SPEED: the first snapshot load after the container starts is slow
(often a few minutes) because Batfish's JVM has to warm up and parse the
configs. Later runs are much faster. Be patient the first time.
"""

import logging
import subprocess
import sys
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints

# --- Settings ---------------------------------------------------------------

# Where the example configs live on our machine. configs/ is git-ignored, so
# nothing here is ever committed -- see .gitignore and CLAUDE.md rule 1.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_DIR = PROJECT_ROOT / "configs" / "example-filters"

# The Batfish image ships example networks. Rather than committing copies, we
# lift them out of the running container the first time they are needed.
CONTAINER_NAME = "batfish"
EXAMPLE_SOURCE = "/notebooks/networks/example-filters/current"

# A Batfish "network" groups snapshots; the snapshot is the set of configs.
NETWORK_NAME = "netwise-smoke"
SNAPSHOT_NAME = "smoke"

# The one flow we test, and what we expect back. See the module docstring.
TEST_NODE = "rtr-with-acl"
TEST_FILTER = "acl_in"
SRC_IP = "11.36.216.170"
DST_IP = "11.36.216.169"
IP_PROTOCOL = "tcp"
DST_PORT = "179"  # BGP. Spelled out as a port -- see the GOTCHA in the docstring.
EXPECTED_ACTION = "PERMIT"


def ensure_example_configs() -> None:
    """Copy the example configs out of the Batfish container if we lack them.

    They are git-ignored, so a teammate cloning this repo will not have them.
    Copying beats committing: it keeps the "no config files in git" rule intact
    and there is nothing to keep in sync.
    """
    if SNAPSHOT_DIR.exists():
        print(f"[1/4] Example configs already present at {SNAPSHOT_DIR}")
        return

    print(f"[1/4] Copying example configs out of the '{CONTAINER_NAME}' container...")
    SNAPSHOT_DIR.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["docker", "cp", f"{CONTAINER_NAME}:{EXAMPLE_SOURCE}", str(SNAPSHOT_DIR)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit(
            "      FAILED to copy example configs.\n"
            f"      {result.stderr.strip()}\n"
            f"      Is the '{CONTAINER_NAME}' container running? Check: docker ps"
        )
    print(f"      Copied to {SNAPSHOT_DIR}")


def main() -> None:
    # pybatfish is chatty at INFO level; quieten it so our output is readable.
    logging.getLogger("pybatfish").setLevel(logging.ERROR)

    ensure_example_configs()

    # --- Connect ------------------------------------------------------------
    print("[2/4] Connecting to Batfish at localhost...")
    bf = Session(host="localhost")
    versions = bf.get_component_versions()
    print(f"      Connected. Batfish service version: {versions.get('Batfish')}")

    # --- Load the configs as a snapshot -------------------------------------
    print(f"[3/4] Loading snapshot from {SNAPSHOT_DIR} (slow on first run)...")
    bf.set_network(NETWORK_NAME)
    bf.init_snapshot(str(SNAPSHOT_DIR), name=SNAPSHOT_NAME, overwrite=True)
    print("      Snapshot loaded.")

    # --- Ask one question ---------------------------------------------------
    # testFilters asks: for ONE specific flow, does this filter permit or deny
    # it, and which line decided? The Line_Content column is what makes Batfish
    # explainable -- it tells us WHY, which is what the AI layer will rephrase.
    print(f"[4/4] Running testFilters on {TEST_NODE} / {TEST_FILTER}...")
    answer = bf.q.testFilters(
        nodes=TEST_NODE,
        filters=TEST_FILTER,
        startLocation=TEST_NODE,
        headers=HeaderConstraints(
            srcIps=SRC_IP,
            dstIps=DST_IP,
            ipProtocols=[IP_PROTOCOL],
            dstPorts=DST_PORT,
        ),
    ).answer()

    # Batfish hands answers back as a pandas DataFrame. Converting these frames
    # into structured data is exactly what the Sprint 2 pipeline has to solve --
    # a printed table cannot ground an AI explanation.
    frame = answer.frame()

    if frame.empty:
        sys.exit("      FAILED: Batfish returned no rows. Check the node/filter names.")

    print()
    print(frame[["Node", "Filter_Name", "Action", "Line_Content"]].to_string(index=False))
    print()

    # --- Check we got what we expected --------------------------------------
    flow_description = f"{IP_PROTOCOL}/{DST_PORT} flow from {SRC_IP} to {DST_IP}"
    action = frame.iloc[0]["Action"]
    if action != EXPECTED_ACTION:
        sys.exit(
            f"SMOKE TEST FAILED: expected {EXPECTED_ACTION} for a {flow_description}, "
            f"but Batfish said {action}."
        )

    print("SMOKE TEST PASSED")
    print(
        f"  A {flow_description} was {action}ted by {TEST_FILTER}, matching line:\n"
        f"    {frame.iloc[0]['Line_Content']}"
    )
    print("  Host-side pybatfish is driving the Batfish container end to end.")


if __name__ == "__main__":
    main()
