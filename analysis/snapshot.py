"""What is actually in the snapshot a check has been handed.

WHY THIS EXISTS
    Every check states its policy against named devices -- `rtr-us5`,
    `rtr-hq`, `rtr-branch`. When the uploaded config does not contain those
    devices, each statement reports `status="error"` ("could not check"),
    which is correct under F-4 and completely unusable in volume:

        routing-secure snapshot      8 of 9 findings were "could not check"
        converted PF Sense config   10 of 10

    Measured, not estimated. Every check we add makes it worse, because each
    contributes more inapplicable statements to every snapshot it was not
    written for.

    The fix is not to skip quietly -- that is the silent omission F-4 exists
    to prevent, and if a device is missing because someone forgot to upload it
    we must still say so. The fix is to say it ONCE per check rather than once
    per statement, which needs a check to know which devices are present.

WHAT THIS IS NOT
    A long-term answer. Policies naming specific devices is itself the deeper
    problem -- see issue #29. Eventually policy should come from the uploaded
    snapshot rather than from constants written against our fixtures. This
    makes the current design usable in the meantime; it does not fix it.
"""

from typing import Any, Optional, Set

from pybatfish.client.session import Session


def device_names(bf: Session) -> Optional[Set[str]]:
    """Every device Batfish found in the loaded snapshot, or None if unknown.

    Read from `fileParseStatus`, which lists the nodes each config file
    defined. That is the same source `access_control` already uses to map a
    file back to a device, so it adds no new dependency.

    RETURNS None -- NOT AN EMPTY SET -- WHEN THE QUESTION CANNOT BE ANSWERED
        These are different facts, and a caller must be able to tell them
        apart:

            set()   we know what is in this snapshot, and it is nothing
            None    we could not find out what is in this snapshot

        Both must lead to reporting that a check could not run, so the SAFETY
        outcome is identical either way. What differs is what a caller may then
        SAY. "rtr-us5 is not in this snapshot" is a claim ABOUT the snapshot,
        and making it after this function failed asserts something nobody
        observed -- sending a reader to look for a missing device when the real
        fault was a broken Batfish query.

        An earlier version of this returned an empty set for both cases and
        produced exactly that false message. Caught in review of #45,
        independently, by two people.
    """
    try:
        frame = bf.q.fileParseStatus().answer().frame()
    except Exception:
        return None

    names: Set[str] = set()
    for _, row in frame.iterrows():
        nodes: Any = row.get("Nodes") or []
        names.update(str(n) for n in nodes)
    return names
