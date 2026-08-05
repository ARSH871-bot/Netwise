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

from typing import Any, Set

from pybatfish.client.session import Session


def device_names(bf: Session) -> Set[str]:
    """Every device Batfish found in the loaded snapshot.

    Read from `fileParseStatus`, which lists the nodes each config file
    defined. That is the same source `access_control` already uses to map a
    file back to a device, so it adds no new dependency.

    Returns an empty set if the question cannot be answered. Callers must treat
    "I do not know what is here" the same as "the device is absent" -- reporting
    that a check could not run. Guessing the other way would let a real blind
    spot pass as a clean result.
    """
    try:
        frame = bf.q.fileParseStatus().answer().frame()
    except Exception:
        return set()

    names: Set[str] = set()
    for _, row in frame.iterrows():
        nodes: Any = row.get("Nodes") or []
        names.update(str(n) for n in nodes)
    return names
