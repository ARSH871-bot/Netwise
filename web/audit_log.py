"""Small, structured audit logging with a closed redaction boundary.

Configuration text, filenames, user questions, policy bodies, Batfish errors
and model prompts are intentionally absent from the event vocabulary. Callers
cannot attach arbitrary fields: an unknown key fails immediately rather than
creating a new route by which sensitive material can reach a log sink.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Final


LOGGER_NAME: Final = "netwise.audit"
logger = logging.getLogger(LOGGER_NAME)

# Each event names only metadata that cannot contain configuration-derived
# content. Keeping this schema close to the emitter turns redaction from a
# convention into a runtime-enforced boundary.
EVENT_FIELDS: Final = {
    "config_upload_accepted": {
        "extension": frozenset({".cfg", ".conf", ".txt", ".xml", ".pfsense"}),
        "size_bytes": int,
        "converted": bool,
        "skipped_count": int,
    },
    "analysis_results_served": {
        "cache_hit": bool,
        "found_count": int,
        "clean_count": int,
        "unavailable_count": int,
    },
    "local_model_host_refused": {},
}


def _valid_value(expected: Any, value: Any) -> bool:
    if isinstance(expected, frozenset):
        return value in expected
    if expected is int:
        return type(value) is int and value >= 0
    return type(value) is expected


def event(name: str, **fields: Any) -> None:
    """Emit one JSON event after enforcing its closed, redacted schema."""
    schema = EVENT_FIELDS.get(name)
    if schema is None:
        raise ValueError(f"unknown audit event: {name}")
    if set(fields) != set(schema):
        raise ValueError(
            f"{name} fields must be exactly {sorted(schema)}, got {sorted(fields)}"
        )
    for field, expected in schema.items():
        if not _valid_value(expected, fields[field]):
            raise ValueError(f"{name}.{field} has an unsafe or invalid value")

    # `json.dumps`, rather than logging's field interpolation, means every
    # emitted record has a stable machine-readable shape.
    logger.info(json.dumps({"event": name, **fields}, sort_keys=True))
