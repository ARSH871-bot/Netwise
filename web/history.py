"""Saved scans: what changed since the last time? (#223)

WHAT THIS IS
    One SQLite table of scans the user CHOSE to save, each under a network
    name they typed. `analysis/scan_diff.py` compares a saved scan with the
    current one; this module only stores and returns them.

THE THREE DECISIONS #223 LEFT OPEN, AND WHAT THIS DOES ABOUT EACH
    1. What is a network, across visits? The name the user gives when they
       save. Never inferred from device names, which change when a router is
       added, and never from the session, which lasts eight hours.
    2. Should history outlive a session? Only what the user explicitly
       saves. Nothing is written by scanning. This install keeps one history
       for everyone who uses it, which is right for a tool bound to
       127.0.0.1 and wrong for a shared server -- accounts (#327) come first
       there.
    3. Retention. A saved scan stays until it is deleted, one at a time or
       all at once. A delete removes the row AND overwrites its bytes: a
       plain SQLite DELETE leaves the old content in the file until the
       space is reused, which is not what "delete" means to a user (#344).

WHAT A SAVED SCAN HOLDS
    `scan_diff.make_scan()`'s row: the F-1 findings verbatim, the coverage
    derived from them, the devices present, the config and policy
    fingerprints, and any pfSense rules the converter skipped. NOT the
    config itself and NOT AI explanations (regenerable, and not evidence).

    It does hold `evidence.detail`, which quotes config lines such as ACL
    entries. That is config-derived data on disk. It never leaves this
    machine (N-1), but it is why deletion has to be real.

No FastAPI import on purpose: the web layer calls this, tests call it
directly with a temporary file.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

#: A network name: starts with a letter or digit, then up to 63 of letters,
#: digits, spaces, dots, hyphens and underscores. It is shown back on screen
#: and in file names people might copy, so nothing that needs escaping.
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}")


class HistoryError(ValueError):
    """A request this store refuses, with a reason a user can act on."""


def valid_name(name: Any) -> str:
    """The name, trimmed, or HistoryError saying what a name may contain."""
    text = str(name or "").strip()
    if not NAME_PATTERN.fullmatch(text):
        raise HistoryError(
            "A network name is 1 to 64 characters: letters, digits, spaces, "
            "dots, hyphens and underscores, starting with a letter or digit.")
    return text


def _counts(scan: Dict[str, Any]) -> Dict[str, int]:
    found = scan.get("findings") or []
    return {status: sum(1 for f in found if f.get("status") == status)
            for status in ("found", "none", "error")}


class ScanHistory:
    """Saved scans in one SQLite file. Each call opens and closes it."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        # Zero deleted content instead of leaving it in free pages.
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS scans ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " name TEXT NOT NULL,"
            " created_at TEXT NOT NULL,"
            " scan TEXT NOT NULL)")
        return connection

    def save(self, name: str, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Store `scan` under `name`; return what was stored, without the scan."""
        name = valid_name(name)
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "INSERT INTO scans (name, created_at, scan) VALUES (?, ?, ?)",
                (name, created_at, json.dumps(scan)))
            scan_id = cursor.lastrowid
        return {"id": scan_id, "name": name, "created_at": created_at,
                "counts": _counts(scan)}

    def list(self) -> List[Dict[str, Any]]:
        """Every saved scan, newest first, without the findings themselves."""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id, name, created_at, scan FROM scans "
                "ORDER BY created_at DESC, id DESC").fetchall()
        return [{"id": i, "name": n, "created_at": c, "counts": _counts(json.loads(s))}
                for i, n, c, s in rows]

    def latest(self, name: str) -> Optional[Dict[str, Any]]:
        """The most recent scan saved under `name`, or None if there is none."""
        name = valid_name(name)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id, name, created_at, scan FROM scans WHERE name = ? "
                "ORDER BY created_at DESC, id DESC LIMIT 1", (name,)).fetchone()
        if row is None:
            return None
        scan_id, stored_name, created_at, scan = row
        return {"id": scan_id, "name": stored_name, "created_at": created_at,
                "scan": json.loads(scan)}

    def delete(self, scan_id: int) -> bool:
        """Remove one saved scan. False if there was no such scan."""
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute("DELETE FROM scans WHERE id = ?", (int(scan_id),))
            return cursor.rowcount > 0

    def delete_all(self) -> int:
        """Remove every saved scan; return how many there were."""
        with closing(self._connect()) as connection, connection:
            return connection.execute("DELETE FROM scans").rowcount
