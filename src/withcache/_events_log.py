"""Slim audit log of withcache activity.

Ported from :mod:`bty.web._events_log` in shape. A single
append-only ``events`` table in ``state.db`` (same DB the Store
writes blobs / misses to) captures the "who did what when"
timeline the operator wants visible in the UI: catalog entries
added / deleted / downloaded, catalog refreshes, blob misses
recorded, settings changes, auth attempts.

Rendering surfaces:

1. ``/ui/events`` -- top-level page with free-text filter +
   pagination.
2. ``/ui/dashboard`` -- recent activity slice under the summary
   cards (top-N events, embedded via a shared template
   fragment).

Conventions:

- ``kind`` is a dotted lowercase namespace, e.g.
  ``catalog.entry.added``, ``catalog.refresh.failed``,
  ``blob.miss.recorded``. Stable strings; the UI keys badge
  colours off them.
- ``subject_kind`` + ``subject_id`` together identify the entity
  the event is about. ``catalog`` / entry-name, ``blob`` / URL,
  ``settings`` / panel-name. Either may be ``None`` for global
  events.
- ``actor`` distinguishes operator-initiated changes from
  system-initiated ones. See :data:`KNOWN_ACTORS`.
- ``details`` is an optional JSON blob with kind-specific extras
  (return code, error text, etc.) surfaced via the JSON
  ``GET /events`` endpoint for scripted consumers.

Retention: append-only, no automatic trimming. Operators with
strict retention requirements run ``DELETE FROM events WHERE ts
< ?`` themselves.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def normalize_ip(host: str | None) -> str | None:
    """Canonicalise a client IP string for storage / filtering."""
    if host is None or not host:
        return host
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


# Catalogue of every ``kind`` value withcache emits. Owned here so
# callsites (_app.py, _api.py, server.py workers) + the /ui/events
# filter share one source. Adding a new event class is a two-step
# change: append a constant here, then use it at the callsite.
# ``record`` no-ops the runtime check when a kind is not in this set;
# the goal is centralisation, not enforcement, so a typo in a logging
# call can't crash a request flow.
KNOWN_EVENT_KINDS: tuple[str, ...] = (
    "catalog.entry.added",
    "catalog.entry.deleted",
    "catalog.entry.download.requested",
    "catalog.entry.download.started",
    "catalog.entry.download.completed",
    "catalog.entry.download.failed",
    "catalog.entry.download.cancelled",
    "catalog.refreshed",
    "catalog.refresh.failed",
    "catalog.source.updated",
    "blob.miss.recorded",
    "blob.miss.dismissed",
    "settings.catalog.updated",
    "settings.logging.updated",
    "auth.login.succeeded",
    "auth.login.failed",
    "auth.logout",
)

KNOWN_SUBJECT_KINDS: tuple[str, ...] = (
    "catalog",
    "blob",
    "settings",
    "auth",
)

KNOWN_ACTORS: tuple[str, ...] = (
    "operator",
    "system",
    "client",
)


@dataclass(frozen=True)
class Event:
    """One row of the events table."""

    id: int
    ts: str
    kind: str
    subject_kind: str | None
    subject_id: str | None
    actor: str | None
    source_ip: str | None
    summary: str
    details: dict[str, Any] | None
    acknowledged: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "kind": self.kind,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "summary": self.summary,
            "details": self.details,
            "acknowledged": self.acknowledged,
        }


def init(conn: sqlite3.Connection) -> None:
    """Create the events table + indexes if they don't exist."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT NOT NULL,
            kind          TEXT NOT NULL,
            subject_kind  TEXT,
            subject_id    TEXT,
            actor         TEXT,
            source_ip     TEXT,
            summary       TEXT NOT NULL,
            details       TEXT,
            acknowledged  INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS events_ts_idx      ON events(ts);
        CREATE INDEX IF NOT EXISTS events_kind_idx    ON events(kind);
        CREATE INDEX IF NOT EXISTS events_subject_idx ON events(subject_kind, subject_id);
        """
    )


def record(
    conn: sqlite3.Connection,
    *,
    kind: str,
    summary: str,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    actor: str | None = None,
    source_ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> int:
    """Insert one event row. Returns the new row id. Caller owns
    the transaction."""
    ts = datetime.now(UTC).isoformat()
    details_json = json.dumps(details) if details is not None else None
    cur = conn.execute(
        """
        INSERT INTO events
            (ts, kind, subject_kind, subject_id, actor, source_ip, summary, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ts, kind, subject_kind, subject_id, actor, source_ip, summary, details_json),
    )
    return int(cur.lastrowid or 0)


RECENT_EVENTS_LIMIT = 10
"""How many rows the dashboard's "Recent activity" card renders."""


def _q_predicate(q: str) -> tuple[str, list[Any]]:
    """SQL fragment + args matching the free-text events search."""
    needle = q.strip()
    if not needle:
        return "", []
    like = f"%{needle.lower()}%"
    cols = ("kind", "subject_kind", "subject_id", "actor", "source_ip", "summary")
    clause = "(" + " OR ".join(f"LOWER(IFNULL({c}, '')) LIKE ?" for c in cols) + ")"
    return clause, [like] * len(cols)


def count_events(conn: sqlite3.Connection, *, q: str = "") -> int:
    """Number of events matching the free-text search (or all, when
    ``q`` is empty). Used by /ui/events for offset pagination."""
    clause, args = _q_predicate(q)
    sql = "SELECT COUNT(*) FROM events"
    if clause:
        sql += " WHERE " + clause
    row = conn.execute(sql, args).fetchone()
    return int(row[0]) if row else 0


def search_events(
    conn: sqlite3.Connection, *, q: str = "", offset: int = 0, limit: int = 50
) -> list[Event]:
    """Offset-paginated event listing with a free-text predicate.
    Newest first (``ORDER BY id DESC``) regardless of ``q``."""
    if limit < 1:
        limit = 1
    elif limit > 500:
        limit = 500
    if offset < 0:
        offset = 0
    clause, args = _q_predicate(q)
    sql = "SELECT * FROM events"
    if clause:
        sql += " WHERE " + clause
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    rows = conn.execute(sql, args).fetchall()
    return [_row_to_event(row) for row in rows]


def list_recent(conn: sqlite3.Connection, *, limit: int = RECENT_EVENTS_LIMIT) -> list[Event]:
    """Most recent ``limit`` events, newest first. Powers the
    dashboard's Recent activity card."""
    return search_events(conn, limit=limit)


def _row_to_event(row: sqlite3.Row) -> Event:
    details_raw = row["details"]
    details: dict[str, Any] | None = None
    if details_raw:
        try:
            decoded = json.loads(details_raw)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            details = decoded
    keys = row.keys() if hasattr(row, "keys") else []
    ack_raw = row["acknowledged"] if "acknowledged" in keys else 0
    return Event(
        id=row["id"],
        ts=row["ts"],
        kind=row["kind"],
        subject_kind=row["subject_kind"],
        subject_id=row["subject_id"],
        actor=row["actor"],
        source_ip=row["source_ip"],
        summary=row["summary"],
        details=details,
        acknowledged=bool(ack_raw or 0),
    )


def set_acknowledged(conn: sqlite3.Connection, event_id: int, value: bool) -> bool:
    """Set one event's acknowledged flag. Returns ``True`` iff a
    row matched. Caller owns the transaction."""
    cur = conn.execute(
        "UPDATE events SET acknowledged = ? WHERE id = ?",
        (1 if value else 0, event_id),
    )
    return cur.rowcount > 0


def count_unacknowledged_failures(conn: sqlite3.Connection) -> int:
    """Count failure events the operator has not acknowledged yet.
    Backs the dashboard Health tripwire."""
    row = conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind LIKE '%failed' AND acknowledged = 0"
    ).fetchone()
    return int(row[0])
