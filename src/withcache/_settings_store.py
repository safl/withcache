"""Operator-overridable settings for withcache.

Mirrors :mod:`nbdmux._settings_store` in shape. A thin key-value
store over a ``settings`` table in the same ``cache.db``
:class:`withcache.server.Store` writes blob metadata to. Values
here are persistent overrides for the two knobs an operator wants
to change without redeploying:

- :data:`KEY_LOG_LEVEL` -- uvicorn / logging level.
  Env: :data:`ENV_LOG_LEVEL`. Default: ``info``.
- :data:`KEY_CATALOG_URL_OVERRIDE` is intentionally NOT here --
  :class:`CatalogState.set_url_override` persists it to a dedicated
  ``<data-dir>/catalog_url`` file the daemon reads at startup, so
  the Catalog page's Set-URL form remains the single source of
  truth for that knob.

Resolution order is always **override -> env -> default**, so
operators can drop an env / systemd-unit config without hunting
the DB.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

KEY_LOG_LEVEL = "log.level"
ENV_LOG_LEVEL = "WITHCACHE_LOG_LEVEL"
DEFAULT_LOG_LEVEL = "info"

# uvicorn accepts a small closed set; the Settings form rejects
# anything else so a hand-edit of cache.db that puts garbage in the
# row surfaces on resolve rather than mid-boot.
LOG_LEVELS: tuple[str, ...] = ("critical", "error", "warning", "info", "debug", "trace")


class SettingValueError(ValueError):
    """Raised when a stored value can't be parsed to the canonical
    form the resolver promises. Same shape as nbdmux's so both
    Settings forms handle failure alike."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def init(conn: sqlite3.Connection) -> None:
    """Create the ``settings`` table if it's not there yet.

    Called from the FastAPI app factory on startup. Idempotent."""
    conn.executescript(_SCHEMA)


def get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None
    v: Any = row[0]
    return None if v is None else str(v)


def set_value(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def clear(conn: sqlite3.Connection, key: str) -> None:
    conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def resolve_log_level(conn: sqlite3.Connection) -> str:
    """DB override > $WITHCACHE_LOG_LEVEL > "info".

    Raises :class:`SettingValueError` when the stored / env value
    isn't in :data:`LOG_LEVELS`; the Settings form normalises to the
    canonical form before persisting so the raise only fires on a
    hand-edit of cache.db or a bogus env var."""
    override = get(conn, KEY_LOG_LEVEL)
    if override:
        raw = override
    else:
        env = (os.environ.get(ENV_LOG_LEVEL) or "").strip()
        if not env:
            return DEFAULT_LOG_LEVEL
        raw = env
    lowered = raw.lower()
    if lowered not in LOG_LEVELS:
        raise SettingValueError(
            f"log level {raw!r} not in {LOG_LEVELS}; "
            "clear the row via /ui/settings or delete cache.db to reset"
        )
    return lowered
