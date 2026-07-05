#!/usr/bin/env python3
"""withcache cache-host, storage + fetch pipeline + daemon entrypoint.

Post-v0.9.0 the HTTP control plane + operator UI moved out to
:mod:`withcache._app` (FastAPI + Jinja + Bootstrap) and the
byte-serving routes to :mod:`withcache._api`; this module now owns
the parts of the daemon that stay stdlib:

- ``Store``: SQLite-backed blob + miss + hit accounting, single
  ``cache.db`` under ``--data-dir``. Reads / writes are HMAC-safe
  under a process-wide write lock.
- ``Auth``: server-signed HMAC cookie, ``WITHCACHE_ADMIN_PASSWORD``
  env gate. Signing key resolution via :func:`resolve_secret`.
- ``DownloadManager`` + ``Stream`` + ``StreamRegistry``: bounded
  worker pool that pulls origin URLs into the cache, plus the
  in-flight progress tracker byte-serving reads share with the
  operator UI.
- ``CatalogState``: the periodically-fetched image manifest that
  bty flashes against, persisted to
  ``<data-dir>/catalog.toml`` between restarts.
- Helpers: ``resolve_secret``, ``parse_size``, ``parse_headers``,
  ``now_iso``, ``human_size``, ``_b64e`` / ``_b64d``,
  ``_serialise_catalog``, ``_oras_tag_moved``.
- ``main()``: CLI entrypoint that constructs Store + DownloadManager
  and hands them to :func:`withcache._app.create_app`, then boots
  uvicorn. SIGTERM / SIGINT handling is uvicorn's.

The read path (``/blob``, ``/b/<b64>/<name>``, ``/healthz``) is
open by design so shims never hold a session cookie; the operator
surface is gated behind :class:`Auth` when
``WITHCACHE_ADMIN_PASSWORD`` is set, otherwise open with a startup
warning (single-tenant LAN deploy).
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
import itertools
import json
import os
import queue
import secrets
import sqlite3
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from . import __version__, oras

CHUNK = 64 * 1024
USER_AGENT = f"withcache-cache/{__version__}"
# Resume budget for a single store_from_origin call. A truncated
# upstream stream re-fetches with ``Range: bytes=<got>-`` so the
# next attempt picks up where the cut happened. Five tries cover
# the realistic failure mode (e.g. ghcr.io serves blobs via Azure
# Blob Storage SAS URLs with a ~10 minute expiry; a >2 GiB image
# at modest bandwidth blows past one window and the connection is
# cut server-side, but a fresh redirect through ghcr yields a new
# SAS URL each retry). The cap is the give-up gate, not a normal
# operating depth.
RESUME_MAX_ATTEMPTS = 5
_DB_WRITE_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or unit == "TiB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


def parse_size(s: str) -> int:
    """Parse '0', '1024', '50M', '20G', '1.5T' into bytes (suffixes are 1024-based)."""
    s = str(s).strip()
    if not s:
        return 0
    units = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    if s[-1].upper() in units:
        return int(float(s[:-1]) * units[s[-1].upper()])
    return int(s)


def parse_headers(raw: str) -> dict | None:
    """Parse 'Name: Value' lines (e.g. a registry Authorization header that bty
    pre-resolves for an oras blob) into a dict for the origin fetch; None if empty."""
    out = {}
    for line in (raw or "").splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip():
            out[name.strip()] = value.strip()
    return out or None


# --------------------------------------------------------------------------
# Auth — server-signed session cookie (bty-style, env-password instead of PAM)
# --------------------------------------------------------------------------
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def resolve_secret(data_dir: str) -> bytes:
    """$WITHCACHE_SESSION_SECRET if set + non-empty, else a random key persisted
    to <data-dir>/session-secret so cookies survive restarts. Mirrors bty's
    _resolve_secret_key: a blank env value must NOT silently weaken signing."""
    env = (os.environ.get("WITHCACHE_SESSION_SECRET") or "").strip()
    if env:
        return env.encode("utf-8")
    path = os.path.join(data_dir, "session-secret")
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read().strip()
        if data:
            return data
    secret = secrets.token_hex(32).encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(secret)
    return secret


DEFAULT_CATALOG_URL = "https://github.com/safl/nosi/releases/latest/download/catalog.toml"


def _serialise_catalog(entries: list[dict[str, Any]]) -> bytes:
    """Serialise a list of catalog entries back to TOML bytes matching the
    nosi ``version = 1`` + ``[[images]]`` schema. Stdlib-only, no
    ``tomli_w`` dep: the schema is flat so a hand-rolled emitter is
    safer than pulling in a write library. Only known scalar keys are
    emitted; unknown keys are dropped (silently) so an operator-added
    row can't smuggle arbitrary TOML through."""
    out: list[str] = ["version = 1", ""]
    for e in entries:
        out.append("[[images]]")
        for key in ("name", "src", "format", "arch", "sha256"):
            val = e.get(key)
            if val is None or val == "":
                continue
            # Escape backslashes + quotes then wrap in double quotes.
            escaped = str(val).replace("\\", "\\\\").replace('"', '\\"')
            out.append(f'{key} = "{escaped}"')
        size = e.get("size_bytes")
        if isinstance(size, int):
            out.append(f"size_bytes = {size}")
        out.append("")
    return "\n".join(out).encode("utf-8")


@dataclass
class CatalogState:
    """Live state of the fetched image catalog.

    withcache does not run a background poller and does not refetch
    on a TTL. The catalog is fetched at process start (best-effort;
    a persisted result from the last successful fetch survives a
    restart) and force-refetched by the operator via the Refresh
    button on the Catalog page (POST /admin/catalog_refresh); every
    other render reads whatever is currently in memory.

    The raw TOML bytes are persisted to ``<data_dir>/catalog.toml``
    so a restart doesn't wipe the last known good catalog. There is
    no HTTP route that serves the file back verbatim; consumers
    resolve entries by name through the dashboard or by reading
    ``entries`` in-process.

    ``env_url`` records the value pinned via ``$WITHCACHE_CATALOG_URL``
    (empty if unset). The operator can override the effective URL at
    runtime via ``POST /admin/catalog_set_url``; the override is
    persisted to ``<data_dir>/catalog_url`` and wins over the built-in
    default, but the env var still wins over the operator override so
    an operator can't silently unblock a locked-down deploy.
    """

    url: str
    persist_path: str
    env_url: str = ""
    url_override_path: str = ""
    entries: list[dict[str, Any]] = field(default_factory=list)
    fetched_at: str = ""
    last_error: str = ""
    last_info: str = ""
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def load_persisted(self) -> None:
        """Best-effort: seed ``entries`` + ``fetched_at`` from the on-disk
        ``catalog.toml`` if it exists. Also loads the operator URL
        override from ``<data_dir>/catalog_url`` when the env var is
        not set. Never raises; a corrupt or missing file leaves the
        state empty so the operator sees the "not fetched yet" hint
        in the dashboard."""
        if self.url_override_path and os.path.isfile(self.url_override_path) and not self.env_url:
            try:
                with open(self.url_override_path, encoding="utf-8") as f:
                    override = f.read().strip()
                if override:
                    self.url = override
            except OSError:
                pass
        if not os.path.isfile(self.persist_path):
            return
        try:
            with open(self.persist_path, "rb") as f:
                raw = f.read()
            parsed = tomllib.loads(raw.decode("utf-8"))
            mtime = os.path.getmtime(self.persist_path)
            self.entries = list(parsed.get("images") or [])
            self.fetched_at = datetime.fromtimestamp(mtime, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            self.last_error = f"failed to load {self.persist_path}: {e}"

    def fetch_now(self, *, timeout: float = 15.0) -> None:
        """Fetch the catalog URL, parse, persist raw bytes, populate
        ``entries``. On failure the previously-cached entries remain;
        the error is recorded so the tab can surface it. Single-writer
        via ``self._lock`` so a burst of clicks doesn't double-fetch."""
        with self._lock:
            try:
                req = urllib.request.Request(self.url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                # Validate before persisting -- a 500 from upstream that
                # returns HTML must not clobber a previously-good
                # catalog.toml on disk.
                parsed = tomllib.loads(raw.decode("utf-8"))
                entries = list(parsed.get("images") or [])
                # Atomic write: tempfile + rename so a crash mid-write
                # never leaves a half-written catalog.toml.
                self._persist_bytes(raw)
                self.entries = entries
                self.fetched_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                self.last_error = ""
                self.last_info = f"fetched {len(entries)} entries from {self.url}"
            except (
                urllib.error.URLError,
                OSError,
                ValueError,
                UnicodeDecodeError,
                tomllib.TOMLDecodeError,
            ) as e:
                self.last_error = str(e)

    def set_url_override(self, new_url: str) -> tuple[bool, str]:
        """Persist an operator-set URL override to
        ``<data_dir>/catalog_url``. Env-var pin wins: if
        ``$WITHCACHE_CATALOG_URL`` is set, the override is rejected
        so a locked-down deploy stays locked down. Returns
        ``(ok, message)`` for the UI to surface."""
        if self.env_url:
            return False, "env WITHCACHE_CATALOG_URL is pinned; unset it to allow overrides"
        candidate = new_url.strip()
        if not candidate:
            return False, "url is empty"
        if not candidate.startswith(("http://", "https://")):
            return False, "url must start with http:// or https://"
        with self._lock:
            try:
                if self.url_override_path:
                    tmp = self.url_override_path + ".tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write(candidate + "\n")
                    os.replace(tmp, self.url_override_path)
                self.url = candidate
            except OSError as e:
                return False, str(e)
        return True, f"catalog url set to {candidate}"

    def add_oras_entry(self, oras_url: str) -> tuple[bool, str]:
        """Append a single ``[[images]]`` row derived from an ``oras://``
        reference. Parses the tag to derive a ``name`` (the last path
        component + tag), fetches the manifest to pick the image layer's
        ``org.opencontainers.image.title`` annotation for ``format``, and
        extracts an ``arch`` hint from the tag suffix when present
        (``…-x86_64`` / ``…-arm64``). Best-effort: parse or fetch
        failures return an error tuple and record ``last_error``."""
        candidate = oras_url.strip()
        if not candidate.startswith("oras://"):
            self.last_error = "expected oras:// URL"
            return False, self.last_error
        try:
            ref = oras.parse_ref(candidate)
        except oras.OrasError as e:
            self.last_error = f"parse failed: {e}"
            return False, self.last_error
        # Derive a display name from the repo tail + tag / digest.
        repo_tail = ref.repository.rsplit("/", 1)[-1]
        version = ref.tag or (ref.digest or "").split(":", 1)[-1][:12]
        name = f"{repo_tail}-{version}" if version else repo_tail
        # Best-effort layer fetch for format + size. Failures still
        # register the entry (the ORAS URL alone is enough for
        # downstream consumers to resolve at flash time).
        fmt = ""
        size_bytes: int | None = None
        try:
            resolved = oras.resolve_ref(ref)
            size_bytes = resolved.size
            if resolved.title:
                # nosi layer titles look like "debian-13-headless.img.zst".
                # Strip the last two dot components as ``format`` when the
                # tail matches a known compressor suffix; else take the
                # single extension.
                title = resolved.title
                for suffix in (".img.zst", ".img.gz", ".img.xz", ".img", ".iso"):
                    if title.endswith(suffix):
                        fmt = suffix.lstrip(".")
                        break
        except (oras.OrasError, OSError) as e:
            # Register the entry anyway; note the reason as info so
            # the operator sees it but the row still lands.
            self.last_info = f"registered {candidate} (layer probe failed: {e})"
        # Arch hint from tag suffix; drop the trailing token when it
        # matches a known arch so ``name`` isn't ``foo-x86_64-x86_64``.
        arch = ""
        known_archs = ("x86_64", "amd64", "arm64", "aarch64", "riscv64")
        for a in known_archs:
            if candidate.endswith(f"-{a}") or candidate.endswith(f":{a}"):
                arch = a
                break
        clean: dict[str, Any] = {"name": name, "src": candidate}
        if fmt:
            clean["format"] = fmt
        if arch:
            clean["arch"] = arch
        if size_bytes is not None:
            clean["size_bytes"] = size_bytes
        with self._lock:
            new_entries = [e for e in self.entries if str(e.get("name") or "") != name]
            new_entries.append(clean)
            raw = _serialise_catalog(new_entries)
            try:
                self._persist_bytes(raw)
            except OSError as e:
                self.last_error = str(e)
                return False, str(e)
            self.entries = new_entries
            self.last_error = ""
            if not self.last_info.startswith("registered "):
                self.last_info = f"added oras entry: {name}"
        return True, self.last_info

    def delete_entry(self, name: str) -> tuple[bool, str]:
        """Remove an entry by ``name``. No-op if absent."""
        target = name.strip()
        if not target:
            return False, "name is required"
        with self._lock:
            new_entries = [e for e in self.entries if str(e.get("name") or "") != target]
            if len(new_entries) == len(self.entries):
                return False, f"no entry named {target!r}"
            raw = _serialise_catalog(new_entries)
            try:
                self._persist_bytes(raw)
            except OSError as e:
                return False, str(e)
            self.entries = new_entries
            self.last_error = ""
            self.last_info = f"deleted entry: {target}"
        return True, self.last_info

    def _persist_bytes(self, raw: bytes) -> None:
        """Atomic-replace ``self.persist_path`` with ``raw`` via
        tempfile + rename so a crash mid-write can never leave a
        half-written catalog.toml. Callers hold ``self._lock``."""
        tmp = self.persist_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.replace(tmp, self.persist_path)


class Auth:
    COOKIE = "withcache-token"
    MAX_AGE = 7 * 24 * 3600  # cookie lifetime, seconds

    def __init__(self, secret: bytes, password: str | None):
        self.secret = secret
        self.password = password or None

    @property
    def enabled(self) -> bool:
        return self.password is not None

    def _sign(self, payload_b64: str) -> str:
        mac = hmac.new(self.secret, payload_b64.encode("ascii"), hashlib.sha256)
        return _b64e(mac.digest())

    def make_token(self) -> str:
        payload = _b64e(json.dumps({"a": 1, "iat": int(time.time())}).encode())
        return f"{payload}.{self._sign(payload)}"

    def valid(self, token: str) -> bool:
        try:
            payload, sig = token.split(".", 1)
            if not hmac.compare_digest(sig, self._sign(payload)):
                return False
            data = json.loads(_b64d(payload))
            if int(time.time()) - int(data.get("iat", 0)) > self.MAX_AGE:
                return False
            return bool(data.get("a"))
        except Exception:
            return False

    def check_password(self, pw: str) -> bool:
        if not self.password:
            return False
        return hmac.compare_digest(pw.encode("utf-8"), self.password.encode("utf-8"))


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------
class Store:
    """Blobs on disk keyed by hash(normalized url); metadata in SQLite."""

    def __init__(self, data_dir: str, keep_query: bool, max_bytes: int = 0):
        self.data_dir = os.path.abspath(data_dir)
        self.blob_dir = os.path.join(self.data_dir, "blobs")
        self.tmp_dir = os.path.join(self.data_dir, "tmp")
        self.db_path = os.path.join(self.data_dir, "cache.db")
        self.keep_query = keep_query
        self.max_bytes = max_bytes  # cap on total cached bytes; 0 = unlimited
        os.makedirs(self.blob_dir, exist_ok=True)
        os.makedirs(self.tmp_dir, exist_ok=True)
        self._init_db()

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _init_db(self):
        with self.conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS blobs (
                    key          TEXT PRIMARY KEY,
                    url          TEXT NOT NULL,
                    size         INTEGER NOT NULL,
                    sha256       TEXT NOT NULL,
                    content_type TEXT,
                    fetched_at   TEXT NOT NULL,
                    hits         INTEGER NOT NULL DEFAULT 0,
                    misses       INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS misses (
                    key        TEXT PRIMARY KEY,
                    url        TEXT NOT NULL,
                    count      INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen  TEXT NOT NULL
                );
                """
            )
            # Migrate DBs created before the per-blob request counters existed.
            cols = {r["name"] for r in c.execute("PRAGMA table_info(blobs)")}
            for col in ("hits", "misses"):
                if col not in cols:
                    c.execute(f"ALTER TABLE blobs ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")

    # -- key handling ------------------------------------------------------
    def normalize(self, url: str) -> str:
        p = urllib.parse.urlsplit(url)
        base = f"{p.scheme.lower()}://{p.netloc.lower()}{p.path}"
        if self.keep_query and p.query:
            return f"{base}?{p.query}"
        return base

    @staticmethod
    def key_of(normalized: str) -> str:
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def blob_path(self, key: str) -> str:
        return os.path.join(self.blob_dir, key)

    # -- reads -------------------------------------------------------------
    def get_blob(self, url: str):
        key = self.key_of(self.normalize(url))
        with self.conn() as c:
            row = c.execute("SELECT * FROM blobs WHERE key=?", (key,)).fetchone()
        if row and os.path.exists(self.blob_path(key)):
            return row
        return None

    def list_blobs(self):
        with self.conn() as c:
            return c.execute("SELECT * FROM blobs ORDER BY fetched_at DESC").fetchall()

    def list_misses(self):
        with self.conn() as c:
            return c.execute("SELECT * FROM misses ORDER BY last_seen DESC").fetchall()

    def counts(self):
        with self.conn() as c:
            b = c.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
            m = c.execute("SELECT COUNT(*) FROM misses").fetchone()[0]
        return b, m

    def total_size(self) -> int:
        with self.conn() as c:
            return c.execute("SELECT COALESCE(SUM(size), 0) FROM blobs").fetchone()[0]

    def has_capacity(self) -> bool:
        """False once stored bytes reach --max-bytes (0 = unlimited). The guard
        refuses *new* fills when full; it never evicts (delete is manual)."""
        return self.max_bytes <= 0 or self.total_size() < self.max_bytes

    # -- writes ------------------------------------------------------------
    def record_miss(self, url: str):
        key = self.key_of(self.normalize(url))
        ts = now_iso()
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute(
                """
                INSERT INTO misses (key, url, count, first_seen, last_seen)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    count = count + 1,
                    last_seen = excluded.last_seen,
                    url = excluded.url
                """,
                (key, url, ts, ts),
            )

    def record_hit(self, key: str):
        """Count one cache-served download (the GET, not the shim's HEAD probe)."""
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute("UPDATE blobs SET hits = hits + 1 WHERE key=?", (key,))

    def dismiss(self, key: str):
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute("DELETE FROM misses WHERE key=?", (key,))

    def delete_blob(self, key: str):
        """Drop a cached artifact (row + bytes). The manual half of eviction."""
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute("DELETE FROM blobs WHERE key=?", (key,))
        with contextlib.suppress(FileNotFoundError):
            os.remove(self.blob_path(key))

    def store_from_origin(
        self,
        url: str,
        progress=None,
        cancel=None,
        headers=None,
        max_resume_attempts: int = RESUME_MAX_ATTEMPTS,
        fetch_resolver=None,
    ) -> sqlite3.Row:
        """Operator-triggered: pull the artifact from origin and store it.

        ``progress(done, total)`` is called as bytes arrive (total may be None);
        ``cancel()`` is polled between chunks and, if truthy, aborts the pull
        with :class:`DownloadCancelled` and leaves no partial file behind.
        ``headers`` adds request headers to the origin fetch (e.g. a registry
        bearer token bty pre-resolved for an oras blob). Raises :class:`CacheFull`
        if the cache is already at --max-bytes.

        ``fetch_resolver`` is an optional zero-arg callable that returns
        ``(fetch_url, fetch_headers)`` for the current attempt. When set,
        every resume attempt re-invokes it -- so an ``oras://...`` cache key
        can be backed by a fresh registry bearer + fresh signed CDN URL on
        each retry (both have short TTLs the resume loop will otherwise blow
        through). When unset, every attempt hits ``url`` directly. The
        ``fetch_headers`` are layered under the caller-supplied ``headers``,
        so an operator-provided override wins.

        Resume-on-truncation: if the upstream stream ends before its
        declared Content-Length, the partial bytes are kept and the
        next attempt requests ``Range: bytes=<got>-`` so the fetch
        picks up where the connection died. Up to
        ``max_resume_attempts`` attempts are made before
        :class:`TruncatedDownload` is raised; on giving up the
        partial file is removed. A 200 response to a Range request
        (the origin chose to ignore the header, common on naive
        upstreams) is handled by restarting from byte 0 and counts
        against the same attempt budget. Re-issuing the request also
        re-resolves any 30x redirect chain, which matters for
        ghcr.io: each ghcr request hands back a fresh Azure Blob
        Storage SAS URL valid only for a short window, and the
        prior cut almost certainly was that SAS expiring mid-stream.
        """
        if not self.has_capacity():
            raise CacheFull(f"cache full (>= {self.max_bytes} bytes); refusing to fetch {url}")
        normalized = self.normalize(url)
        key = self.key_of(normalized)
        tmp = os.path.join(self.tmp_dir, key + ".part")
        sha = hashlib.sha256()
        size = 0
        total: int | None = None
        content_type: str | None = None
        try:
            for _ in range(max_resume_attempts):
                # Resolve fetch URL + headers afresh per attempt: for
                # oras://, the bearer + signed CDN URL each have short
                # TTLs the prior attempt may have blown through; for
                # plain HTTP the resolver is unset and we fetch ``url``
                # with a stable header set.
                if fetch_resolver is not None:
                    fetch_url, resolved_headers = fetch_resolver()
                else:
                    fetch_url = url
                    resolved_headers = {}
                req_headers = {"User-Agent": USER_AGENT, **resolved_headers}
                if headers:
                    req_headers.update(headers)
                if size > 0:
                    # Resume from where the previous attempt cut.
                    # A 206 response continues the stream; a 200
                    # means the origin ignored Range (e.g. a dumb
                    # static server) and we restart from 0.
                    req_headers["Range"] = f"bytes={size}-"
                req = urllib.request.Request(fetch_url, headers=req_headers)
                with urllib.request.urlopen(req, timeout=120) as resp:
                    status = getattr(resp, "status", None) or resp.getcode()
                    if content_type is None:
                        content_type = resp.headers.get_content_type()
                    if size > 0 and status == 200:
                        # Range ignored by origin: discard the partial
                        # and start a fresh full-stream attempt.
                        size = 0
                        sha = hashlib.sha256()
                        if os.path.exists(tmp):
                            os.remove(tmp)
                    if size > 0 and status == 206:
                        # ``Content-Range: bytes <start>-<end>/<total>``;
                        # use the total declared there as the contract,
                        # not Content-Length (which on 206 is the size
                        # of the partial response, not the whole blob).
                        cr = resp.headers.get("Content-Range") or ""
                        if "/" in cr:
                            tail = cr.rsplit("/", 1)[1].strip()
                            if tail.isdigit():
                                total = int(tail)
                    else:
                        cl = resp.headers.get("Content-Length")
                        if cl and cl.isdigit():
                            total = int(cl)
                    if progress:
                        progress(size, total)
                    mode = "ab" if size > 0 else "wb"
                    with open(tmp, mode) as f:
                        while True:
                            if cancel and cancel():
                                raise DownloadCancelled()
                            chunk = resp.read(CHUNK)
                            if not chunk:
                                break
                            f.write(chunk)
                            sha.update(chunk)
                            size += len(chunk)
                            if progress:
                                progress(size, total)
                # urllib's read loop exits on clean EOF AND on transport-
                # aborted close; HTTPResponse only raises IncompleteRead
                # in some configurations. When the origin declared a
                # total (either via Content-Length on a 200 or via
                # Content-Range on a 206), treat that as the contract:
                # try to resume from the cut, give up after the budget
                # is exhausted. Without a declared total there is no
                # truncation signal, so a single attempt is the whole
                # story.
                if total is None or size >= total:
                    break
            else:
                # for/else: ran out of attempts before reaching total
                raise TruncatedDownload(
                    f"upstream truncated for {url}: declared {total} bytes, got {size}"
                    f" after {max_resume_attempts} attempts"
                )
            os.replace(tmp, self.blob_path(key))
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)  # no half-written blob on cancel/error/give-up
            raise
        ts = now_iso()
        with _DB_WRITE_LOCK, self.conn() as c:
            # Carry the miss count accumulated while uncached onto the blob, so a
            # URL's total request history (misses-before-cached + hits-since)
            # survives the miss->cached transition. hits are preserved on a
            # re-download (not in the UPDATE set).
            row = c.execute("SELECT count FROM misses WHERE key=?", (key,)).fetchone()
            prior_misses = row["count"] if row else 0
            c.execute(
                """
                INSERT INTO blobs (key, url, size, sha256, content_type, fetched_at, hits, misses)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(key) DO UPDATE SET
                    url = excluded.url, size = excluded.size,
                    sha256 = excluded.sha256, content_type = excluded.content_type,
                    fetched_at = excluded.fetched_at,
                    misses = blobs.misses + excluded.misses
                """,
                (key, url, size, sha.hexdigest(), content_type, ts, prior_misses),
            )
            c.execute("DELETE FROM misses WHERE key=?", (key,))
            return c.execute("SELECT * FROM blobs WHERE key=?", (key,)).fetchone()


# --------------------------------------------------------------------------
# Background download manager (thread pool; modelled on bty's job managers)
# --------------------------------------------------------------------------
PENDING_STATES = frozenset(("queued", "running"))


class DownloadCancelled(Exception):
    """Raised inside a worker when its job's cancel flag is set."""


class CacheFull(Exception):
    """Raised when --max-bytes is reached; the fill is refused, not evicted."""


class TruncatedDownload(Exception):
    """Raised when the upstream stream ended before the declared
    Content-Length. The temp file is removed and no blob row is
    written, so the same URL re-enqueues cleanly on the next request
    instead of permanently serving a malformed file.
    """


@dataclass
class Stream:
    """One in-flight blob serve. Lives in memory only for the duration of
    the response: registered before the first byte goes out, deregistered
    in a finally block. Operator visibility into "what is the cache
    currently uploading, and to whom" without touching the kernel's
    /proc/net/tcp or the access log.
    """

    id: int
    url: str
    client: str  # ``ip:port`` of the consumer
    started_at: float
    bytes_sent: int = 0
    total: int | None = None  # known up front from the blob row


class StreamRegistry:
    """Thread-safe registry of in-flight blob serves. Reads (snapshot for
    the operator dash) and writes (start / progress / finish from
    request handler threads) all serialised on a single lock; the
    contention window is the few microseconds of a dict mutation, and
    progress updates are batched at one per chunk (see PROGRESS_STRIDE)
    so a 4 GiB stream is ~64k updates, not millions.
    """

    PROGRESS_STRIDE = 16  # update bytes_sent every N chunks (~1 MiB at CHUNK=64K)

    def __init__(self) -> None:
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._active: dict[int, Stream] = {}

    def start(self, url: str, client: str, total: int | None) -> Stream:
        with self._lock:
            s = Stream(
                id=next(self._ids), url=url, client=client, started_at=time.time(), total=total
            )
            self._active[s.id] = s
            return s

    def bump(self, stream_id: int, bytes_sent: int) -> None:
        # Caller already gates by PROGRESS_STRIDE so this is cheap; the
        # write itself only takes the lock long enough to mutate the int.
        with self._lock:
            s = self._active.get(stream_id)
            if s is not None:
                s.bytes_sent = bytes_sent

    def finish(self, stream_id: int) -> None:
        with self._lock:
            self._active.pop(stream_id, None)

    def snapshot(self) -> list[Stream]:
        with self._lock:
            # Stable order: oldest first (matches the queue mental model).
            return sorted(self._active.values(), key=lambda s: s.started_at)


@dataclass
class Job:
    id: int
    url: str
    status: str = "queued"
    bytes_done: int = 0
    bytes_total: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    error: str | None = None
    sha256: str | None = None
    headers: dict | None = field(default=None, repr=False)  # e.g. registry auth; never logged
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)


class DownloadManager:
    """Operator-triggered downloads run here, not in the request handler:
    enqueue() returns immediately, worker threads pull from a queue, each job
    reports progress and honors a per-job cancel flag. Jobs are in-memory
    (completed artifacts persist as blobs); restarting drops in-flight jobs."""

    _STOP = -1

    def __init__(self, store: Store, workers: int = 2):
        self.store = store
        self._jobs: dict[int, Job] = {}
        self._active: dict[str, int] = {}  # url -> job id, while queued/running
        self._lock = threading.Lock()
        self._q: queue.Queue[int] = queue.Queue()
        self._ids = itertools.count(1)
        self._threads: list[threading.Thread] = []
        for _ in range(max(1, workers)):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def close(self, timeout: float = 3.0) -> None:
        """Ask each worker to exit and wait for them. Pushes one
        ``_STOP`` sentinel per worker so an idle ``queue.get()``
        unblocks; running workers finish their current job first.
        The daemon=True flag lets ``main()`` exit without calling
        this, but test fixtures + explicit shutdowns should call
        it to avoid the sqlite3 finalizer warnings that leaked
        worker threads produce."""
        for _ in self._threads:
            self._q.put(self._STOP)
        for t in self._threads:
            t.join(timeout=timeout)

    def enqueue(self, url: str, headers: dict | None = None) -> Job:
        with self._lock:
            jid = self._active.get(url)
            if jid is not None and self._jobs[jid].status in PENDING_STATES:
                return self._jobs[jid]  # dedup an already-pending pull
            job = Job(id=next(self._ids), url=url, headers=headers)
            self._jobs[job.id] = job
            self._active[url] = job.id
        self._q.put(job.id)
        return job

    def cancel(self, jid: int) -> Job | None:
        with self._lock:
            job = self._jobs.get(jid)
            if job is None:
                return None
            if job.status in PENDING_STATES:
                job._cancel.set()
                if job.status == "queued":  # never started: terminate now
                    job.status = "cancelled"
                    job.finished_at = time.time()
                    self._active.pop(job.url, None)
            return job

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.id, reverse=True)

    def clear_finished(self):
        with self._lock:
            for jid in [j.id for j in self._jobs.values() if j.status not in PENDING_STATES]:
                self._jobs.pop(jid, None)

    def _worker(self):
        while True:
            jid = self._q.get()
            if jid == self._STOP:
                return
            with self._lock:
                job = self._jobs.get(jid)
                if job is None or job.status != "queued":
                    continue  # cancelled while queued, or gone
                job.status = "running"
                job.started_at = time.time()
            try:
                # For oras://, the cache key stays the original ref but
                # the actual request goes through a freshly-minted
                # bearer + resolved blob URL. The resolver runs per
                # resume attempt so a long fetch survives bearer /
                # signed-URL TTL expiry mid-stream (the same kind of
                # cut the surrounding Range-resume loop was built for).
                fetch_resolver: object = None
                if oras.is_oras_url(job.url):

                    def _oras_resolve(_url: str = job.url) -> tuple[str, dict[str, str]]:
                        resolved = oras.resolve_ref(_url)
                        return resolved.blob_url, dict(resolved.headers)

                    fetch_resolver = _oras_resolve
                row = self.store.store_from_origin(
                    job.url,
                    progress=lambda done, total, j=job: _set_progress(j, done, total),
                    cancel=job._cancel.is_set,
                    headers=job.headers,
                    fetch_resolver=fetch_resolver,
                )
                with self._lock:
                    job.status = "completed"
                    job.sha256 = row["sha256"]
                    job.bytes_done = job.bytes_total = row["size"]
            except DownloadCancelled:
                with self._lock:
                    job.status = "cancelled"
            except Exception as e:
                with self._lock:
                    job.status = "cancelled" if job._cancel.is_set() else "failed"
                    job.error = str(e)
            finally:
                with self._lock:
                    job.finished_at = time.time()
                    if self._active.get(job.url) == job.id:
                        self._active.pop(job.url, None)


def _set_progress(job: Job, done: int, total: int | None):
    job.bytes_done = done
    if total is not None:
        job.bytes_total = total


def _oras_tag_moved(url: str, cached_sha: str | None, *, resolve=oras.resolve_ref) -> bool:
    """True iff ``url`` is an ``oras://`` *tag* whose layer the registry now
    resolves to something other than ``cached_sha``.

    The store keys on the ref string, not the resolved digest, so a mutable
    tag that is re-pushed (e.g. a rolling weekly image tag) would otherwise
    serve the first-cached bytes forever. Re-resolve the tag and compare its
    current layer digest against the cached bytes' ``sha256`` -- which IS that
    layer's content digest, so the comparison is exact.

    Returns False (keep the cached copy) for anything we cannot prove has
    moved: a non-oras URL, a digest-pinned ref (content-addressed, immutable),
    a missing ``cached_sha``, or a registry/resolve error -- availability
    beats freshness when the origin is unreachable, and a transient failure
    must never nuke a good entry. Returns True only on a demonstrated move, so
    the caller invalidates and re-fetches. ``resolve`` is injectable for tests.
    """
    if not oras.is_oras_url(url):
        return False
    try:
        ref = oras.parse_ref(url)
    except Exception:
        return False
    if ref.digest is not None:
        return False  # digest-pinned: the ref already names the content
    cached = (cached_sha or "").lower()
    if not cached:
        return False
    try:
        current = resolve(ref).digest.split(":", 1)[-1].lower()
    except Exception as exc:
        print(f"withcache: oras revalidate {url} failed: {exc}; serving cached copy", flush=True)
        return False
    if current == cached:
        return False
    print(
        f"withcache: oras tag moved {url}: "
        f"cached sha256:{cached[:12]} -> registry sha256:{current[:12]}; invalidating",
        flush=True,
    )
    return True


def main():
    """Daemon entry point.

    Constructs Store + DownloadManager, hands them to
    :func:`withcache._app.create_app`, then boots uvicorn.
    Background catalog init runs from the FastAPI lifespan hook;
    SIGTERM / SIGINT handling is uvicorn's.
    """
    import uvicorn

    from ._app import create_app

    ap = argparse.ArgumentParser(description="withcache cache-host")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument(
        "--keep-query",
        action="store_true",
        help="include the URL query string in the cache key "
        "(default: drop it, so signed/tokened URLs still match by path)",
    )
    ap.add_argument(
        "--workers", type=int, default=2, help="concurrent background download workers (default: 2)"
    )
    ap.add_argument(
        "--curate",
        action="store_true",
        help="require an operator to approve each pull (default: auto-fetch a "
        "missed artifact in the background so the next request hits)",
    )
    ap.add_argument(
        "--max-bytes",
        default="0",
        help="cap total cached bytes and refuse new fills when full (0 = "
        "unlimited; accepts 1024-based suffixes, e.g. 50G). Eviction is manual.",
    )
    args = ap.parse_args()

    store = Store(args.data_dir, keep_query=args.keep_query, max_bytes=parse_size(args.max_bytes))
    mgr = DownloadManager(store, workers=args.workers)
    auth_password = os.environ.get("WITHCACHE_ADMIN_PASSWORD")

    print(
        f"withcache cache-host on http://{args.host}:{args.port}  "
        f"(data={store.data_dir}, keep_query={args.keep_query}, workers={args.workers}, "
        f"mode={'curate' if args.curate else 'auto-fetch'}, "
        f"max_bytes={'unlimited' if not store.max_bytes else human_size(store.max_bytes)})",
        flush=True,
    )
    if not auth_password:
        print(
            "WARNING: WITHCACHE_ADMIN_PASSWORD not set — operator UI is UNAUTHENTICATED.",
            flush=True,
        )

    app = create_app(
        data_dir=store.data_dir,
        store=store,
        mgr=mgr,
        auto_fetch=not args.curate,
        keep_query=args.keep_query,
        max_bytes=parse_size(args.max_bytes),
        run_lifecycle=True,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
