#!/usr/bin/env python3
"""withcache cache-host — a URL-keyed artifact cache.

Stdlib only (http.server + sqlite3 + urllib). Serves cached blobs keyed by
their origin URL. By default a cache miss is auto-fetched: it is recorded in the
miss table and pulled from origin in the background, so the next request hits
(the client falls through to origin on the first miss). Run with `--curate` to
require an operator to approve each pull via a small web UI instead; either way
you can pre-seed an artifact with the Downloads-page Fetch form.

This is the only component that needs internet egress (and any vendor creds).
Clients never write to it.

Auth (single-tenant: env password + signed cookie): the read path
(`/blob`, `/healthz`) is open so clients never log in; the operator surface
(`/` and `/admin/*`) is gated behind a server-signed session cookie. Login at
`POST /ui/login` checks the password in $WITHCACHE_ADMIN_PASSWORD and flips the
cookie to authenticated; the cookie is HMAC-signed with a secret read from
$WITHCACHE_SESSION_SECRET or persisted to ``<data-dir>/session-secret``. If no
admin password is set, the operator UI is left open (with a startup warning).
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
import html
import http.cookies
import http.server
import itertools
import json
import os
import queue
import secrets
import socketserver
import sqlite3
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

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
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}
_DB_WRITE_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_human(started_at: float, *, now: float | None = None) -> str:
    """Render seconds-since as a compact ``Ns`` / ``Nm`` / ``Nh`` string for
    the streams table. ``now`` is injectable so tests don't need
    monkeypatching ``time.time`` to assert formatting."""
    elapsed = int(max(0.0, (now if now is not None else time.time()) - started_at))
    if elapsed < 60:
        return f"{elapsed}s"
    if elapsed < 3600:
        return f"{elapsed // 60}m{elapsed % 60:02d}s"
    return f"{elapsed // 3600}h{(elapsed % 3600) // 60:02d}m"


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
    so a restart doesn't wipe the last known good catalog and the
    same file can be re-served verbatim to consumers on a future
    ``GET /catalog.toml`` route.

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

    def __init__(self, store: Store, workers: int = 2):
        self.store = store
        self._jobs: dict[int, Job] = {}
        self._active: dict[str, int] = {}  # url -> job id, while queued/running
        self._lock = threading.Lock()
        self._q: queue.Queue[int] = queue.Queue()
        self._ids = itertools.count(1)
        for _ in range(max(1, workers)):
            threading.Thread(target=self._worker, daemon=True).start()

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


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = f"withcache/{__version__}"
    protocol_version = "HTTP/1.1"

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def auth(self) -> Auth:
        return self.server.auth  # type: ignore[attr-defined]

    @property
    def mgr(self) -> DownloadManager:
        return self.server.mgr  # type: ignore[attr-defined]

    @property
    def auto_fetch(self) -> bool:
        return self.server.auto_fetch  # type: ignore[attr-defined]

    @property
    def streams(self) -> StreamRegistry:
        return self.server.streams  # type: ignore[attr-defined]

    @property
    def catalog(self) -> CatalogState:
        return self.server.catalog  # type: ignore[attr-defined]

    def log_message(self, format, *args):  # quieter, single-line
        print(f"{self.address_string()} - {format % args}", flush=True)

    # Multi-page navigation matching bty's shape: five top-level pages,
    # one nav-btn each in the dark navbar. Fragment routes (``_fragment``)
    # power the per-page 1 Hz htmx auto-refresh so only the table body
    # swaps under the operator's cursor.
    NAV_ITEMS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("cached", "Cached", "bi-hdd-stack"),
        ("streams", "Streams", "bi-arrow-repeat"),
        ("downloads", "Downloads", "bi-cloud-download"),
        ("misses", "Misses", "bi-question-circle"),
        ("catalog", "Catalog", "bi-collection"),
    )
    _NAV_KEYS: ClassVar[frozenset[str]] = frozenset(k for k, _label, _icon in NAV_ITEMS)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/blob" or parsed.path.startswith("/b/"):
            self.handle_blob(parsed, head_only=False)
            return
        if parsed.path == "/healthz":
            self.send_text(200, "ok\n")
            return
        if parsed.path.startswith("/static/"):
            self.serve_static(parsed)
            return
        if parsed.path == "/ui/login":
            self.handle_login_form()
            return
        if parsed.path == "/":
            if not self.is_authed():
                self.redirect("/ui/login")
            else:
                self.redirect("/ui/cached")
            return
        # /ui/<page> (full page) or /ui/<page>_fragment (htmx body swap).
        if parsed.path.startswith("/ui/"):
            tail = parsed.path[len("/ui/") :]
            fragment = tail.endswith("_fragment")
            key = tail[: -len("_fragment")] if fragment else tail
            if key in self._NAV_KEYS:
                if not self.is_authed():
                    if fragment:
                        self.send_text(401, "login required\n")
                    else:
                        self.redirect("/ui/login")
                    return
                self._render_page(key, fragment=fragment)
                return
        self.send_text(404, "not found\n")

    def do_HEAD(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/blob" or parsed.path.startswith("/b/"):
            self.handle_blob(parsed, head_only=True)
        else:
            self.send_text(404, "")

    ADMIN_POST = (
        "/admin/fetch",
        "/admin/dismiss",
        "/admin/delete",
        "/admin/cancel",
        "/admin/clear",
        "/admin/catalog_refresh",
        "/admin/catalog_set_url",
        "/admin/catalog_add_oras",
        "/admin/catalog_delete_entry",
    )

    # Map each POST admin action to the /ui/<page> the operator was
    # on so ``respond_admin`` sends non-htmx callers back to a sensible
    # landing after the action.
    _ADMIN_HOME: ClassVar[dict[str, str]] = {
        "/admin/fetch": "/ui/downloads",
        "/admin/dismiss": "/ui/misses",
        "/admin/delete": "/ui/cached",
        "/admin/cancel": "/ui/downloads",
        "/admin/clear": "/ui/downloads",
        "/admin/catalog_refresh": "/ui/catalog",
        "/admin/catalog_set_url": "/ui/catalog",
        "/admin/catalog_add_oras": "/ui/catalog",
        "/admin/catalog_delete_entry": "/ui/catalog",
    }

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        form = self.read_form()
        if parsed.path == "/ui/login":
            self.handle_login_submit(form)
        elif parsed.path == "/ui/logout":
            self.handle_logout()
        elif parsed.path in self.ADMIN_POST:
            if not self.is_authed():
                self.send_text(401, "login required\n")
                return
            if parsed.path == "/admin/fetch":
                url = form.get("url", "").strip()
                if url:
                    self.mgr.enqueue(url, headers=parse_headers(form.get("header", "")))
            elif parsed.path == "/admin/dismiss":
                self.store.dismiss(form.get("key", "").strip())
            elif parsed.path == "/admin/delete":
                self.store.delete_blob(form.get("key", "").strip())
            elif parsed.path == "/admin/cancel":
                jid = form.get("id", "")
                if jid.isdigit():
                    self.mgr.cancel(int(jid))
            elif parsed.path == "/admin/clear":
                self.mgr.clear_finished()
            elif parsed.path == "/admin/catalog_refresh":
                self.catalog.fetch_now()
            elif parsed.path == "/admin/catalog_set_url":
                ok, msg = self.catalog.set_url_override(form.get("url", ""))
                if ok:
                    # Trigger an immediate fetch so the operator sees
                    # the new source's entries without a second click.
                    self.catalog.fetch_now()
                else:
                    self.catalog.last_error = msg
            elif parsed.path == "/admin/catalog_add_oras":
                self.catalog.add_oras_entry(form.get("url", ""))
            elif parsed.path == "/admin/catalog_delete_entry":
                ok, msg = self.catalog.delete_entry(form.get("name", ""))
                if not ok:
                    self.catalog.last_error = msg
            self.respond_admin(parsed.path)
        else:
            self.send_text(404, "not found\n")

    # -- auth helpers ------------------------------------------------------
    def is_authed(self) -> bool:
        if not self.auth.enabled:
            return True  # no password configured -> open operator UI
        token = self.cookie(Auth.COOKIE)
        return bool(token and self.auth.valid(token))

    def cookie(self, name: str):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw)
        except http.cookies.CookieError:
            return None
        m = jar.get(name)
        return m.value if m else None

    def is_htmx(self) -> bool:
        return self.headers.get("HX-Request") == "true"

    def serve_static(self, parsed):
        """Serve files under ``src/withcache/static/`` (Bootstrap CSS +
        Bootstrap Icons CSS + htmx.min.js + the icon font files under
        ``static/fonts/`` that bootstrap-icons.min.css references via
        a relative ``fonts/…`` src). Constrain to ``static/`` and
        ``static/fonts/`` explicitly; abspath+startswith rejects any
        ``..`` traversal past the static root."""
        rel = parsed.path[len("/static/") :]
        if not rel or rel.endswith("/"):
            self.send_text(404, "not found\n")
            return
        target = os.path.abspath(os.path.join(STATIC_DIR, rel))
        static_root = os.path.abspath(STATIC_DIR) + os.sep
        if not target.startswith(static_root) or not os.path.isfile(target):
            self.send_text(404, "not found\n")
            return
        with open(target, "rb") as f:
            data = f.read()
        ext = os.path.splitext(target)[1]
        self.send_response(200)
        self.send_header("Content-Type", MIME_TYPES.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def respond_admin(self, endpoint: str):
        """HTMX actions get the refreshed per-page fragment; plain form
        posts (no JS) fall back to a full-page redirect at the page
        that hosts this action."""
        home = self._ADMIN_HOME.get(endpoint, "/ui/cached")
        if self.is_htmx():
            # The htmx form set ``hx-target`` to the page's fragment
            # container (``#cached-fragment`` etc.) and ``hx-swap`` to
            # ``innerHTML``; render just the inner rows.
            key = home[len("/ui/") :] if home.startswith("/ui/") else "cached"
            self.send_html(200, self._render_fragment_only(key))
        else:
            self.redirect(home)

    def handle_login_form(self):
        if self.is_authed():
            self.redirect("/ui/cached")
            return
        self.send_html(200, self.render_login())

    def handle_login_submit(self, form):
        if not self.auth.enabled:
            self.redirect("/ui/cached")
            return
        if self.auth.check_password(form.get("password", "")):
            cookie = (
                f"{Auth.COOKIE}={self.auth.make_token()}; HttpOnly; "
                f"SameSite=Lax; Path=/; Max-Age={Auth.MAX_AGE}"
            )
            self.redirect("/ui/cached", set_cookie=cookie)
            print(f"{self.address_string()} - login succeeded", flush=True)
        else:
            print(f"{self.address_string()} - login failed", flush=True)
            self.send_html(401, self.render_login(error="Invalid password."))

    def handle_logout(self):
        expired = f"{Auth.COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
        self.redirect("/ui/login", set_cookie=expired)

    # -- blob serving ------------------------------------------------------
    def _blob_origin(self, parsed) -> str:
        """Origin URL from either /blob?url=<origin> or /b/<base64>/<name>."""
        if parsed.path.startswith("/b/"):
            token = parsed.path[len("/b/") :].split("/", 1)[0]
            try:
                return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return ""
        return (urllib.parse.parse_qs(parsed.query).get("url") or [""])[0]

    def handle_blob(self, parsed, head_only: bool):
        url = self._blob_origin(parsed)
        if not url:
            self.send_text(400, "missing url\n")
            return
        row = self.store.get_blob(url)
        if row is not None and _oras_tag_moved(url, row["sha256"]):
            # The tag was re-pushed to a different layer since we cached it.
            # Drop the stale bytes and fall through to the miss path so the
            # current content is (auto-)fetched. Deleting first also frees the
            # space the refill needs when the store is near --max-bytes.
            self.store.delete_blob(row["key"])
            row = None
        if row is None:
            self.store.record_miss(url)
            if self.auto_fetch and self.store.has_capacity():
                # Pull it in the background so the next request hits; the client
                # gets this one from origin (the shim, or bty's fallback chain,
                # falls through on a miss). In --curate mode an operator triggers
                # the pull instead; when the cache is full we record the miss but
                # schedule nothing (delete something first).
                #
                # Forward the client's ``Authorization`` header into the worker
                # job so a token-gated origin (typical use case: a fresh OCI
                # bearer on a ghcr.io blob URL minted by bty-web at catalog
                # import time) can be fetched. Without this the worker runs
                # anonymous and 401s; the URL stays uncached forever. Keep the
                # allowlist narrow on purpose: ``Authorization`` is the only
                # request header we proxy onto the worker. The ``/admin/fetch``
                # operator endpoint still carries its own ``headers=`` payload
                # for the curated path.
                fwd_headers = None
                auth = self.headers.get("Authorization")
                if auth:
                    fwd_headers = {"Authorization": auth}
                self.mgr.enqueue(url, headers=fwd_headers)
            self.send_text(404, "cache miss (recorded)\n")
            return
        path = self.store.blob_path(row["key"])
        self.send_response(200)
        self.send_header("Content-Type", row["content_type"] or "application/octet-stream")
        self.send_header("Content-Length", str(row["size"]))
        self.send_header("X-Withcache-Sha256", row["sha256"])
        self.end_headers()
        if head_only:
            return  # the shim's HEAD probe (not a served download, so don't count it)
        self.store.record_hit(row["key"])
        # Register the stream BEFORE we open the file so an operator
        # watching the dash sees the serve immediately (even if the
        # disk read stalls). The handler runs on a worker thread per
        # the ThreadingHTTPServer mixin, so the registry sees
        # concurrent calls; StreamRegistry serialises on its own lock.
        client = f"{self.client_address[0]}:{self.client_address[1]}"
        stream = self.streams.start(url=url, client=client, total=row["size"])
        try:
            with open(path, "rb") as f:
                sent = 0
                ticks = 0
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    sent += len(chunk)
                    ticks += 1
                    # Batched progress update: every 16 chunks (~1 MiB
                    # at CHUNK=64K) is plenty for a 1 Hz dashboard and
                    # keeps lock-contention sane on a busy box.
                    if ticks % StreamRegistry.PROGRESS_STRIDE == 0:
                        self.streams.bump(stream.id, sent)
                # Final position so the dash's last frame shows the
                # serve completing at the declared total, not at
                # whatever the last batched update happened to be.
                self.streams.bump(stream.id, sent)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away mid-stream
        finally:
            self.streams.finish(stream.id)

    # -- helpers -----------------------------------------------------------
    def read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8") if length else ""
        return {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}

    def send_text(self, code: int, text: str):
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_html(self, code: int, body: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, set_cookie: str | None = None):
        self.send_response(303)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # -- HTML --------------------------------------------------------------
    STATUS_COLORS: ClassVar[dict[str, str]] = {
        "queued": "var(--bs-secondary)",
        "running": "var(--bs-primary)",
        "completed": "var(--bs-success)",
        "failed": "var(--bs-danger)",
        "cancelled": "var(--bs-secondary)",
    }

    # bty ships a Bootstrap 5 stack (bootstrap.min.css +
    # bootstrap-icons.min.css + htmx). All three ecosystem services
    # (bty, nbdmux, withcache) share that stack so operators only
    # learn one UI grammar; the primary hue is what tells them
    # which service they're on. The trio sits on a
    # navy -> dark-magenta -> magenta gradient (cool -> hot);
    # withcache is the dark-magenta middle (the byte cache that
    # feeds nbdmux and every other consumer).
    _PRIMARY_HEX = "#8f1b71"  # dark-magenta
    _PRIMARY_HOVER = "#7a1861"
    _PRIMARY_RGB = "143, 27, 113"

    def _head(self, title: str) -> str:
        """Emit the shared page prelude: Bootstrap + icons + htmx +
        the full bty-family chrome CSS. Every service (bty, withcache,
        nbdmux) uses this same block; the only per-service knob is the
        primary hue (``--bs-primary`` and the derived button /
        rgba() variants). See bty's ``_layout.html`` for the origin
        of these class names -- kept identical here so operators
        moving between consoles see one visual grammar."""
        primary = self._PRIMARY_HEX
        hover = self._PRIMARY_HOVER
        rgb = self._PRIMARY_RGB
        return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/static/bootstrap.min.css">
<link rel="stylesheet" href="/static/bootstrap-icons.min.css">
<script src="/static/htmx.min.js"></script>
<style>
  /* Palette anchor for the three-service trio (bty navy,
     withcache dark-magenta, nbdmux magenta). Bootstrap 5
     exposes --bs-primary + a matching -rgb triplet used for
     translucent variants (alerts, focus rings, .bg-*-subtle).
     Overriding both here re-tints every stock component
     without patching bootstrap.min.css. */
  :root {{
    --bs-primary: {primary};
    --bs-primary-rgb: {rgb};
    --bs-link-color: {primary};
    --bs-link-hover-color: {hover};
  }}
  .btn-primary {{
    --bs-btn-bg: {primary};
    --bs-btn-border-color: {primary};
    --bs-btn-hover-bg: {hover};
    --bs-btn-hover-border-color: {hover};
    --bs-btn-active-bg: {hover};
    --bs-btn-active-border-color: {hover};
  }}
  .bg-primary {{ --bs-bg-opacity: 1; background-color: {primary} !important; }}
  .text-primary {{ --bs-text-opacity: 1; color: {primary} !important; }}
  .border-primary {{ --bs-border-opacity: 1; border-color: {primary} !important; }}
  /* Brand strip: a thin gradient accent above the navbar.
     Stable across themes; defined inline rather than in
     bootstrap.min.css so it renders even when the CSS load
     races the initial paint. Shared navy -> dark-magenta ->
     magenta gradient across bty (navy), withcache
     (dark-magenta) and nbdmux (magenta) so the trio reads as
     one product family from any of the three consoles. */
  .brand-accent {{
    height: 3px;
    background: linear-gradient(90deg, #0d3585 0%, #8f1b71 50%, #d63384 100%);
  }}
  /* The accent + navbar + sub-nav pin to the top as one unit so
     the sub-nav jump links stay visible while scrolling. */
  .sticky-header {{
    position: sticky;
    top: 0;
    z-index: 1030;
  }}
  /* In-page ``#anchor`` jumps (the sub-nav tab pills) land below
     the sticky header instead of under it. */
  html {{
    scroll-padding-top: 6.5rem;
    scroll-behavior: smooth;
  }}
  /* Brand pill keeps the same padding + radius everywhere; the
     ``brand-active`` variant lights up on the home page so the
     brand doubles as a Home indicator. */
  .navbar-brand {{
    border-radius: 0.5rem;
    padding-left: 0.6rem;
    padding-right: 0.6rem;
    margin-right: 0.25rem;
    transition: background-color 0.15s;
  }}
  .navbar-brand.brand-active {{
    background-color: rgba({rgb}, 0.85);
  }}
  .navbar-brand:hover {{
    background-color: rgba(255, 255, 255, 0.06);
  }}
  .navbar-brand.brand-active:hover {{
    background-color: rgba({rgb}, 0.95);
  }}
  /* Version sits in the navbar alongside the brand pill but
     OUTSIDE it -- so the brand button stays a clean click target
     and the version reads as adjacent metadata. */
  .navbar-version {{
    color: rgba(255, 255, 255, 0.55);
    font-weight: 400;
    font-size: 0.85rem;
    align-self: center;
    white-space: nowrap;
  }}
  .navbar-brand .brand-icon {{
    /* Sized to match bty's mascot PNG (1.05rem tall). Using a
       Bootstrap Icon rather than an image keeps the shell
       stdlib-only. */
    font-size: 1.05rem;
    vertical-align: -0.05rem;
  }}
  .navbar .nav-btn {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.4rem 0.8rem;
    margin-right: 0.25rem;
    border-radius: 0.5rem;
    color: rgba(255, 255, 255, 0.85);
    text-decoration: none;
    transition: background-color 0.15s;
  }}
  .navbar .nav-btn:hover {{
    background-color: rgba(255, 255, 255, 0.10);
    color: #fff;
  }}
  .navbar .nav-btn.active {{
    background-color: {primary};
    color: #fff;
    box-shadow: 0 0 0 1px rgba({rgb}, 0.6);
  }}
  .navbar .nav-btn i {{
    font-size: 1.05rem;
  }}
  /* User-bar: a single pill containing username + logout, with a
     thin vertical divider between them. Visually one widget,
     but two click targets and zero JavaScript. */
  .user-bar {{
    display: inline-flex;
    align-items: stretch;
    border-radius: 999px;
    background-color: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.12);
    overflow: hidden;
    font-size: 0.85rem;
  }}
  .user-bar-name {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.35rem 0.8rem;
    color: rgba(255, 255, 255, 0.92);
  }}
  .user-bar-name code {{
    color: #fff;
    background: transparent;
    padding: 0;
  }}
  .user-bar-divider {{
    width: 1px;
    background-color: rgba(255, 255, 255, 0.18);
  }}
  .user-bar-action {{
    display: inline-flex;
    align-items: center;
    padding: 0.35rem 0.7rem;
    background: transparent;
    border: none;
    color: rgba(255, 255, 255, 0.85);
    text-decoration: none;
    transition: background-color 0.15s, color 0.15s;
  }}
  .user-bar-action:hover,
  .user-bar-action:focus {{
    background-color: rgba(255, 255, 255, 0.10);
    color: #fff;
    outline: none;
  }}
  .user-bar-action.active {{
    background-color: rgba(255, 255, 255, 0.16);
    color: #fff;
  }}
  /* Logout hover keeps the danger-red signal so it doesn't
     look indistinguishable from the account action. */
  .user-bar-logout:hover,
  .user-bar-logout:focus {{
    background-color: rgba(220, 53, 69, 0.65);
    color: #fff;
  }}
  /* Sub-nav strip. Sits immediately below the main ``bg-dark``
     navbar; coloured CLEARLY lighter so it reads as "second-tier
     nav, still chrome". Same ``#495057`` (--bs-gray-700) bty
     uses so the boundary is unambiguous regardless of theme. */
  .subnav-strip {{
    background-color: #495057;
    border-bottom: 1px solid rgba(255, 255, 255, 0.10);
    padding-top: 0.25rem;
    padding-bottom: 0.25rem;
    font-size: 0.85rem;
    line-height: 1.4;
  }}
  .subnav-strip > .container {{
    min-height: 2rem;
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }}
  .subnav-strip .form-control-sm,
  .subnav-strip .btn-sm,
  .subnav-strip a,
  .subnav-strip label,
  .subnav-strip .small,
  .subnav-strip small {{
    font-size: inherit;
    line-height: inherit;
  }}
  .subnav-strip .form-control-sm,
  .subnav-strip .btn-sm {{
    padding-top: 0.15rem;
    padding-bottom: 0.15rem;
  }}
  .subnav-strip .nav-pills {{
    gap: 0.25rem;
  }}
  .subnav-strip .nav-pills .nav-link {{
    color: rgba(255, 255, 255, 0.78);
    padding: 0.15rem 0.55rem;
  }}
  .subnav-strip .nav-pills .nav-link:hover {{
    color: #fff;
    background-color: rgba(255, 255, 255, 0.10);
  }}
  .subnav-strip .text-muted {{
    color: rgba(255, 255, 255, 0.55) !important;
  }}
  .subnav-strip code {{
    color: rgba(255, 255, 255, 0.85);
    background-color: transparent;
  }}
  .subnav-strip a {{
    color: rgba(255, 255, 255, 0.78);
  }}
  .subnav-strip a:hover {{
    color: #fff;
  }}
  /* Withcache-specific bits kept minimal. Everything else
     inherits from Bootstrap + the chrome above. */
  code {{ color: inherit; font-size: .85em; }}
  .url {{ word-break: break-all; }}
  .num {{ text-align: right; }}
  .mono {{ font-family: var(--bs-font-monospace); font-size: .85em; }}
  #spin {{ width: 7rem; height: .5rem; margin: 0; }}
</style>
</head>"""

    def render_login(self, error: str = "") -> str:
        """The unauthenticated shell: accent strip + dark navbar with the
        brand pill (no user-bar since there's no session), then a
        centered login card. Same chrome the authenticated page uses,
        so the operator sees continuity across the auth boundary."""
        err = f'<div class="alert alert-danger">{html.escape(error)}</div>' if error else ""
        return f"""{self._head("withcache - login")}
<body class="bg-light">
<div class="sticky-header">
<div class="brand-accent"></div>
<nav class="navbar navbar-expand-md bg-dark navbar-dark py-2">
    <div class="container">
        <a class="navbar-brand fw-semibold brand-active" href="/">
            <i class="bi bi-database brand-icon me-1"></i>WITHCACHE
        </a>
        <span class="navbar-version">v{html.escape(__version__)}</span>
    </div>
</nav>
</div>
<main class="container">
  <div class="card mx-auto mt-5" style="max-width: 24rem;">
    <div class="card-body">
      <h5 class="card-title mb-3">Operator login</h5>
      {err}
      <form method="post" action="/ui/login">
        <div class="mb-3">
          <label class="form-label" for="pw">Admin password</label>
          <input class="form-control" id="pw" type="password" name="password" autofocus required>
        </div>
        <button class="btn btn-primary w-100" type="submit">Log in</button>
      </form>
    </div>
  </div>
</main></body></html>"""

    # ---- Multi-page shell ------------------------------------------------
    def _user_bar_html(self) -> str:
        if not self.auth.enabled:
            return ""
        return (
            '<div class="user-bar mt-2 mt-md-0" title="Operator session">'
            '<span class="user-bar-name">'
            '<i class="bi bi-person-circle"></i><code>operator</code>'
            "</span>"
            '<span class="user-bar-divider"></span>'
            '<form action="/ui/logout" method="post" class="m-0 d-inline-flex">'
            '<button type="submit" class="user-bar-action user-bar-logout" title="Sign out">'
            '<i class="bi bi-box-arrow-right"></i>'
            "</button></form>"
            "</div>"
        )

    def _nav_btns_html(self, active_key: str) -> str:
        """Render the five middle nav-btns in the dark navbar with
        their live counts and icons. One carries ``.active`` for the
        current page."""
        counts = self._nav_counts()
        parts: list[str] = []
        for key, label, icon in self.NAV_ITEMS:
            n = counts.get(key, 0)
            active = " active" if key == active_key else ""
            parts.append(
                f'<a class="nav-btn{active}" href="/ui/{key}">'
                f'<i class="bi {icon}"></i>{label} ({n})'
                "</a>"
            )
        return "".join(parts)

    def _nav_counts(self) -> dict[str, int]:
        nblobs, nmisses = self.store.counts()
        return {
            "cached": nblobs,
            "streams": len(self.streams.snapshot()),
            "downloads": len(self.mgr.list()),
            "misses": nmisses,
            "catalog": len(self.catalog.entries),
        }

    def _render_shell(
        self,
        title: str,
        nav_active: str,
        subnav_html: str,
        body_html: str,
    ) -> str:
        return f"""{self._head(title)}
<body class="bg-light">
<div class="sticky-header">
<div class="brand-accent"></div>
<nav class="navbar navbar-expand-md bg-dark navbar-dark py-2">
    <div class="container">
        <a class="navbar-brand fw-semibold" href="/ui/cached">
            <i class="bi bi-database brand-icon me-1"></i>WITHCACHE
        </a>
        <div class="d-flex flex-grow-1 align-items-center flex-wrap">
            <div class="me-auto d-flex flex-wrap">
                {self._nav_btns_html(nav_active)}
            </div>
            <span class="navbar-version me-2">v{html.escape(__version__)}</span>
            {self._user_bar_html()}
        </div>
    </div>
</nav>
{subnav_html}
</div><!-- /.sticky-header -->
<main class="container py-4">
{body_html}
</main></body></html>"""

    def _render_page(self, key: str, *, fragment: bool) -> None:
        """Dispatch a full-page render or a fragment-only refresh for
        the given nav key. Fragment mode is used by the per-page htmx
        auto-refresh trigger (``hx-get=/ui/<key>_fragment`` on the
        wrapping div) so only the table body swaps."""
        if fragment:
            self.send_html(200, self._render_fragment_only(key))
            return
        subnav, body = self._render_page_parts(key)
        title = {
            "cached": "withcache -- Cached",
            "streams": "withcache -- Streams",
            "downloads": "withcache -- Downloads",
            "misses": "withcache -- Misses",
            "catalog": "withcache -- Catalog",
        }[key]
        self.send_html(200, self._render_shell(title, key, subnav, body))

    def _render_page_parts(self, key: str) -> tuple[str, str]:
        """Return ``(subnav_html, main_body_html)`` for the given page.
        The main body embeds an ``hx-get=/ui/<key>_fragment`` wrapper
        so the 1 Hz auto-refresh only swaps the inner rows."""
        if key == "cached":
            subnav = self._subnav("")
            body = self._cached_body_html()
        elif key == "streams":
            subnav = self._subnav("")
            body = self._streams_body_html()
        elif key == "downloads":
            subnav = self._downloads_subnav_html()
            body = self._downloads_body_html()
        elif key == "misses":
            subnav = self._subnav("")
            body = self._misses_body_html()
        else:  # catalog
            subnav = self._catalog_subnav_html()
            body = self._catalog_body_html()
        return subnav, body

    def _render_fragment_only(self, key: str) -> str:
        """The inner (auto-refresh) fragment for a page: just the
        rows / cards that change under polling. Wrapping ``div`` lives
        in the full page and stays static across swaps."""
        if key == "cached":
            return self._cached_fragment_html()
        if key == "streams":
            return self._streams_fragment_html()
        if key == "downloads":
            return self._downloads_fragment_html()
        if key == "misses":
            return self._misses_fragment_html()
        return self._catalog_fragment_html()

    def _subnav(self, right_html: str, *, left_html: str = "") -> str:
        """Assemble the subnav strip from optional left / right slots.
        Left slot defaults to empty; right slot goes into
        ``.subnav-actions.ms-auto`` per bty convention."""
        left = left_html
        right = ""
        if right_html:
            right = (
                '<div class="subnav-actions ms-auto d-flex '
                f'align-items-center gap-1">{right_html}'
                '<progress id="spin" class="htmx-indicator ms-1" '
                'style="width:4rem;height:.4rem;"></progress></div>'
            )
        return f'<div class="subnav-strip"><div class="container">{left}{right}</div></div>'

    # ---- Cached page -----------------------------------------------------
    def _cached_body_html(self) -> str:
        return f"""
  <div id="cached-fragment"
       hx-get="/ui/cached_fragment"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML">
    {self._cached_fragment_html()}
  </div>"""

    def _cached_fragment_html(self) -> str:
        blobs = self.store.list_blobs()

        def _serve_url_for(row: sqlite3.Row) -> str:
            origin = row["url"]
            token = base64.urlsafe_b64encode(origin.encode("utf-8")).decode("ascii").rstrip("=")
            name = urllib.parse.urlsplit(origin).path.rsplit("/", 1)[-1] or "download"
            return f"/b/{token}/{urllib.parse.quote(name)}"

        rows = (
            "".join(
                f"""<tr>
                <td class="url">
                  <a href="{_serve_url_for(b)}"
                     title="Download the cached object">{html.escape(b["url"])}</a>
                </td>
                <td>{human_size(b["size"])}</td>
                <td class="num">{b["hits"]}</td>
                <td class="num">{b["misses"]}</td>
                <td class="mono">{html.escape(b["sha256"][:12])}...</td>
                <td><small>{html.escape(b["fetched_at"])}</small></td>
                <td>
                  <form hx-post="/admin/delete" hx-target="#cached-fragment"
                        hx-swap="innerHTML"
                        hx-confirm="Delete this cached artifact?" class="m-0">
                    <input type="hidden" name="key"
                           value="{html.escape(b["key"], quote=True)}">
                    <button class="btn btn-sm btn-outline-danger" type="submit"
                      >Delete</button>
                  </form>
                </td>
            </tr>"""
                for b in blobs
            )
            or '<tr><td colspan="7" class="text-center text-muted">'
            "<em>Cache is empty.</em></td></tr>"
        )
        return f"""
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th>Size</th><th class="num">Hits</th><th class="num">Misses</th>
        <th>SHA-256</th><th>Fetched</th><th>Action</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""

    # ---- Streams page ----------------------------------------------------
    def _streams_body_html(self) -> str:
        return f"""
  <div id="streams-fragment"
       hx-get="/ui/streams_fragment"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML">
    {self._streams_fragment_html()}
  </div>"""

    def _streams_fragment_html(self) -> str:
        streams = self.streams.snapshot()
        rows = (
            "".join(
                f"""<tr>
                <td class="url">{html.escape(s.url)}</td>
                <td class="mono"><small>{html.escape(s.client)}</small></td>
                <td>{self._stream_progress_cell(s)}</td>
                <td><small>{_age_human(s.started_at)}</small></td>
            </tr>"""
                for s in streams
            )
            or '<tr><td colspan="4" class="text-center text-muted">'
            "<em>No active streams.</em></td></tr>"
        )
        return f"""
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th>Client</th><th>Progress</th><th>Age</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""

    # ---- Downloads page --------------------------------------------------
    def _downloads_subnav_html(self) -> str:
        """Downloads carries the Add-from-URI form in the subnav's
        right slot -- this is the page that hosts the auto-fetch
        workers those inputs feed."""
        right = (
            '<form hx-post="/admin/fetch" hx-target="#downloads-fragment" '
            'hx-swap="innerHTML" hx-indicator="#spin" '
            'hx-on::after-request="this.reset()" '
            'class="m-0 d-flex align-items-center gap-1">'
            '<input class="form-control form-control-sm" type="url" name="url" '
            'style="width: 22rem;" '
            'placeholder="https://origin/path/artifact.tar.gz" required>'
            '<button class="btn btn-sm btn-primary" type="submit" title="Fetch URI"'
            ">Fetch</button>"
            "</form>"
        )
        return self._subnav(right)

    def _downloads_body_html(self) -> str:
        return f"""
  <div id="downloads-fragment"
       hx-get="/ui/downloads_fragment"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML">
    {self._downloads_fragment_html()}
  </div>"""

    def _downloads_fragment_html(self) -> str:
        jobs = self.mgr.list()
        rows = (
            "".join(self._job_row(j) for j in jobs)
            or '<tr><td colspan="4" class="text-center text-muted">'
            "<em>No downloads yet.</em></td></tr>"
        )
        return f"""
    <div class="d-flex align-items-center justify-content-between mb-2">
      <small class="text-muted">Auto-fetch workers feeding the cache.</small>
      <form hx-post="/admin/clear" hx-target="#downloads-fragment" hx-swap="innerHTML"
            class="m-0">
        <button class="btn btn-sm btn-outline-secondary" type="submit"
          >Clear finished</button>
      </form>
    </div>
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>Artifact</th><th>Progress</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""

    # ---- Misses page -----------------------------------------------------
    def _misses_body_html(self) -> str:
        return f"""
  <div id="misses-fragment"
       hx-get="/ui/misses_fragment"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML">
    {self._misses_fragment_html()}
  </div>"""

    def _misses_fragment_html(self) -> str:
        misses = self.store.list_misses()
        rows = (
            "".join(
                f"""<tr>
                <td class="url">{html.escape(m["url"])}</td>
                <td class="num">{m["count"]}</td>
                <td><small>{html.escape(m["last_seen"])}</small></td>
                <td class="d-flex gap-2 flex-wrap">
                  <form hx-post="/admin/fetch" hx-target="#misses-fragment"
                        hx-swap="innerHTML" hx-indicator="#spin" class="m-0">
                    <input type="hidden" name="url"
                           value="{html.escape(m["url"], quote=True)}">
                    <button class="btn btn-sm btn-primary" type="submit">Download</button>
                  </form>
                  <form hx-post="/admin/dismiss" hx-target="#misses-fragment"
                        hx-swap="innerHTML" class="m-0">
                    <input type="hidden" name="key"
                           value="{html.escape(m["key"], quote=True)}">
                    <button class="btn btn-sm btn-outline-secondary" type="submit"
                      >Dismiss</button>
                  </form>
                </td>
            </tr>"""
                for m in misses
            )
            or '<tr><td colspan="4" class="text-center text-muted">'
            "<em>No misses recorded.</em></td></tr>"
        )
        return f"""
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th class="num">Misses</th><th>Last seen</th><th>Action</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table></div>"""

    # ---- Catalog page ----------------------------------------------------
    def _catalog_subnav_html(self) -> str:
        """Catalog subnav-actions right side: the Catalog URL form
        (Set & fetch + Refresh) plus a small oras-only input that
        appends a single {name, src, format?, arch?} entry."""
        catalog = self.catalog
        env_pinned = bool(catalog.env_url)
        url_input_attrs = (
            'disabled title="pinned by env WITHCACHE_CATALOG_URL"' if env_pinned else ""
        )
        env_hint = (
            '<span class="badge bg-secondary bg-opacity-10 text-secondary ms-1"'
            ' title="pinned by env">env</span>'
            if env_pinned
            else ""
        )
        right = f"""
    <form hx-post="/admin/catalog_set_url" hx-target="#catalog-fragment"
          hx-swap="innerHTML" hx-indicator="#spin"
          class="m-0 d-flex align-items-center gap-1">
      <label class="text-muted small mb-0">URL {env_hint}</label>
      <input class="form-control form-control-sm" type="url" name="url"
             value="{html.escape(catalog.url, quote=True)}"
             style="width: 20rem;" required {url_input_attrs}>
      <button class="btn btn-sm btn-primary" type="submit"
              {url_input_attrs}>Set &amp; fetch</button>
      <button class="btn btn-sm btn-outline-secondary" type="button"
              hx-post="/admin/catalog_refresh" hx-target="#catalog-fragment"
              hx-swap="innerHTML" hx-indicator="#spin"
              title="Refetch from current URL">Refresh</button>
    </form>
    <span class="text-muted small ms-2">|</span>
    <form hx-post="/admin/catalog_add_oras" hx-target="#catalog-fragment"
          hx-swap="innerHTML" hx-indicator="#spin"
          hx-on::after-request="this.reset()"
          class="m-0 d-flex align-items-center gap-1">
      <input class="form-control form-control-sm" type="text" name="url"
             style="width: 22rem;"
             placeholder="oras://ghcr.io/owner/repo:tag" required>
      <button class="btn btn-sm btn-primary" type="submit"
              title="Add a single image from an oras:// reference"
              >Add from oras</button>
    </form>"""
        return self._subnav(right)

    def _catalog_body_html(self) -> str:
        return f"""
  <div id="catalog-fragment"
       hx-get="/ui/catalog_fragment"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML">
    {self._catalog_fragment_html()}
  </div>"""

    def _catalog_fragment_html(self) -> str:
        catalog = self.catalog
        banner = ""
        if catalog.last_error:
            banner = (
                '<div class="alert alert-danger py-1 px-2 mb-2 small">'
                '<i class="bi bi-exclamation-triangle-fill me-1"></i>'
                f"{html.escape(catalog.last_error)}</div>"
            )
        elif catalog.last_info:
            banner = (
                '<div class="alert alert-success py-1 px-2 mb-2 small">'
                '<i class="bi bi-check-circle-fill me-1"></i>'
                f"{html.escape(catalog.last_info)}</div>"
            )
        meta = (
            '<p class="text-muted small mb-2">Last fetched '
            f"<code>{html.escape(catalog.fetched_at) or 'never'}</code> &middot; "
            f"{len(catalog.entries)} entries</p>"
        )
        return f"""
    {meta}
    {banner}
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>Name</th><th>Format</th><th>Arch</th><th>Size</th><th>Source</th><th></th>
      </tr></thead>
      <tbody>{self._catalog_rows()}</tbody>
    </table></div>"""

    def _catalog_rows(self) -> str:
        entries = self.catalog.entries
        if not entries:
            hint = self.catalog.last_error or "click Refresh above, or Add from oras, to populate."
            return (
                '<tr><td colspan="6" class="text-center text-muted">'
                f"<em>{html.escape(hint)}</em></td></tr>"
            )
        rows: list[str] = []
        for entry in entries:
            name = str(entry.get("name") or "")
            src = str(entry.get("src") or "")
            fmt = str(entry.get("format") or "")
            arch = str(entry.get("arch") or "")
            size_bytes = entry.get("size_bytes")
            size = human_size(int(size_bytes)) if isinstance(size_bytes, int) else ""
            if src.startswith(("http://", "https://", "oras://")):
                token = base64.urlsafe_b64encode(src.encode("utf-8")).decode("ascii").rstrip("=")
                filename = urllib.parse.urlsplit(src).path.rsplit("/", 1)[-1] or "download"
                link = f"/b/{token}/{urllib.parse.quote(filename)}"
                src_cell = f'<a href="{link}" title="{html.escape(src)}">{html.escape(src)}</a>'
            else:
                src_cell = html.escape(src)
            delete_cell = (
                '<form hx-post="/admin/catalog_delete_entry" '
                'hx-target="#catalog-fragment" hx-swap="innerHTML" '
                'hx-confirm="Delete this catalog entry?" class="m-0">'
                f'<input type="hidden" name="name" value="{html.escape(name, quote=True)}">'
                '<button class="btn btn-sm btn-outline-danger" type="submit">Delete</button>'
                "</form>"
            )
            rows.append(
                f"<tr>"
                f"<td>{html.escape(name)}</td>"
                f'<td class="mono"><small>{html.escape(fmt)}</small></td>'
                f'<td class="mono"><small>{html.escape(arch)}</small></td>'
                f"<td>{html.escape(size)}</td>"
                f'<td class="url">{src_cell}</td>'
                f"<td>{delete_cell}</td>"
                "</tr>"
            )
        return "".join(rows)

    def _stream_progress_cell(self, s: Stream) -> str:
        """One progress cell for an active stream: a <progress> bar when the
        total is known (always for a cached blob, since the size came off
        the row), with a small ``sent / total`` line under it. Falls back
        to bytes-only when total somehow went missing."""
        if s.total is None or s.total <= 0:
            return f'<small class="mono">{human_size(s.bytes_sent)}</small>'
        pct = min(100, int(s.bytes_sent * 100 / s.total))
        return (
            f'<progress value="{s.bytes_sent}" max="{s.total}"></progress>'
            f'<br><small class="mono">{human_size(s.bytes_sent)} / '
            f"{human_size(s.total)} ({pct}%)</small>"
        )

    def _job_row(self, j: Job) -> str:
        name = os.path.basename(urllib.parse.urlsplit(j.url).path) or j.url
        if j.status == "running":
            if j.bytes_total:
                pct = int(j.bytes_done * 100 / j.bytes_total)
                prog = (
                    f'<progress value="{j.bytes_done}" max="{j.bytes_total}"></progress>'
                    f"<small>{human_size(j.bytes_done)} / {human_size(j.bytes_total)} "
                    f"({pct}%)</small>"
                )
            else:
                prog = f"<progress></progress><small>{human_size(j.bytes_done)}</small>"
        elif j.status == "completed":
            prog = f"<small>{human_size(j.bytes_done)}</small>"
        elif j.status == "failed":
            prog = f"<small>{html.escape(j.error or 'error')}</small>"
        else:  # queued / cancelled
            prog = "<small>—</small>"
        cancel = ""
        if j.status in PENDING_STATES:
            cancel = (
                '<form hx-post="/admin/cancel" hx-target="#dash" hx-swap="innerHTML" class="m-0">'
                f'<input type="hidden" name="id" value="{j.id}">'
                '<button class="btn btn-sm btn-outline-secondary" type="submit"'
                ">Cancel</button></form>"
            )
        color = self.STATUS_COLORS.get(j.status, "var(--bs-secondary)")
        return f"""<tr>
            <td class="url" title="{html.escape(j.url, quote=True)}">{html.escape(name)}</td>
            <td>{prog}</td>
            <td><small style="color:{color};font-weight:600">{j.status}</small></td>
            <td>{cancel}</td>
        </tr>"""


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
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
    auth = Auth(resolve_secret(store.data_dir), os.environ.get("WITHCACHE_ADMIN_PASSWORD"))
    mgr = DownloadManager(store, workers=args.workers)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.auth = auth  # type: ignore[attr-defined]
    httpd.mgr = mgr  # type: ignore[attr-defined]
    httpd.auto_fetch = not args.curate  # type: ignore[attr-defined]
    httpd.streams = StreamRegistry()  # type: ignore[attr-defined]
    # Catalog state: env pin wins over everything, then the operator
    # override on disk (set via /admin/catalog_set_url), then the
    # shipping default (nosi's rolling catalog manifest). Seeded from
    # the last persisted catalog.toml on disk so a restart doesn't
    # wipe the cache.
    env_catalog_url = (os.environ.get("WITHCACHE_CATALOG_URL") or "").strip()
    catalog_url = env_catalog_url or DEFAULT_CATALOG_URL
    catalog = CatalogState(
        url=catalog_url,
        persist_path=os.path.join(store.data_dir, "catalog.toml"),
        env_url=env_catalog_url,
        url_override_path=os.path.join(store.data_dir, "catalog_url"),
    )
    catalog.load_persisted()
    httpd.catalog = catalog  # type: ignore[attr-defined]
    # If no catalog is persisted yet, kick a single startup fetch
    # in a daemon thread so the operator has something to look at
    # without needing to click Refresh on their first visit.
    # Failures record ``last_error`` in memory; the dashboard row
    # shows it. Never blocks the serve loop.
    if not catalog.entries:
        threading.Thread(
            target=catalog.fetch_now, name="withcache-catalog-init", daemon=True
        ).start()
    print(
        f"withcache cache-host on http://{args.host}:{args.port}  "
        f"(data={store.data_dir}, keep_query={args.keep_query}, workers={args.workers}, "
        f"mode={'curate' if args.curate else 'auto-fetch'}, "
        f"max_bytes={'unlimited' if not store.max_bytes else human_size(store.max_bytes)})",
        flush=True,
    )
    if not auth.enabled:
        print(
            "WARNING: WITHCACHE_ADMIN_PASSWORD not set — operator UI is UNAUTHENTICATED.",
            flush=True,
        )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


if __name__ == "__main__":
    main()
