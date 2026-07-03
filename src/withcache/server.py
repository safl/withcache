#!/usr/bin/env python3
"""withcache cache-host — a URL-keyed artifact cache.

Stdlib only (http.server + sqlite3 + urllib). Serves cached blobs keyed by
their origin URL. By default a cache miss is auto-fetched: it is recorded in the
miss table and pulled from origin in the background, so the next request hits
(the client falls through to origin on the first miss). Run with `--curate` to
require an operator to approve each pull via a small web UI instead; either way
you can pre-seed an artifact with the "Add from URI" form.

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
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    def log_message(self, format, *args):  # quieter, single-line
        print(f"{self.address_string()} - {format % args}", flush=True)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/blob" or parsed.path.startswith("/b/"):
            self.handle_blob(parsed, head_only=False)
        elif parsed.path == "/healthz":
            self.send_text(200, "ok\n")
        elif parsed.path.startswith("/static/"):
            self.serve_static(parsed)
        elif parsed.path == "/ui/login":
            self.handle_login_form()
        elif parsed.path == "/admin/dash":
            if not self.is_authed():
                self.send_text(401, "login required\n")
            else:
                # The browser sends the current URL hash (the active
                # tab id) via the ``X-Active-Tab`` request header on
                # every 1 Hz refresh. Server bakes the matching
                # ``.active-tab`` class directly into the rendered
                # HTML so the htmx innerHTML swap doesn't visibly
                # blink while the post-swap JS would otherwise
                # re-apply the class. See render_dash().
                active = (self.headers.get("X-Active-Tab") or "").strip()
                self.send_html(200, self.render_dash(active_tab=active))
        elif parsed.path == "/":
            if not self.is_authed():
                self.redirect("/ui/login")
            else:
                self.send_html(200, self.render_page())
        else:
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
    )

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
            self.respond_admin()
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

    def respond_admin(self):
        """HTMX actions get the refreshed dashboard fragment; plain form posts
        (no JS) fall back to a full-page redirect."""
        if self.is_htmx():
            self.send_html(200, self.render_dash())
        else:
            self.redirect("/")

    def handle_login_form(self):
        if self.is_authed():
            self.redirect("/")
            return
        self.send_html(200, self.render_login())

    def handle_login_submit(self, form):
        if not self.auth.enabled:
            self.redirect("/")
            return
        if self.auth.check_password(form.get("password", "")):
            cookie = (
                f"{Auth.COOKIE}={self.auth.make_token()}; HttpOnly; "
                f"SameSite=Lax; Path=/; Max-Age={Auth.MAX_AGE}"
            )
            self.redirect("/", set_cookie=cookie)
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
  /* Bootstrap 5 exposes --bs-primary + a matching -rgb triplet
     used for translucent variants (alerts, focus rings, .bg-*-
     subtle). Overriding both here re-tints every stock component
     without patching bootstrap.min.css. */
  :root {{
    --bs-primary: {primary};
    --bs-primary-rgb: {rgb};
    --bs-link-color: {primary};
    --bs-link-hover-color: {hover};
  }}
  .btn-primary {{ --bs-btn-bg: {primary}; --bs-btn-border-color: {primary};
                 --bs-btn-hover-bg: {hover}; --bs-btn-hover-border-color: {hover};
                 --bs-btn-active-bg: {hover}; --bs-btn-active-border-color: {hover}; }}
  .bg-primary {{ --bs-bg-opacity: 1; background-color: {primary} !important; }}
  .text-primary {{ --bs-text-opacity: 1; color: {primary} !important; }}
  .border-primary {{ --bs-border-opacity: 1; border-color: {primary} !important; }}
  /* Brand strip: navy -> dark-magenta -> magenta gradient shared
     across bty (navy), withcache (dark-magenta) and nbdmux
     (magenta) so the trio reads as one product family from any
     of the three consoles. */
  .brand-accent {{ height: 3px;
    background: linear-gradient(90deg, #0d3585 0%, #8f1b71 50%, #d63384 100%); }}
  code {{ color: inherit; font-size: .85em; }}
  .url {{ word-break: break-all; }}
  .num {{ text-align: right; }}
  .mono {{ font-family: var(--bs-font-monospace); font-size: .85em; }}
  #spin {{ width: 7rem; height: .5rem; margin: 0; }}
  /* Tabs: Bootstrap nav-tabs, tinted via the active class. The
     content panels toggle visibility via ``section.tab.active-tab``
     so the same 1 Hz htmx innerHTML swap that used to work with
     the Pico shell keeps working here without changing the JS. */
  nav.tabs .nav-link {{ color: var(--bs-secondary-color); border: none;
    border-bottom: 2px solid transparent; padding: .45rem .9rem;
    font-size: .9rem; margin-bottom: -1px; }}
  nav.tabs .nav-link:hover {{ color: var(--bs-body-color); }}
  nav.tabs .nav-link.active-tab {{ color: var(--bs-body-color);
    border-bottom-color: var(--bs-primary); font-weight: 600; }}
  section.tab {{ display: none; padding-top: .75rem; }}
  section.tab.active-tab {{ display: block; }}
</style>
</head>"""

    def render_login(self, error: str = "") -> str:
        err = f'<div class="alert alert-danger">{html.escape(error)}</div>' if error else ""
        return f"""{self._head("withcache - login")}
<body>
<div class="brand-accent"></div>
<main class="container py-5">
  <div class="card mx-auto" style="max-width: 24rem;">
    <div class="card-body">
      <h3 class="card-title fw-bold text-primary">
        <i class="bi bi-hdd-stack"></i> withcache
        <small class="text-muted fs-6">v{html.escape(__version__)}</small>
      </h3>
      <p class="text-muted small mb-3">Operator login</p>
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

    def render_page(self) -> str:
        logout = (
            '<form method="post" action="/ui/logout" class="d-inline m-0">'
            '<button type="submit" class="btn btn-sm btn-outline-secondary">'
            "Log out</button></form>"
            if self.auth.enabled
            else ""
        )
        return f"""{self._head("withcache cache-host")}
<body>
<div class="brand-accent"></div>
<nav class="navbar navbar-expand navbar-light bg-light border-bottom">
  <div class="container">
    <a class="navbar-brand fw-bold text-primary" href="/">
      <i class="bi bi-hdd-stack"></i> withcache
      <span class="badge bg-primary bg-opacity-10 text-primary ms-1"
        >v{html.escape(__version__)}</span>
    </a>
    <div class="d-flex align-items-center gap-3">
      <progress id="spin" class="htmx-indicator"></progress>
      {logout}
    </div>
  </div>
</nav>
<main class="container py-4">
  <div class="card mb-4">
    <div class="card-header"><i class="bi bi-cloud-download text-primary"></i> Add from URI</div>
    <div class="card-body">
      <form hx-post="/admin/fetch" hx-target="#dash" hx-swap="innerHTML"
            hx-indicator="#spin" hx-on::after-request="this.reset()">
        <div class="input-group">
          <input class="form-control" type="url" name="url"
            placeholder="https://origin/path/artifact.tar.gz" required>
          <button class="btn btn-primary" type="submit" style="white-space: nowrap;"
            >Fetch &amp; store</button>
        </div>
      </form>
    </div>
  </div>

  <!-- The hx-trigger gates polling on the user NOT having an active
       text selection, so highlight-and-copy a URL out of a table cell
       isn't wiped by the 1 Hz refresh. ``isCollapsed`` is true when
       there's no selection or the caret is a zero-width point; once
       the operator releases / clears the selection polling resumes
       on the next 1 s tick.
       ``hx-headers`` sends the current URL hash (the active tab id)
       as ``X-Active-Tab`` on every refresh so the server can bake
       ``.active-tab`` into the rendered HTML -- eliminating the
       visible flicker the post-swap JS-applied class would otherwise
       cause when the new innerHTML lands without the class. -->
  <div id="dash" hx-get="/admin/dash"
       hx-trigger="load, every 1s [document.getSelection().isCollapsed]"
       hx-swap="innerHTML"
       hx-headers='js:{{"X-Active-Tab": (location.hash || "").replace(/^#/, "")}}'>
    {self.render_dash(active_tab=(self.headers.get("X-Active-Tab") or "").strip())}
  </div>

  <!-- Tab activation. Applies an ``active-tab`` class to the
       ``section.tab`` whose id matches the URL hash (defaulting to
       the first section when no hash is set) and to the
       corresponding ``nav.tabs a``. Runs on initial load, on every
       click into a tab link (so the operator gets immediate
       feedback before the next htmx tick), and on every
       ``htmx:afterSettle`` so the class survives the 1 Hz
       innerHTML replacement of ``#dash``. Without this the
       previous ``:target``-based CSS would snap the operator back
       to the first tab within a second of any click. -->
  <script>
    (function () {{
      function applyActiveTab() {{
        var hash = (window.location.hash || '').replace(/^#/, '');
        var sections = document.querySelectorAll('#dash section.tab');
        if (!sections.length) return;
        var ids = Array.prototype.map.call(sections, function (s) {{ return s.id; }});
        if (ids.indexOf(hash) === -1) hash = ids[0];
        sections.forEach(function (s) {{
          s.classList.toggle('active-tab', s.id === hash);
        }});
        document.querySelectorAll('#dash nav.tabs a').forEach(function (a) {{
          var target = (a.getAttribute('href') || '').replace(/^#/, '');
          a.classList.toggle('active-tab', target === hash);
        }});
      }}
      window.addEventListener('hashchange', applyActiveTab);
      document.body.addEventListener('htmx:afterSettle', applyActiveTab);
      document.addEventListener('click', function (ev) {{
        var a = ev.target.closest && ev.target.closest('#dash nav.tabs a');
        if (a) setTimeout(applyActiveTab, 0);
      }});
      applyActiveTab();
    }})();
  </script>
</main></body></html>"""

    def render_dash(self, active_tab: str = "") -> str:
        # Tab activation is baked into the rendered HTML so the htmx
        # innerHTML swap doesn't strip `.active-tab` between the
        # swap and the post-settle JS re-apply. The client sends
        # the current hash via the ``X-Active-Tab`` header on each
        # 1 Hz refresh (and on every operator click via the same
        # script that watches hashchange). Unknown / empty value
        # defaults to the first tab.
        _TAB_IDS = ("tab-cached", "tab-streams", "tab-downloads", "tab-misses")
        if active_tab not in _TAB_IDS:
            active_tab = _TAB_IDS[0]

        def _active(tab_id: str) -> str:
            return " active-tab" if tab_id == active_tab else ""

        nblobs, nmisses = self.store.counts()
        jobs = self.mgr.list()
        misses = self.store.list_misses()
        blobs = self.store.list_blobs()
        streams = self.streams.snapshot()
        used = human_size(self.store.total_size())
        if self.store.max_bytes:
            used += f" / {human_size(self.store.max_bytes)}"
        full = "" if self.store.has_capacity() else " &middot; <strong>cache full</strong>"

        # Tabs are driven by an ``active-tab`` class applied to one
        # ``section.tab`` (and matching ``nav.tabs a``). A tiny script
        # at the bottom of the dash watches the URL hash, the htmx
        # post-swap event, and click events on the tab links so the
        # class survives every 1 Hz innerHTML replacement.
        #
        # An earlier pure-CSS attempt used ``:target`` + ``:has()``.
        # That works on a static page, but when htmx swaps the
        # ``#dash`` innerHTML each second the freshly-inserted
        # ``section.tab`` elements do not always get re-matched by
        # ``:target`` (the browser keeps the URL hash but the
        # newly-inserted node is not the one ``:target`` resolved to
        # at hash-change time). The visible symptom was the tab
        # snapping back to Streams within a second of every click.
        # The class hooks live in _head's <style> so this dash render
        # can be swapped 1 Hz without re-declaring them.

        stream_rows = (
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

        job_rows = (
            "".join(self._job_row(j) for j in jobs)
            or '<tr><td colspan="4" class="text-center text-muted">'
            "<em>No downloads yet.</em></td></tr>"
        )

        miss_rows = (
            "".join(
                f"""<tr>
                <td class="url">{html.escape(m["url"])}</td>
                <td class="num">{m["count"]}</td>
                <td><small>{html.escape(m["last_seen"])}</small></td>
                <td class="d-flex gap-2 flex-wrap">
                  <form hx-post="/admin/fetch" hx-target="#dash"
                        hx-swap="innerHTML" hx-indicator="#spin" class="m-0">
                    <input type="hidden" name="url" value="{html.escape(m["url"], quote=True)}">
                    <button class="btn btn-sm btn-primary" type="submit">Download</button>
                  </form>
                  <form hx-post="/admin/dismiss" hx-target="#dash" hx-swap="innerHTML" class="m-0">
                    <input type="hidden" name="key" value="{html.escape(m["key"], quote=True)}">
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

        # Build the per-row /b/ serve URL once; the cell wraps the
        # origin string in a link that GETs the cached bytes when
        # the operator clicks. Same path-encoded form the shim
        # generates so curl / wget / a browser save all end up
        # writing the correct output filename.
        def _serve_url_for(row: sqlite3.Row) -> str:
            origin = row["url"]
            token = base64.urlsafe_b64encode(origin.encode("utf-8")).decode("ascii").rstrip("=")
            # last path segment of the origin, fallback "download" so a
            # URL ending in / still serves with a usable filename.
            name = urllib.parse.urlsplit(origin).path.rsplit("/", 1)[-1] or "download"
            return f"/b/{token}/{urllib.parse.quote(name)}"

        blob_rows = (
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
                  <form hx-post="/admin/delete" hx-target="#dash" hx-swap="innerHTML"
                        hx-confirm="Delete this cached artifact?" class="m-0">
                    <input type="hidden" name="key" value="{html.escape(b["key"], quote=True)}">
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

        # Per-tab counts let the operator see at a glance whether each
        # section is empty without flipping to it.
        nstreams = len(streams)
        njobs = len(jobs)

        return f"""
  <p class="text-muted small mb-2">{nblobs} cached ({used}){full}
    &middot; {nmisses} pending miss(es)</p>
  <nav class="tabs border-bottom mb-2">
    <ul class="nav">
      <li class="nav-item"><a class="nav-link {_active("tab-cached").lstrip()}"
        href="#tab-cached">Cached ({nblobs})</a></li>
      <li class="nav-item"><a class="nav-link {_active("tab-streams").lstrip()}"
        href="#tab-streams">Streams ({nstreams})</a></li>
      <li class="nav-item"><a class="nav-link {_active("tab-downloads").lstrip()}"
        href="#tab-downloads">Downloads ({njobs})</a></li>
      <li class="nav-item"><a class="nav-link {_active("tab-misses").lstrip()}"
        href="#tab-misses">Misses ({nmisses})</a></li>
    </ul>
  </nav>

  <section id="tab-cached" class="tab{_active("tab-cached")}">
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th>Size</th><th class="num">Hits</th><th class="num">Misses</th>
        <th>SHA-256</th><th>Fetched</th><th>Action</th>
      </tr></thead>
      <tbody>{blob_rows}</tbody>
    </table></div>
  </section>

  <section id="tab-streams" class="tab{_active("tab-streams")}">
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th>Client</th><th>Progress</th><th>Age</th>
      </tr></thead>
      <tbody>{stream_rows}</tbody>
    </table></div>
  </section>

  <section id="tab-downloads" class="tab{_active("tab-downloads")}">
    <div class="d-flex align-items-center justify-content-between mb-2">
      <small class="text-muted">Auto-fetch workers feeding the cache.</small>
      <form hx-post="/admin/clear" hx-target="#dash" hx-swap="innerHTML" class="m-0">
        <button class="btn btn-sm btn-outline-secondary" type="submit"
          >Clear finished</button>
      </form>
    </div>
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>Artifact</th><th>Progress</th><th>Status</th><th></th>
      </tr></thead>
      <tbody>{job_rows}</tbody>
    </table></div>
  </section>

  <section id="tab-misses" class="tab{_active("tab-misses")}">
    <div class="table-responsive"><table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light"><tr>
        <th>URL</th><th class="num">Misses</th><th>Last seen</th><th>Action</th>
      </tr></thead>
      <tbody>{miss_rows}</tbody>
    </table></div>
  </section>"""

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
    ap.add_argument("--port", type=int, default=3000)
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
