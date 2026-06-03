#!/usr/bin/env python3
"""withcache cache-host — an operator-curated artifact cache.

Stdlib only (http.server + sqlite3 + urllib). Serves cached blobs keyed by
their origin URL. A cache miss is *not* fetched automatically: it is recorded
in a miss table so an operator can review it and press "Download", at which
point the cache-host pulls the artifact from origin and stores it. There is
also an "add from URI" form to pre-seed an artifact before anyone misses it.

This is the only component that needs internet egress (and any vendor creds).
Clients never write to it.

Auth (modelled on bty's single-tenant approach, minus PAM): the read path
(`/blob`, `/healthz`) is open so clients never log in; the operator surface
(`/` and `/admin/*`) is gated behind a server-signed session cookie. Login at
`POST /ui/login` checks the password in $WITHCACHE_ADMIN_PASSWORD and flips the
cookie to authenticated; the cookie is HMAC-signed with a secret read from
$WITHCACHE_SESSION_SECRET or persisted to ``<data-dir>/session-secret``. If no
admin password is set, the operator UI is left open (with a startup warning).
"""

import argparse
import base64
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

CHUNK = 64 * 1024
USER_AGENT = "withcache-cache/0.1"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MIME_TYPES = {".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8"}
_DB_WRITE_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        try:
            os.remove(self.blob_path(key))
        except FileNotFoundError:
            pass

    def store_from_origin(self, url: str, progress=None, cancel=None, headers=None) -> sqlite3.Row:
        """Operator-triggered: pull the artifact from origin and store it.

        ``progress(done, total)`` is called as bytes arrive (total may be None);
        ``cancel()`` is polled between chunks and, if truthy, aborts the pull
        with :class:`DownloadCancelled` and leaves no partial file behind.
        ``headers`` adds request headers to the origin fetch (e.g. a registry
        bearer token bty pre-resolved for an oras blob). Raises :class:`CacheFull`
        if the cache is already at --max-bytes.
        """
        if not self.has_capacity():
            raise CacheFull(f"cache full (>= {self.max_bytes} bytes); refusing to fetch {url}")
        normalized = self.normalize(url)
        key = self.key_of(normalized)
        tmp = os.path.join(self.tmp_dir, key + ".part")
        req_headers = {"User-Agent": USER_AGENT}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        sha = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                content_type = resp.headers.get_content_type()
                cl = resp.headers.get("Content-Length")
                total = int(cl) if cl and cl.isdigit() else None
                if progress:
                    progress(0, total)
                with open(tmp, "wb") as f:
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
            os.replace(tmp, self.blob_path(key))
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)  # no half-written blob on cancel/error
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
JOB_STATES = ("queued", "running", "completed", "cancelled", "failed")
PENDING_STATES = frozenset(("queued", "running"))


class DownloadCancelled(Exception):
    """Raised inside a worker when its job's cancel flag is set."""


class CacheFull(Exception):
    """Raised when --max-bytes is reached; the fill is refused, not evicted."""


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
                row = self.store.store_from_origin(
                    job.url,
                    progress=lambda done, total, j=job: _set_progress(j, done, total),
                    cancel=job._cancel.is_set,
                    headers=job.headers,
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


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "withcache/0.1"
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
                self.send_html(200, self.render_dash())
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
        name = os.path.basename(parsed.path)  # basename blocks path traversal
        path = os.path.join(STATIC_DIR, name)
        if not name or not os.path.isfile(path):
            self.send_text(404, "not found\n")
            return
        with open(path, "rb") as f:
            data = f.read()
        ext = os.path.splitext(name)[1]
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
        if row is None:
            self.store.record_miss(url)
            if self.auto_fetch and self.store.has_capacity():
                # Pull it in the background so the next request hits; the client
                # gets this one from origin (the shim, or bty's fallback chain,
                # falls through on a miss). In --curate mode an operator triggers
                # the pull instead; when the cache is full we record the miss but
                # schedule nothing (delete something first).
                self.mgr.enqueue(url)
            self.send_text(404, "cache miss (recorded)\n")
            return
        path = self.store.blob_path(row["key"])
        self.send_response(200)
        self.send_header("Content-Type", row["content_type"] or "application/octet-stream")
        self.send_header("Content-Length", str(row["size"]))
        self.send_header("X-Withcache-Sha256", row["sha256"])
        self.end_headers()
        if head_only:
            return  # the shim's HEAD probe — not a served download, so don't count it
        self.store.record_hit(row["key"])
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away mid-stream

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
    STATUS_COLORS = {
        "queued": "#888",
        "running": "var(--pico-primary, #0172ad)",
        "completed": "#2e7d32",
        "failed": "#c0392b",
        "cancelled": "#888",
    }

    def _head(self, title: str) -> str:
        return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/static/pico.min.css">
<script src="/static/htmx.min.js"></script>
<style>
  main.container {{ max-width: 1100px; padding-top: 1rem; }}
  h4 {{ margin-bottom: .4rem; }}
  table {{ font-size: .9rem; margin-bottom: 0; }}
  .url {{ word-break: break-all; }}
  .num {{ text-align: right; }}
  .mono {{ font-family: var(--pico-font-family-monospace); font-size: .85em; }}
  td form {{ display: inline; margin: 0; }}
  td button {{ width: auto; display: inline-block; margin: 0 .3rem 0 0;
               padding: .15rem .6rem; font-size: .8rem; }}
  td progress {{ margin: 0 0 .15rem; }}
  #spin {{ width: 7rem; height: .5rem; margin: 0; }}
  .row {{ display: flex; align-items: center; justify-content: space-between; }}
  .err {{ background: var(--pico-del-color, #c0392b); color: #fff;
          padding: .7rem 1rem; border-radius: var(--pico-border-radius); margin-bottom: 1rem; }}
</style>
</head>"""

    def render_login(self, error: str = "") -> str:
        err = f'<div class="err">{html.escape(error)}</div>' if error else ""
        return f"""{self._head("withcache — login")}
<body><main class="container">
  <article style="max-width: 24rem; margin: 4rem auto;">
    <hgroup><h2>withcache</h2><p>operator login</p></hgroup>
    {err}
    <form method="post" action="/ui/login">
      <input type="password" name="password" placeholder="Admin password" autofocus required>
      <button type="submit">Log in</button>
    </form>
  </article>
</main></body></html>"""

    def render_page(self) -> str:
        logout = (
            '<li><form method="post" action="/ui/logout" style="margin:0">'
            '<button type="submit" class="secondary outline" '
            'style="width:auto;padding:.3rem .8rem">Log out</button></form></li>'
            if self.auth.enabled
            else ""
        )
        return f"""{self._head("withcache cache-host")}
<body><main class="container">
  <nav>
    <ul><li><strong>withcache</strong> &nbsp;<small>cache-host</small></li></ul>
    <ul>
      <li><progress id="spin" class="htmx-indicator"></progress></li>
      {logout}
    </ul>
  </nav>

  <h4>Add from URI</h4>
  <form hx-post="/admin/fetch" hx-target="#dash" hx-swap="innerHTML"
        hx-indicator="#spin" hx-on::after-request="this.reset()">
    <fieldset role="group">
      <input type="url" name="url" placeholder="https://origin/path/artifact.tar.gz" required>
      <button type="submit">Fetch &amp; store</button>
    </fieldset>
  </form>

  <div id="dash" hx-get="/admin/dash" hx-trigger="load, every 1s" hx-swap="innerHTML">
    {self.render_dash()}
  </div>
</main></body></html>"""

    def render_dash(self) -> str:
        nblobs, nmisses = self.store.counts()
        jobs = self.mgr.list()
        misses = self.store.list_misses()
        blobs = self.store.list_blobs()
        used = human_size(self.store.total_size())
        if self.store.max_bytes:
            used += f" / {human_size(self.store.max_bytes)}"
        full = "" if self.store.has_capacity() else " &middot; <strong>cache full</strong>"

        job_rows = (
            "".join(self._job_row(j) for j in jobs)
            or '<tr><td colspan="4"><em>No downloads yet.</em></td></tr>'
        )

        miss_rows = (
            "".join(
                f"""<tr>
                <td class="url">{html.escape(m["url"])}</td>
                <td class="num">{m["count"]}</td>
                <td><small>{html.escape(m["last_seen"])}</small></td>
                <td>
                  <form hx-post="/admin/fetch" hx-target="#dash"
                        hx-swap="innerHTML" hx-indicator="#spin">
                    <input type="hidden" name="url" value="{html.escape(m["url"], quote=True)}">
                    <button type="submit">Download</button>
                  </form>
                  <form hx-post="/admin/dismiss" hx-target="#dash" hx-swap="innerHTML">
                    <input type="hidden" name="key" value="{html.escape(m["key"], quote=True)}">
                    <button type="submit" class="secondary outline">Dismiss</button>
                  </form>
                </td>
            </tr>"""
                for m in misses
            )
            or '<tr><td colspan="4"><em>No misses recorded.</em></td></tr>'
        )

        blob_rows = (
            "".join(
                f"""<tr>
                <td class="url">{html.escape(b["url"])}</td>
                <td>{human_size(b["size"])}</td>
                <td class="num">{b["hits"]}</td>
                <td class="num">{b["misses"]}</td>
                <td class="mono">{html.escape(b["sha256"][:12])}…</td>
                <td><small>{html.escape(b["fetched_at"])}</small></td>
                <td>
                  <form hx-post="/admin/delete" hx-target="#dash" hx-swap="innerHTML"
                        hx-confirm="Delete this cached artifact?">
                    <input type="hidden" name="key" value="{html.escape(b["key"], quote=True)}">
                    <button type="submit" class="secondary outline">Delete</button>
                  </form>
                </td>
            </tr>"""
                for b in blobs
            )
            or '<tr><td colspan="7"><em>Cache is empty.</em></td></tr>'
        )

        return f"""
  <p><small>{nblobs} cached ({used}){full} &middot; {nmisses} pending miss(es)</small></p>

  <div class="row">
    <h4>Downloads</h4>
    <form hx-post="/admin/clear" hx-target="#dash" hx-swap="innerHTML" style="margin:0">
      <button type="submit" class="secondary outline" style="width:auto;padding:.2rem .7rem">
        Clear finished</button>
    </form>
  </div>
  <figure><table class="striped">
    <thead><tr><th>Artifact</th><th>Progress</th><th>Status</th><th></th></tr></thead>
    <tbody>{job_rows}</tbody>
  </table></figure>

  <h4>Misses</h4>
  <figure><table class="striped">
    <thead><tr><th>URL</th><th class="num">Misses</th><th>Last seen</th><th>Action</th></tr></thead>
    <tbody>{miss_rows}</tbody>
  </table></figure>

  <h4>Cached artifacts</h4>
  <figure><table class="striped">
    <thead><tr>
      <th>URL</th><th>Size</th><th class="num">Hits</th><th class="num">Misses</th>
      <th>SHA-256</th><th>Fetched</th><th>Action</th>
    </tr></thead>
    <tbody>{blob_rows}</tbody>
  </table></figure>"""

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
                '<form hx-post="/admin/cancel" hx-target="#dash" hx-swap="innerHTML">'
                f'<input type="hidden" name="id" value="{j.id}">'
                '<button type="submit" class="secondary outline">Cancel</button></form>'
            )
        color = self.STATUS_COLORS.get(j.status, "#888")
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
