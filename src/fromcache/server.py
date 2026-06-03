#!/usr/bin/env python3
"""fromcache cache-host — an operator-curated artifact cache.

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
`POST /ui/login` checks the password in $FROMCACHE_ADMIN_PASSWORD and flips the
cookie to authenticated; the cookie is HMAC-signed with a secret read from
$FROMCACHE_SESSION_SECRET or persisted to ``<data-dir>/session-secret``. If no
admin password is set, the operator UI is left open (with a startup warning).
"""

import argparse
import base64
import hashlib
import hmac
import html
import http.cookies
import http.server
import json
import os
import secrets
import socketserver
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CHUNK = 64 * 1024
USER_AGENT = "fromcache-cache/0.1"
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


# --------------------------------------------------------------------------
# Auth — server-signed session cookie (bty-style, env-password instead of PAM)
# --------------------------------------------------------------------------
def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def resolve_secret(data_dir: str) -> bytes:
    """$FROMCACHE_SESSION_SECRET if set + non-empty, else a random key persisted
    to <data-dir>/session-secret so cookies survive restarts. Mirrors bty's
    _resolve_secret_key: a blank env value must NOT silently weaken signing."""
    env = (os.environ.get("FROMCACHE_SESSION_SECRET") or "").strip()
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
    COOKIE = "fromcache-token"
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

    def __init__(self, data_dir: str, keep_query: bool):
        self.data_dir = os.path.abspath(data_dir)
        self.blob_dir = os.path.join(self.data_dir, "blobs")
        self.tmp_dir = os.path.join(self.data_dir, "tmp")
        self.db_path = os.path.join(self.data_dir, "cache.db")
        self.keep_query = keep_query
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
                    fetched_at   TEXT NOT NULL
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
            return c.execute(
                "SELECT * FROM blobs ORDER BY fetched_at DESC"
            ).fetchall()

    def list_misses(self):
        with self.conn() as c:
            return c.execute(
                "SELECT * FROM misses ORDER BY last_seen DESC"
            ).fetchall()

    def counts(self):
        with self.conn() as c:
            b = c.execute("SELECT COUNT(*) FROM blobs").fetchone()[0]
            m = c.execute("SELECT COUNT(*) FROM misses").fetchone()[0]
        return b, m

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

    def dismiss(self, key: str):
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute("DELETE FROM misses WHERE key=?", (key,))

    def store_from_origin(self, url: str) -> sqlite3.Row:
        """Operator-triggered: pull the artifact from origin and store it."""
        normalized = self.normalize(url)
        key = self.key_of(normalized)
        tmp = os.path.join(self.tmp_dir, key + ".part")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        sha = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(req, timeout=120) as resp:
            content_type = resp.headers.get_content_type()
            with open(tmp, "wb") as f:
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    sha.update(chunk)
                    size += len(chunk)
        os.replace(tmp, self.blob_path(key))
        ts = now_iso()
        with _DB_WRITE_LOCK, self.conn() as c:
            c.execute(
                """
                INSERT INTO blobs (key, url, size, sha256, content_type, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    url = excluded.url, size = excluded.size,
                    sha256 = excluded.sha256, content_type = excluded.content_type,
                    fetched_at = excluded.fetched_at
                """,
                (key, url, size, sha.hexdigest(), content_type, ts),
            )
            c.execute("DELETE FROM misses WHERE key=?", (key,))
            return c.execute("SELECT * FROM blobs WHERE key=?", (key,)).fetchone()


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "fromcache/0.1"
    protocol_version = "HTTP/1.1"

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def auth(self) -> Auth:
        return self.server.auth  # type: ignore[attr-defined]

    def log_message(self, format, *args):  # quieter, single-line
        print(f"{self.address_string()} - {format % args}", flush=True)

    # -- routing -----------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/blob":
            self.handle_blob(parsed, head_only=False)
        elif parsed.path == "/healthz":
            self.send_text(200, "ok\n")
        elif parsed.path == "/ui/login":
            self.handle_login_form()
        elif parsed.path == "/":
            if not self.is_authed():
                self.redirect("/ui/login")
            else:
                self.send_html(200, self.render_page())
        else:
            self.send_text(404, "not found\n")

    def do_HEAD(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/blob":
            self.handle_blob(parsed, head_only=True)
        else:
            self.send_text(404, "")

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        form = self.read_form()
        if parsed.path == "/ui/login":
            self.handle_login_submit(form)
        elif parsed.path == "/ui/logout":
            self.handle_logout()
        elif parsed.path in ("/admin/fetch", "/admin/dismiss"):
            if not self.is_authed():
                self.send_text(401, "login required\n")
                return
            if parsed.path == "/admin/fetch":
                self.handle_admin_fetch(form)
            else:
                self.store.dismiss(form.get("key", "").strip())
                self.redirect("/")
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
    def handle_blob(self, parsed, head_only: bool):
        qs = urllib.parse.parse_qs(parsed.query)
        url = (qs.get("url") or [""])[0]
        if not url:
            self.send_text(400, "missing ?url=\n")
            return
        row = self.store.get_blob(url)
        if row is None:
            self.store.record_miss(url)
            self.send_text(404, "cache miss (recorded)\n")
            return
        path = self.store.blob_path(row["key"])
        self.send_response(200)
        self.send_header("Content-Type", row["content_type"] or "application/octet-stream")
        self.send_header("Content-Length", str(row["size"]))
        self.send_header("X-Fromcache-Sha256", row["sha256"])
        self.end_headers()
        if head_only:
            return
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass  # client went away mid-stream

    # -- admin -------------------------------------------------------------
    def handle_admin_fetch(self, form):
        url = form.get("url", "").strip()
        if not url:
            self.send_html(400, self.render_page(error="No URL provided."))
            return
        try:
            self.store.store_from_origin(url)
        except Exception as e:  # surface the failure to the operator
            self.send_html(502, self.render_page(error=f"Fetch failed for {html.escape(url)}: {html.escape(str(e))}"))
            return
        self.redirect("/")

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
    def render_login(self, error: str = "") -> str:
        err = f'<div class="error">{error}</div>' if error else ""
        return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fromcache — login</title>{self._style()}
</head><body>
  <h1>fromcache</h1>
  <p class="sub">operator login</p>
  {err}
  <form class="seed" method="post" action="/ui/login">
    <input type="password" name="password" placeholder="admin password" autofocus required>
    <button type="submit">Log in</button>
  </form>
</body></html>"""

    def render_page(self, error: str = "") -> str:
        nblobs, nmisses = self.store.counts()
        misses = self.store.list_misses()
        blobs = self.store.list_blobs()

        miss_rows = "".join(
            f"""<tr>
                <td class="url">{html.escape(m["url"])}</td>
                <td class="num">{m["count"]}</td>
                <td>{html.escape(m["last_seen"])}</td>
                <td class="actions">
                  <form method="post" action="/admin/fetch">
                    <input type="hidden" name="url" value="{html.escape(m["url"], quote=True)}">
                    <button type="submit">Download</button>
                  </form>
                  <form method="post" action="/admin/dismiss">
                    <input type="hidden" name="key" value="{html.escape(m["key"], quote=True)}">
                    <button type="submit" class="ghost">Dismiss</button>
                  </form>
                </td>
            </tr>"""
            for m in misses
        ) or '<tr><td colspan="4" class="empty">No misses recorded.</td></tr>'

        blob_rows = "".join(
            f"""<tr>
                <td class="url">{html.escape(b["url"])}</td>
                <td>{human_size(b["size"])}</td>
                <td class="mono">{html.escape(b["sha256"][:12])}…</td>
                <td>{html.escape(b["fetched_at"])}</td>
            </tr>"""
            for b in blobs
        ) or '<tr><td colspan="4" class="empty">Cache is empty.</td></tr>'

        err = f'<div class="error">{error}</div>' if error else ""
        logout = (
            '<form method="post" action="/ui/logout" class="logout">'
            '<button type="submit" class="ghost">Log out</button></form>'
            if self.auth.enabled
            else ""
        )

        return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fromcache cache-host</title>{self._style()}
</head><body>
  {logout}
  <h1>fromcache cache-host</h1>
  <p class="sub">{nblobs} cached &middot; {nmisses} pending miss(es)</p>
  {err}

  <h2>Add from URI</h2>
  <form class="seed" method="post" action="/admin/fetch">
    <input type="url" name="url" placeholder="https://origin/path/artifact.tar.gz" required>
    <button type="submit">Fetch &amp; store</button>
  </form>

  <h2>Misses</h2>
  <table>
    <thead><tr><th>URL</th><th>Hits</th><th>Last seen</th><th>Action</th></tr></thead>
    <tbody>{miss_rows}</tbody>
  </table>

  <h2>Cached artifacts</h2>
  <table>
    <thead><tr><th>URL</th><th>Size</th><th>SHA-256</th><th>Fetched</th></tr></thead>
    <tbody>{blob_rows}</tbody>
  </table>
</body></html>"""

    @staticmethod
    def _style() -> str:
        return """
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 1000px; padding: 1.5rem; }
  h1 { margin: 0; } h2 { margin-top: 2rem; }
  .sub { color: #888; margin: .25rem 0 1.5rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .45rem .5rem; border-bottom: 1px solid #8884; vertical-align: top; }
  th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: #888; }
  td.url { word-break: break-all; }
  td.num { text-align: right; } td.mono { font-family: ui-monospace, monospace; }
  td.empty { color: #888; font-style: italic; }
  td.actions { white-space: nowrap; }
  td.actions form { display: inline; }
  button { font: inherit; padding: .25rem .7rem; cursor: pointer; }
  button.ghost { background: transparent; border: 1px solid #8886; }
  form.seed { display: flex; gap: .5rem; margin: 1rem 0 0; }
  form.seed input { flex: 1; padding: .4rem .6rem; font: inherit; }
  form.logout { float: right; margin: 0; }
  .error { background: #c0392b; color: #fff; padding: .6rem .9rem; border-radius: 4px; margin: 1rem 0; }
</style>"""


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser(description="fromcache cache-host")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--data-dir", default="./data")
    ap.add_argument(
        "--keep-query",
        action="store_true",
        help="include the URL query string in the cache key "
        "(default: drop it, so signed/tokened URLs still match by path)",
    )
    args = ap.parse_args()

    store = Store(args.data_dir, keep_query=args.keep_query)
    auth = Auth(resolve_secret(store.data_dir), os.environ.get("FROMCACHE_ADMIN_PASSWORD"))

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.auth = auth  # type: ignore[attr-defined]
    print(
        f"fromcache cache-host on http://{args.host}:{args.port}  "
        f"(data={store.data_dir}, keep_query={args.keep_query})",
        flush=True,
    )
    if not auth.enabled:
        print(
            "WARNING: FROMCACHE_ADMIN_PASSWORD not set — operator UI is UNAUTHENTICATED.",
            flush=True,
        )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye", flush=True)


if __name__ == "__main__":
    main()
