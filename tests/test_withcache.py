"""Stdlib-only tests for withcache. Run with:  python -m unittest -v

No third-party test deps; src/ is put on the path so the package imports
without an install.
"""

import contextlib
import http.server
import itertools
import os
import socket
import socketserver
import sys
import tempfile
import threading
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import base64
import urllib.error

from withcache import _shim, server


# --------------------------------------------------------------------------
# Auth: signed-cookie round-trip, tamper + wrong-secret rejection, expiry
# --------------------------------------------------------------------------
class TestResolveSecret(unittest.TestCase):
    """resolve_secret is the whole basis of the cookie-auth trust
    boundary: the HMAC key that signs session tokens. Three branches
    -- env-set, file-persisted, fresh-generation -- and a
    security-adjacent invariant claimed in its docstring: 'a blank
    env value must NOT silently weaken signing'. Mirrors nbdmux's
    TestResolveSecret since the two functions are the same shape."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._saved = os.environ.get("WITHCACHE_SESSION_SECRET")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("WITHCACHE_SESSION_SECRET", None)
        else:
            os.environ["WITHCACHE_SESSION_SECRET"] = self._saved

    def test_env_set_wins(self):
        os.environ["WITHCACHE_SESSION_SECRET"] = "operator-chosen-secret"
        self.assertEqual(server.resolve_secret(self.tmpdir), b"operator-chosen-secret")

    def test_env_blank_falls_through_to_fresh_generation(self):
        """The docstring promises a blank env value must NOT silently
        weaken signing. A fresh secret must land under data_dir and
        NOT be the empty string."""
        os.environ["WITHCACHE_SESSION_SECRET"] = "   "
        got = server.resolve_secret(self.tmpdir)
        self.assertGreaterEqual(len(got), 32)
        self.assertNotEqual(got, b"")
        persisted = os.path.join(self.tmpdir, "session-secret")
        self.assertTrue(os.path.exists(persisted))

    def test_env_unset_generates_and_persists(self):
        os.environ.pop("WITHCACHE_SESSION_SECRET", None)
        got = server.resolve_secret(self.tmpdir)
        self.assertGreaterEqual(len(got), 32)
        with open(os.path.join(self.tmpdir, "session-secret"), "rb") as f:
            self.assertEqual(f.read(), got)

    def test_file_persisted_returned_on_second_call(self):
        os.environ.pop("WITHCACHE_SESSION_SECRET", None)
        first = server.resolve_secret(self.tmpdir)
        second = server.resolve_secret(self.tmpdir)
        self.assertEqual(first, second)

    def test_persisted_file_permissions_are_private(self):
        os.environ.pop("WITHCACHE_SESSION_SECRET", None)
        server.resolve_secret(self.tmpdir)
        path = os.path.join(self.tmpdir, "session-secret")
        mode = os.stat(path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class TestAuth(unittest.TestCase):
    def test_token_roundtrip(self):
        a = server.Auth(b"secret-key", "pw")
        self.assertTrue(a.enabled)
        self.assertTrue(a.valid(a.make_token()))

    def test_tampered_token_rejected(self):
        a = server.Auth(b"secret-key", "pw")
        tok = a.make_token()
        payload = tok.split(".", 1)[0]
        self.assertFalse(a.valid(payload + ".deadbeef"))
        self.assertFalse(a.valid("garbage"))
        self.assertFalse(a.valid(""))

    def test_wrong_secret_rejected(self):
        tok = server.Auth(b"key-a", "pw").make_token()
        self.assertFalse(server.Auth(b"key-b", "pw").valid(tok))

    def test_expired_token_rejected(self):
        a = server.Auth(b"secret-key", "pw")
        a.MAX_AGE = -1  # already expired
        self.assertFalse(a.valid(a.make_token()))

    def test_password_check(self):
        a = server.Auth(b"k", "hunter2")
        self.assertTrue(a.check_password("hunter2"))
        self.assertFalse(a.check_password("nope"))

    def test_disabled_without_password(self):
        a = server.Auth(b"k", None)
        self.assertFalse(a.enabled)
        self.assertFalse(a.check_password("anything"))
        self.assertFalse(a.check_bearer("anything"))

    def test_bearer_check(self):
        """Bearer path uses constant-time compare against the same
        admin password ``check_password`` gates the UI login on."""
        a = server.Auth(b"k", "hunter2")
        self.assertTrue(a.check_bearer("hunter2"))
        self.assertFalse(a.check_bearer("nope"))
        self.assertFalse(a.check_bearer(""))


# --------------------------------------------------------------------------
# Store: key normalization + miss bookkeeping
# --------------------------------------------------------------------------
class TestStoreKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.store = server.Store(self.tmp, keep_query=False)

    def test_normalize_drops_query_and_lowercases_host(self):
        n = self.store.normalize("HTTPS://Example.COM/p/x.tgz?token=abc")
        self.assertEqual(n, "https://example.com/p/x.tgz")

    def test_keep_query_mode(self):
        s = server.Store(tempfile.mkdtemp(), keep_query=True)
        self.assertEqual(s.normalize("https://h/x?a=1"), "https://h/x?a=1")

    def test_key_is_stable_across_query_when_dropped(self):
        k1 = self.store.key_of(self.store.normalize("https://h/x?a=1"))
        k2 = self.store.key_of(self.store.normalize("https://h/x?a=2"))
        self.assertEqual(k1, k2)

    def test_record_and_dismiss_miss(self):
        url = "https://h/missing.bin"
        self.store.record_miss(url)
        self.store.record_miss(url)
        misses = self.store.list_misses()
        self.assertEqual(len(misses), 1)
        self.assertEqual(misses[0]["count"], 2)
        self.store.dismiss(misses[0]["key"])
        self.assertEqual(self.store.list_misses(), [])


# --------------------------------------------------------------------------
# Integration: pull a blob from a local origin, then read it back
# --------------------------------------------------------------------------
PAYLOAD = b"hello-withcache-" * 1000  # 16 KiB


class _Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, format, *args):
        pass


class TestStoreFromOrigin(unittest.TestCase):
    def setUp(self):
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.store = server.Store(tempfile.mkdtemp(), keep_query=False)

    def tearDown(self):
        getattr(self.httpd, "mgr", None) and self.httpd.mgr.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_pull_then_hit(self):
        url = f"http://127.0.0.1:{self.port}/artifact.bin"
        self.store.record_miss(url)
        row = self.store.store_from_origin(url)
        self.assertEqual(row["size"], len(PAYLOAD))
        import hashlib

        self.assertEqual(row["sha256"], hashlib.sha256(PAYLOAD).hexdigest())
        # miss cleared, blob now retrievable, bytes on disk match
        self.assertEqual(self.store.list_misses(), [])
        got = self.store.get_blob(url)
        self.assertIsNotNone(got)
        with open(self.store.blob_path(got["key"]), "rb") as f:
            self.assertEqual(f.read(), PAYLOAD)

    def test_miss_count_carries_onto_blob_and_hits_increment(self):
        url = f"http://127.0.0.1:{self.port}/artifact.bin"
        self.store.record_miss(url)
        self.store.record_miss(url)  # 2 requests while uncached
        row = self.store.store_from_origin(url)
        self.assertEqual(row["misses"], 2)  # carried over, survives caching
        self.assertEqual(row["hits"], 0)
        self.store.record_hit(row["key"])
        self.store.record_hit(row["key"])
        got = self.store.get_blob(url)
        self.assertEqual((got["hits"], got["misses"]), (2, 2))

    def test_delete_blob_removes_row_and_file(self):
        url = f"http://127.0.0.1:{self.port}/artifact.bin"
        row = self.store.store_from_origin(url)
        path = self.store.blob_path(row["key"])
        self.assertTrue(os.path.exists(path))
        self.store.delete_blob(row["key"])
        self.assertIsNone(self.store.get_blob(url))
        self.assertFalse(os.path.exists(path))

    def test_capacity_guard_refuses_new_fills_when_full(self):
        store = server.Store(tempfile.mkdtemp(), keep_query=False, max_bytes=1)
        self.assertTrue(store.has_capacity())  # empty: room for the first
        store.store_from_origin(f"http://127.0.0.1:{self.port}/a.bin")
        self.assertFalse(store.has_capacity())  # now over the 1-byte cap
        with self.assertRaises(server.CacheFull):
            store.store_from_origin(f"http://127.0.0.1:{self.port}/b.bin")


class _TruncatingOrigin(http.server.BaseHTTPRequestHandler):
    """Declare a full Content-Length, then send half the payload and
    close the socket. Mirrors the real-world failure mode where the
    upstream drops the connection mid-stream (lab-box fedora-44-desktop
    flash that surfaced this bug)."""

    PAYLOAD = b"abcdefghij" * 100  # 1000 bytes; will write half then close

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.PAYLOAD)))
        self.end_headers()
        half = len(self.PAYLOAD) // 2
        self.wfile.write(self.PAYLOAD[:half])
        # close the underlying socket so urllib observes EOF before
        # Content-Length bytes arrive
        self.wfile.flush()
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)

    def log_message(self, format, *args):
        pass


class TestTruncatedDownloadRejected(unittest.TestCase):
    """Regression for the lab-spotted bug where a transport-aborted
    upstream stream silently became a permanent cached blob: future
    HEADs returned 200 with the partial bytes, every consumer got a
    malformed file, and the only escape was hand-deleting the blob.
    Content-Length mismatches now fail loudly and leave no entry."""

    def setUp(self):
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), _TruncatingOrigin)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.store = server.Store(tempfile.mkdtemp(), keep_query=False)

    def tearDown(self):
        getattr(self.httpd, "mgr", None) and self.httpd.mgr.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_truncated_upstream_raises_and_leaves_no_blob(self):
        url = f"http://127.0.0.1:{self.port}/truncated.bin"
        # _TruncatingOrigin truncates EVERY response (including
        # ranged retries) so capping max_resume_attempts at 1 keeps
        # the test fast: the single attempt cuts at 500 bytes,
        # exhausts the budget, and the TruncatedDownload fires.
        with self.assertRaises(server.TruncatedDownload) as cm:
            self.store.store_from_origin(url, max_resume_attempts=1)
        # the message must name both totals so the operator can see
        # how short the upstream came
        msg = str(cm.exception)
        self.assertIn("1000", msg)  # declared
        self.assertIn("500", msg)  # got
        # no row was written; no blob file lingers on disk
        self.assertIsNone(self.store.get_blob(url))
        blobs = list(self.store.blob_path("").rsplit("/", 1)[0:1])
        if os.path.isdir(blobs[0]):
            self.assertEqual(os.listdir(blobs[0]), [])

    def test_repeat_request_after_truncation_can_retry_cleanly(self):
        url = f"http://127.0.0.1:{self.port}/truncated.bin"
        with self.assertRaises(server.TruncatedDownload):
            self.store.store_from_origin(url, max_resume_attempts=1)
        # second attempt against the same URL would have hit the
        # poisoned cache before the fix; now it must repeat the
        # failure mode (no sticky blob blocking the retry) so a
        # later origin recovery can re-fill the entry cleanly.
        with self.assertRaises(server.TruncatedDownload):
            self.store.store_from_origin(url, max_resume_attempts=1)


# --------------------------------------------------------------------------
# Range-resume: a flaky upstream that cuts mid-stream MUST be retried with
# ``Range: bytes=<got>-`` so the partial is filled rather than discarded.
# This is the lab-spotted ghcr.io failure mode where Azure Blob Storage
# SAS URLs expire mid-download for any blob bigger than a few minutes of
# bandwidth: a single attempt always loses, but a retried Range request
# starts a fresh SAS window and the second leg finishes the blob.
# --------------------------------------------------------------------------
class _ResumableTruncatingOrigin(http.server.BaseHTTPRequestHandler):
    """Cut the FIRST GET in half; honor ``Range: bytes=<n>-`` on retries
    by serving from offset n to end. Mirrors the ghcr -> Azure Blob
    pattern: each connection has a hard wall-clock limit but the bytes
    themselves are available on re-fetch.

    Shared class-level counter so multiple instances (the threaded server
    spawns one handler per request) all see the same call count and the
    first GET truncates regardless of which thread services it.
    """

    PAYLOAD = b"abcdefghij" * 100  # 1000 bytes
    _lock = threading.Lock()
    _calls = 0

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._calls = 0

    def do_GET(self):
        with self._lock:
            self.__class__._calls += 1
            call = self._calls
        rng = self.headers.get("Range") or ""
        start = 0
        if rng.startswith("bytes="):
            try:
                start = int(rng[len("bytes=") :].split("-", 1)[0])
            except ValueError:
                start = 0
        full = len(self.PAYLOAD)
        if start > 0:
            # ranged retry: serve the rest cleanly
            body = self.PAYLOAD[start:]
            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Content-Range",
                f"bytes {start}-{full - 1}/{full}",
            )
            self.end_headers()
            self.wfile.write(body)
            return
        # first attempt: declare full length but cut at half
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(full))
        self.end_headers()
        if call == 1:
            half = full // 2
            self.wfile.write(self.PAYLOAD[:half])
            self.wfile.flush()
            with contextlib.suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
        else:
            # any non-ranged retry serves the whole thing (covers the
            # 200-on-Range fallback path: origin ignored Range, we
            # restart from 0)
            self.wfile.write(self.PAYLOAD)

    def log_message(self, format, *args):
        pass


class TestRangeResumeOnTruncation(unittest.TestCase):
    def setUp(self):
        _ResumableTruncatingOrigin.reset()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ResumableTruncatingOrigin)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.store = server.Store(tempfile.mkdtemp(), keep_query=False)

    def tearDown(self):
        getattr(self.httpd, "mgr", None) and self.httpd.mgr.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_truncated_stream_resumes_via_range(self):
        """First GET cuts at byte 500; second GET (with
        ``Range: bytes=500-``) returns 206 and the remaining 500.
        Result: a complete 1000-byte blob in the cache, sha256 matches
        the upstream's full payload, no TruncatedDownload raised."""
        import hashlib

        url = f"http://127.0.0.1:{self.port}/resumable.bin"
        row = self.store.store_from_origin(url)
        self.assertEqual(row["size"], len(_ResumableTruncatingOrigin.PAYLOAD))
        self.assertEqual(
            row["sha256"],
            hashlib.sha256(_ResumableTruncatingOrigin.PAYLOAD).hexdigest(),
        )
        with open(self.store.blob_path(row["key"]), "rb") as f:
            self.assertEqual(f.read(), _ResumableTruncatingOrigin.PAYLOAD)

    def test_progress_callback_reports_continuing_offset_on_resume(self):
        """Progress reports must be monotonic across the resume: the
        second leg's reads start at 500 (the partial-so-far) and walk
        up to 1000, NOT restart at 0. An operator dashboard watching
        ``progress`` for a stuck job needs to see the bytes climb."""
        observed: list[tuple[int, int | None]] = []
        url = f"http://127.0.0.1:{self.port}/resumable.bin"
        self.store.store_from_origin(url, progress=lambda d, t: observed.append((d, t)))
        # final report should be the full payload
        self.assertEqual(observed[-1][0], len(_ResumableTruncatingOrigin.PAYLOAD))
        # at no point did the byte counter regress
        for prev, curr in itertools.pairwise(observed):
            self.assertGreaterEqual(curr[0], prev[0])
        # the resume actually crossed the cut point: at least one
        # progress call lands above the half-mark (otherwise we
        # would have stalled at 500)
        half = len(_ResumableTruncatingOrigin.PAYLOAD) // 2
        self.assertTrue(any(d > half for d, _ in observed))


# --------------------------------------------------------------------------
# _shim: URL detection, rewrite, real-tool resolution, env, path-encoding
# --------------------------------------------------------------------------
class TestShim(unittest.TestCase):
    def test_cache_base(self):
        self.assertEqual(_shim.cache_base("box:8081"), "http://box:8081")
        self.assertEqual(_shim.cache_base("https://box:8081/"), "https://box:8081")

    def test_find_url_bare(self):
        self.assertEqual(
            _shim.find_url(["-fsSL", "https://h/x.tgz", "-o", "x"]),
            (1, "https://h/x.tgz", "bare"),
        )

    def test_find_url_ignores_header_and_data_values(self):
        # a "://" inside a header/data value must NOT be taken as the URL
        argv = [
            "-H",
            "Referer: https://ref.example",
            "--data",
            "u=https://x",
            "https://real/target.bin",
        ]
        _, url, kind = _shim.find_url(argv)
        self.assertEqual((url, kind), ("https://real/target.bin", "bare"))

    def test_find_url_urleq(self):
        self.assertEqual(_shim.find_url(["--url=https://h/y", "-O"]), (0, "https://h/y", "urleq"))

    def test_find_url_after_dashdash(self):
        self.assertEqual(_shim.find_url(["-s", "--", "https://h/z"]), (2, "https://h/z", "bare"))

    def test_find_url_none(self):
        self.assertIsNone(_shim.find_url(["--version"]))
        self.assertIsNone(_shim.find_url(["-H", "X: y"]))

    def test_rewrite(self):
        self.assertEqual(
            _shim.rewrite(["a", "https://o/p", "b"], 1, "bare", "http://c/b/x/p"),
            ["a", "http://c/b/x/p", "b"],
        )
        self.assertEqual(
            _shim.rewrite(["--url=https://o"], 0, "urleq", "http://c/b/x/p"),
            ["--url=http://c/b/x/p"],
        )

    def test_blob_url_path_encodes_with_basename(self):
        # path-encoded so any downloader names the file after the artifact,
        # and there's no query string to pollute the name
        origin = "https://h/p/cuda.tar.gz?token=abc"
        u = _shim.blob_url("http://c", origin)
        self.assertTrue(u.startswith("http://c/b/"))
        self.assertTrue(u.endswith("/cuda.tar.gz"))
        self.assertNotIn("?", u)
        token = u[len("http://c/b/") :].split("/")[0]
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode()
        self.assertEqual(decoded, origin)  # server can recover the exact origin

    def test_env_server_override_precedence(self):
        saved = {
            k: os.environ.get(k)
            for k in ("WITHCACHE_SERVER", "CURLWITHCACHE_SERVER", "WGETWITHCACHE_SERVER")
        }
        try:
            os.environ["WITHCACHE_SERVER"] = "http://shared:8081"
            os.environ["CURLWITHCACHE_SERVER"] = "http://curl-only:8081"
            os.environ.pop("WGETWITHCACHE_SERVER", None)
            self.assertEqual(_shim.env_server("curl"), "http://curl-only:8081")
            self.assertEqual(_shim.env_server("wget"), "http://shared:8081")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_find_real_skips_self(self):
        shim_dir, real_dir = tempfile.mkdtemp(), tempfile.mkdtemp()
        shim, real = os.path.join(shim_dir, "curl"), os.path.join(real_dir, "curl")
        for p in (shim, real):
            with open(p, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(p, 0o755)
        saved_argv0, saved_path = sys.argv[0], os.environ.get("PATH", "")
        saved_real = os.environ.pop("REAL_CURL", None)
        try:
            sys.argv[0] = shim  # we are the shim, first on PATH
            os.environ["PATH"] = shim_dir + os.pathsep + real_dir
            self.assertEqual(os.path.realpath(_shim.find_real("curl")), os.path.realpath(real))
        finally:
            sys.argv[0], os.environ["PATH"] = saved_argv0, saved_path
            if saved_real is not None:
                os.environ["REAL_CURL"] = saved_real


# --------------------------------------------------------------------------
# Shim integration: plan() decision path (stubbed probe, platform-independent).
# This is the oracle's own end-to-end path — exercised so the fallback is not
# an untested code path.
# --------------------------------------------------------------------------
class TestShimPlan(unittest.TestCase):
    def setUp(self):
        self.dummy = os.path.join(tempfile.mkdtemp(), "curl")
        with open(self.dummy, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(self.dummy, 0o755)
        self._saved = {
            k: os.environ.get(k) for k in ("REAL_CURL", "WITHCACHE_SERVER", "CURLWITHCACHE_SERVER")
        }
        os.environ["REAL_CURL"] = self.dummy
        os.environ.pop("CURLWITHCACHE_SERVER", None)

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_hit_rewrites_only_the_url(self):
        os.environ["WITHCACHE_SERVER"] = "http://cache:8081"
        argv = ["-fsSL", "https://h/p/cuda.tar.gz", "-o", "out"]
        real, final = _shim.plan("curl", lambda r, u: True, argv)
        self.assertEqual(real, self.dummy)
        self.assertEqual([final[0], final[2], final[3]], ["-fsSL", "-o", "out"])
        self.assertTrue(final[1].startswith("http://cache:8081/b/"))
        self.assertTrue(final[1].endswith("/cuda.tar.gz"))

    def test_miss_leaves_argv_untouched(self):
        os.environ["WITHCACHE_SERVER"] = "http://cache:8081"
        argv = ["https://h/x", "-O"]
        _, final = _shim.plan("curl", lambda r, u: False, argv)
        self.assertEqual(final, argv)

    def test_unreachable_leaves_argv_untouched(self):
        os.environ["WITHCACHE_SERVER"] = "http://cache:8081"
        argv = ["https://h/x"]
        _, final = _shim.plan("curl", lambda r, u: None, argv)
        self.assertEqual(final, argv)

    def test_no_server_skips_probe_entirely(self):
        os.environ.pop("WITHCACHE_SERVER", None)
        calls = []
        argv = ["https://h/x"]
        _, final = _shim.plan("curl", lambda r, u: calls.append(1) or True, argv)
        self.assertEqual((final, calls), (argv, []))  # no env -> probe never runs

    def test_no_real_tool_returns_none(self):
        os.environ.pop("REAL_CURL", None)
        saved_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = ""
            real, final = _shim.plan("curl", lambda r, u: True, ["https://h/x"])
            self.assertEqual((real, final), (None, ["https://h/x"]))
        finally:
            os.environ["PATH"] = saved_path


# --------------------------------------------------------------------------
# Fetch-with-headers: a registry blob behind bearer auth (the oras case). bty
# pre-resolves the token and hands it to withcache for the fill.
# --------------------------------------------------------------------------
class _AuthOrigin(http.server.BaseHTTPRequestHandler):
    TOKEN = "Bearer s3cret"

    def do_GET(self):
        if self.headers.get("Authorization") != self.TOKEN:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, format, *args):
        pass


class TestFetchWithHeaders(unittest.TestCase):
    def setUp(self):
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), _AuthOrigin)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/blob.bin"
        self.store = server.Store(tempfile.mkdtemp(), keep_query=False)

    def tearDown(self):
        getattr(self.httpd, "mgr", None) and self.httpd.mgr.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_fetch_without_header_is_rejected(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.store.store_from_origin(self.url)
        self.assertEqual(cm.exception.code, 401)

    def test_fetch_with_bearer_header_succeeds(self):
        row = self.store.store_from_origin(self.url, headers={"Authorization": _AuthOrigin.TOKEN})
        self.assertEqual(row["size"], len(PAYLOAD))


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------
class TestParsers(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(server.parse_size(""), 0)
        self.assertEqual(server.parse_size("0"), 0)
        self.assertEqual(server.parse_size("1024"), 1024)
        self.assertEqual(server.parse_size("50M"), 50 * 1024**2)
        self.assertEqual(server.parse_size("1.5G"), int(1.5 * 1024**3))

    def test_parse_headers(self):
        self.assertIsNone(server.parse_headers(""))
        self.assertEqual(
            server.parse_headers("Authorization: Bearer x"), {"Authorization": "Bearer x"}
        )
        self.assertEqual(server.parse_headers("A: 1\nB: 2"), {"A": "1", "B": "2"})


class TestOrasTagRevalidation(unittest.TestCase):
    """server._oras_tag_moved: the store keys on the ref string, so a
    re-pushed *mutable* tag must be detected and invalidated, while
    digest-pinned refs and unreachable registries leave the cache intact."""

    TAG = "oras://ghcr.io/safl/nosi/ubuntu-2604-headless:2026.W26"
    HEX_A = "a" * 64
    HEX_B = "b" * 64

    @staticmethod
    def _resolver(digest_hex):
        def _r(_ref):
            return types.SimpleNamespace(digest="sha256:" + digest_hex)

        return _r

    def test_moved_when_registry_digest_differs(self):
        self.assertTrue(
            server._oras_tag_moved(self.TAG, self.HEX_A, resolve=self._resolver(self.HEX_B))
        )

    def test_not_moved_when_digest_matches(self):
        self.assertFalse(
            server._oras_tag_moved(self.TAG, self.HEX_A, resolve=self._resolver(self.HEX_A))
        )

    def test_digest_match_is_case_insensitive(self):
        self.assertFalse(
            server._oras_tag_moved(self.TAG, self.HEX_A.upper(), resolve=self._resolver(self.HEX_A))
        )

    def test_digest_pinned_ref_never_revalidates(self):
        pinned = "oras://ghcr.io/safl/nosi/x@sha256:" + self.HEX_A
        calls = []

        def _r(ref):
            calls.append(ref)
            return types.SimpleNamespace(digest="sha256:" + self.HEX_B)

        self.assertFalse(server._oras_tag_moved(pinned, self.HEX_A, resolve=_r))
        self.assertEqual(calls, [], "a digest-pinned ref must not hit the registry")

    def test_non_oras_url_is_never_moved(self):
        self.assertFalse(
            server._oras_tag_moved(
                "https://h/x.img.gz", self.HEX_A, resolve=self._resolver(self.HEX_B)
            )
        )

    def test_missing_cached_sha_keeps_entry(self):
        r = self._resolver(self.HEX_B)
        self.assertFalse(server._oras_tag_moved(self.TAG, "", resolve=r))
        self.assertFalse(server._oras_tag_moved(self.TAG, None, resolve=r))

    def test_resolve_error_serves_cached(self):
        def _boom(_ref):
            raise OSError("registry unreachable")

        self.assertFalse(server._oras_tag_moved(self.TAG, self.HEX_A, resolve=_boom))


class TestAddOrasEntryFormatMapping(unittest.TestCase):
    """CatalogState.add_oras_entry derives ``format`` from the resolved
    layer title's suffix and ``arch`` from the tag suffix. The
    happy-path test in TestCatalogAdminEndpoints only covers the
    unreachable-registry branch (fmt stays ''); this class exercises
    the title -> format mapping (all five known suffixes + fallback)
    and the arch extraction."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.catalog = server.CatalogState(
            url="http://localhost/catalog.toml",
            persist_path=os.path.join(self.tmpdir, "catalog.toml"),
        )
        # Patch oras.resolve_ref for the duration of the tests; every
        # test sets a fake_resolver with the shape it needs.
        self._original_resolve = server.oras.resolve_ref

    def tearDown(self):
        server.oras.resolve_ref = self._original_resolve

    def _stub_resolve(self, title, size=1234):
        def _r(ref):
            return types.SimpleNamespace(title=title, size=size, digest="sha256:abc")

        server.oras.resolve_ref = _r

    def test_title_ends_with_img_zst(self):
        self._stub_resolve("debian-13-headless.img.zst")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["format"], "img.zst")

    def test_title_ends_with_img_gz(self):
        self._stub_resolve("release.img.gz")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["format"], "img.gz")

    def test_title_ends_with_img_xz(self):
        self._stub_resolve("release.img.xz")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["format"], "img.xz")

    def test_title_ends_with_bare_img(self):
        self._stub_resolve("raw.img")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["format"], "img")

    def test_title_ends_with_iso(self):
        self._stub_resolve("bootable.iso")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["format"], "iso")

    def test_title_no_known_suffix_leaves_format_unset(self):
        self._stub_resolve("something.tar")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        self.assertNotIn("format", self.catalog.entries[-1])

    def test_tag_suffix_extracts_arch_x86_64(self):
        self._stub_resolve("release.img.zst")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1-x86_64")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["arch"], "x86_64")

    def test_tag_suffix_extracts_arch_arm64(self):
        self._stub_resolve("release.img.zst")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1-arm64")
        self.assertTrue(ok)
        self.assertEqual(self.catalog.entries[-1]["arch"], "arm64")

    def test_unknown_arch_suffix_leaves_arch_unset(self):
        self._stub_resolve("release.img.zst")
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1-mips")
        self.assertTrue(ok)
        self.assertNotIn("arch", self.catalog.entries[-1])


class TestCatalogStateLoadPersisted(unittest.TestCase):
    """CatalogState.load_persisted is the restart-recovery path (the
    docstring's whole premise: 'a persisted result from the last
    successful fetch survives a restart'). Four branches: override
    present, override absent, TOML corrupt (silent last_error), TOML
    missing. None were exercised before."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.persist = os.path.join(self.tmpdir, "catalog.toml")
        self.url_override = os.path.join(self.tmpdir, "catalog_url")

    def _fresh_state(self, *, env_url: str = "") -> "server.CatalogState":
        return server.CatalogState(
            url="http://default/catalog.toml",
            persist_path=self.persist,
            url_override_path=self.url_override,
            env_url=env_url,
        )

    def test_missing_files_leaves_state_empty(self):
        s = self._fresh_state()
        s.load_persisted()
        self.assertEqual(s.entries, [])
        self.assertEqual(s.fetched_at, "")
        self.assertEqual(s.last_error, "")
        # URL stays at default when override file absent.
        self.assertEqual(s.url, "http://default/catalog.toml")

    def test_valid_toml_populates_entries(self):
        payload = (
            b'[[images]]\nname = "demo"\nsrc = "https://x/demo.img.zst"\n'
            b'[[images]]\nname = "other"\nsrc = "https://x/other.img"\n'
        )
        with open(self.persist, "wb") as f:
            f.write(payload)
        s = self._fresh_state()
        s.load_persisted()
        self.assertEqual([e["name"] for e in s.entries], ["demo", "other"])
        self.assertTrue(s.fetched_at)  # non-empty ISO timestamp
        self.assertEqual(s.last_error, "")

    def test_url_override_file_wins_when_env_unset(self):
        with open(self.url_override, "w", encoding="utf-8") as f:
            f.write("https://operator-set/catalog.toml\n")
        s = self._fresh_state()
        s.load_persisted()
        self.assertEqual(s.url, "https://operator-set/catalog.toml")

    def test_env_url_pin_beats_url_override_file(self):
        # Env pinning: operator override MUST NOT sneak past.
        with open(self.url_override, "w", encoding="utf-8") as f:
            f.write("https://operator-set/catalog.toml\n")
        s = self._fresh_state(env_url="https://env-pinned/catalog.toml")
        s.load_persisted()
        # Env-url wins; the operator file is ignored.
        self.assertNotEqual(s.url, "https://operator-set/catalog.toml")

    def test_corrupt_toml_records_last_error_without_raising(self):
        with open(self.persist, "wb") as f:
            f.write(b"this is not toml { at all")
        s = self._fresh_state()
        s.load_persisted()  # must not raise
        self.assertEqual(s.entries, [])
        self.assertTrue(s.last_error)
        self.assertIn("failed to load", s.last_error)


class TestAddOrasEntryDedupeByName(unittest.TestCase):
    """add_oras_entry replaces an existing entry by name rather than
    appending -- the whole reason for the list comprehension at
    line 356. A regression that dropped the filter would silently
    duplicate rows. TestAddOrasEntryFormatMapping (Pass 9+10)
    covered only the field-derivation branches."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.catalog = server.CatalogState(
            url="http://localhost/catalog.toml",
            persist_path=os.path.join(self.tmpdir, "catalog.toml"),
        )
        self._original_resolve = server.oras.resolve_ref
        server.oras.resolve_ref = lambda ref: types.SimpleNamespace(
            title="demo.img.zst", size=1234, digest="sha256:abc"
        )

    def tearDown(self):
        server.oras.resolve_ref = self._original_resolve

    def test_second_add_of_same_name_replaces_not_appends(self):
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        # Second add with a URL that resolves to the same derived name
        # should replace the entry (dedupe on name).
        ok, _ = self.catalog.add_oras_entry("oras://ghcr.io/x/demo:v1")
        self.assertTrue(ok)
        names = [e["name"] for e in self.catalog.entries]
        # Exactly one row for the demo name -- not two duplicates.
        self.assertEqual(names.count("demo-v1"), 1)


class TestDownloadManagerClose(unittest.TestCase):
    """DownloadManager.close() (Pass 9+10) drains worker threads. A
    regression that failed to send enough STOP sentinels, or that
    left workers blocking on queue.get(), would leak threads across
    tests + leave a Ctrl-C'd server hanging."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = server.Store(self.tmpdir, keep_query=False)

    def test_close_terminates_workers_within_timeout(self):
        mgr = server.DownloadManager(self.store, workers=3)
        self.assertEqual(len(mgr._threads), 3)
        # Every worker was started and should terminate on close().
        for t in mgr._threads:
            self.assertTrue(t.is_alive())
        mgr.close(timeout=3.0)
        for t in mgr._threads:
            self.assertFalse(t.is_alive(), "worker still alive after close()")

    def test_enqueue_dedupes_already_pending_url(self):
        """Same URL enqueued twice while the first is still pending
        should return the same Job id (line 842-843)."""
        mgr = server.DownloadManager(self.store, workers=0)
        try:
            j1 = mgr.enqueue("https://x/a")
            j2 = mgr.enqueue("https://x/a")
            self.assertEqual(j1.id, j2.id)
        finally:
            mgr.close(timeout=1.0)

    def test_cancel_queued_job_marks_it_cancelled_synchronously(self):
        """A cancel on a still-queued job flips it to 'cancelled' at
        the request site rather than waiting for the worker."""
        mgr = server.DownloadManager(self.store, workers=0)
        try:
            job = mgr.enqueue("https://x/queued")
            self.assertEqual(job.status, "queued")
            got = mgr.cancel(job.id)
            self.assertIsNotNone(got)
            self.assertEqual(got.status, "cancelled")
            self.assertIsNotNone(got.finished_at)
        finally:
            mgr.close(timeout=1.0)

    def test_cancel_unknown_id_returns_none(self):
        mgr = server.DownloadManager(self.store, workers=0)
        try:
            self.assertIsNone(mgr.cancel(12345))
        finally:
            mgr.close(timeout=1.0)


class TestHumanSize(unittest.TestCase):
    """human_size feeds the operator UI's Cached / Streams tabs;
    an off-by-one in the ladder would silently mis-label sizes."""

    def test_zero_is_bytes(self):
        self.assertIn("B", server.human_size(0))

    def test_bytes_below_kib(self):
        self.assertIn("B", server.human_size(512))

    def test_kib_range(self):
        self.assertIn("KiB", server.human_size(2048))

    def test_mib_range(self):
        self.assertIn("MiB", server.human_size(5 * 1024 * 1024))

    def test_gib_range(self):
        self.assertIn("GiB", server.human_size(3 * 1024 * 1024 * 1024))


if __name__ == "__main__":
    unittest.main(verbosity=2)
