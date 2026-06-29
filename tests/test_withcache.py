"""Stdlib-only tests for withcache. Run with:  python -m unittest -v

No third-party test deps; src/ is put on the path so the package imports
without an install.
"""

import http.server
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import base64  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

from withcache import _shim, client, curlwithcache, server, wgetwithcache  # noqa: E402


# --------------------------------------------------------------------------
# Auth: signed-cookie round-trip, tamper + wrong-secret rejection, expiry
# --------------------------------------------------------------------------
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
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

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
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
        for prev, curr in zip(observed, observed[1:], strict=False):
            self.assertGreaterEqual(curr[0], prev[0])
        # the resume actually crossed the cut point: at least one
        # progress call lands above the half-mark (otherwise we
        # would have stalled at 500)
        half = len(_ResumableTruncatingOrigin.PAYLOAD) // 2
        self.assertTrue(any(d > half for d, _ in observed))


# --------------------------------------------------------------------------
# StreamRegistry: in-flight blob-serve registry powering the operator dash's
# "Streams" tab. Validates thread-safety + snapshot ordering + lifecycle.
# --------------------------------------------------------------------------
class TestStreamRegistry(unittest.TestCase):
    def test_start_assigns_unique_ids_and_records_metadata(self):
        reg = server.StreamRegistry()
        a = reg.start(url="http://o/x", client="10.0.0.1:5000", total=1024)
        b = reg.start(url="http://o/y", client="10.0.0.2:5000", total=None)
        self.assertNotEqual(a.id, b.id)
        self.assertEqual(a.url, "http://o/x")
        self.assertEqual(a.client, "10.0.0.1:5000")
        self.assertEqual(a.total, 1024)
        self.assertIsNone(b.total)
        # both visible in snapshot, oldest-first
        snap = reg.snapshot()
        self.assertEqual([s.id for s in snap], [a.id, b.id])

    def test_bump_updates_bytes_sent_for_known_id(self):
        reg = server.StreamRegistry()
        s = reg.start(url="http://o/x", client="c", total=100)
        reg.bump(s.id, 42)
        self.assertEqual(reg.snapshot()[0].bytes_sent, 42)
        # later bump moves forward; the registry doesn't enforce
        # monotonicity (the handler is the only caller and it is monotonic)
        reg.bump(s.id, 99)
        self.assertEqual(reg.snapshot()[0].bytes_sent, 99)

    def test_bump_unknown_id_is_a_silent_noop(self):
        """A finish() that races against a final bump() must not crash:
        the bump arrives, finds the id gone, returns silently. The
        handler relies on this so its tight write loop doesn't have to
        special-case the race."""
        reg = server.StreamRegistry()
        reg.bump(99999, 7)
        self.assertEqual(reg.snapshot(), [])

    def test_finish_removes_from_snapshot(self):
        reg = server.StreamRegistry()
        s = reg.start(url="http://o/x", client="c", total=10)
        self.assertEqual(len(reg.snapshot()), 1)
        reg.finish(s.id)
        self.assertEqual(reg.snapshot(), [])
        # second finish is a no-op (handler's finally: block can fire twice)
        reg.finish(s.id)
        self.assertEqual(reg.snapshot(), [])

    def test_snapshot_returns_a_copy_not_the_live_dict(self):
        """Operator code iterating a snapshot must not see torn state when
        a worker thread starts/finishes a stream mid-iteration."""
        reg = server.StreamRegistry()
        s = reg.start(url="http://o/x", client="c", total=10)
        snap = reg.snapshot()
        reg.finish(s.id)
        reg.start(url="http://o/y", client="c", total=10)
        # snapshot taken before the mutations stays put
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0].url, "http://o/x")

    def test_concurrent_start_finish_under_load(self):
        """Hammer the lock with 500 starts + 500 finishes from 10 threads;
        the registry must end empty with no exception leaks."""
        reg = server.StreamRegistry()
        errors: list[BaseException] = []

        def churn():
            try:
                for _ in range(50):
                    s = reg.start(url="http://o/x", client="c", total=10)
                    reg.bump(s.id, 5)
                    reg.finish(s.id)
            except BaseException as e:
                errors.append(e)

        threads = [threading.Thread(target=churn) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(reg.snapshot(), [])


class TestAgeHuman(unittest.TestCase):
    """``_age_human`` renders elapsed seconds into the compact form the
    Streams table cell shows. Inject ``now`` so the test doesn't have
    to monkeypatch ``time.time``."""

    def test_seconds_only(self):
        self.assertEqual(server._age_human(100.0, now=100.0), "0s")
        self.assertEqual(server._age_human(100.0, now=159.0), "59s")

    def test_minutes_pad_seconds(self):
        self.assertEqual(server._age_human(100.0, now=160.0), "1m00s")
        self.assertEqual(server._age_human(100.0, now=222.0), "2m02s")

    def test_hours_pad_minutes(self):
        self.assertEqual(server._age_human(0.0, now=3600.0), "1h00m")
        self.assertEqual(server._age_human(0.0, now=3661.0), "1h01m")
        self.assertEqual(server._age_human(0.0, now=7320.0), "2h02m")

    def test_negative_clamps_to_zero(self):
        # Started-at in the future (clock skew, replayed snapshot) renders
        # as 0s rather than a confusing negative.
        self.assertEqual(server._age_human(200.0, now=100.0), "0s")


# --------------------------------------------------------------------------
# _shim: URL detection, rewrite, real-tool resolution, env, path-encoding
# --------------------------------------------------------------------------
class TestShim(unittest.TestCase):
    def test_cache_base(self):
        self.assertEqual(_shim.cache_base("box:3000"), "http://box:3000")
        self.assertEqual(_shim.cache_base("https://box:3000/"), "https://box:3000")

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
            os.environ["WITHCACHE_SERVER"] = "http://shared:3000"
            os.environ["CURLWITHCACHE_SERVER"] = "http://curl-only:3000"
            os.environ.pop("WGETWITHCACHE_SERVER", None)
            self.assertEqual(_shim.env_server("curl"), "http://curl-only:3000")
            self.assertEqual(_shim.env_server("wget"), "http://shared:3000")
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
        os.environ["WITHCACHE_SERVER"] = "http://cache:3000"
        argv = ["-fsSL", "https://h/p/cuda.tar.gz", "-o", "out"]
        real, final = _shim.plan("curl", lambda r, u: True, argv)
        self.assertEqual(real, self.dummy)
        self.assertEqual([final[0], final[2], final[3]], ["-fsSL", "-o", "out"])
        self.assertTrue(final[1].startswith("http://cache:3000/b/"))
        self.assertTrue(final[1].endswith("/cuda.tar.gz"))

    def test_miss_leaves_argv_untouched(self):
        os.environ["WITHCACHE_SERVER"] = "http://cache:3000"
        argv = ["https://h/x", "-O"]
        _, final = _shim.plan("curl", lambda r, u: False, argv)
        self.assertEqual(final, argv)

    def test_unreachable_leaves_argv_untouched(self):
        os.environ["WITHCACHE_SERVER"] = "http://cache:3000"
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
# Real probe against an in-process cache (skipped where the tool is absent).
# Validates the actual curl -I / wget --spider exit-code interpretation.
# --------------------------------------------------------------------------
def _start_withcache(auto_fetch=False):
    store = server.Store(tempfile.mkdtemp(), keep_query=False)
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    httpd.store = store
    httpd.auth = server.Auth(b"k", None)  # auth disabled -> read path open
    httpd.mgr = server.DownloadManager(store, workers=1)
    httpd.auto_fetch = auto_fetch
    httpd.streams = server.StreamRegistry()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, store


class TestProbeReal(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"
        self.httpd, self.store = _start_withcache()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        for s in (self.origin, self.httpd):
            s.shutdown()
            s.server_close()

    def _check(self, probe, real):
        miss = self.origin_url + "/not-cached"
        self.assertIs(probe(real, _shim.blob_url(self.base, miss)), False)
        self.store.store_from_origin(self.origin_url)  # seed it
        self.assertIs(probe(real, _shim.blob_url(self.base, self.origin_url)), True)

    @unittest.skipUnless(shutil.which("curl"), "curl not installed")
    def test_curl_probe(self):
        self._check(curlwithcache.probe, shutil.which("curl"))

    @unittest.skipUnless(shutil.which("wget"), "wget not installed")
    def test_wget_probe(self):
        self._check(wgetwithcache.probe, shutil.which("wget"))


# --------------------------------------------------------------------------
# Handler counters: a served GET counts as a hit; the shim's HEAD probe does
# not; an uncached GET/HEAD records a miss.
# --------------------------------------------------------------------------
class TestHandlerCounters(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"
        self.httpd, self.store = _start_withcache()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        for s in (self.origin, self.httpd):
            s.shutdown()
            s.server_close()

    def test_head_probe_does_not_count_but_get_does(self):
        self.store.store_from_origin(self.origin_url)
        bu = _shim.blob_url(self.base, self.origin_url)
        # the shim probes with HEAD before the real download — must not count
        urllib.request.urlopen(urllib.request.Request(bu, method="HEAD")).read()
        self.assertEqual(self.store.get_blob(self.origin_url)["hits"], 0)
        # the real download is a GET — counts as one served hit
        urllib.request.urlopen(bu).read()
        self.assertEqual(self.store.get_blob(self.origin_url)["hits"], 1)

    def test_uncached_request_records_a_miss(self):
        bu = _shim.blob_url(self.base, self.origin_url + "/nope")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(bu)
        self.assertEqual(cm.exception.code, 404)
        self.assertEqual(self.store.list_misses()[0]["count"], 1)


# --------------------------------------------------------------------------
# Auto-fetch vs --curate: a miss schedules a background pull by default; with
# curation it only records the miss and waits for an operator.
# --------------------------------------------------------------------------
class TestAutoFetchOnMiss(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"

    def tearDown(self):
        self.origin.shutdown()
        self.origin.server_close()

    def _miss(self, httpd):
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(_shim.blob_url(base, self.origin_url))

    def test_miss_schedules_pull_by_default(self):
        httpd, store = _start_withcache(auto_fetch=True)
        try:
            self._miss(httpd)
            # the miss enqueued a background pull, no operator needed
            self.assertTrue(any(j.url == self.origin_url for j in httpd.mgr.list()))
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_curate_mode_records_miss_but_schedules_nothing(self):
        httpd, store = _start_withcache(auto_fetch=False)
        try:
            self._miss(httpd)
            self.assertEqual(httpd.mgr.list(), [])  # nothing pulled without approval
            self.assertEqual(store.list_misses()[0]["count"], 1)  # but it is recorded
        finally:
            httpd.shutdown()
            httpd.server_close()


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
# HEAD with an Authorization header should propagate that header into the
# auto-fetch worker so a 401-gated origin (e.g. a ghcr.io blob URL behind a
# bty-minted OCI bearer) actually fills. Without this propagation the worker
# pulls anonymous, the origin 401s, and the URL stays uncached forever.
# --------------------------------------------------------------------------
class TestHeadForwardsAuthorizationToAutoFetch(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _AuthOrigin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/blob.bin"
        self.httpd, self.store = _start_withcache(auto_fetch=True)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        for s in (self.origin, self.httpd):
            s.shutdown()
            s.server_close()

    def _wait_for_fill(self, timeout_s=2.0):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.store.get_blob(self.origin_url) is not None:
                return True
            time.sleep(0.02)
        return False

    def test_head_with_authorization_triggers_authed_fetch(self):
        bu = _shim.blob_url(self.base, self.origin_url)
        req = urllib.request.Request(bu, method="HEAD")
        req.add_header("Authorization", _AuthOrigin.TOKEN)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 404)  # miss; recorded + enqueued
        # The worker should have fetched in the background using the header.
        self.assertTrue(
            self._wait_for_fill(),
            "expected blob to be cached after auth-bearing HEAD",
        )

    def test_head_without_authorization_leaves_origin_401_and_cache_empty(self):
        # Negative: no Authorization on the HEAD means the worker is enqueued
        # anonymous, the origin 401s, nothing lands. Verifies the new code
        # path is genuinely opt-in (HEAD without auth keeps the old behaviour).
        bu = _shim.blob_url(self.base, self.origin_url)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(urllib.request.Request(bu, method="HEAD"))
        self.assertEqual(cm.exception.code, 404)
        self.assertFalse(
            self._wait_for_fill(timeout_s=0.5),
            "expected no blob without forwarded auth",
        )


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


# --------------------------------------------------------------------------
# Client library: what a consumer (e.g. bty) imports instead of reimplementing
# the /b/ protocol.
# --------------------------------------------------------------------------
class TestClientLibrary(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"
        self.httpd, self.store = _start_withcache()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        for s in (self.origin, self.httpd):
            s.shutdown()
            s.server_close()

    def test_blob_url_matches_shim_and_normalizes_server(self):
        # accepts a host/host:port/http URL and emits the same /b/ URL as the shim
        self.assertEqual(
            client.blob_url(self.base, self.origin_url),
            _shim.blob_url(_shim.cache_base(self.base), self.origin_url),
        )

    def test_is_cached_and_serve_url_track_the_cache(self):
        self.assertFalse(client.is_cached(self.base, self.origin_url))
        self.assertIsNone(client.serve_url(self.base, self.origin_url))
        self.store.store_from_origin(self.origin_url)  # warm it
        self.assertTrue(client.is_cached(self.base, self.origin_url))
        self.assertEqual(
            client.serve_url(self.base, self.origin_url),
            client.blob_url(self.base, self.origin_url),
        )

    def test_is_cached_unreachable_is_false(self):
        self.assertFalse(client.is_cached("http://127.0.0.1:9", self.origin_url, timeout=0.5))


# --------------------------------------------------------------------------
# Client + server end-to-end: a HEAD with ``headers={"Authorization": ...}``
# warms the cache against a 401-gated origin. Mirrors the bty oras case
# (resolved ghcr.io blob URL + freshly-minted OCI bearer).
# --------------------------------------------------------------------------
class TestClientLibraryAuthForwarding(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _AuthOrigin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/blob.bin"
        self.httpd, self.store = _start_withcache(auto_fetch=True)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        for s in (self.origin, self.httpd):
            s.shutdown()
            s.server_close()

    def test_is_cached_with_authorization_warms_auth_gated_origin(self):
        # Cold: no auth -> background fetch goes anonymous, 401s, cache empty.
        self.assertFalse(client.is_cached(self.base, self.origin_url))
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if self.store.get_blob(self.origin_url) is not None:
                break
            time.sleep(0.02)
        self.assertIsNone(self.store.get_blob(self.origin_url))

        # Warm-with-token: HEAD carries Authorization; server forwards it
        # into the fetch worker; the auth-gated origin returns the bytes.
        self.assertFalse(
            client.is_cached(
                self.base,
                self.origin_url,
                headers={"Authorization": _AuthOrigin.TOKEN},
            )
        )
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self.store.get_blob(self.origin_url) is not None:
                break
            time.sleep(0.02)
        self.assertIsNotNone(
            self.store.get_blob(self.origin_url),
            "expected auth-bearing HEAD to fill the cache via forwarded Authorization",
        )

        # And once cached, the auth header is no longer needed: a plain HEAD
        # hits 200, serve_url returns the blob URL without auth.
        self.assertTrue(client.is_cached(self.base, self.origin_url))
        self.assertEqual(
            client.serve_url(self.base, self.origin_url),
            client.blob_url(self.base, self.origin_url),
        )


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


class TestDashActiveTabFromHeader(unittest.TestCase):
    """``GET /admin/dash`` bakes ``.active-tab`` into the rendered HTML
    based on the ``X-Active-Tab`` request header. The browser sends the
    current URL hash on every refresh so the htmx innerHTML swap doesn't
    visibly blink while a post-swap JS would otherwise re-apply the class.
    """

    def setUp(self):
        self.httpd, self.store = _start_withcache()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _dash(self, active_tab=None):
        req = urllib.request.Request(self.base + "/admin/dash")
        if active_tab is not None:
            req.add_header("X-Active-Tab", active_tab)
        return urllib.request.urlopen(req).read().decode("utf-8")

    def test_default_tab_when_header_missing(self):
        body = self._dash()
        # tab-cached is the first tab and the no-header default
        self.assertIn('<section id="tab-cached" class="tab active-tab">', body)
        self.assertIn('<section id="tab-streams" class="tab">', body)

    def test_header_picks_the_active_tab(self):
        body = self._dash("tab-misses")
        self.assertIn('<section id="tab-misses" class="tab active-tab">', body)
        self.assertIn('<section id="tab-cached" class="tab">', body)

    def test_unknown_header_value_falls_back_to_first(self):
        """A hand-crafted X-Active-Tab with a bogus value must not echo
        into the HTML; the renderer falls back to the first tab."""
        body = self._dash("tab-totally-not-real")
        self.assertIn('<section id="tab-cached" class="tab active-tab">', body)
        self.assertNotIn("tab-totally-not-real", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
