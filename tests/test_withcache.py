"""Stdlib-only tests for withcache. Run with:  python -m unittest -v

No third-party test deps; src/ is put on the path so the package imports
without an install.
"""

import http.server
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
