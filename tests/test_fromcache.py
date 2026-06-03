"""Stdlib-only tests for fromcache. Run with:  python -m unittest -v

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
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import base64  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402

from fromcache import _shim, curlfromcache, server, wgetfromcache  # noqa: E402


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
PAYLOAD = b"hello-fromcache-" * 1000  # 16 KiB


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
            for k in ("FROMCACHE_SERVER", "CURLFROMCACHE_SERVER", "WGETFROMCACHE_SERVER")
        }
        try:
            os.environ["FROMCACHE_SERVER"] = "http://shared:3000"
            os.environ["CURLFROMCACHE_SERVER"] = "http://curl-only:3000"
            os.environ.pop("WGETFROMCACHE_SERVER", None)
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
            k: os.environ.get(k) for k in ("REAL_CURL", "FROMCACHE_SERVER", "CURLFROMCACHE_SERVER")
        }
        os.environ["REAL_CURL"] = self.dummy
        os.environ.pop("CURLFROMCACHE_SERVER", None)

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def test_hit_rewrites_only_the_url(self):
        os.environ["FROMCACHE_SERVER"] = "http://cache:3000"
        argv = ["-fsSL", "https://h/p/cuda.tar.gz", "-o", "out"]
        real, final = _shim.plan("curl", lambda r, u: True, argv)
        self.assertEqual(real, self.dummy)
        self.assertEqual([final[0], final[2], final[3]], ["-fsSL", "-o", "out"])
        self.assertTrue(final[1].startswith("http://cache:3000/b/"))
        self.assertTrue(final[1].endswith("/cuda.tar.gz"))

    def test_miss_leaves_argv_untouched(self):
        os.environ["FROMCACHE_SERVER"] = "http://cache:3000"
        argv = ["https://h/x", "-O"]
        _, final = _shim.plan("curl", lambda r, u: False, argv)
        self.assertEqual(final, argv)

    def test_unreachable_leaves_argv_untouched(self):
        os.environ["FROMCACHE_SERVER"] = "http://cache:3000"
        argv = ["https://h/x"]
        _, final = _shim.plan("curl", lambda r, u: None, argv)
        self.assertEqual(final, argv)

    def test_no_server_skips_probe_entirely(self):
        os.environ.pop("FROMCACHE_SERVER", None)
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
def _start_fromcache():
    store = server.Store(tempfile.mkdtemp(), keep_query=False)
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    httpd.store = store
    httpd.auth = server.Auth(b"k", None)  # auth disabled -> read path open
    httpd.mgr = server.DownloadManager(store, workers=1)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, store


class TestProbeReal(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"
        self.httpd, self.store = _start_fromcache()
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
        self._check(curlfromcache.probe, shutil.which("curl"))

    @unittest.skipUnless(shutil.which("wget"), "wget not installed")
    def test_wget_probe(self):
        self._check(wgetfromcache.probe, shutil.which("wget"))


# --------------------------------------------------------------------------
# Handler counters: a served GET counts as a hit; the shim's HEAD probe does
# not; an uncached GET/HEAD records a miss.
# --------------------------------------------------------------------------
class TestHandlerCounters(unittest.TestCase):
    def setUp(self):
        self.origin = socketserver.TCPServer(("127.0.0.1", 0), _Origin)
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.origin_url = f"http://127.0.0.1:{self.origin.server_address[1]}/art.bin"
        self.httpd, self.store = _start_fromcache()
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
