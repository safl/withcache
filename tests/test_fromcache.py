"""Stdlib-only tests for fromcache. Run with:  python -m unittest -v

No third-party test deps; src/ is put on the path so the package imports
without an install.
"""

import http.server
import os
import socketserver
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fromcache import client, server  # noqa: E402


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
        self.assertEqual(
            s.normalize("https://h/x?a=1"), "https://h/x?a=1"
        )

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


# --------------------------------------------------------------------------
# Client pure-function helpers
# --------------------------------------------------------------------------
class TestClientHelpers(unittest.TestCase):
    def test_cache_base_prepends_scheme(self):
        self.assertEqual(client.cache_base("box:3000"), "http://box:3000")
        self.assertEqual(client.cache_base("https://box:3000/"), "https://box:3000")

    def test_default_output_is_basename(self):
        self.assertEqual(client.default_output("https://h/a/b/cuda.tgz"), "cuda.tgz")
        self.assertEqual(client.default_output("https://h/"), "download")


if __name__ == "__main__":
    unittest.main(verbosity=2)
