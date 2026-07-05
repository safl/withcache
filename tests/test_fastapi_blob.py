"""TestClient tests for the byte-serving routes.

Pins the wire contract bty depends on: URL shape
(``/blob?url=<origin>`` and ``/b/<b64(src)>/<name>``), status
codes (200 on hit / 404 on miss with recording / 400 on missing
URL), headers (Content-Length + Content-Type + X-Withcache-Sha256),
streamed body payload identity, HEAD parity, and the miss-side
enqueue with Authorization forwarding.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("fastapi not installed") from None

from withcache._app import create_app  # noqa: E402

TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


def _b64_url(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class _BlobBase(unittest.TestCase):
    """Real Store on a temp data-dir + a capture-only DownloadManager
    stub so the miss-side enqueue is observable without a worker
    thread spawning."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("WITHCACHE_ADMIN_PASSWORD")
        os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)

        self.enqueue_calls: list[tuple[str, dict[str, str] | None]] = []

        outer = self

        class _CaptureMgr:
            def enqueue(self, url: str, headers: dict[str, str] | None = None) -> None:
                outer.enqueue_calls.append((url, headers))

        self.app = create_app(
            data_dir=self._tmpdir,
            secret_key=TEST_SECRET,
            mgr=_CaptureMgr(),
        )
        self.client = TestClient(self.app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        if self._saved_pw is None:
            os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)
        else:
            os.environ["WITHCACHE_ADMIN_PASSWORD"] = self._saved_pw
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _seed(
        self, url: str, content: bytes, content_type: str = "application/octet-stream"
    ) -> str:
        """Insert a cached blob directly into the Store so the hit
        path exercises the streaming shape without needing a real
        upstream fetch. Returns the store key."""
        store = self.app.state.store
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        sha = hashlib.sha256(content).hexdigest()
        path = store.blob_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with store.conn() as c:
            c.execute(
                "INSERT INTO blobs "
                "(key, url, size, sha256, content_type, fetched_at, hits, misses) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
                (key, url, len(content), sha, content_type, now),
            )
        return key


class BlobLegacyShapeTests(_BlobBase):
    def test_hit_returns_200_and_body(self) -> None:
        url = "https://example.invalid/hit.bin"
        content = b"cached payload" * 100
        self._seed(url, content, "application/octet-stream")
        r = self.client.get("/blob", params={"url": url})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, content)
        self.assertEqual(r.headers["Content-Length"], str(len(content)))
        self.assertTrue(
            r.headers["Content-Type"].startswith("application/octet-stream"),
            r.headers["Content-Type"],
        )
        self.assertEqual(r.headers["X-Withcache-Sha256"], hashlib.sha256(content).hexdigest())

    def test_miss_returns_404_and_records(self) -> None:
        url = "https://example.invalid/miss.bin"
        r = self.client.get("/blob", params={"url": url})
        self.assertEqual(r.status_code, 404)
        self.assertIn("cache miss", r.text)
        with self.app.state.store.conn() as c:
            rows = c.execute("SELECT url FROM misses WHERE url = ?", (url,)).fetchall()
        self.assertEqual(len(rows), 1)

    def test_missing_url_400(self) -> None:
        r = self.client.get("/blob")
        self.assertEqual(r.status_code, 400)
        self.assertIn("missing url", r.text)


class BlobCanonicalShapeTests(_BlobBase):
    def test_hit_via_b64_returns_body(self) -> None:
        url = "https://example.invalid/canonical.img.gz"
        content = b"canonical payload " * 50
        self._seed(url, content)
        b64 = _b64_url(url)
        r = self.client.get(f"/b/{b64}/canonical.img.gz")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, content)
        self.assertEqual(r.headers["Content-Length"], str(len(content)))

    def test_hit_name_segment_is_decorative(self) -> None:
        url = "https://example.invalid/decorative.bin"
        content = b"one payload"
        self._seed(url, content)
        b64 = _b64_url(url)
        r1 = self.client.get(f"/b/{b64}/decorative.bin")
        r2 = self.client.get(f"/b/{b64}/anything-else.txt")
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r1.content, r2.content)

    def test_miss_via_b64_returns_404(self) -> None:
        url = "https://example.invalid/miss-b64.bin"
        r = self.client.get(f"/b/{_b64_url(url)}/name.bin")
        self.assertEqual(r.status_code, 404)


class BlobHeadTests(_BlobBase):
    def test_head_hit_returns_headers_no_body(self) -> None:
        url = "https://example.invalid/head.bin"
        content = b"body payload"
        self._seed(url, content)
        r = self.client.head("/blob", params={"url": url})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"")
        self.assertEqual(r.headers["Content-Length"], str(len(content)))
        self.assertEqual(r.headers["X-Withcache-Sha256"], hashlib.sha256(content).hexdigest())

    def test_head_miss_returns_404(self) -> None:
        r = self.client.head("/blob", params={"url": "https://example.invalid/miss.bin"})
        self.assertEqual(r.status_code, 404)

    def test_head_hit_via_b64(self) -> None:
        url = "https://example.invalid/head-b64.bin"
        self._seed(url, b"payload")
        r = self.client.head(f"/b/{_b64_url(url)}/name.bin")
        self.assertEqual(r.status_code, 200)


class BlobMissAutoFetchTests(_BlobBase):
    def test_miss_enqueues_on_auto_fetch(self) -> None:
        url = "https://example.invalid/enqueue.bin"
        self.client.get("/blob", params={"url": url})
        self.assertEqual(len(self.enqueue_calls), 1)
        self.assertEqual(self.enqueue_calls[0][0], url)

    def test_miss_forwards_authorization_header(self) -> None:
        url = "https://example.invalid/token-gated.bin"
        self.client.get(
            "/blob",
            params={"url": url},
            headers={"Authorization": "Bearer xyz123"},
        )
        self.assertEqual(len(self.enqueue_calls), 1)
        _, headers = self.enqueue_calls[0]
        self.assertIsNotNone(headers)
        self.assertEqual(headers["Authorization"], "Bearer xyz123")

    def test_miss_no_authorization_no_headers_forwarded(self) -> None:
        self.client.get("/blob", params={"url": "https://example.invalid/anon.bin"})
        self.assertEqual(self.enqueue_calls[0][1], None)


class BlobAutoFetchOffTests(_BlobBase):
    def setUp(self) -> None:
        super().setUp()
        self.client.close()
        outer = self

        class _CaptureMgr:
            def enqueue(self, url: str, headers: dict[str, str] | None = None) -> None:
                outer.enqueue_calls.append((url, headers))

        self.app = create_app(
            data_dir=self._tmpdir + "-curate",
            secret_key=TEST_SECRET,
            mgr=_CaptureMgr(),
            auto_fetch=False,
        )
        self.client = TestClient(self.app, follow_redirects=False)

    def test_miss_records_but_does_not_enqueue(self) -> None:
        pre = len(self.enqueue_calls)
        r = self.client.get("/blob", params={"url": "https://example.invalid/curated.bin"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(len(self.enqueue_calls), pre)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
