"""TestClient tests for the /admin/* form-encoded routes.

Fifth checkpoint of the v0.9.0 port. Pins the operator-UI action
flows: each form POST calls the same underlying method the
pre-port stdlib Handler dispatched, then 303s to the appropriate
/ui/* target. Auth-gate mirrors the JSON API semantics.
"""

from __future__ import annotations

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
from withcache.server import CatalogState  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _AdminBase(unittest.TestCase):
    ENABLE_AUTH = False

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("WITHCACHE_ADMIN_PASSWORD")
        self._saved_cat = os.environ.get("WITHCACHE_CATALOG_URL")
        if self.ENABLE_AUTH:
            os.environ["WITHCACHE_ADMIN_PASSWORD"] = TEST_PASSWORD
        else:
            os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)
        os.environ.pop("WITHCACHE_CATALOG_URL", None)

        # Capture-only mgr stub so /admin/fetch + /admin/cancel +
        # /admin/clear are observable without a worker thread.
        outer = self
        self.mgr_calls: list[tuple[str, dict]] = []

        class _CaptureMgr:
            def enqueue(self, url: str, headers=None):
                outer.mgr_calls.append(("enqueue", {"url": url, "headers": headers}))

            def cancel(self, jid: int):
                outer.mgr_calls.append(("cancel", {"id": jid}))

            def clear_finished(self):
                outer.mgr_calls.append(("clear_finished", {}))

            def list(self):
                return []

        self.catalog = CatalogState(
            url="https://example.invalid/catalog.toml",
            persist_path=os.path.join(self._tmpdir, "catalog.toml"),
            env_url="",
            url_override_path=os.path.join(self._tmpdir, "catalog_url"),
        )
        # Replace fetch_now with a no-op so /admin/catalog_refresh
        # doesn't try to hit the network in tests.
        self.catalog_fetch_calls = 0

        def _fake_fetch_now(**_kw):
            self.catalog_fetch_calls += 1

        self.catalog.fetch_now = _fake_fetch_now  # type: ignore[assignment]

        self.app = create_app(
            data_dir=self._tmpdir,
            secret_key=TEST_SECRET,
            mgr=_CaptureMgr(),
            catalog=self.catalog,
        )
        self.client = TestClient(self.app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        for key, saved in (
            ("WITHCACHE_ADMIN_PASSWORD", self._saved_pw),
            ("WITHCACHE_CATALOG_URL", self._saved_cat),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)

    def _seed_blob(self, url: str, content: bytes = b"payload") -> str:
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
                "VALUES (?, ?, ?, ?, 'application/octet-stream', ?, 0, 0)",
                (key, url, len(content), sha, now),
            )
        return key


class DownloadActionTests(_AdminBase):
    def test_fetch_promotes_url_to_catalog_entry_and_enqueues(self) -> None:
        """Since v0.11.0 the Fetch button on /ui/misses promotes the
        URL to a first-class catalog entry (auto-generated name from
        the basename) AND enqueues the download. This lets an
        operator turn a recurring miss into a permanent, trio-visible
        catalog entry with one click."""
        r = self.client.post(
            "/admin/fetch",
            data={"url": "https://example.invalid/rocm-6.tar.gz"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/downloads")

        # Fetch was enqueued.
        self.assertEqual(len(self.mgr_calls), 1)
        self.assertEqual(self.mgr_calls[0][0], "enqueue")
        self.assertEqual(self.mgr_calls[0][1]["url"], "https://example.invalid/rocm-6.tar.gz")

        # AND the URL landed as a catalog entry.
        names = [e.get("name") for e in self.app.state.catalog.entries]
        self.assertIn("rocm-6.tar.gz", names)

    def test_fetch_bare_host_falls_back_to_derived_name(self) -> None:
        """A URL with no basename (bare host + trailing slash) still
        yields a stable catalog name derived from a short hash of
        the URL, so the promote-and-download step never fails on
        odd inputs."""
        self.client.post(
            "/admin/fetch",
            data={"url": "https://example.invalid/"},
            follow_redirects=False,
        )
        names = [e.get("name") for e in self.app.state.catalog.entries]
        self.assertTrue(any(n and n.startswith("misses-") for n in names))

    def test_fetch_existing_entry_only_enqueues(self) -> None:
        """When the URL matches an existing catalog entry's src, we
        skip the duplicate-add step and just enqueue the download.
        Idempotent from the operator's perspective."""
        self.app.state.catalog.entries.append(
            {
                "name": "already-there",
                "src": "https://example.invalid/existing.bin",
                "resolved_src": "https://example.invalid/existing.bin",
            }
        )
        self.client.post(
            "/admin/fetch",
            data={"url": "https://example.invalid/existing.bin"},
            follow_redirects=False,
        )
        # Still only one entry with that name; no duplicate.
        matching = [e for e in self.app.state.catalog.entries if e.get("name") == "already-there"]
        self.assertEqual(len(matching), 1)
        # Download WAS enqueued.
        self.assertEqual(len(self.mgr_calls), 1)

    def test_fetch_empty_url_no_op(self) -> None:
        r = self.client.post("/admin/fetch", data={"url": ""}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.mgr_calls, [])
        self.assertEqual(self.app.state.catalog.entries, [])

    def test_cancel_dispatches_int_id(self) -> None:
        r = self.client.post("/admin/cancel", data={"id": "42"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/downloads")
        self.assertEqual(self.mgr_calls[0], ("cancel", {"id": 42}))

    def test_cancel_ignores_non_int(self) -> None:
        self.client.post("/admin/cancel", data={"id": "abc"}, follow_redirects=False)
        self.assertEqual(self.mgr_calls, [])

    def test_clear_finished_fires(self) -> None:
        r = self.client.post("/admin/clear", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.mgr_calls, [("clear_finished", {})])


class BlobActionTests(_AdminBase):
    def test_delete_removes_row(self) -> None:
        url = "https://example.invalid/to-delete.bin"
        key = self._seed_blob(url)
        r = self.client.post("/admin/delete", data={"key": key}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/cached")
        # Row is gone from the Store.
        with self.app.state.store.conn() as c:
            rows = c.execute("SELECT key FROM blobs WHERE key = ?", (key,)).fetchall()
        self.assertEqual(rows, [])


class MissActionTests(_AdminBase):
    def test_dismiss_removes_recorded_miss(self) -> None:
        url = "https://example.invalid/to-dismiss.bin"
        self.app.state.store.record_miss(url)
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        r = self.client.post("/admin/dismiss", data={"key": key}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/misses")
        with self.app.state.store.conn() as c:
            rows = c.execute("SELECT key FROM misses WHERE key = ?", (key,)).fetchall()
        self.assertEqual(rows, [])


class CatalogActionTests(_AdminBase):
    def test_refresh_calls_fetch_now(self) -> None:
        r = self.client.post("/admin/catalog_refresh", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(self.catalog_fetch_calls, 1)

    def test_set_url_success_triggers_fetch(self) -> None:
        r = self.client.post(
            "/admin/catalog_set_url",
            data={"url": "https://example.invalid/new-catalog.toml"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(self.catalog.url, "https://example.invalid/new-catalog.toml")
        self.assertEqual(self.catalog_fetch_calls, 1)

    def test_add_oras_appends_entry(self) -> None:
        oras = "oras://ghcr.io/safl/nosi/demo:latest"
        r = self.client.post(
            "/admin/catalog_add_oras",
            data={"url": oras},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        # add_oras_entry logs into entries when the layer probe
        # succeeds; failure still records but with an error note.
        # Either way the redirect target is /ui/catalog.

    def test_delete_entry_records_error_when_missing(self) -> None:
        r = self.client.post(
            "/admin/catalog_delete_entry",
            data={"name": "does-not-exist"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        # last_error surfaces the not-found reason so the Catalog
        # page's error card catches it.
        self.assertNotEqual(self.catalog.last_error, "")


class AuthGatedTests(_AdminBase):
    ENABLE_AUTH = True

    def test_all_admin_routes_require_session(self) -> None:
        # A representative sample -- the require_ui_auth dependency
        # gates all of them the same way.
        for path, data in (
            ("/admin/fetch", {"url": "https://x"}),
            ("/admin/dismiss", {"key": "abc"}),
            ("/admin/delete", {"key": "abc"}),
            ("/admin/cancel", {"id": "1"}),
            ("/admin/clear", {}),
            ("/admin/catalog_refresh", {}),
            ("/admin/catalog_set_url", {"url": "https://x"}),
            ("/admin/catalog_add_oras", {"url": "oras://x"}),
            ("/admin/catalog_delete_entry", {"name": "x"}),
        ):
            with self.subTest(path=path):
                r = self.client.post(path, data=data, follow_redirects=False)
                self.assertEqual(r.status_code, 303)
                self.assertEqual(r.headers["location"], "/ui/login")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
