"""TestClient tests for the operator UI pages.

Since v0.12.0 the pages are /ui/dashboard, /ui/catalog, /ui/misses,
/ui/settings. The retired /ui/cached + /ui/downloads folded into
Catalog (hits + per-row download progress).
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

TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _PagesBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("WITHCACHE_ADMIN_PASSWORD")
        self._saved_cat = os.environ.get("WITHCACHE_CATALOG_URL")
        os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)
        os.environ.pop("WITHCACHE_CATALOG_URL", None)

        self.catalog = CatalogState(
            url="https://example.invalid/catalog.toml",
            persist_path=os.path.join(self._tmpdir, "catalog.toml"),
            env_url="",
            url_override_path=os.path.join(self._tmpdir, "catalog_url"),
        )

        self.app = create_app(
            data_dir=self._tmpdir,
            secret_key=TEST_SECRET,
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

    def _seed_blob(self, url: str, content: bytes) -> None:
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
                "VALUES (?, ?, ?, ?, 'application/octet-stream', ?, 3, 0)",
                (key, url, len(content), sha, now),
            )


class DashboardPageTests(_PagesBase):
    def test_renders_summary_cards(self) -> None:
        body = self.client.get("/ui/dashboard").text
        self.assertIn("WITHCACHE", body)
        self.assertIn("brand-accent", body)
        self.assertIn("Catalog", body)
        # Recent activity card replaces the old Recent misses card
        self.assertIn("Recent activity", body)
        # Health check list has the label copy
        self.assertIn("Catalog source", body)

    def test_dashboard_recent_events_empty_state(self) -> None:
        body = self.client.get("/ui/dashboard").text
        self.assertIn("No events yet", body)


class MissesPageTests(_PagesBase):
    def test_renders_empty_state(self) -> None:
        body = self.client.get("/ui/misses").text
        self.assertIn("No recorded misses yet", body)

    def test_renders_recorded_miss(self) -> None:
        url = "https://example.invalid/miss-for-page.bin"
        self.app.state.store.record_miss(url)
        body = self.client.get("/ui/misses").text
        self.assertIn(url, body)

    def test_filter_narrows_results(self) -> None:
        self.app.state.store.record_miss("https://example.invalid/keep.bin")
        self.app.state.store.record_miss("https://example.invalid/drop.bin")
        body = self.client.get("/ui/misses?q=keep").text
        self.assertIn("keep.bin", body)
        self.assertNotIn("drop.bin", body)


class CatalogPageTests(_PagesBase):
    def test_renders_entries_and_fetched_at(self) -> None:
        self.catalog.entries = [
            {
                "name": "demo.img.gz",
                "src": "https://example.invalid/demo.img.gz",
                "format": "img.gz",
            }
        ]
        self.catalog.fetched_at = "2026-07-05T12:00:00Z"
        body = self.client.get("/ui/catalog").text
        self.assertIn("demo.img.gz", body)

    def test_renders_error_when_last_error_set(self) -> None:
        self.catalog.last_error = "upstream 503 no gateway"
        body = self.client.get("/ui/catalog").text
        self.assertIn("upstream 503 no gateway", body)

    def test_subnav_has_three_inline_actions(self) -> None:
        body = self.client.get("/ui/catalog").text
        # Three inline forms live in the subnav strip
        self.assertIn('action="/admin/catalog_add_oras"', body)
        self.assertIn('action="/admin/catalog_add_entry"', body)
        self.assertIn('action="/admin/catalog_refresh"', body)
        self.assertIn("Add ORAS", body)
        self.assertIn("Add HTTPS", body)
        self.assertIn("Fetch default", body)

    def test_filter_narrows_entries(self) -> None:
        self.catalog.entries = [
            {"name": "keeper.img.gz", "src": "https://example.invalid/keeper.img.gz"},
            {"name": "reject.img.gz", "src": "https://example.invalid/reject.img.gz"},
        ]
        body = self.client.get("/ui/catalog?q=keeper").text
        self.assertIn("keeper.img.gz", body)
        self.assertNotIn("reject.img.gz", body)


class SettingsPageTests(_PagesBase):
    def test_renders_all_cards_with_subnav_anchors(self) -> None:
        body = self.client.get("/ui/settings").text
        for anchor in ("identity", "paths", "catalog", "logging", "auth"):
            with self.subTest(anchor=anchor):
                self.assertIn(f'id="{anchor}"', body)
                self.assertIn(f'href="#{anchor}"', body)

    def test_shows_open_mode_when_no_admin_password(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("open mode", body)

    def test_shows_catalog_source_form(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn("https://example.invalid/catalog.toml", body)
        # Editable form + Fetch default action live on Settings now.
        self.assertIn('action="/admin/catalog_set_url"', body)
        self.assertIn("Fetch default catalog", body)


class AuthGateTests(_PagesBase):
    def setUp(self) -> None:
        super().setUp()
        self.client.close()
        os.environ["WITHCACHE_ADMIN_PASSWORD"] = "test-admin-pw"
        self.app = create_app(
            data_dir=self._tmpdir,
            secret_key=TEST_SECRET,
            catalog=self.catalog,
        )
        self.client = TestClient(self.app, follow_redirects=False)

    def test_all_pages_redirect_to_login_when_unauth(self) -> None:
        for path in (
            "/ui/dashboard",
            "/ui/misses",
            "/ui/catalog",
            "/ui/settings",
        ):
            with self.subTest(path=path):
                r = self.client.get(path)
                self.assertEqual(r.status_code, 303)
                self.assertEqual(r.headers["location"], "/ui/login")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
