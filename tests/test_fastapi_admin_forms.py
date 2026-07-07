"""TestClient tests for the /admin/* form-encoded routes.

Pins the operator-UI action flows: each form POST calls the same
underlying method the pre-port stdlib Handler dispatched, then 303s
to the appropriate /ui/* target. Auth-gate mirrors the JSON API
semantics.

Since v0.12.0 the /ui/cached + /ui/downloads pages are retired;
their affordances fold into the Catalog page (cache hits + progress
per entry) so the corresponding admin routes were retired too.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from typing import Any

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

        # Capture-only mgr stub so /admin/fetch is observable without
        # a worker thread. Newer /admin/cancel_entry walks
        # ``mgr.list()`` looking for a job matching the entry's URL;
        # tests inject rows via self.jobs.
        outer = self
        self.mgr_calls: list[tuple[str, dict]] = []
        self.jobs: list[Any] = []

        class _CaptureMgr:
            def enqueue(self, url: str, headers=None):
                outer.mgr_calls.append(("enqueue", {"url": url, "headers": headers}))

            def cancel(self, jid):
                outer.mgr_calls.append(("cancel", {"id": jid}))

            def list(self):
                return outer.jobs

        self.catalog = CatalogState(
            url="https://example.invalid/catalog.toml",
            persist_path=os.path.join(self._tmpdir, "catalog.toml"),
            env_url="",
            url_override_path=os.path.join(self._tmpdir, "catalog_url"),
        )
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


class FetchButtonTests(_AdminBase):
    def test_fetch_promotes_url_to_catalog_entry_and_enqueues(self) -> None:
        """The Fetch button on /ui/misses promotes the URL to a
        first-class catalog entry (name from URL basename) AND
        enqueues the download. Redirects to /ui/catalog since v0.12.0
        so the operator sees the new entry immediately."""
        r = self.client.post(
            "/admin/fetch",
            data={"url": "https://example.invalid/rocm-6.tar.gz"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(len(self.mgr_calls), 1)
        self.assertEqual(self.mgr_calls[0][0], "enqueue")
        self.assertEqual(self.mgr_calls[0][1]["url"], "https://example.invalid/rocm-6.tar.gz")
        names = [e.get("name") for e in self.app.state.catalog.entries]
        self.assertIn("rocm-6.tar.gz", names)

    def test_fetch_bare_host_falls_back_to_derived_name(self) -> None:
        self.client.post(
            "/admin/fetch",
            data={"url": "https://example.invalid/"},
            follow_redirects=False,
        )
        names = [e.get("name") for e in self.app.state.catalog.entries]
        self.assertTrue(any(n and n.startswith("misses-") for n in names))

    def test_fetch_existing_entry_only_enqueues(self) -> None:
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
        matching = [e for e in self.app.state.catalog.entries if e.get("name") == "already-there"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(len(self.mgr_calls), 1)

    def test_fetch_empty_url_no_op(self) -> None:
        r = self.client.post("/admin/fetch", data={"url": ""}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.mgr_calls, [])
        self.assertEqual(self.app.state.catalog.entries, [])


class CancelEntryTests(_AdminBase):
    def test_cancel_entry_cancels_matching_job(self) -> None:
        """The Cancel button on a Catalog row posts the entry name;
        the handler walks mgr.list() looking for a queued/running
        job whose URL matches the entry's src, then cancels it."""

        class _Job:
            def __init__(self, jid, url, status):
                self.id = jid
                self.url = url
                self.status = status

        url = "https://example.invalid/vm.img.zst"
        self.app.state.catalog.entries.append({"name": "vm", "src": url, "resolved_src": url})
        self.jobs = [_Job(7, url, "running")]
        r = self.client.post("/admin/cancel_entry", data={"name": "vm"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(self.mgr_calls, [("cancel", {"id": 7})])

    def test_cancel_entry_unknown_name_no_op(self) -> None:
        r = self.client.post(
            "/admin/cancel_entry", data={"name": "does-not-exist"}, follow_redirects=False
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.mgr_calls, [])


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
    def test_refresh_default_redirects_to_catalog(self) -> None:
        r = self.client.post("/admin/catalog_refresh", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(self.catalog_fetch_calls, 1)

    def test_refresh_next_settings_redirects_to_settings(self) -> None:
        r = self.client.post(
            "/admin/catalog_refresh", data={"next": "settings"}, follow_redirects=False
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings")
        self.assertEqual(self.catalog_fetch_calls, 1)

    def test_set_url_success_triggers_fetch_and_lands_on_settings(self) -> None:
        r = self.client.post(
            "/admin/catalog_set_url",
            data={"url": "https://example.invalid/new-catalog.toml"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings")
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

    def test_add_entry_derives_name_and_format_from_url(self) -> None:
        """Since v0.12.0 the Add HTTPS form takes only a URL. The
        handler derives ``name`` from the basename and ``format`` from
        a known compressor suffix. sha256 + arch + size stay unset
        until Download populates them."""
        r = self.client.post(
            "/admin/catalog_add_entry",
            data={"url": "https://example.invalid/appliance-2026.W27.img.gz"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(len(self.catalog.entries), 1)
        entry = self.catalog.entries[0]
        self.assertEqual(entry["name"], "appliance-2026.W27.img.gz")
        self.assertEqual(entry["src"], "https://example.invalid/appliance-2026.W27.img.gz")
        self.assertEqual(entry["format"], "img.gz")
        self.assertNotIn("sha256", entry)

    def test_add_entry_empty_url_records_error(self) -> None:
        r = self.client.post("/admin/catalog_add_entry", data={"url": ""}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertEqual(self.catalog.entries, [])
        self.assertIn("url is required", (self.catalog.last_error or "").lower())

    def test_add_entry_refuses_oras_url(self) -> None:
        r = self.client.post(
            "/admin/catalog_add_entry",
            data={"url": "oras://ghcr.io/x/y:tag"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.catalog.entries, [])
        self.assertIn("add oras", (self.catalog.last_error or "").lower())

    def test_add_entry_duplicate_url_records_error(self) -> None:
        self.app.state.catalog.entries.append(
            {
                "name": "vm",
                "src": "https://example.invalid/vm.img.zst",
                "resolved_src": "https://example.invalid/vm.img.zst",
            }
        )
        r = self.client.post(
            "/admin/catalog_add_entry",
            data={"url": "https://example.invalid/vm.img.zst"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        # Still one entry
        self.assertEqual(len(self.catalog.entries), 1)
        self.assertIn("already", (self.catalog.last_error or "").lower())

    def test_delete_entry_records_error_when_missing(self) -> None:
        r = self.client.post(
            "/admin/catalog_delete_entry",
            data={"name": "does-not-exist"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/catalog")
        self.assertNotEqual(self.catalog.last_error, "")


class AuthGatedTests(_AdminBase):
    ENABLE_AUTH = True

    def test_all_admin_routes_require_session(self) -> None:
        # A representative sample; require_ui_auth gates all admin
        # routes the same way.
        for path, data in (
            ("/admin/fetch", {"url": "https://x"}),
            ("/admin/dismiss", {"key": "abc"}),
            ("/admin/cancel_entry", {"name": "x"}),
            ("/admin/catalog_refresh", {}),
            ("/admin/catalog_set_url", {"url": "https://x"}),
            ("/admin/catalog_add_oras", {"url": "oras://x"}),
            ("/admin/catalog_add_entry", {"url": "https://x/y.img.gz"}),
            ("/admin/catalog_delete_entry", {"name": "x"}),
        ):
            with self.subTest(path=path):
                r = self.client.post(path, data=data, follow_redirects=False)
                self.assertEqual(r.status_code, 303)
                self.assertEqual(r.headers["location"], "/ui/login")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
