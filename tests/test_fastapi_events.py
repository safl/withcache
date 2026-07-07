"""Tests for the withcache events log + /ui/events page.

Covers the emit-on-action pattern (login / catalog add / delete /
refresh / miss) and the render + pagination + free-text search on
the /ui/events page.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("fastapi not installed") from None

from withcache import _events_log  # noqa: E402
from withcache._app import create_app  # noqa: E402
from withcache.server import CatalogState  # noqa: E402

TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _EventsBase(unittest.TestCase):
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
        self.catalog.fetch_now = lambda **_kw: None  # type: ignore[assignment]

        class _CaptureMgr:
            def enqueue(self, _url, headers=None):
                pass

            def cancel(self, _jid):
                pass

            def list(self):
                return []

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

    def _events(self):
        with self.app.state.store.conn() as conn:
            return _events_log.search_events(conn, limit=200)


class EmitterTests(_EventsBase):
    def test_catalog_add_entry_emits_event(self) -> None:
        self.client.post(
            "/admin/catalog_add_entry",
            data={"url": "https://example.invalid/vm.img.zst"},
            follow_redirects=False,
        )
        events = self._events()
        kinds = [e.kind for e in events]
        self.assertIn("catalog.entry.added", kinds)
        added = next(e for e in events if e.kind == "catalog.entry.added")
        self.assertEqual(added.subject_kind, "catalog")
        self.assertEqual(added.actor, "operator")
        self.assertIn("vm.img.zst", added.summary)

    def test_catalog_delete_entry_emits_event(self) -> None:
        self.catalog.entries.append(
            {"name": "vm", "src": "https://example.invalid/vm.img.zst"}
        )
        self.client.post(
            "/admin/catalog_delete_entry",
            data={"name": "vm"},
            follow_redirects=False,
        )
        kinds = [e.kind for e in self._events()]
        self.assertIn("catalog.entry.deleted", kinds)

    def test_catalog_refresh_success_emits_event(self) -> None:
        self.client.post("/admin/catalog_refresh", follow_redirects=False)
        kinds = [e.kind for e in self._events()]
        self.assertIn("catalog.refreshed", kinds)

    def test_catalog_refresh_failure_emits_failed_event(self) -> None:
        self.catalog.last_error = "upstream 503 no gateway"
        self.client.post("/admin/catalog_refresh", follow_redirects=False)
        kinds = [e.kind for e in self._events()]
        self.assertIn("catalog.refresh.failed", kinds)

    def test_settings_logging_update_emits_event(self) -> None:
        self.client.post(
            "/admin/settings/logging",
            data={"log_level": "info"},
            follow_redirects=False,
        )
        kinds = [e.kind for e in self._events()]
        self.assertIn("settings.logging.updated", kinds)

    def test_dismiss_miss_emits_event(self) -> None:
        self.app.state.store.record_miss("https://example.invalid/miss.bin")
        import hashlib

        key = hashlib.sha256(b"https://example.invalid/miss.bin").hexdigest()
        self.client.post("/admin/dismiss", data={"key": key}, follow_redirects=False)
        kinds = [e.kind for e in self._events()]
        self.assertIn("blob.miss.dismissed", kinds)

    def test_record_miss_returns_fresh_flag(self) -> None:
        store = self.app.state.store
        fresh1 = store.record_miss("https://example.invalid/new-miss.bin")
        fresh2 = store.record_miss("https://example.invalid/new-miss.bin")
        self.assertTrue(fresh1)
        self.assertFalse(fresh2)


class EventsPageTests(_EventsBase):
    def _emit_test_events(self, count: int = 3) -> None:
        with self.app.state.store.conn() as conn:
            for i in range(count):
                _events_log.record(
                    conn,
                    kind="catalog.entry.added",
                    summary=f"test event {i}",
                    subject_kind="catalog",
                    subject_id=f"test-{i}",
                    actor="operator",
                )
            conn.commit()

    def test_events_page_renders_empty_state(self) -> None:
        r = self.client.get("/ui/events")
        self.assertEqual(r.status_code, 200)
        self.assertIn("No events recorded yet", r.text)

    def test_events_page_renders_row(self) -> None:
        self._emit_test_events(1)
        r = self.client.get("/ui/events")
        self.assertEqual(r.status_code, 200)
        self.assertIn("test event 0", r.text)
        self.assertIn("catalog.entry.added", r.text)

    def test_events_page_filter_narrows(self) -> None:
        self._emit_test_events(3)
        with self.app.state.store.conn() as conn:
            _events_log.record(
                conn,
                kind="catalog.refresh.failed",
                summary="upstream returned 503",
                subject_kind="catalog",
                actor="operator",
            )
            conn.commit()
        r = self.client.get("/ui/events?q=503")
        body = r.text
        self.assertIn("upstream returned 503", body)
        self.assertNotIn("test event", body)

    def test_ack_endpoint_marks_event_acknowledged(self) -> None:
        with self.app.state.store.conn() as conn:
            ev_id = _events_log.record(
                conn,
                kind="catalog.refresh.failed",
                summary="failure to ack",
                subject_kind="catalog",
                actor="system",
            )
            conn.commit()
        r = self.client.post(f"/admin/events/{ev_id}/ack", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        with self.app.state.store.conn() as conn:
            rows = _events_log.search_events(conn, limit=10)
            found = next(e for e in rows if e.id == ev_id)
            self.assertTrue(found.acknowledged)
            self.assertEqual(_events_log.count_unacknowledged_failures(conn), 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
