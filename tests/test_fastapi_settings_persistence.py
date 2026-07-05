"""TestClient tests for Settings persistence (log level).

Sixth checkpoint of the v0.9.0 port. Pins the persistent-override
half of the Warming card: a Settings save writes to the DB, the
next render reflects it, and the process env stays in sync for
code paths that read ``WITHCACHE_LOG_LEVEL`` directly.

Withcache differs from nbdmux by one row: catalog URL persistence
already went through :meth:`CatalogState.set_url_override` in the
pre-port code (persists to ``<data-dir>/catalog_url`` so the
daemon reads the same file at boot). The Catalog page's
/admin/catalog_set_url form drives that path unchanged; this
Settings-form path handles the log level only.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from fastapi.testclient import TestClient  # noqa: E402
except (ImportError, RuntimeError):  # pragma: no cover
    raise unittest.SkipTest("fastapi + httpx not installed") from None

from withcache import _settings_store  # noqa: E402
from withcache._app import create_app  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class SettingsStoreUnitTests(unittest.TestCase):
    """Direct coverage of :mod:`_settings_store`: get / set / clear +
    resolve_log_level. Runs against an in-memory DB so no fixture /
    teardown needed."""

    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        _settings_store.init(self.conn)
        self._saved_ll = os.environ.get(_settings_store.ENV_LOG_LEVEL)
        os.environ.pop(_settings_store.ENV_LOG_LEVEL, None)

    def tearDown(self) -> None:
        self.conn.close()
        if self._saved_ll is None:
            os.environ.pop(_settings_store.ENV_LOG_LEVEL, None)
        else:
            os.environ[_settings_store.ENV_LOG_LEVEL] = self._saved_ll

    def test_init_creates_settings_table(self) -> None:
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_init_is_idempotent(self) -> None:
        _settings_store.init(self.conn)
        _settings_store.init(self.conn)
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_get_returns_none_when_unset(self) -> None:
        self.assertIsNone(_settings_store.get(self.conn, _settings_store.KEY_LOG_LEVEL))

    def test_set_then_get_round_trip(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "debug")
        self.assertEqual(_settings_store.get(self.conn, _settings_store.KEY_LOG_LEVEL), "debug")

    def test_set_upserts_existing_row(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "info")
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "trace")
        self.assertEqual(_settings_store.get(self.conn, _settings_store.KEY_LOG_LEVEL), "trace")

    def test_clear_removes_row(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "debug")
        _settings_store.clear(self.conn, _settings_store.KEY_LOG_LEVEL)
        self.assertIsNone(_settings_store.get(self.conn, _settings_store.KEY_LOG_LEVEL))

    def test_resolve_log_level_default_when_unset(self) -> None:
        self.assertEqual(
            _settings_store.resolve_log_level(self.conn),
            _settings_store.DEFAULT_LOG_LEVEL,
        )

    def test_resolve_log_level_env_when_no_override(self) -> None:
        os.environ[_settings_store.ENV_LOG_LEVEL] = "debug"
        self.assertEqual(_settings_store.resolve_log_level(self.conn), "debug")

    def test_resolve_log_level_env_lowercased(self) -> None:
        os.environ[_settings_store.ENV_LOG_LEVEL] = "DEBUG"
        self.assertEqual(_settings_store.resolve_log_level(self.conn), "debug")

    def test_resolve_log_level_override_beats_env(self) -> None:
        os.environ[_settings_store.ENV_LOG_LEVEL] = "info"
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "trace")
        self.assertEqual(_settings_store.resolve_log_level(self.conn), "trace")

    def test_resolve_log_level_raises_on_invalid_override(self) -> None:
        _settings_store.set_value(self.conn, _settings_store.KEY_LOG_LEVEL, "chatty")
        with self.assertRaises(_settings_store.SettingValueError):
            _settings_store.resolve_log_level(self.conn)

    def test_resolve_log_level_raises_on_invalid_env(self) -> None:
        os.environ[_settings_store.ENV_LOG_LEVEL] = "chatty"
        with self.assertRaises(_settings_store.SettingValueError):
            _settings_store.resolve_log_level(self.conn)


class _SettingsFormBase(unittest.TestCase):
    ENABLE_AUTH = False

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._saved_pw = os.environ.get("WITHCACHE_ADMIN_PASSWORD")
        self._saved_ll = os.environ.get(_settings_store.ENV_LOG_LEVEL)
        if self.ENABLE_AUTH:
            os.environ["WITHCACHE_ADMIN_PASSWORD"] = TEST_PASSWORD
        else:
            os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)
        os.environ.pop(_settings_store.ENV_LOG_LEVEL, None)
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        for key, saved in (
            ("WITHCACHE_ADMIN_PASSWORD", self._saved_pw),
            (_settings_store.ENV_LOG_LEVEL, self._saved_ll),
        ):
            if saved is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = saved
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class SettingsFormRenderTests(_SettingsFormBase):
    """The Settings page's Warming card now renders as an editable
    form with the Override / Effective / Default three-column
    pattern bty + nbdmux use."""

    def test_renders_form_with_action_target(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn('action="/admin/settings/warming"', body)
        self.assertIn('name="log_level"', body)

    def test_renders_all_log_level_options(self) -> None:
        body = self.client.get("/ui/settings").text
        for lvl in _settings_store.LOG_LEVELS:
            self.assertIn(f'value="{lvl}"', body)

    def test_effective_shows_env_when_no_override(self) -> None:
        os.environ[_settings_store.ENV_LOG_LEVEL] = "debug"
        body = self.client.get("/ui/settings").text
        self.assertIn("debug", body)

    def test_effective_shows_override_when_persisted(self) -> None:
        self.client.post("/admin/settings/warming", data={"log_level": "trace"})
        body = self.client.get("/ui/settings").text
        # The trace option is preselected + Effective column shows it.
        self.assertRegex(body, r'value="trace"\s+selected')
        self.assertIn("<code>trace</code>", body)

    def test_warming_anchor_present(self) -> None:
        body = self.client.get("/ui/settings").text
        self.assertIn('id="warming"', body)


class SettingsFormPersistTests(_SettingsFormBase):
    def test_valid_form_saves_and_redirects_with_flash(self) -> None:
        r = self.client.post(
            "/admin/settings/warming",
            data={"log_level": "debug"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings?saved=warming#warming")
        body = self.client.get("/ui/settings?saved=warming").text
        self.assertIn("Warming settings saved", body)

    def test_saving_syncs_env_immediately(self) -> None:
        """The uvicorn boot path reads ``WITHCACHE_LOG_LEVEL`` from
        env; a form save syncs the env at write time so the change
        takes effect without a restart."""
        self.assertNotIn(_settings_store.ENV_LOG_LEVEL, os.environ)
        self.client.post("/admin/settings/warming", data={"log_level": "debug"})
        self.assertEqual(os.environ.get(_settings_store.ENV_LOG_LEVEL), "debug")

    def test_empty_override_clears_row(self) -> None:
        self.client.post("/admin/settings/warming", data={"log_level": "debug"})
        self.client.post("/admin/settings/warming", data={"log_level": ""})
        r = self.client.get("/ui/settings")
        self.assertEqual(r.status_code, 200)

    def test_case_insensitive_form_input(self) -> None:
        self.client.post("/admin/settings/warming", data={"log_level": "DEBUG"})
        self.assertEqual(os.environ.get(_settings_store.ENV_LOG_LEVEL), "debug")

    def test_invalid_log_level_303s_with_error_and_no_persist(self) -> None:
        """A submit with an invalid log level 303s back with
        ``?error=<msg>`` and does NOT persist. Guards the resolver
        from having to raise on the next render."""
        r = self.client.post(
            "/admin/settings/warming",
            data={"log_level": "chatty"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertIn("error=", r.headers["location"])
        self.assertNotIn(_settings_store.ENV_LOG_LEVEL, os.environ)


class SettingsFormAuthTests(_SettingsFormBase):
    ENABLE_AUTH = True

    def test_save_requires_session(self) -> None:
        r = self.client.post(
            "/admin/settings/warming",
            data={"log_level": ""},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_save_works_after_login(self) -> None:
        self._login()
        r = self.client.post(
            "/admin/settings/warming",
            data={"log_level": "debug"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/settings?saved=warming#warming")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
