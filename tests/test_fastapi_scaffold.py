"""FastAPI-port scaffolding smoke tests.

First checkpoint of the v0.9.0 port. Mirrors nbdmux's
``tests/test_fastapi_scaffold.py`` shape so reviewers move
between the two by muscle memory.

Pins:

- /healthz returns 200 + JSON body naming service + version
- /ui/login renders on GET
- Un-authed /ui/cached 303s to /ui/login
- / redirects to /ui/cached
- Invalid password re-renders form with error
- Valid password mints session + reaches /ui/cached
- Logout clears session

Written as unittest.TestCase so ``make test`` (``python3 -m
unittest discover``) picks them up alongside the legacy suite.
The pre-port stdlib server + tests stay green during the port
because ``server.py`` and its stdlib http.server handler are
unchanged.
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
    raise unittest.SkipTest("fastapi + httpx not available (port scaffolding deps)") from None

from withcache._app import create_app  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class FastAPIScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_pw = os.environ.get("WITHCACHE_ADMIN_PASSWORD")
        os.environ["WITHCACHE_ADMIN_PASSWORD"] = TEST_PASSWORD
        self._tmpdir = tempfile.mkdtemp()
        app = create_app(data_dir=self._tmpdir, secret_key=TEST_SECRET)
        self.client = TestClient(app, follow_redirects=False)

    def tearDown(self) -> None:
        self.client.close()
        if self._saved_pw is None:
            os.environ.pop("WITHCACHE_ADMIN_PASSWORD", None)
        else:
            os.environ["WITHCACHE_ADMIN_PASSWORD"] = self._saved_pw
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _login(self, password: str = TEST_PASSWORD) -> None:
        r = self.client.post("/ui/login", data={"password": password}, follow_redirects=False)
        self.assertIn(r.status_code, (200, 303))

    def test_healthz_returns_200_json(self) -> None:
        r = self.client.get("/healthz")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["service"], "withcache")
        self.assertIn("version", body)

    def test_ui_login_form_renders_without_auth(self) -> None:
        r = self.client.get("/ui/login")
        self.assertEqual(r.status_code, 200)
        body = r.text
        self.assertIn("Log in", body)
        self.assertIn('name="password"', body)
        self.assertIn("WITHCACHE_ADMIN_PASSWORD", body)

    def test_ui_cached_without_auth_redirects_to_login(self) -> None:
        r = self.client.get("/ui/cached")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")

    def test_root_redirects_to_cached(self) -> None:
        r = self.client.get("/")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/cached")

    def test_ui_login_wrong_password_re_renders_with_error(self) -> None:
        r = self.client.post("/ui/login", data={"password": "not-the-password"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("Invalid password", r.text)

    def test_ui_login_valid_password_sets_session_and_reaches_cached(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/cached")
        r2 = self.client.get("/ui/cached")
        self.assertEqual(r2.status_code, 200)
        self.assertIn("WITHCACHE", r2.text)
        self.assertIn("brand-accent", r2.text)

    def test_ui_logout_clears_session_and_redirects(self) -> None:
        self._login()
        r = self.client.post("/ui/logout", follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/ui/login")
        r2 = self.client.get("/ui/cached")
        self.assertEqual(r2.status_code, 303)
        self.assertEqual(r2.headers["location"], "/ui/login")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
