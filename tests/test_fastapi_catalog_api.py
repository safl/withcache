"""TestClient tests for the JSON catalog API.

Pins the ``GET /catalog`` + ``POST /catalog/entries`` +
``DELETE /catalog/entries`` surface that bty consumes as the
single source of truth for what images are flashable. Mirrors the
Bearer / session dual-auth pattern nbdmux uses on its write
routes.
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

from withcache._app import create_app  # noqa: E402
from withcache.server import CatalogState  # noqa: E402

TEST_PASSWORD = "test-admin-pw"
TEST_SECRET = b"test-secret-not-for-prod-use-32b_"


class _CatalogApiBase(unittest.TestCase):
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

        self.catalog = CatalogState(
            url="https://example.invalid/catalog.toml",
            persist_path=os.path.join(self._tmpdir, "catalog.toml"),
            env_url="",
            url_override_path=os.path.join(self._tmpdir, "catalog_url"),
        )

        def _fake_fetch_now(**_kw: object) -> None:
            pass

        self.catalog.fetch_now = _fake_fetch_now  # type: ignore[assignment]

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

    def _login(self) -> None:
        r = self.client.post("/ui/login", data={"password": TEST_PASSWORD}, follow_redirects=False)
        self.assertEqual(r.status_code, 303, r.text)


class ListCatalogTests(_CatalogApiBase):
    def test_list_empty_returns_metadata_with_empty_entries(self) -> None:
        r = self.client.get("/catalog")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["entries"], [])
        self.assertEqual(body["url"], "https://example.invalid/catalog.toml")
        self.assertIn("fetched_at", body)
        self.assertIn("last_error", body)

    def test_list_returns_seeded_entries(self) -> None:
        self.catalog.entries = [
            {
                "name": "demo",
                "src": "https://example/demo.img.gz",
                "format": "img.gz",
                "sha256": "a" * 64,
                "size_bytes": 1024,
                "description": "demo image",
                "resolved_src": "https://example/demo.img.gz",
            }
        ]
        r = self.client.get("/catalog")
        self.assertEqual(r.status_code, 200)
        entries = r.json()["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "demo")
        self.assertEqual(entries[0]["sha256"], "a" * 64)
        self.assertEqual(entries[0]["description"], "demo image")


class AddCatalogEntryTests(_CatalogApiBase):
    def test_add_minimum_entry(self) -> None:
        """Only ``name`` + ``src`` are required."""
        r = self.client.post(
            "/catalog/entries",
            json={"name": "demo", "src": "https://example/demo.img.gz"},
        )
        self.assertEqual(r.status_code, 201, r.text)
        body = r.json()
        self.assertEqual(body["name"], "demo")
        self.assertEqual(body["src"], "https://example/demo.img.gz")
        # And it landed in the catalog state.
        self.assertEqual(len(self.catalog.entries), 1)

    def test_add_full_entry_round_trips_all_fields(self) -> None:
        r = self.client.post(
            "/catalog/entries",
            json={
                "name": "debian",
                "src": "https://example/debian.img.gz",
                "resolved_src": "https://example/debian.img.gz",
                "format": "img.gz",
                "arch": "x86_64",
                "sha256": "b" * 64,
                "size_bytes": 2048,
                "description": "Debian sysdev",
            },
        )
        self.assertEqual(r.status_code, 201, r.text)
        stored = self.catalog.entries[0]
        self.assertEqual(stored["description"], "Debian sysdev")
        self.assertEqual(stored["resolved_src"], "https://example/debian.img.gz")

    def test_add_persists_to_disk(self) -> None:
        self.client.post(
            "/catalog/entries", json={"name": "demo", "src": "https://example/demo.img.gz"}
        )
        toml_path = os.path.join(self._tmpdir, "catalog.toml")
        self.assertTrue(os.path.exists(toml_path))
        content = open(toml_path, encoding="utf-8").read()
        self.assertIn('name = "demo"', content)

    def test_add_rejects_missing_name(self) -> None:
        r = self.client.post("/catalog/entries", json={"src": "https://example/demo.img.gz"})
        self.assertEqual(r.status_code, 400)

    def test_add_rejects_missing_src(self) -> None:
        r = self.client.post("/catalog/entries", json={"name": "demo"})
        self.assertEqual(r.status_code, 400)

    def test_add_rejects_unknown_field(self) -> None:
        """Unknown fields are refused at the API boundary so operators
        catch typos loud (``notes`` → ``description``) instead of
        watching them silently drop through the emitter."""
        r = self.client.post(
            "/catalog/entries",
            json={"name": "demo", "src": "https://example/x", "notes": "typo"},
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("notes", r.json()["detail"])

    def test_add_duplicate_name_409s(self) -> None:
        first = {"name": "demo", "src": "https://example/one.img.gz"}
        self.client.post("/catalog/entries", json=first)
        r = self.client.post(
            "/catalog/entries",
            json={"name": "demo", "src": "https://example/two.img.gz"},
        )
        self.assertEqual(r.status_code, 409)


class DeleteCatalogEntryTests(_CatalogApiBase):
    def test_delete_removes_entry(self) -> None:
        self.catalog.entries = [{"name": "demo", "src": "https://example/demo.img.gz"}]
        r = self.client.delete("/catalog/entries?name=demo")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(self.catalog.entries, [])

    def test_delete_unknown_returns_404(self) -> None:
        r = self.client.delete("/catalog/entries?name=missing")
        self.assertEqual(r.status_code, 404)

    def test_delete_requires_name(self) -> None:
        r = self.client.delete("/catalog/entries")
        self.assertEqual(r.status_code, 400)


class CatalogApiAuthTests(_CatalogApiBase):
    ENABLE_AUTH = True

    def test_get_catalog_open_even_with_auth(self) -> None:
        """Bty polls the catalog from a sibling container without a
        session; read stays open regardless of auth."""
        r = self.client.get("/catalog")
        self.assertEqual(r.status_code, 200)

    def test_add_entry_401_without_auth(self) -> None:
        r = self.client.post("/catalog/entries", json={"name": "demo", "src": "https://example/x"})
        self.assertEqual(r.status_code, 401)

    def test_add_entry_200_with_session(self) -> None:
        self._login()
        r = self.client.post("/catalog/entries", json={"name": "demo", "src": "https://example/x"})
        self.assertEqual(r.status_code, 201)

    def test_add_entry_200_with_bearer(self) -> None:
        """Service-to-service path: bty reads WITHCACHE_ADMIN_PASSWORD
        from env and sends it as ``Authorization: Bearer <pw>``."""
        r = self.client.post(
            "/catalog/entries",
            json={"name": "demo", "src": "https://example/x"},
            headers={"Authorization": f"Bearer {TEST_PASSWORD}"},
        )
        self.assertEqual(r.status_code, 201)

    def test_add_entry_401_with_bearer_mismatch(self) -> None:
        r = self.client.post(
            "/catalog/entries",
            json={"name": "demo", "src": "https://example/x"},
            headers={"Authorization": "Bearer wrong-pw"},
        )
        self.assertEqual(r.status_code, 401)

    def test_delete_entry_401_without_auth(self) -> None:
        r = self.client.delete("/catalog/entries?name=demo")
        self.assertEqual(r.status_code, 401)

    def test_delete_entry_204_with_bearer(self) -> None:
        self.catalog.entries = [{"name": "demo", "src": "https://example/x"}]
        r = self.client.delete(
            "/catalog/entries?name=demo",
            headers={"Authorization": f"Bearer {TEST_PASSWORD}"},
        )
        self.assertEqual(r.status_code, 204)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
