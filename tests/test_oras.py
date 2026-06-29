"""Stdlib-only tests for withcache.oras (the OCI registry adapter).

Parser tests are pure; resolver tests mock ``urllib.request.urlopen`` so
they run on offline CI and don't hit a real registry. Mirrors the test
matrix that lived at ``bty/tests/test_oras.py`` before withcache took
over OCI handling.
"""

import http.server
import io
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
import urllib.error
from typing import Any
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from withcache import oras, server

# A trimmed-down version of a real nosi manifest -- two layers (the
# .img.gz and a .sha256 sidecar), one annotation each, OCI media types.
_NOSI_MANIFEST: dict[str, Any] = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "artifactType": "application/vnd.nosi.disk-image.v1+gzip",
    "layers": [
        {
            "mediaType": "application/vnd.nosi.disk-image.layer.v1+gzip",
            "digest": "sha256:" + "aa" * 32,
            "size": 1923658046,
            "annotations": {"org.opencontainers.image.title": "nosi-debian-sysdev-x86_64.img.gz"},
        },
        {
            "mediaType": "text/plain",
            "digest": "sha256:" + "bb" * 32,
            "size": 130,
            "annotations": {
                "org.opencontainers.image.title": "nosi-debian-sysdev-x86_64.img.gz.sha256"
            },
        },
    ],
}


class _BytesResp(io.BytesIO):
    def __enter__(self) -> "_BytesResp":
        return self

    def __exit__(self, *_a: object) -> None:
        return None


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x/y", code, f"err {code}", {}, None)  # type: ignore[arg-type]


def _make_urlopen_mock(token: str = "anon-token-xyz"):
    """urlopen replacement returning a token payload for /token and the
    nosi manifest for any /manifests/ URL."""

    def _fake_urlopen(req, timeout=None):
        url = req if isinstance(req, str) else req.full_url
        if "/token" in url:
            return _BytesResp(json.dumps({"token": token}).encode())
        if "/manifests/" in url:
            return _BytesResp(json.dumps(_NOSI_MANIFEST).encode())
        raise AssertionError(f"unexpected URL in test: {url}")

    return _fake_urlopen


class TestParseRef(unittest.TestCase):
    def test_tag_form(self):
        ref = oras.parse_ref("oras://ghcr.io/safl/nosi/debian-sysdev:latest")
        self.assertEqual(ref.host, "ghcr.io")
        self.assertEqual(ref.repository, "safl/nosi/debian-sysdev")
        self.assertEqual(ref.tag, "latest")
        self.assertIsNone(ref.digest)
        self.assertEqual(ref.manifest_locator, "latest")

    def test_digest_form(self):
        digest = "sha256:" + "ab" * 32
        ref = oras.parse_ref(f"oras://ghcr.io/safl/nosi/debian-sysdev@{digest}")
        self.assertEqual(ref.host, "ghcr.io")
        self.assertEqual(ref.repository, "safl/nosi/debian-sysdev")
        self.assertIsNone(ref.tag)
        self.assertEqual(ref.digest, digest)
        self.assertEqual(ref.manifest_locator, digest)

    def test_owner_repo_minimum(self):
        """Two-segment owner/repo under the host is the minimum."""
        ref = oras.parse_ref("oras://ghcr.io/owner/repo:v1")
        self.assertEqual(ref.host, "ghcr.io")
        self.assertEqual(ref.repository, "owner/repo")

    def test_accepts_host_with_port(self):
        """Private registries on non-443 ports preserve host:port verbatim."""
        ref = oras.parse_ref("oras://registry.example.com:5000/foo/bar:v1")
        self.assertEqual(ref.host, "registry.example.com:5000")
        self.assertEqual(ref.repository, "foo/bar")

    def test_rejects_bare_repo_after_host(self):
        with self.assertRaisesRegex(oras.OrasError, r"host.*owner.*repo"):
            oras.parse_ref("oras://ghcr.io/nosi:latest")

    def test_rejects_missing_scheme(self):
        with self.assertRaisesRegex(oras.OrasError, "not an oras://"):
            oras.parse_ref("ghcr.io/safl/nosi:latest")

    def test_rejects_empty_body(self):
        with self.assertRaisesRegex(oras.OrasError, "empty"):
            oras.parse_ref("oras://")

    def test_rejects_missing_tag_and_digest(self):
        """Tagless / digestless refs aren't pullable."""
        with self.assertRaisesRegex(oras.OrasError, "malformed"):
            oras.parse_ref("oras://ghcr.io/safl/nosi/debian-sysdev")

    def test_rejects_short_digest(self):
        """sha256 must be 64 hex chars; partial digests would mis-address."""
        with self.assertRaisesRegex(oras.OrasError, "malformed"):
            oras.parse_ref("oras://ghcr.io/safl/nosi/debian-sysdev@sha256:abc123")


class TestPickImageLayer(unittest.TestCase):
    def test_skips_sha256_sidecar(self):
        layer = oras.pick_image_layer(_NOSI_MANIFEST)
        title = layer["annotations"]["org.opencontainers.image.title"]
        self.assertEqual(title, "nosi-debian-sysdev-x86_64.img.gz")
        self.assertFalse(title.endswith(".sha256"))

    def test_picks_largest_when_no_sidecar(self):
        manifest: dict[str, Any] = {
            "layers": [
                {"digest": "sha256:" + "11" * 32, "size": 100, "annotations": {}},
                {"digest": "sha256:" + "22" * 32, "size": 1_000_000, "annotations": {}},
            ]
        }
        self.assertEqual(oras.pick_image_layer(manifest)["size"], 1_000_000)

    def test_raises_on_empty_layers(self):
        with self.assertRaisesRegex(oras.OrasError, "no layers"):
            oras.pick_image_layer({"layers": []})

    def test_raises_on_non_list_layers(self):
        with self.assertRaisesRegex(oras.OrasError, "no layers"):
            oras.pick_image_layer({"layers": "not-a-list"})

    def test_skips_non_dict_layer_entries(self):
        manifest: dict[str, Any] = {
            "layers": [
                None,
                "garbage",
                {"digest": "sha256:" + "33" * 32, "size": 4096, "annotations": {}},
            ]
        }
        self.assertEqual(oras.pick_image_layer(manifest)["size"], 4096)

    def test_names_multiarch_index(self):
        """A multi-arch image index gets a specific error pointing the
        operator at a concrete digest, not the generic 'no layers'."""
        index = {
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:" + "aa" * 32, "platform": {"architecture": "amd64"}},
                {"digest": "sha256:" + "bb" * 32, "platform": {"architecture": "arm64"}},
            ],
        }
        with self.assertRaisesRegex(oras.OrasError, "multi-arch image index"):
            oras.pick_image_layer(index)

    def test_refuses_helm_chart(self):
        """Helm tarball mediaType must be refused: flashing tar+gzip
        bytes onto a target disk is data-loss territory."""
        helm: dict[str, Any] = {
            "layers": [
                {
                    "digest": "sha256:" + "55" * 32,
                    "size": 4_096,
                    "mediaType": "application/vnd.cncf.helm.chart.v1.tar+gzip",
                },
                {
                    "digest": "sha256:" + "66" * 32,
                    "size": 256,
                    "mediaType": "application/vnd.cncf.helm.chart.provenance.v1.prov",
                },
            ]
        }
        with self.assertRaisesRegex(oras.OrasError, "non-disk-image artifact"):
            oras.pick_image_layer(helm)

    def test_refuses_cosign_sig(self):
        cosign: dict[str, Any] = {
            "layers": [
                {
                    "digest": "sha256:" + "77" * 32,
                    "size": 512,
                    "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
                },
            ]
        }
        with self.assertRaisesRegex(oras.OrasError, "non-disk-image artifact"):
            oras.pick_image_layer(cosign)

    def test_picks_image_alongside_provenance(self):
        """One real image layer + a non-image sidecar still resolves
        to the image; only all-non-image manifests get refused."""
        mixed: dict[str, Any] = {
            "layers": [
                {
                    "digest": "sha256:" + "aa" * 32,
                    "size": 256,
                    "mediaType": "application/vnd.in-toto+json",
                },
                {
                    "digest": "sha256:" + "bb" * 32,
                    "size": 2_000_000,
                    "annotations": {"org.opencontainers.image.title": "appliance.img.gz"},
                },
            ]
        }
        self.assertEqual(oras.pick_image_layer(mixed)["size"], 2_000_000)

    def test_falls_back_when_all_look_like_sidecars(self):
        """If every layer is annotated with a sidecar-suffix title,
        fall back to picking the largest (the resolver fails downstream
        rather than silently mis-classifying)."""
        manifest: dict[str, Any] = {
            "layers": [
                {
                    "digest": "sha256:" + "33" * 32,
                    "size": 50,
                    "annotations": {"org.opencontainers.image.title": "a.sha256"},
                },
                {
                    "digest": "sha256:" + "44" * 32,
                    "size": 500,
                    "annotations": {"org.opencontainers.image.title": "b.sha256"},
                },
            ]
        }
        self.assertEqual(oras.pick_image_layer(manifest)["size"], 500)


class TestResolveRef(unittest.TestCase):
    def test_tag_resolves_to_layer_digest(self):
        with patch("urllib.request.urlopen", _make_urlopen_mock()):
            resolved = oras.resolve_ref("oras://ghcr.io/safl/nosi/debian-sysdev:latest")
        self.assertEqual(resolved.digest, "sha256:" + "aa" * 32)
        self.assertEqual(resolved.size, 1923658046)
        self.assertEqual(resolved.title, "nosi-debian-sysdev-x86_64.img.gz")
        self.assertEqual(
            resolved.blob_url,
            f"https://ghcr.io/v2/safl/nosi/debian-sysdev/blobs/sha256:{'aa' * 32}",
        )
        self.assertEqual(resolved.headers, {"Authorization": "Bearer anon-token-xyz"})

    def test_digest_skips_manifest(self):
        """Digest-pinned references skip the manifest fetch entirely."""

        def _strict_urlopen(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            if "/manifests/" in url:
                raise AssertionError("digest-pinned ref should not fetch manifest")
            return _BytesResp(json.dumps({"token": "pinned-token"}).encode())

        digest = "sha256:" + "cd" * 32
        with patch("urllib.request.urlopen", _strict_urlopen):
            resolved = oras.resolve_ref(f"oras://ghcr.io/safl/nosi/debian-sysdev@{digest}")
        self.assertEqual(resolved.digest, digest)
        self.assertIsNone(resolved.size)
        self.assertIsNone(resolved.title)
        self.assertEqual(
            resolved.blob_url, f"https://ghcr.io/v2/safl/nosi/debian-sysdev/blobs/{digest}"
        )

    def test_uses_host_from_url_in_token_endpoint(self):
        """Token endpoint URL must follow the ref's host (not hardcoded
        to ghcr.io). Verifies cross-registry support."""
        seen: list[str] = []

        def _capturing(req, timeout=None):
            url = req if isinstance(req, str) else req.full_url
            seen.append(url)
            if "/token" in url:
                return _BytesResp(json.dumps({"token": "tok"}).encode())
            return _BytesResp(json.dumps(_NOSI_MANIFEST).encode())

        with patch("urllib.request.urlopen", _capturing):
            oras.resolve_ref("oras://registry.example.com:5000/foo/bar:v1")

        self.assertTrue(
            any(u.startswith("https://registry.example.com:5000/token") for u in seen),
            f"expected custom-host token URL in {seen}",
        )

    def test_propagates_token_failure(self):
        def _failing(req, timeout=None):
            raise OSError("network unreachable")

        with (
            patch("urllib.request.urlopen", _failing),
            self.assertRaisesRegex(oras.OrasError, "token fetch failed"),
        ):
            oras.resolve_ref("oras://ghcr.io/safl/nosi/debian-sysdev:latest")


class TestIsOrasUrl(unittest.TestCase):
    def test_recognises_only_oras_scheme(self):
        self.assertTrue(oras.is_oras_url("oras://ghcr.io/safl/nosi/debian-sysdev:latest"))
        self.assertFalse(oras.is_oras_url("https://ghcr.io/v2/safl/nosi/debian-sysdev/blobs/sha:x"))
        self.assertFalse(oras.is_oras_url("https://example.invalid/x.img.gz"))
        # ``ghcr:`` is NOT recognised; the explicit ``oras://`` form is required.
        self.assertFalse(oras.is_oras_url("ghcr:safl/nosi/debian-sysdev:latest"))


class TestUrlopenRetry(unittest.TestCase):
    def test_retries_transient_then_succeeds(self):
        with patch.object(oras.time, "sleep", lambda *_a: None):
            calls = {"n": 0}

            def _flaky(req, timeout=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise _http_error(503)
                return _BytesResp(b"ok")

            with patch("urllib.request.urlopen", _flaky):
                self.assertEqual(oras._urlopen_retry("https://x/y", timeout=5), b"ok")
            self.assertEqual(calls["n"], 2)

    def test_does_not_retry_permanent(self):
        with patch.object(oras.time, "sleep", lambda *_a: None):
            calls = {"n": 0}

            def _notfound(req, timeout=None):
                calls["n"] += 1
                raise _http_error(404)

            with (
                patch("urllib.request.urlopen", _notfound),
                self.assertRaises(urllib.error.HTTPError),
            ):
                oras._urlopen_retry("https://x/y", timeout=5)
            self.assertEqual(calls["n"], 1)

    def test_exhausts_then_reraises(self):
        with patch.object(oras.time, "sleep", lambda *_a: None):
            calls = {"n": 0}

            def _down(req, timeout=None):
                calls["n"] += 1
                raise _http_error(503)

            with (
                patch("urllib.request.urlopen", _down),
                self.assertRaises(urllib.error.HTTPError),
            ):
                oras._urlopen_retry("https://x/y", timeout=5)
            self.assertEqual(calls["n"], oras._RETRY_ATTEMPTS)


class TestFetchAnonymousToken(unittest.TestCase):
    def test_rides_through_transient_503(self):
        with patch.object(oras.time, "sleep", lambda *_a: None):
            calls = {"n": 0}

            def _flaky(req, timeout=None):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise _http_error(503)
                return _BytesResp(json.dumps({"token": "tok"}).encode())

            with patch("urllib.request.urlopen", _flaky):
                self.assertEqual(oras.fetch_anonymous_token("ghcr.io", "owner/repo"), "tok")
            self.assertEqual(calls["n"], 2)

    def test_discovers_realm_when_convention_fails(self):
        """Conventional <host>/token 404s -> read the /v2/ Bearer
        challenge's realm and fetch from there (Docker-Hub style)."""
        with patch.object(oras.time, "sleep", lambda *_a: None):
            realm = "https://auth.example.io/token"

            def _fake(req, timeout=None):
                url = req if isinstance(req, str) else req.full_url
                if url.startswith("https://reg.example.io/token"):
                    raise _http_error(404)
                if url == "https://reg.example.io/v2/":
                    raise urllib.error.HTTPError(
                        url,
                        401,
                        "unauthorized",
                        {"WWW-Authenticate": f'Bearer realm="{realm}",service="reg.example.io"'},  # type: ignore[arg-type]
                        None,
                    )
                if url.startswith(realm):
                    return _BytesResp(json.dumps({"token": "disc-tok"}).encode())
                raise AssertionError(f"unexpected URL in test: {url}")

            with patch("urllib.request.urlopen", _fake):
                self.assertEqual(
                    oras.fetch_anonymous_token("reg.example.io", "owner/repo"), "disc-tok"
                )


class TestParseWwwAuthenticate(unittest.TestCase):
    def test_bearer(self):
        params = oras.parse_www_authenticate(
            'Bearer realm="https://a/token",service="svc",scope="repository:x:pull"'
        )
        self.assertEqual(params["realm"], "https://a/token")
        self.assertEqual(params["service"], "svc")
        self.assertEqual(params["scope"], "repository:x:pull")

    def test_ignores_non_bearer(self):
        self.assertEqual(oras.parse_www_authenticate('Basic realm="x"'), {})
        self.assertEqual(oras.parse_www_authenticate(""), {})


# --------------------------------------------------------------------------
# Integration: Store.store_from_origin with a fetch_resolver
# --------------------------------------------------------------------------
_BLOB_PAYLOAD = b"oras-blob-bytes-" * 64  # 1 KiB


class _BlobOrigin(http.server.BaseHTTPRequestHandler):
    """Fake registry CDN: serves the blob bytes on any GET, no auth check."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(_BLOB_PAYLOAD)))
        self.end_headers()
        self.wfile.write(_BLOB_PAYLOAD)

    def log_message(self, format, *args):
        pass


class TestStoreFromOriginWithResolver(unittest.TestCase):
    """The contract that makes oras work end-to-end: the cache key is
    the original ``url`` (the ``oras://`` ref), but the actual HTTP
    request is sent to whatever the ``fetch_resolver`` callback hands
    back. A subsequent ``get_blob(oras_url)`` must hit -- not require
    re-resolving."""

    def setUp(self):
        self.httpd = socketserver.TCPServer(("127.0.0.1", 0), _BlobOrigin)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        self.store = server.Store(tempfile.mkdtemp(), keep_query=False)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_cache_key_is_oras_url_fetch_goes_through_resolver(self):
        oras_url = "oras://ghcr.io/safl/nosi/sample:latest"
        cdn_url = f"http://127.0.0.1:{self.port}/blobs/sha256:fake"

        calls = {"n": 0}

        def _resolver():
            calls["n"] += 1
            return cdn_url, {"Authorization": "Bearer test-bearer"}

        row = self.store.store_from_origin(oras_url, fetch_resolver=_resolver)
        self.assertEqual(row["size"], len(_BLOB_PAYLOAD))
        # Resolver called at least once (a clean fetch is one attempt).
        self.assertGreaterEqual(calls["n"], 1)
        # Cache key is bound to the oras:// ref, not the CDN URL.
        hit = self.store.get_blob(oras_url)
        self.assertIsNotNone(hit)
        # The CDN URL is NOT directly looked up: clients only know the oras ref.
        self.assertIsNone(self.store.get_blob(cdn_url))


if __name__ == "__main__":
    unittest.main()
