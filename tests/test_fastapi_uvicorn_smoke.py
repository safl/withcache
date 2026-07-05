"""Uvicorn boot smoke test for the v0.9.0 runtime cut-over.

TestClient tests exercise the FastAPI app in-process. This test
proves the runtime path actually works: boot the app under
uvicorn in a subprocess (matching what ``server.main`` does),
verify /healthz returns 200 + expected JSON, verify /ui/login
renders, then send SIGTERM and confirm the process exits cleanly.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _find_free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_http(url: str, *, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:  # noqa: S310
                if resp.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_err = exc
        time.sleep(0.1)
    raise TimeoutError(f"{url!r} did not respond 200 within {timeout}s: {last_err}")


class UvicornRuntimeSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._port = _find_free_port()
        env = os.environ.copy()
        env.pop("WITHCACHE_ADMIN_PASSWORD", None)
        env.pop("WITHCACHE_CATALOG_URL", None)
        self._env = env

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _spawn(self) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "withcache.server",
                "--host",
                "127.0.0.1",
                "--port",
                str(self._port),
                "--data-dir",
                self._tmpdir,
            ],
            env=self._env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_uvicorn_boot_healthz_then_sigterm(self) -> None:
        """Full runtime lifecycle: boot -> serve /healthz + /ui/login
        -> SIGTERM -> clean exit. Proves the FastAPI lifespan hook
        wires DownloadManager start/stop correctly, uvicorn is
        actually being launched, and the routes registered under
        create_app are reachable from an out-of-process client."""
        proc = self._spawn()
        try:
            _wait_for_http(f"http://127.0.0.1:{self._port}/healthz", timeout=15.0)
            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{self._port}/healthz", timeout=2.0
            ) as resp:
                body = json.loads(resp.read())
            self.assertEqual(body["status"], "ok")
            self.assertEqual(body["service"], "withcache")
            self.assertIn("version", body)

            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{self._port}/ui/login", timeout=2.0
            ) as resp:
                page = resp.read().decode("utf-8")
            self.assertIn("Log in", page)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
        self.assertIn(proc.returncode, (0, -15))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
