"""Differential test: the Python plan() oracle and the native Zig shim MUST
produce identical argv rewrites. This is what lets the Python implementation
stay a trustworthy fallback — it can't silently drift from the binary.

Skipped when the Zig binary isn't built (set WITHCACHE_SHIM or run `zig build`
in ../shim). Run with:  python -m unittest -v
"""

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from withcache import _shim  # noqa: E402

SHIM = os.environ.get(
    "WITHCACHE_SHIM", os.path.join(HERE, "..", "shim", "zig-out", "bin", "withcache-shim")
)

# Each case is run through both implementations, as both curl and wget, hit+miss.
CORPUS = [
    ["-fsSL", "https://h/p/cuda.tar.gz", "-o", "out"],
    ["--url=https://h/y", "-O"],
    ["-H", "Referer: https://ref.example", "https://real/target.bin"],
    ["https://h/z"],
    ["--version"],  # no URL -> unchanged, no probe
]


@unittest.skipUnless(os.path.exists(SHIM) and os.access(SHIM, os.X_OK), "zig shim not built")
class TestDifferential(unittest.TestCase):
    def _mkfake(self, probe_exit):
        # A fake tool: as a probe (-I / --spider) it exits with a baked-in code
        # (the probe runs with a clean env, so this can't depend on $VARS);
        # otherwise (the real exec) it prints its argv — the final command the
        # shim chose to run.
        p = os.path.join(self.d, f"fake{probe_exit}")
        with open(p, "w") as f:
            f.write(
                "#!/bin/sh\n"
                f'for a in "$@"; do case "$a" in -I|--spider) exit {probe_exit};; esac; done\n'
                'for a in "$@"; do printf "%s\\n" "$a"; done\n'
            )
        os.chmod(p, 0o755)
        return p

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.fake_hit = self._mkfake(0)
        self.fake_miss = self._mkfake(1)
        for name in ("curl", "wget"):
            os.symlink(SHIM, os.path.join(self.d, name))
        self._saved = {
            k: os.environ.get(k)
            for k in (
                "WITHCACHE_SERVER",
                "REAL_CURL",
                "REAL_WGET",
                "CURLWITHCACHE_SERVER",
                "WGETWITHCACHE_SERVER",
            )
        }
        os.environ["WITHCACHE_SERVER"] = "http://cache:3000"
        os.environ["REAL_CURL"] = self.fake_hit  # Python find_real just needs an exe
        os.environ["REAL_WGET"] = self.fake_hit
        os.environ.pop("CURLWITHCACHE_SERVER", None)
        os.environ.pop("WGETWITHCACHE_SERVER", None)

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

    def _zig(self, name, argv, hit):
        fake = self.fake_hit if hit else self.fake_miss
        env = dict(os.environ, REAL_CURL=fake, REAL_WGET=fake)
        r = subprocess.run(
            [os.path.join(self.d, name), *argv],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return r.stdout.splitlines()

    def _py(self, name, argv, hit):
        _, final = _shim.plan(name, lambda r, u: hit, argv)
        return final

    def test_rewrites_match_oracle(self):
        for name in ("curl", "wget"):
            for argv in CORPUS:
                for hit in (True, False):
                    with self.subTest(tool=name, argv=argv, hit=hit):
                        self.assertEqual(self._zig(name, argv, hit), self._py(name, argv, hit))


if __name__ == "__main__":
    unittest.main(verbosity=2)
