"""Hatchling build hook: ship the shim command (curlfromcache / wgetfromcache).

On a wheel build it installs, into the wheel's scripts dir (-> bin/):
  * the native Zig binary, if `zig` is available -> a platform wheel; or
  * a tiny Python launcher into fromcache.{curl,wget}fromcache -> a pure wheel.

So `curlfromcache`/`wgetfromcache` resolve to the native binary where we built
one, and to the Python shim (the tested oracle/fallback) everywhere else —
under the same command name, with no console-script/binary collision.

CI sets these per target; both default sensibly for a local build:
  FROMCACHE_ZIG_TARGET   e.g. x86_64-linux-musl   (unset => native, dynamic)
  FROMCACHE_WHEEL_TAG    e.g. py3-none-manylinux2014_x86_64  (unset => native)
  ZIG                    path to zig               (unset => found on PATH)
"""

import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

ROOT = os.path.dirname(os.path.abspath(__file__))
SHIM_DIR = os.path.join(ROOT, "shim")
NAMES = ("curlfromcache", "wgetfromcache")


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        if self.target_name != "wheel":
            return

        tmp = tempfile.mkdtemp(prefix="fromcache-shim-")
        binary = self._build_native()

        scripts = {}
        if binary:
            for name in NAMES:
                dst = os.path.join(tmp, name)
                shutil.copy2(binary, dst)
                os.chmod(dst, 0o755)
                scripts[dst] = name
            build_data["pure_python"] = False
            build_data["tag"] = os.environ.get("FROMCACHE_WHEEL_TAG") or self._native_tag()
            self._log(f"bundling native shim -> {build_data['tag']}")
        else:
            for name in NAMES:
                dst = os.path.join(tmp, name)
                with open(dst, "w") as f:
                    f.write(self._launcher(name))
                os.chmod(dst, 0o755)
                scripts[dst] = name
            self._log("zig not available -> Python launcher scripts (pure wheel)")

        build_data["shared_scripts"] = scripts

    # -- helpers ------------------------------------------------------------
    def _build_native(self):
        zig = os.environ.get("ZIG") or shutil.which("zig")
        if not zig or not os.path.isdir(SHIM_DIR):
            return None
        cmd = [zig, "build", "-Doptimize=ReleaseSmall"]
        target = os.environ.get("FROMCACHE_ZIG_TARGET")
        if target:
            cmd += [f"-Dtarget={target}", "-Dstatic"]
        try:
            subprocess.run(cmd, cwd=SHIM_DIR, check=True)
        except (OSError, subprocess.CalledProcessError) as e:
            self._log(f"zig build failed ({e}); falling back to Python launchers")
            return None
        out = os.path.join(SHIM_DIR, "zig-out", "bin", "fromcache-shim")
        return out if os.path.exists(out) else None

    @staticmethod
    def _native_tag():
        plat = sysconfig.get_platform().replace("-", "_").replace(".", "_")
        return f"py3-none-{plat}"

    @staticmethod
    def _launcher(name):
        tool = "wget" if "wget" in name else "curl"
        return (
            "#!/usr/bin/env python3\n"
            f"import sys\nfrom fromcache.{tool}fromcache import main\n"
            "sys.exit(main())\n"
        )

    def _log(self, msg):
        sys.stderr.write(f"fromcache build hook: {msg}\n")
