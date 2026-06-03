# fromcache

[![ci](https://github.com/safl/fromcache/actions/workflows/ci.yml/badge.svg)](https://github.com/safl/fromcache/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fromcache.svg)](https://pypi.org/project/fromcache/)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![built with Zig](https://img.shields.io/badge/built%20with-Zig%200.16.0-f7a41d.svg)](https://ziglang.org)
[![static musl](https://img.shields.io/badge/static%20musl-x86__64%20%7C%20aarch64-blue.svg)](https://github.com/safl/fromcache/releases)

A tiny, **operator-curated** artifact cache for a small lab, for the big vendor
downloads you re-pull constantly (CUDA, ROCm, DOCA, firmware, drivers), fronted
by **transparent `curl`/`wget` shims** so existing scripts use it with no changes.

Think of it as **"`ccache` for HTTP artifacts, without a proxy."**

```
curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz     # your script, unchanged
   └─ curlfromcache shim ─ FROMCACHE_SERVER set?
        ├─ cached  → served from the cache-host (fast, local)
        └─ miss/unset/unreachable → runs the real curl, exactly as written
```

Artifacts are cached **by their origin URL as a key**; the shim opts in by
re-pointing the URL at the cache. No transparent proxy, no TLS interception, no
client CA. The URL is a lookup key, not a connection target.

Misses are **not** fetched automatically. An operator reviews the miss list in a
small web UI and presses **Download** (or pre-seeds via *Add from URI*); only
then does the cache-host pull from origin. So the cache-host is the only box that
needs internet egress (and any vendor credentials), and clients never write to it.

## Why not just curl + a caching proxy?

For `https://` (i.e. every vendor download) a forward proxy can't cache without
**SSL-bump / MITM**: curl tunnels TLS end-to-end via `CONNECT`, so the proxy
only sees ciphertext. The shim sidesteps that entirely by *re-pointing the URL*
to the cache instead of intercepting the connection. And no proxy offers the
**operator-curated** model (a miss queue a human approves).

## Components

| Path                          | What it is                                                  |
|-------------------------------|-------------------------------------------------------------|
| `src/fromcache/server.py`     | The cache-host: blob store + miss table + **background download manager** + operator UI (Pico.css + HTMX) |
| `src/fromcache/_shim.py`      | Shared shim core (find URL → probe → rewrite → exec)        |
| `src/fromcache/curlfromcache.py` / `wgetfromcache.py` | The Python `curl` / `wget` shims    |
| `shim/shim.zig`               | The native shim: one static binary, both tools via `argv[0]` |
| `deploy/Containerfile`, `deploy/compose.yml` | Single Podman/Docker host deploy             |

The cache-host and the Python shims are **stdlib-only** (no third-party runtime
deps); the native shim is a dependency-free static binary.

## Install

The **cache-host** and **Python shims** (works on any box with Python):

```sh
pipx install fromcache    # or: uv tool install fromcache  /  pip install fromcache
# provides: curlfromcache  wgetfromcache  fromcache-server
```

The **native shim** (no Python needed, for minimal/distroless boxes; ~200 KB
static musl binary). Grab it from the [Releases] page; one binary serves both
tools by the name it's invoked as:

```sh
curl -L .../releases/.../fromcache-shim-x86_64-linux-musl -o /usr/local/bin/curlfromcache
chmod +x /usr/local/bin/curlfromcache
```

The Python shim is also the tested **oracle** and install-time fallback for
platforms without a prebuilt binary; a [differential test](tests/test_differential.py)
asserts the binary and the Python `plan()` rewrite argv identically.

[Releases]: https://github.com/safl/fromcache/releases
[direnv]: https://direnv.net

## Deploy the cache-host

```sh
export FROMCACHE_ADMIN_PASSWORD=change-me    # protects the operator UI
podman compose -f deploy/compose.yml up -d   # or: docker compose -f ...
# operator UI:  http://fromcache-server:3000/
```

Or without containers:

```sh
FROMCACHE_ADMIN_PASSWORD=change-me fromcache-server --data-dir ./data --port 3000
```

Data (blobs + `cache.db` + `session-secret`) lives in the `/data` volume (or
`--data-dir`). Artifacts are immutable per version, so there's no cache
invalidation. `--workers N` sets the number of concurrent download workers.

## Use the shims (transparent `curl` / `wget`)

Every approach is the same two ingredients: (1) point at the cache with
`FROMCACHE_SERVER`, and (2) make `curl`/`wget` resolve to the shim. They differ
only in **how widely the system `curl`/`wget` is shadowed**. Pick the least
invasive one that fits.

> **Safety:** with `FROMCACHE_SERVER` unset the shim is a pure pass-through (it
> just `exec`s the real tool, zero network/parsing), so even the system-wide
> setup is harmless wherever the cache isn't configured. Worst case is always
> "no caching, `curl` still works."

These all use `command -v curlfromcache`, so they work whether you installed the
native binary or the Python launcher (both land under that name).

### 1. No shadowing: call the shims by name (least invasive)

Nothing is renamed; you opt in per command. Good for trying it out or a script
you can edit.

```sh
export FROMCACHE_SERVER=http://fromcache-server:3000
curlfromcache -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz
wgetfromcache https://the/origin/rocm.tar.gz
```

### 2. This shell only: shadow `curl`/`wget` for the session

Put `curl`/`wget` symlinks in a dir and prepend it to `PATH` in the current
shell. Reversible by just closing the shell.

```sh
mkdir -p ~/.fromcache/bin
ln -sf "$(command -v curlfromcache)" ~/.fromcache/bin/curl
ln -sf "$(command -v wgetfromcache)" ~/.fromcache/bin/wget

export FROMCACHE_SERVER=http://fromcache-server:3000
export PATH="$HOME/.fromcache/bin:$PATH"
hash -r                       # forget any cached curl/wget location

command -v curl               # -> ~/.fromcache/bin/curl  (verify it's the shim)
curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz   # existing scripts, unchanged
wget https://the/origin/rocm.tar.gz                        # still saved as rocm.tar.gz
```

### 3. Your user: make it the default for your shells (persistent)

Create the symlinks once, then add the two exports to your shell rc. Affects all
your future interactive shells; undo by deleting the block.

```sh
mkdir -p ~/.fromcache/bin
ln -sf "$(command -v curlfromcache)" ~/.fromcache/bin/curl
ln -sf "$(command -v wgetfromcache)" ~/.fromcache/bin/wget

cat >> ~/.bashrc <<'EOF'

# fromcache: transparent curl/wget caching
export FROMCACHE_SERVER=http://fromcache-server:3000
export PATH="$HOME/.fromcache/bin:$PATH"
EOF
```

### 4. One project only: scope it with direnv

Drop an `.envrc` in a project tree (requires [direnv]); caching applies only
inside that directory.

```sh
# .envrc
export FROMCACHE_SERVER=http://fromcache-server:3000
PATH_add ~/.fromcache/bin        # assumes the symlinks from approach 2/3 exist
```

Then `direnv allow`.

### 5. The whole machine: every user, every shell (most invasive)

Install the shim as `curl`/`wget` in `/usr/local/bin` (ahead of `/usr/bin` on
the default `PATH`) and set the server globally. This also catches build tools
and package managers that shell out to `curl`/`wget`.

```sh
sudo ln -sf "$(command -v curlfromcache)" /usr/local/bin/curl
sudo ln -sf "$(command -v wgetfromcache)" /usr/local/bin/wget

# A login-shell env file (covers interactive logins; daemons started outside a
# login shell won't see it; set FROMCACHE_SERVER in their unit if you need it).
echo 'export FROMCACHE_SERVER=http://fromcache-server:3000' \
  | sudo tee /etc/profile.d/fromcache.sh >/dev/null
```

On minimal/distroless hosts use the [native shim binary](#install) here: same
symlink, no Python required.

### Verify / turn it off

```sh
command -v curl                       # which curl is in effect (the shim, or the real one)
export REAL_CURL=/usr/bin/curl        # optional: pin the wrapped tool (also $REAL_WGET)

unset FROMCACHE_SERVER                 # instantly back to plain curl (pass-through)
rm ~/.fromcache/bin/curl ~/.fromcache/bin/wget   # remove shadowing entirely
```

How it works: the shim **scans for the URL, asks the cache, and execs the real tool**:

1. Find the real `curl`/`wget` on `$PATH` (skipping itself; `$REAL_CURL`/`$REAL_WGET` override).
2. With `FROMCACHE_SERVER` set, find the URL (the `scheme://` arg, or `--url`).
3. Probe the cache with that same tool (`curl -I` / `wget --spider`).
   - **Hit** → re-point only the URL at `http://server/b/<base64(origin)>/<basename>` and `exec` the real tool (so `-o`, `-O`, `-L`, `--retry`, … all still apply, and the file is named after the artifact).
   - **Miss / unreachable** → `exec` the real tool with your **arguments untouched** (origin); the miss is recorded for the operator.
4. With no `FROMCACHE_SERVER`, it does **zero** network/parsing, just `exec`s the real tool.

Notes & limits (all degrade gracefully; worst case is "no caching, curl still works"):
- Needs the wrapped tool present (it shims it). Adds ~Python-startup latency per call.
- URLs hidden in a `-K`/`-i` config file or piped via stdin aren't seen → those calls pass through uncached.
- Per-tool env override: `CURLFROMCACHE_SERVER` / `WGETFROMCACHE_SERVER` beat `FROMCACHE_SERVER`.

## Operator UI

`http://fromcache-server:3000/` (Pico.css + HTMX, bundled offline) shows:
- **Misses**: each with **Download** (queues a background pull) and **Dismiss**.
- **Downloads**: live progress bars, `queued/running/completed/cancelled/failed`, **Cancel**, and **Clear finished**. Downloads run in a background worker pool, not in the request, so large pulls never block, modelled on [bty]'s job managers.
- **Cached artifacts**: URL, size, **hits** (times served) and **misses** (times requested before it was cached), SHA-256, fetched-at.
- **Add from URI**: pre-seed an artifact before anyone misses it.

## Auth

Single-tenant session-cookie auth (modelled on [bty]'s approach, env password
instead of PAM). The **read path** (`/blob`, `/b/…`, `/healthz`) is open so shims
never log in; the **operator surface** (`/`, `/admin/*`) is gated.

| Env var                    | Purpose                                                  |
|----------------------------|----------------------------------------------------------|
| `FROMCACHE_SERVER`         | Cache-host URL the shims use                             |
| `CURLFROMCACHE_SERVER` / `WGETFROMCACHE_SERVER` | Per-tool override of the above       |
| `FROMCACHE_ADMIN_PASSWORD` | Operator login password (unset ⇒ UI open, with a warning) |
| `FROMCACHE_SESSION_SECRET` | Override the persisted cookie-signing key (optional)     |

[bty]: https://github.com/safl/bty

## Cache keys & signed URLs

The key is `scheme://host/path` with the **query string dropped** by default, so
CDN/presigned URLs (whose tokens change every request) still match by path. Pass
`--keep-query` to the server for query-sensitive keys. Package-manager repos
(`.deb`/`.rpm`) are GPG-signed and verified by the client regardless of
transport, so caching them this way is safe.

## Tests

```sh
python -m unittest discover -s tests   # stdlib only, no test deps
```
