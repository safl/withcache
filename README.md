# fromcache

[![ci](https://github.com/safl/fromcache/actions/workflows/ci.yml/badge.svg)](https://github.com/safl/fromcache/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fromcache.svg)](https://pypi.org/project/fromcache/)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![built with Zig](https://img.shields.io/badge/built%20with-Zig%200.16.0-f7a41d.svg)](https://ziglang.org)
[![static musl](https://img.shields.io/badge/static%20musl-x86__64%20%7C%20aarch64-blue.svg)](https://github.com/safl/fromcache/releases)

A tiny, **operator-curated** artifact cache for a small lab — for the big vendor
downloads you re-pull constantly: CUDA, ROCm, DOCA, firmware, drivers — fronted
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
client CA — the URL is a lookup key, not a connection target.

Misses are **not** fetched automatically. An operator reviews the miss list in a
small web UI and presses **Download** (or pre-seeds via *Add from URI*); only
then does the cache-host pull from origin. So the cache-host is the only box that
needs internet egress (and any vendor credentials), and clients never write to it.

## Why not just curl + a caching proxy?

For `https://` (i.e. every vendor download) a forward proxy can't cache without
**SSL-bump / MITM** — curl tunnels TLS end-to-end via `CONNECT`, so the proxy
only sees ciphertext. The shim sidesteps that entirely by *re-pointing the URL*
to the cache instead of intercepting the connection. And no proxy offers the
**operator-curated** model (a miss queue a human approves).

## Components

| Path                          | What it is                                                  |
|-------------------------------|-------------------------------------------------------------|
| `src/fromcache/server.py`     | The cache-host: blob store + miss table + **background download manager** + operator UI (Pico.css + HTMX) |
| `src/fromcache/_shim.py`      | Shared shim core (find URL → probe → rewrite → exec)        |
| `src/fromcache/curlfromcache.py` | The `curl` shim                                          |
| `src/fromcache/wgetfromcache.py` | The `wget` shim                                          |
| `deploy/Containerfile`, `deploy/compose.yml` | Single Podman/Docker host deploy             |

Everything is **stdlib-only Python** — no third-party runtime dependencies.

## Install

```sh
pip install fromcache    # provides: curlfromcache  wgetfromcache  fromcache-server
```

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

Point at the cache-host, then put the shims earlier on `$PATH` as `curl`/`wget`
(a symlink to the installed command is the recommended install):

```sh
export FROMCACHE_SERVER=http://fromcache-server:3000

mkdir -p ~/.fromcache/bin
ln -s "$(command -v curlfromcache)" ~/.fromcache/bin/curl
ln -s "$(command -v wgetfromcache)" ~/.fromcache/bin/wget
export PATH="$HOME/.fromcache/bin:$PATH"

# now existing scripts are transparently cached — no changes:
curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz
wget https://the/origin/rocm.tar.gz                       # still saved as rocm.tar.gz
```

How it works — the shim **scans for the URL, asks the cache, and execs the real tool**:

1. Find the real `curl`/`wget` on `$PATH` (skipping itself; `$REAL_CURL`/`$REAL_WGET` override).
2. With `FROMCACHE_SERVER` set, find the URL (the `scheme://` arg, or `--url`).
3. Probe the cache with that same tool (`curl -I` / `wget --spider`).
   - **Hit** → re-point only the URL at `http://server/b/<base64(origin)>/<basename>` and `exec` the real tool (so `-o`, `-O`, `-L`, `--retry`, … all still apply, and the file is named after the artifact).
   - **Miss / unreachable** → `exec` the real tool with your **arguments untouched** (origin); the miss is recorded for the operator.
4. With no `FROMCACHE_SERVER`, it does **zero** network/parsing — just `exec`s the real tool.

Notes & limits (all degrade gracefully — worst case is "no caching, curl still works"):
- Needs the wrapped tool present (it shims it). Adds ~Python-startup latency per call.
- URLs hidden in a `-K`/`-i` config file or piped via stdin aren't seen → those calls pass through uncached.
- Per-tool env override: `CURLFROMCACHE_SERVER` / `WGETFROMCACHE_SERVER` beat `FROMCACHE_SERVER`.

## Operator UI

`http://fromcache-server:3000/` (Pico.css + HTMX, bundled offline) shows:
- **Misses** — each with **Download** (queues a background pull) and **Dismiss**.
- **Downloads** — live progress bars, `queued/running/completed/cancelled/failed`, **Cancel**, and **Clear finished**. Downloads run in a background worker pool, not in the request, so large pulls never block — modelled on [bty]'s job managers.
- **Cached artifacts** — URL, size, SHA-256, fetched-at.
- **Add from URI** — pre-seed an artifact before anyone misses it.

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
