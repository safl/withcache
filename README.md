# withcache

[![ci](https://github.com/safl/withcache/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/safl/withcache/actions/workflows/ci-cd.yml)
[![PyPI](https://img.shields.io/pypi/v/withcache.svg)](https://pypi.org/project/withcache/)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![built with Zig](https://img.shields.io/badge/built%20with-Zig%200.16.0-f7a41d.svg)](https://ziglang.org)
[![static musl](https://img.shields.io/badge/static%20musl-x86__64%20%7C%20aarch64-blue.svg)](https://github.com/safl/withcache/releases)

A tiny, **operator-curated** artifact cache for a small lab, for the big vendor
downloads you re-pull constantly (CUDA, ROCm, DOCA, firmware, drivers), fronted
by **transparent `curl`/`wget` shims** so existing scripts use it with no changes.

Think of it as **"`ccache` for HTTP artifacts, without a proxy."**

```
curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz     # your script, unchanged
   └─ curlwithcache shim ─ WITHCACHE_SERVER set?
        ├─ cached  → served from the cache-host (fast, local)
        └─ miss/unset/unreachable → runs the real curl, exactly as written
```

Artifacts are cached **by their origin URL as a key**; the shim opts in by
re-pointing the URL at the cache. No transparent proxy, no TLS interception, no
client CA. The URL is a lookup key, not a connection target.

A miss falls through to origin (the caller gets its file straight away) and
withcache records the miss on the operator's **`/ui/misses`** page. The operator
reviews the miss list, picks what's worth caching, and one click **Fetch**s a URL
into the catalog + downloads it. Every entry in the catalog is a byte-perfect
copy of the origin at the time the operator hit Download; subsequent requests
hit the local cache. The cache-host is the only box that needs internet egress
(and any vendor credentials); clients never write to it.

## Why not just curl + a caching proxy?

For `https://` (i.e. every vendor download) a forward proxy can't cache without
**SSL-bump / MITM**: curl tunnels TLS end-to-end via `CONNECT`, so the proxy
only sees ciphertext. The shim sidesteps that entirely by *re-pointing the URL*
to the cache instead of intercepting the connection. And a proxy that
auto-fetches everything a client asks for isn't what you want in a lab; the
**operator-curated** model here means only bytes the operator chose live on
disk.

## Components

| Path                          | What it is                                                  |
|-------------------------------|-------------------------------------------------------------|
| `src/withcache/server.py`     | The cache-host: blob store + miss table + **background download manager** + operator UI (Bootstrap 5 + Bootstrap Icons + HTMX) |
| `src/withcache/_shim.py`      | Shared shim core (find URL → probe → rewrite → exec)        |
| `src/withcache/curlwithcache.py` / `wgetwithcache.py` | The Python `curl` / `wget` shims    |
| `shim/shim.zig`               | The native shim: one static binary, both tools via `argv[0]` |
| `deploy/Containerfile`, `deploy/compose.yml` | Single Podman/Docker host deploy             |

The cache-host and the Python shims are **stdlib-only** (no third-party runtime
deps); the native shim is a dependency-free static binary.

## Install

The **cache-host** and **Python shims** (works on any box with Python):

```sh
pipx install withcache    # or: uv tool install withcache  /  pip install withcache
# provides: curlwithcache  wgetwithcache  withcache-server
```

The **native shim** (no Python needed, for minimal/distroless boxes; ~200 KB
static musl binary). Grab it from the [Releases] page; one binary serves both
tools by the name it's invoked as:

```sh
curl -L .../releases/.../withcache-shim-x86_64-linux-musl -o /usr/local/bin/curlwithcache
chmod +x /usr/local/bin/curlwithcache
```

The Python shim is also the tested **oracle** and install-time fallback for
platforms without a prebuilt binary; a [differential test](tests/test_differential.py)
asserts the binary and the Python `plan()` rewrite argv identically.

[Releases]: https://github.com/safl/withcache/releases
[direnv]: https://direnv.net

## Deploy the cache-host

```sh
export WITHCACHE_ADMIN_PASSWORD=change-me    # protects the operator UI
podman compose -f deploy/compose.yml up -d   # or: docker compose -f ...
# operator UI:  http://withcache-server:8081/
```

Or without containers:

```sh
WITHCACHE_ADMIN_PASSWORD=change-me withcache-server --data-dir ./data --port 8081
```

Data (blobs + `cache.db` + `session-secret`) lives in the `/data` volume (or
`--data-dir`). Artifacts are immutable per version, so there's no cache
invalidation. `--workers N` sets the number of concurrent download workers,
`--max-bytes` (e.g. `50G`) caps the cache: when full it refuses new fills (no
auto-eviction), and you free space by deleting artifacts in the UI.

## Use the shims (transparent `curl` / `wget`)

Every approach is the same two ingredients: (1) point at the cache with
`WITHCACHE_SERVER`, and (2) make `curl`/`wget` resolve to the shim. They differ
only in **how widely the system `curl`/`wget` is shadowed**. Pick the least
invasive one that fits.

> **Safety:** with `WITHCACHE_SERVER` unset the shim is a pure pass-through (it
> just `exec`s the real tool, zero network/parsing), so even the system-wide
> setup is harmless wherever the cache isn't configured. Worst case is always
> "no caching, `curl` still works."

These all use `command -v curlwithcache`, so they work whether you installed the
native binary or the Python launcher (both land under that name).

### 1. No shadowing: call the shims by name (least invasive)

Nothing is renamed; you opt in per command. Good for trying it out or a script
you can edit.

```sh
export WITHCACHE_SERVER=http://withcache-server:8081
curlwithcache -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz
wgetwithcache https://the/origin/rocm.tar.gz
```

### 2. This shell only: shadow `curl`/`wget` for the session

Put `curl`/`wget` symlinks in a dir and prepend it to `PATH` in the current
shell. Reversible by just closing the shell.

```sh
mkdir -p ~/.withcache/bin
ln -sf "$(command -v curlwithcache)" ~/.withcache/bin/curl
ln -sf "$(command -v wgetwithcache)" ~/.withcache/bin/wget

export WITHCACHE_SERVER=http://withcache-server:8081
export PATH="$HOME/.withcache/bin:$PATH"
hash -r                       # forget any cached curl/wget location

command -v curl               # -> ~/.withcache/bin/curl  (verify it's the shim)
curl -fsSL https://the/origin/cuda.tar.gz -o cuda.tar.gz   # existing scripts, unchanged
wget https://the/origin/rocm.tar.gz                        # still saved as rocm.tar.gz
```

### 3. Your user: make it the default for your shells (persistent)

Create the symlinks once, then add the two exports to your shell rc. Affects all
your future interactive shells; undo by deleting the block.

```sh
mkdir -p ~/.withcache/bin
ln -sf "$(command -v curlwithcache)" ~/.withcache/bin/curl
ln -sf "$(command -v wgetwithcache)" ~/.withcache/bin/wget

cat >> ~/.bashrc <<'EOF'

# withcache: transparent curl/wget caching
export WITHCACHE_SERVER=http://withcache-server:8081
export PATH="$HOME/.withcache/bin:$PATH"
EOF
```

### 4. One project only: scope it with direnv

Drop an `.envrc` in a project tree (requires [direnv]); caching applies only
inside that directory.

```sh
# .envrc
export WITHCACHE_SERVER=http://withcache-server:8081
PATH_add ~/.withcache/bin        # assumes the symlinks from approach 2/3 exist
```

Then `direnv allow`.

### 5. The whole machine: every user, every shell (most invasive)

Install the shim as `curl`/`wget` in `/usr/local/bin` (ahead of `/usr/bin` on
the default `PATH`) and set the server globally. This also catches build tools
and package managers that shell out to `curl`/`wget`.

```sh
sudo ln -sf "$(command -v curlwithcache)" /usr/local/bin/curl
sudo ln -sf "$(command -v wgetwithcache)" /usr/local/bin/wget

# A login-shell env file (covers interactive logins; daemons started outside a
# login shell won't see it; set WITHCACHE_SERVER in their unit if you need it).
echo 'export WITHCACHE_SERVER=http://withcache-server:8081' \
  | sudo tee /etc/profile.d/withcache.sh >/dev/null
```

On minimal/distroless hosts use the [native shim binary](#install) here: same
symlink, no Python required.

### Verify / turn it off

```sh
command -v curl                       # which curl is in effect (the shim, or the real one)
export REAL_CURL=/usr/bin/curl        # optional: pin the wrapped tool (also $REAL_WGET)

unset WITHCACHE_SERVER                 # instantly back to plain curl (pass-through)
rm ~/.withcache/bin/curl ~/.withcache/bin/wget   # remove shadowing entirely
```

How it works: the shim **scans for the URL, asks the cache, and execs the real tool**:

1. Find the real `curl`/`wget` on `$PATH` (skipping itself; `$REAL_CURL`/`$REAL_WGET` override).
2. With `WITHCACHE_SERVER` set, find the URL (the `scheme://` arg, or `--url`).
3. Probe the cache with that same tool (`curl -I` / `wget --spider`).
   - **Hit** → re-point only the URL at `http://server/b/<base64(origin)>/<basename>` and `exec` the real tool (so `-o`, `-O`, `-L`, `--retry`, … all still apply, and the file is named after the artifact).
   - **Miss / unreachable** → `exec` the real tool with your **arguments untouched** (origin); the miss is recorded for the operator.
4. With no `WITHCACHE_SERVER`, it does **zero** network/parsing, just `exec`s the real tool.

Notes & limits (all degrade gracefully; worst case is "no caching, curl still works"):
- Needs the wrapped tool present (it shims it). Adds ~Python-startup latency per call.
- URLs hidden in a `-K`/`-i` config file or piped via stdin aren't seen → those calls pass through uncached.
- Per-tool env override: `CURLWITHCACHE_SERVER` / `WGETWITHCACHE_SERVER` beat `WITHCACHE_SERVER`.

## Operator UI

`http://withcache-server:8081/` (Bootstrap 5 + Bootstrap Icons + HTMX, bundled
offline; matches bty's chrome for a consistent trio) is a five-page dashboard:
- **Dashboard** (landing): catalog + cache + activity summary, health checklist, and the last N audit events.
- **Catalog**: image catalog fetched from a nosi-style `catalog.toml` (URL configured on Settings > Catalog source). Add entries via the subnav's inline "Add ORAS" / "Add HTTPS" forms or "Fetch default" button, then **Download** each entry. Rows carry hits, size, download progress (live), and cached/failed pills.
- **Misses**: URLs clients asked for that aren't downloaded yet. Each with **Fetch** (promotes to a catalog entry AND downloads it) and **Dismiss** (forget it).
- **Events**: append-only audit log with a free-text filter and per-page pagination. Failure rows carry an ack button; the dashboard's Health tripwire flags unacknowledged failures.
- **Settings**: identity + storage paths + catalog source (editable) + logging (uvicorn level) + auth.

## Auth

Single-tenant session-cookie auth (modelled on [bty]'s approach, env password
instead of PAM). The **read path** (`/blob`, `/b/…`, `/healthz`) is open so shims
never log in; the **operator surface** (`/`, `/admin/*`) is gated.

| Env var                    | Purpose                                                  |
|----------------------------|----------------------------------------------------------|
| `WITHCACHE_SERVER`         | Cache-host URL the shims use                             |
| `CURLWITHCACHE_SERVER` / `WGETWITHCACHE_SERVER` | Per-tool override of the above       |
| `WITHCACHE_ADMIN_PASSWORD` | Operator login password (unset ⇒ UI open, with a warning) |
| `WITHCACHE_SESSION_SECRET` | Override the persisted cookie-signing key (optional)     |
| `WITHCACHE_CATALOG_URL`    | Pin the image-catalog URL; env value beats the /admin/catalog_set_url override so a locked-down deploy stays locked (optional) |

[bty]: https://github.com/safl/bty

## Cache keys & signed URLs

The key is `scheme://host/path` with the **query string dropped** by default, so
CDN/presigned URLs (whose tokens change every request) still match by path. Pass
`--keep-query` to the server for query-sensitive keys. Package-manager repos
(`.deb`/`.rpm`) are GPG-signed and verified by the client regardless of
transport, so caching them this way is safe.

## Consume from another tool (the client library)

A tool that already knows its download URLs (e.g. an installer or a provisioner)
can prefer the cache without shelling out to a shim or re-implementing the `/b/`
scheme. `withcache.client` is stdlib-only, so importing it adds no dependencies:

```python
from withcache import client

# "use the cache when it's warm, the origin otherwise"
url = client.serve_url("http://cache:8081", origin) or origin
```

`is_cached()` is a graceful `HEAD` (a miss, timeout, or unreachable cache all
return `False`, so you fall back to the origin). Since v0.10.0 a miss is
recorded on the cache-host's `/ui/misses` page but no background fetch fires
-- the operator explicitly chooses what to Download. The encoding is shared
with the shims and server, so consumers stay in lockstep with the cache-host.

### Pull an `oras://` artifact (oras + client together)

For a registry blob, pair `withcache.oras` (resolve the reference to a blob URL
+ bearer) with `client.serve_url` (prefer the cache when warm). A runnable
example is in [`examples/pull_oras_blob.py`](examples/pull_oras_blob.py):

```python
from withcache import client, oras

resolved = oras.resolve_ref("oras://ghcr.io/<owner>/<repo>@sha256:<digest>")
url, headers = resolved.blob_url, dict(resolved.headers)
url = client.serve_url(server, url, headers=headers) or url   # cache when warm
```

## Tests

```sh
python -m unittest discover -s tests   # stdlib only, no test deps
```
