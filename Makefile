# withcache — common tasks (and the home of the CI logic: the GitHub workflows
# call these targets, so everything CI does is reproducible locally).
# Run `make` for the list. Override vars on the CLI, e.g.
#   make serve PORT=8081            make bump VERSION=0.2.0
#   make wheel-one ZTARGET=x86_64-linux-musl WTAG=py3-none-musllinux_1_2_x86_64
PYTHON    ?= python3
RUFF      ?= ruff
PRECOMMIT ?= pre-commit
ZIG       ?= zig
PORT      ?= 8081
# Containerized deploy: prefer podman, fall back to docker.
COMPOSE   ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker) compose
COMPOSE_FILE = deploy/compose.yml

# Single source of truth = src/withcache/__init__.py; pyproject derives it via
# Hatch. Zig forces a literal in build.zig.zon, so we mirror it there and guard
# against drift with `version-check`.
SRC_VERSION = $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/withcache/__init__.py)
ZON_VERSION = $(shell sed -n 's/^[[:space:]]*\.version = "\(.*\)",/\1/p' shim/build.zig.zon)

# Platform wheels: one static-musl binary per arch, tagged for glibc + musl.
WHEEL_MATRIX = \
	x86_64-linux-musl:py3-none-manylinux_2_17_x86_64 \
	x86_64-linux-musl:py3-none-musllinux_1_2_x86_64 \
	aarch64-linux-musl:py3-none-manylinux_2_17_aarch64 \
	aarch64-linux-musl:py3-none-musllinux_1_2_aarch64
BIN_TARGETS = x86_64-linux-musl aarch64-linux-musl

.DEFAULT_GOAL := help
.PHONY: help dev hooks-install hooks lint format format-check test shim \
        shim-target shim-static binaries wheel wheel-one wheel-pure wheels serve \
        up down logs version version-check bump check clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# -- dev setup -------------------------------------------------------------
dev: ## Install dev tooling (ruff, build, pre-commit)
	$(PYTHON) -m pip install --upgrade ruff build pre-commit

hooks-install: ## Install the git pre-commit hook
	$(PRECOMMIT) install

hooks: ## Run all pre-commit hooks over the tree
	$(PRECOMMIT) run --all-files

# -- lint / test (CI: lint job, test job, shim job) ------------------------
lint: ## Lint with ruff
	$(RUFF) check .

format: ## Auto-format with ruff
	$(RUFF) format .

format-check: ## Check formatting (no changes)
	$(RUFF) format --check .

test: ## Run the test suite (build the shim first to include the differential test)
	$(PYTHON) -m unittest discover -s tests -v

# -- the native shim (CI: shim + binaries jobs) ----------------------------
shim: ## Build the native shim binary (debug, native)
	cd shim && $(ZIG) build

shim-target: ## Build one static binary (TARGET=x86_64-linux-musl)
	@test -n "$(TARGET)" || { echo "usage: make shim-target TARGET=<zig-target>"; exit 2; }
	cd shim && $(ZIG) build -Dtarget=$(TARGET) -Doptimize=ReleaseSmall -Dstatic

shim-static: ## Build all static binaries (x86_64 + aarch64)
	@for t in $(BIN_TARGETS); do $(MAKE) --no-print-directory shim-target TARGET=$$t; done

binaries: ## Build + stage the release static binaries (+ sha256) into dist-bin/
	@rm -rf dist-bin && mkdir -p dist-bin
	@for t in $(BIN_TARGETS); do \
		$(MAKE) --no-print-directory shim-target TARGET=$$t; \
		cp shim/zig-out/bin/withcache-shim dist-bin/withcache-shim-$$t; \
		( cd dist-bin && sha256sum withcache-shim-$$t > withcache-shim-$$t.sha256 ); \
	done
	@ls -l dist-bin

# -- wheels / sdist (CI: wheels + sdist jobs) ------------------------------
wheel: ## Build sdist + wheel (native-binary wheel when zig is present, else pure)
	$(PYTHON) -m build

wheel-one: ## Build one platform wheel (ZTARGET=<zig-target> WTAG=<wheel-tag>)
	@test -n "$(ZTARGET)" -a -n "$(WTAG)" || { echo "usage: make wheel-one ZTARGET=.. WTAG=.."; exit 2; }
	WITHCACHE_ZIG_TARGET=$(ZTARGET) WITHCACHE_WHEEL_TAG=$(WTAG) $(PYTHON) -m build --wheel

wheel-pure: ## Build the universal py3-none-any wheel + sdist (Python launchers, no zig)
	WITHCACHE_NO_ZIG=1 $(PYTHON) -m build

wheels: ## Build the full release set locally: platform wheels + pure wheel + sdist
	@rm -rf dist
	@for pair in $(WHEEL_MATRIX); do \
		$(MAKE) --no-print-directory wheel-one ZTARGET=$${pair%%:*} WTAG=$${pair##*:}; \
	done
	@$(MAKE) --no-print-directory wheel-pure
	@ls -l dist

# -- run -------------------------------------------------------------------
serve: ## Run the cache-host locally (set WITHCACHE_ADMIN_PASSWORD to gate the UI)
	PYTHONPATH=src $(PYTHON) -m withcache.server --data-dir ./data --port $(PORT)

# -- deploy (containerized cache-host via compose) -------------------------
up: ## Bring up the containerized cache-host (set WITHCACHE_ADMIN_PASSWORD to gate the UI)
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --build
	@echo "cache-host up -> operator UI: http://localhost:8081/"

down: ## Stop and remove the cache-host container
	$(COMPOSE) -f $(COMPOSE_FILE) down

logs: ## Follow the cache-host logs
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

# -- version (single source: src/withcache/__init__.py) --------------------
version: ## Show the version and where it lives
	@echo "source  src/withcache/__init__.py : $(SRC_VERSION)"
	@echo "mirror  shim/build.zig.zon        : $(ZON_VERSION)"
	@echo "derived pyproject (Hatch dynamic) : <from source>"

version-check: ## Fail if the zon mirror drifted from the source
	@test "$(SRC_VERSION)" = "$(ZON_VERSION)" \
		|| { echo "version drift: __init__=$(SRC_VERSION) zon=$(ZON_VERSION) (run: make bump VERSION=$(SRC_VERSION))"; exit 1; }
	@echo "version OK: $(SRC_VERSION)"

bump: ## Bump the version (usage: make bump VERSION=0.2.0)
	@test -n "$(VERSION)" || { echo "usage: make bump VERSION=X.Y.Z"; exit 2; }
	sed -i 's/^__version__ = ".*"/__version__ = "$(VERSION)"/' src/withcache/__init__.py
	sed -i 's/^\([[:space:]]*\)\.version = "[^"]*"/\1.version = "$(VERSION)"/' shim/build.zig.zon
	@$(MAKE) --no-print-directory version-check

# -- aggregate / cleanup ---------------------------------------------------
check: lint format-check version-check shim test ## Everything CI checks, locally

clean: ## Remove build/test artifacts
	rm -rf dist dist-bin build *.egg-info .pytest_cache shim/zig-out shim/.zig-cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
