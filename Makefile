# ==============================================================================
# elyrn. Makefile
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Detect Docker Compose v2 ("docker compose") vs v1 ("docker-compose")
DOCKER_COMPOSE ?= $(shell if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "docker-compose-not-found"; fi)

# Project paths
ENV_FILE := .env
ENV_EXAMPLE := .env.example
# TLS between the backend and the bundled PostgreSQL (make certs): outside git and images
CERT_DIR := certs

# Crypto engine compiled into the backend: openssl (default, libcrypto >= 3.2 via cgo) or
# native (Go standard library). Both are byte-for-byte equivalent (make test-equivalence).
ENGINE ?= openssl
ENGINES := openssl native
ifeq ($(filter $(ENGINE),$(ENGINES)),)
$(error ENGINE must be one of: $(ENGINES) (got "$(ENGINE)"))
endif
GO_TAGS_openssl := openssl
GO_TAGS_native :=
CGO_openssl := 1
CGO_native := 0

# Release tags: elyrn-<engine>-vX.Y.Z on main; elyrn-<engine>-dev follow elyrn-dev
# The onion key directory and the database names (not the branch any more) keep "noaddx" across the rename to elyrn.
DEV_BRANCH := elyrn-dev
RELEASE_BRANCH := main
COMPOSE_ENV := ENGINE=$(ENGINE)
# APP_ENV as Compose sees it (the shell's value wins over .env), lower case without quotes.
# Recursive: read when a recipe runs, after $(ENV_FILE) may have been created.
APP_ENV_NOW = $(shell e="$${APP_ENV:-$$(sed -n 's/^APP_ENV=//p' "$(ENV_FILE)" 2>/dev/null | tail -n 1)}"; \
	printf '%s' "$$e" | tr -d "\"' \r" | tr '[:upper:]' '[:lower:]')
IS_PRODUCTION = $(filter production prod,$(APP_ENV_NOW))
# Production publishes nginx alone; development adds docker-compose.dev.yaml (backend and
# PostgreSQL on loopback). See docs/operations/hardening.md.
DEV_COMPOSE := -f docker-compose.dev.yaml
COMPOSE_FILES = -f docker-compose.yaml $(if $(IS_PRODUCTION),,$(DEV_COMPOSE))
# Every file and the opt-in tor service, so stopping and listing always cover all of it
COMPOSE_ALL := $(DOCKER_COMPOSE) -f docker-compose.yaml $(DEV_COMPOSE) --profile onion
# Before the split networks (S-08) every service shared this one; it holds their address range
LEGACY_NETWORK := noaddx_default
# Fingerprints of the current certificates, as container labels: a renewed certificate changes
# its label, so `up` recreates exactly the container that must load it (volumes stay)
TLS_ENV = PG_TLS_CERT_SHA256="$$(openssl x509 -noout -fingerprint -sha256 -in "$(CERT_DIR)/postgres/server.crt" | cut -d= -f2)" \
	DB_CA_SHA256="$$(openssl x509 -noout -fingerprint -sha256 -in "$(CERT_DIR)/ca/ca.crt" | cut -d= -f2)"
# The one list of Go fuzz targets lives in the CI fuzz step; this script checks and prints it
FUZZ_TARGETS := scripts/check-fuzz-targets.py
# Frontend manifest: what the release workflow signs and verify-frontend checks against
MANIFEST ?= frontend.sha256

.PHONY: help setup certs check-production check-hardening check-docker migrate-networks build up onion onion-address start run down stop restart logs ps clean agent agent-cross \
        test test-engines test-equivalence test-run test-unit test-crypto test-all test-db fuzz fuzz-js \
        build-ref tag-dev release check-clean-branch-dev check-clean-branch-release shell-backend shell-db \
        manifest verify-frontend backup-accounts test-restore

## -----------------------------------------------------------------------------
## Help
## -----------------------------------------------------------------------------

help:
	@echo "elyrn. build system"
	@echo "======================"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Crypto engine: ENGINE=openssl (default) | native  e.g. make up ENGINE=native"
	@echo ""
	@echo "Targets:"
	@echo "  setup         Generate .env with fresh keys (kept if it exists) and the database TLS certificates"
	@echo "  certs         Create or renew the database TLS certificates in $(CERT_DIR)/ (never touches .env or data)"
	@echo "  build         Build Docker container images for ENGINE"
	@echo "  up            Build and start services in background for ENGINE (APP_ENV from .env;"
	@echo "                development also publishes the backend and PostgreSQL on loopback)"
	@echo "  onion         Like up, and publish the app as a Tor onion service (requires APP_ENV=production)"
	@echo "  onion-address Print the onion address (published by make onion)"
	@echo "  down          Stop and remove running containers"
	@echo "  restart       Restart services"
	@echo "  logs          Stream container logs (Ctrl+C to exit)"
	@echo "  ps            Display service container status"
	@echo "  clean         Stop services, delete images, volumes and test artifacts"
	@echo "  check-hardening  Fail unless the rendered compose config keeps every container control"
	@echo "  agent         Build bin/elyrn-agent (the robot entrance, MCP on stdio) for this host and ENGINE"
	@echo "                (openssl, the default, needs OpenSSL >= $(AGENT_OPENSSL_MIN) headers and links to them: this host only)"
	@echo "  agent-cross   Build a portable, static native-engine agent: make agent-cross GOOS=linux GOARCH=arm64"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test          Full Go suite for ENGINE in Docker (openssl also runs equivalence)"
	@echo "  test-engines  Full Go suite for both engines, one after the other"
	@echo "  test-equivalence  Prove both engines give byte-identical results (Docker)"
	@echo "  test-run      Run Docker test suite; if passed, start services"
	@echo "  test-unit     Run Go unit tests locally for ENGINE (no database needed)"
	@echo "  test-crypto   Run frontend WebCrypto derivation tests (Node.js 20+)"
	@echo "  test-all      Run local Go unit tests and frontend crypto tests"
	@echo "  test-db       Run Go database and integration tests (requires local PostgreSQL)"
	@echo "  fuzz          Run every Go fuzz target of the CI list for FUZZTIME each (default $(FUZZTIME)) on ENGINE"
	@echo "  fuzz-js       Run the frontend fuzz files (FUZZ_SCALE multiplies iterations, FUZZ_SEED replays a seed)"
	@echo "  test-restore  Restore drill in the disposable test stack: seed, dump (backup-accounts' command), restore, log in"
	@echo ""
	@echo "Release Targets:"
	@echo "  build-ref     Build the backend image of any tag or commit: make build-ref REF=elyrn-openssl-v1.0.0"
	@echo "  tag-dev       Test both engines, then move elyrn-{openssl,native}-dev to $(DEV_BRANCH) HEAD"
	@echo "  release       Test both engines on $(RELEASE_BRANCH), tag elyrn-{openssl,native}-VERSION: make release VERSION=v1.0.0"
	@echo "  manifest      Write $(MANIFEST): SHA-256 of every file the frontend serves (signed in each release)"
	@echo "  verify-frontend  Check an instance serves exactly $(MANIFEST): make verify-frontend URL=https://host"
	@echo ""
	@echo "Utility Targets:"
	@echo "  shell-backend Open interactive shell inside backend container"
	@echo "  shell-db      Open PostgreSQL CLI inside database container"
	@echo "  backup-accounts  Dump the accounts (never messages) to backups/; restore: docs/operations/disaster-recovery.md"

## -----------------------------------------------------------------------------
## Environment Configuration & Key Generation
## -----------------------------------------------------------------------------

setup:
	@if [ "$(DOCKER_COMPOSE)" = "docker-compose-not-found" ]; then \
		echo "ERROR: Docker Compose is required but neither 'docker compose' nor 'docker-compose' was found in PATH."; \
		exit 1; \
	fi
	@if ! command -v openssl >/dev/null 2>&1; then \
		echo "ERROR: openssl is required (OpenSSL or LibreSSL both work)."; \
		exit 1; \
	fi
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "[INFO] $(ENV_FILE) already exists. Skipping key generation."; \
		echo "       To regenerate keys, remove $(ENV_FILE) first: rm $(ENV_FILE)"; \
	else \
		echo "[INFO] Generating fresh cryptographic keys and $(ENV_FILE)..."; \
		umask 077; \
		JWT_SECRET=$$(openssl rand -hex 32); \
		PEPPER=$$(openssl rand -hex 32); \
		MASTER_KEY=$$(openssl rand -hex 32); \
		MASTER_KEY_ID=$$(openssl rand -hex 4); \
		DB_PASSWORD=$$(openssl rand -hex 24); \
		sed -e "s|^JWT_SECRET=.*|JWT_SECRET=$$JWT_SECRET|" \
		    -e "s|^ACCOUNT_LOOKUP_PEPPER=.*|ACCOUNT_LOOKUP_PEPPER=$$PEPPER|" \
		    -e "s|^MASTER_KEY_ACTIVE=.*|MASTER_KEY_ACTIVE=$$MASTER_KEY|" \
		    -e "s|^MASTER_KEY_ACTIVE_ID=.*|MASTER_KEY_ACTIVE_ID=$$MASTER_KEY_ID|" \
		    -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$$DB_PASSWORD|" \
		    $(ENV_EXAMPLE) > $(ENV_FILE); \
		chmod 600 $(ENV_FILE); \
		echo "[OK] $(ENV_FILE) created successfully with secure permissions (0600)."; \
	fi
	@$(MAKE) --no-print-directory certs

# Idempotent: creates what is missing, renews what expires within 30 days, keeps the rest
certs:
	@sh postgres/certs.sh "$(CERT_DIR)"

# make onion publishes the instance: refuse to do it in development mode (unprefixed cookie
# without Secure, production checks off). The shell's APP_ENV wins over .env, as in Compose.
check-production: $(ENV_FILE)
	@if [ -z "$(IS_PRODUCTION)" ]; then \
		echo "[ERROR] make onion requires APP_ENV=production (now: $(or $(APP_ENV_NOW),unset))."; \
		echo "        Set APP_ENV=production in $(ENV_FILE); see docs/operations/onion-service.md"; exit 1; \
	fi

# Every service keeps its container controls (docs/operations/hardening.md), in both layouts.
# The rendered config holds .env values: it goes straight into the checker, which prints names only.
check-hardening:
	@python3 -I $(FUZZ_TARGETS)
	@set -o pipefail; for layout in production development; do \
		files="-f docker-compose.yaml"; [ "$$layout" = development ] && files="$$files $(DEV_COMPOSE)"; \
		$(DOCKER_COMPOSE) $$files --profile onion config --format json \
			| python3 -I scripts/check-hardening.py "$$layout" || exit 1; \
	done
	@grep -qx 'location /api/ { include /etc/nginx/elyrn/api-errors.conf; return 404; }' nginx-site.conf \
		|| { echo "[FAIL] nginx-site.conf: the /api/ default-deny line is missing"; exit 1; }
	@echo "[OK] check-hardening: nginx /api/ ends in default deny; its own answers are the registered JSON (apperr/edge.go)"

$(ENV_FILE):
	@$(MAKE) setup

## -----------------------------------------------------------------------------
## Container Management
## -----------------------------------------------------------------------------

check-docker:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "[ERROR] Docker is not installed or not in PATH."; exit 1; \
	fi; \
	if ! docker info >/dev/null 2>&1; then \
		echo "[ERROR] Docker daemon is not running. Please start Docker Desktop (or OrbStack/Colima) and try again."; exit 1; \
	fi

build: check-docker $(ENV_FILE)
	@echo "[INFO] Building Docker images (crypto engine: $(ENGINE))..."
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.yaml build

# Once, on an installation from before the split networks: stop its containers (volumes stay)
# and remove the old network, whose address range the app network takes over
migrate-networks: check-docker
	@if docker network inspect $(LEGACY_NETWORK) >/dev/null 2>&1; then \
		echo "[INFO] Moving to the split networks: stopping the old stack once (volumes stay)"; \
		$(COMPOSE_ALL) down && docker network rm $(LEGACY_NETWORK) >/dev/null; \
	fi

up: check-docker $(ENV_FILE) certs migrate-networks
	@echo "[INFO] Starting services (crypto engine: $(ENGINE), APP_ENV: $(or $(APP_ENV_NOW),development))..."
	@$(COMPOSE_ENV) $(TLS_ENV) $(DOCKER_COMPOSE) $(COMPOSE_FILES) up -d --build
	@echo "[OK] Services running"
	@$(DOCKER_COMPOSE) $(COMPOSE_FILES) ps

# The tor service is opt-in: it makes this instance reachable from anywhere through Tor.
# Production only, so the development file (published backend and database) is never included.
onion: check-docker check-production certs migrate-networks
	@echo "[INFO] Starting services and the onion service (crypto engine: $(ENGINE))..."
	@$(COMPOSE_ENV) $(TLS_ENV) $(DOCKER_COMPOSE) $(COMPOSE_FILES) --profile onion up -d --build
	@echo "[OK] Services running; the onion address appears once tor has published it (about a minute):"
	@echo "     make onion-address"

onion-address:
	@docker exec elyrn-tor cat /var/lib/tor/noaddx/hostname 2>/dev/null \
		|| echo "[INFO] Not published yet: run make onion, then retry in a minute"

start: up
run: up

down:
	@echo "[INFO] Stopping services..."
	@$(COMPOSE_ALL) down

stop: down

restart:
	@echo "[INFO] Restarting services..."
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.yaml restart

logs:
	@$(COMPOSE_ALL) logs -f

ps:
	@$(COMPOSE_ALL) ps

clean:
	@echo "[INFO] Cleaning containers, volumes and test artifacts..."
	@$(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v --rmi local 2>/dev/null || true
	@$(COMPOSE_ALL) down -v --rmi local 2>/dev/null || true
	@docker images --filter "reference=*elyrn*" -q | xargs docker rmi -f 2>/dev/null || true
	@rm -rf test-results
	@echo "[OK] Clean complete"

## -----------------------------------------------------------------------------
## Testing
## -----------------------------------------------------------------------------

test: check-docker
	@echo "[INFO] Running the containerized test suite (crypto engine: $(ENGINE))..."
	@mkdir -p test-results
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml build
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml up --abort-on-container-exit --exit-code-from test-runner; \
	EXIT_CODE=$$?; \
	$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v; \
	if [ $$EXIT_CODE -eq 0 ]; then \
		echo "[OK] All containerized tests passed ($(ENGINE))"; \
	else \
		echo "[ERROR] Tests failed with exit code $$EXIT_CODE ($(ENGINE))"; \
	fi; \
	exit $$EXIT_CODE

test-engines:
	@for engine in $(ENGINES); do $(MAKE) --no-print-directory test ENGINE=$$engine || exit 1; done
	@echo "[OK] Both crypto engines pass the complete suite"

# Links both engines into one test binary and compares every primitive (no database needed)
test-equivalence: check-docker
	@echo "[INFO] Proving openssl and native engines are byte-for-byte equivalent..."
	@ENGINE=openssl $(DOCKER_COMPOSE) -f docker-compose.test.yaml build test-runner
	@ENGINE=openssl $(DOCKER_COMPOSE) -f docker-compose.test.yaml run --rm --no-deps -e CGO_ENABLED=1 test-runner \
		go test -count=1 -tags 'test openssl' -v ./internal/cryptoengine/...

test-run: test up

# The robot entrance (docs/architecture/agents.md), built on the host for ENGINE: stripped,
# position independent, no local paths (RULES.md §14.1)
AGENT_BIN := bin/elyrn-agent
AGENT_BUILD := go build -trimpath -buildmode=pie -ldflags "-s -w"
# The openssl engine compiles against these headers and links to this libcrypto at run time
AGENT_OPENSSL_MIN := 3.2
AGENT_OPENSSL_PC := libcrypto

agent:
	@if [ "$(ENGINE)" = openssl ] && ! pkg-config --atleast-version=$(AGENT_OPENSSL_MIN) $(AGENT_OPENSSL_PC) 2>/dev/null; then \
		echo "[ERROR] ENGINE=openssl needs OpenSSL >= $(AGENT_OPENSSL_MIN) development headers that pkg-config finds ($(AGENT_OPENSSL_PC))."; \
		echo "        Install them (Debian/Ubuntu: libssl-dev, Alpine: openssl-dev, macOS: brew install openssl@3 with"; \
		echo "        PKG_CONFIG_PATH set to its lib/pkgconfig), or build the portable native engine instead:"; \
		echo "        make agent ENGINE=native, or make agent-cross GOOS=<os> GOARCH=<arch> for another system."; \
		exit 1; \
	fi
	@echo "[INFO] Building $(AGENT_BIN) (crypto engine: $(ENGINE))..."
	@mkdir -p bin
	@cd backend && CGO_ENABLED=$(CGO_$(ENGINE)) $(AGENT_BUILD) \
		-tags "$(GO_TAGS_$(ENGINE))" -o ../$(AGENT_BIN) ./cmd/agent
	@echo "[OK] $(AGENT_BIN)"

# The agent for another system (or a portable one for this host): the native engine without
# cgo, so one static binary per GOOS/GOARCH, named after them. Both are required.
AGENT_CROSS_BIN = $(AGENT_BIN)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe)

agent-cross:
	@if [ -z "$(GOOS)" ] || [ -z "$(GOARCH)" ]; then \
		echo "[ERROR] usage: make agent-cross GOOS=<os> GOARCH=<arch> (e.g. GOOS=linux GOARCH=arm64; list: go tool dist list)"; exit 1; fi
	@cd backend && go tool dist list | grep -qx "$(GOOS)/$(GOARCH)" || { \
		echo "[ERROR] $(GOOS)/$(GOARCH) is not a Go target (go tool dist list)"; exit 1; }
	@echo "[INFO] Building $(AGENT_CROSS_BIN) (crypto engine: native, $(GOOS)/$(GOARCH), static)..."
	@mkdir -p bin
	@cd backend && CGO_ENABLED=$(CGO_native) GOOS=$(GOOS) GOARCH=$(GOARCH) $(AGENT_BUILD) \
		-tags "$(GO_TAGS_native)" -o ../$(AGENT_CROSS_BIN) ./cmd/agent
	@echo "[OK] $(AGENT_CROSS_BIN)"

test-unit:
	@echo "[INFO] Running local Go unit tests (crypto engine: $(ENGINE), no database)..."
	@cd backend && CGO_ENABLED=$(CGO_$(ENGINE)) go test -tags "test $(GO_TAGS_$(ENGINE))" ./internal/... ./tests/auth/... ./tests/encryption/... ./tests/identity/... ./tests/middleware/... ./tests/utils/...

test-crypto:
	@echo "[INFO] Running frontend WebCrypto verification tests..."
	@node --test frontend/tests/*.test.mjs

test-all: test-crypto test-unit

# Every Go fuzz target, read from the CI fuzz step (the one list; the script refuses an
# incomplete, duplicated or unsorted list first), each for FUZZTIME on ENGINE, locally
FUZZTIME ?= 20s

fuzz:
	@targets="$$(python3 -I $(FUZZ_TARGETS) --list)" || exit 1; \
	cd backend && while read -r pkg target; do \
		echo "[INFO] $$target ($$pkg, $(FUZZTIME), crypto engine: $(ENGINE))"; \
		CGO_ENABLED=$(CGO_$(ENGINE)) go test -tags "test $(GO_TAGS_$(ENGINE))" -run '^$$' -fuzz "^$$target\$$" \
			-fuzztime "$(FUZZTIME)" "$$pkg" < /dev/null || exit 1; \
	done <<< "$$targets"
	@echo "[OK] Every Go fuzz target ran $(FUZZTIME) without a failure ($(ENGINE))"

# The frontend fuzz files; FUZZ_SCALE and FUZZ_SEED pass through from the environment or the
# command line (frontend/tests/fuzz-helpers.mjs)
fuzz-js:
	@node --test frontend/tests/*.fuzz.test.mjs

# Database and integration tests against a separate local PostgreSQL (TEST_DB_* overrides), never
# the bundled one: it holds live data and accepts TLS connections only
TEST_DB_HOST ?= 127.0.0.1
TEST_DB_PORT ?= 5432
TEST_DB_USER ?= postgres
TEST_DB_PASSWORD ?= postgres
TEST_DB_NAME ?= noaddx_test

test-db:
	@echo "[INFO] Running database and integration tests (requires local PostgreSQL)..."
	@cd backend && DB_HOST=$(TEST_DB_HOST) DB_PORT=$(TEST_DB_PORT) DB_USER=$(TEST_DB_USER) \
		DB_PASSWORD=$(TEST_DB_PASSWORD) DB_NAME=$(TEST_DB_NAME) CGO_ENABLED=$(CGO_$(ENGINE)) \
		go test -p 1 -count=1 -tags "test $(GO_TAGS_$(ENGINE))" ./tests/database/... ./tests/integration/...

## -----------------------------------------------------------------------------
## Releases
## -----------------------------------------------------------------------------

# Builds the backend image of any tag or commit from git history (not the working tree).
# The engine follows the tag name (elyrn-openssl-* / elyrn-native-*) unless ENGINE is given.
build-ref: check-docker
	@if [ -z "$(REF)" ]; then echo "[ERROR] usage: make build-ref REF=<tag|commit> [ENGINE=openssl|native]"; exit 1; fi
	@git rev-parse --verify --quiet "$(REF)^{commit}" >/dev/null || { echo "[ERROR] unknown ref: $(REF)"; exit 1; }
	@engine="$(ENGINE)"; \
	case "$(REF)" in elyrn-openssl-*) engine=openssl ;; elyrn-native-*) engine=native ;; esac; \
	if [ "$(origin ENGINE)" = "command line" ] && [ "$$engine" != "$(ENGINE)" ]; then \
		echo "[ERROR] REF $(REF) is a $$engine release; drop ENGINE or pick a matching tag"; exit 1; fi; \
	echo "[INFO] Building $(REF) ($$(git rev-parse --short "$(REF)^{commit}")) with the $$engine engine..."; \
	git archive --format=tar "$(REF)" | docker build --build-arg ENGINE=$$engine -f dev.backend.Dockerfile \
		-t "elyrn-backend:$$(echo '$(REF)' | tr '/:' '--')" - && \
	echo "[OK] Image: elyrn-backend:$$(echo '$(REF)' | tr '/:' '--')"

# Moves the dev tags to the tested HEAD of the dev branch (both engines must pass first)
tag-dev: check-clean-branch-dev test-engines
	@for engine in $(ENGINES); do git tag -f -a "elyrn-$$engine-dev" -m "elyrn. $$engine engine, development build ($$(git rev-parse --short HEAD))" HEAD >/dev/null; done
	@git push -f origin $(foreach e,$(ENGINES),refs/tags/elyrn-$(e)-dev)
	@echo "[OK] elyrn-openssl-dev and elyrn-native-dev -> $$(git rev-parse --short HEAD)"

# Tags one tested commit of the release branch for both engines: make release VERSION=v1.0.0
release: check-clean-branch-release test-engines
	@if ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then echo "[ERROR] VERSION must look like v1.2.3"; exit 1; fi
	@for engine in $(ENGINES); do \
		if git rev-parse -q --verify "refs/tags/elyrn-$$engine-$(VERSION)" >/dev/null; then echo "[ERROR] elyrn-$$engine-$(VERSION) exists"; exit 1; fi; \
	done
	@for engine in $(ENGINES); do git tag -a "elyrn-$$engine-$(VERSION)" -m "elyrn. $(VERSION) ($$engine crypto engine)" HEAD; done
	@git push origin $(foreach e,$(ENGINES),refs/tags/elyrn-$(e)-$(VERSION))
	@echo "[OK] Released $(VERSION): $(foreach e,$(ENGINES),elyrn-$(e)-$(VERSION))"

check-clean-branch-dev:
	@[ "$$(git rev-parse --abbrev-ref HEAD)" = "$(DEV_BRANCH)" ] || { echo "[ERROR] check out $(DEV_BRANCH) first"; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "[ERROR] commit or stash your changes first"; exit 1; }

check-clean-branch-release:
	@[ "$$(git rev-parse --abbrev-ref HEAD)" = "$(RELEASE_BRANCH)" ] || { echo "[ERROR] releases are cut from $(RELEASE_BRANCH)"; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "[ERROR] commit or stash your changes first"; exit 1; }

## -----------------------------------------------------------------------------
## Debug & Utilities
## -----------------------------------------------------------------------------

# Tracked files only (no local leftovers), paths as served under the web root
manifest:
	@git ls-files -- frontend ':!frontend/tests' | LC_ALL=C sort | sed 's|^frontend/||' \
		| (cd frontend && xargs shasum -a 256) > $(MANIFEST)
	@echo "[OK] $(MANIFEST): $$(wc -l < $(MANIFEST) | tr -d ' ') files"

# Fetches every file in MANIFEST from URL and compares hashes; index.html is served at /.
# For an onion address: CURL_OPTS="--socks5-hostname 127.0.0.1:9150" (Tor Browser's proxy)
verify-frontend:
	@test -n "$(URL)" || { echo "[ERROR] usage: make verify-frontend URL=https://host [MANIFEST=$(MANIFEST)]"; exit 1; }
	@test -s "$(MANIFEST)" || { echo "[ERROR] $(MANIFEST) missing: download it from the release or run make manifest"; exit 1; }
	@fail=0; while read -r want path; do \
		route="/$$path"; [ "$$path" = "index.html" ] && route="/"; \
		got=$$(curl -fsS $(CURL_OPTS) "$(URL)$$route" | shasum -a 256 | cut -d' ' -f1); \
		[ "$$got" = "$$want" ] || { echo "[MISMATCH] $$route"; fail=1; }; \
	done < $(MANIFEST); \
	if [ $$fail -eq 0 ]; then echo "[OK] $(URL) serves exactly $(MANIFEST)"; else exit 1; fi

shell-backend:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec backend /bin/sh

# The container's own POSTGRES_USER and POSTGRES_DB (DB_USER, DB_NAME): any configured names
shell-db:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec postgres sh -c 'exec psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

# Accounts only (users with their id sequence, and key_checks: the pepper commitment, the
# schema version and the retention mark): messages expire and burned conversations must stay
# gone, so they are never backed up. pg_dump --table dumps a table's owned sequence with it, so
# users_id_seq and its position come along. Keep the file apart from .env.
ACCOUNTS_DUMP := pg_dump -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" --no-owner --table=users --table=key_checks

backup-accounts:
	@mkdir -p backups
	@umask 077; file="backups/accounts-$$(date -u +%Y%m%dT%H%M%SZ).sql"; \
	$(DOCKER_COMPOSE) -f docker-compose.yaml exec -T postgres sh -c '$(ACCOUNTS_DUMP)' > "$$file" \
		|| { rm -f "$$file"; echo "[ERROR] backup failed (is the database running?)"; exit 1; }; \
	echo "[OK] $$file: store it apart from .env"

# Restore drill, entirely inside the disposable test stack (docker-compose.test.yaml: project
# noaddx-test, its database on tmpfs), so no development or production volume is ever touched:
# seed an account, dump with backup-accounts' command, empty the test database, restore the dump
# the way docs/operations/disaster-recovery.md does, then start on it, log in and register again.
# The drill's keys are drawn once here and passed to the containers by name only.
TEST_COMPOSE := $(DOCKER_COMPOSE) -f docker-compose.test.yaml
RESTORE_DRILL_DIR := test-results/restore-drill
RESTORE_DRILL_RUN = $(TEST_COMPOSE) run --rm -e CGO_ENABLED=$(CGO_$(ENGINE)) -e RESTORE_DRILL_DIR=/$(RESTORE_DRILL_DIR) \
	-e RESTORE_DRILL_JWT_SECRET -e RESTORE_DRILL_MASTER_KEY_ACTIVE -e RESTORE_DRILL_ACCOUNT_LOOKUP_PEPPER

test-restore: check-docker
	@echo "[INFO] Restore drill in the test stack (crypto engine: $(ENGINE))..."
	@set -e; umask 077; mkdir -p $(RESTORE_DRILL_DIR); \
	trap '$(TEST_COMPOSE) down -v >/dev/null 2>&1; rm -f $(RESTORE_DRILL_DIR)/accounts.sql $(RESTORE_DRILL_DIR)/account' EXIT; \
	export RESTORE_DRILL_JWT_SECRET=$$(openssl rand -hex 32) RESTORE_DRILL_MASTER_KEY_ACTIVE=$$(openssl rand -hex 32) \
		RESTORE_DRILL_ACCOUNT_LOOKUP_PEPPER=$$(openssl rand -hex 32); \
	$(COMPOSE_ENV) $(TEST_COMPOSE) build test-runner; \
	$(TEST_COMPOSE) up -d --wait postgres-test; \
	drill() { $(COMPOSE_ENV) $(RESTORE_DRILL_RUN) -e RESTORE_DRILL=$$1 test-runner \
		go test -count=1 -tags "test $(GO_TAGS_$(ENGINE))" -run '^TestRestoreDrill$$' ./tests/integration/; }; \
	drill seed; \
	$(TEST_COMPOSE) exec -T postgres-test sh -c '$(ACCOUNTS_DUMP)' > $(RESTORE_DRILL_DIR)/accounts.sql; \
	$(TEST_COMPOSE) exec -T postgres-test sh -c 'dropdb -U "$$POSTGRES_USER" --force "$$POSTGRES_DB" && createdb -U "$$POSTGRES_USER" "$$POSTGRES_DB"'; \
	$(TEST_COMPOSE) exec -T postgres-test sh -c 'psql -v ON_ERROR_STOP=1 -q -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"' < $(RESTORE_DRILL_DIR)/accounts.sql; \
	drill verify; \
	echo "[OK] Restore drill: the dump restores, the key check passes, its account logs in, a new one registers"
