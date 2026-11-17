# Container Hardening

Every service runs restricted: no capabilities it does not need, a read-only root filesystem,
an unprivileged user, bounded resources, and a network that reaches only its own peers. In the
production layout only nginx publishes a port, on loopback (development also publishes the
backend and PostgreSQL on loopback; see [Layouts](#layouts)). `make check-hardening` fails if the rendered Compose config
(production and development layouts) loses any control below or gains a forbidden one.

```bash
make check-hardening     # the fuzz list, the rendered config of both layouts, nginx's /api/ answers and log levels
```

It first checks the one list of Go fuzz targets (`scripts/check-fuzz-targets.py`: every target
listed once, sorted, and every listed one exists), then pipes `docker compose config` for each
layout into `scripts/check-hardening.py`, which prints variable names only, never values.

Besides the per-service controls below it fails when a service loses its log rotation, when the
backend's `stop_grace_period` no longer exceeds its shutdown budget (read from
`backend/cmd/server/main.go`), when `BACKEND_PORT` is not pinned to 8080 or the healthcheck stops
probing `/internal/health`, when nginx intercepts the backend's answers again, when an `/api/`
location that proxies lacks the JSON error include, when an nginx JSON answer differs by one byte
from its registered code (`backend/internal/apperr/edge.go`), or when nginx's `error_log` level or
`access_log off` changes.

---

## Layouts

| Layout | When | Published on 127.0.0.1 |
|---|---|---|
| production | `APP_ENV=production` (`.env` or shell); always for `make onion` | nginx (`HTTP_PORT`, default 80) |
| development | any other `APP_ENV` (the default) | nginx, plus the backend on 8080 and PostgreSQL on `DB_HOST_PORT` from [docker-compose.dev.yaml](../../docker-compose.dev.yaml) |

`make up` picks the layout from `APP_ENV`; `make down`, `ps` and `logs` cover both. In
development the backend and PostgreSQL also join `devhost`, a network with a gateway (a port
cannot be published from an internal network), which gives them outbound access there. The
backend still trusts nginx's address alone, so a request from the host is an untrusted client.

## Networks

```text
              edge (172.29.72.0/24)            app (172.29.73.0/24, internal)    data (172.29.74.0/24, internal)
host:80 ──▶ nginx ◀── tor (TOR_IP .11)      nginx (PROXY_IP .10) ──▶ backend (BACKEND_IP .12) ──▶ postgres
```

| Network | Members | Internet | Why |
|---|---|---|---|
| `edge` | nginx, tor | yes | the published port; tor's way into the Tor network |
| `app` | nginx, backend | no | the backend trusts `X-Forwarded-For` only from nginx's fixed address here (`TRUSTED_PROXIES` = `PROXY_IP`) |
| `data` | backend, postgres | no | nothing else reaches the database |

`app` and `data` are `internal` and set `com.docker.network.bridge.gateway_mode_ipv4=isolated`
(Docker Engine 28+): their bridges carry no address, so the host cannot route into them. Without
it, a runtime that routes between bridges (OrbStack does) let the host and a container on `edge`
reach the backend and PostgreSQL by IP; with it both are refused. Ranges: `EDGE_SUBNET`,
`COMPOSE_SUBNET` (app, the range kept its name) and `DATA_SUBNET` in `.env`.

An installation from before this layout had one network, `noaddx_default` (the Compose project keeps the name `noaddx`, so its volumes and networks are `noaddx_*`); `make up` stops
that stack once (volumes stay) and removes it, so `app` can take over its range. The fixed
addresses `PROXY_IP` and `BACKEND_IP` are unchanged. `TOR_IP` moved to `edge`: an `.env` that
sets `TOR_IP=172.29.73.11` must change it to `172.29.72.11` (or delete the line) before
`make onion`.

## Per service

Docker's default seccomp profile stays on everywhere (no `seccomp=` option); no service is
`privileged`, shares a host namespace, maps a device or mounts the Docker socket.

| Control | backend | nginx (frontend) | postgres | tor | Prevents | Verify |
|---|---|---|---|---|---|---|
| User | 10001 | 101 (`nginx`) | starts as root, then 70 for good | `debian-tor` (100) | a container root that owns its files | `docker top <c> -o user,comm`; `grep Uid /proc/1/status` |
| `cap_drop: ALL`, added back | none | none | `CHOWN`, `DAC_READ_SEARCH`, `FOWNER`, `SETUID`, `SETGID` (below) | none | raw sockets, chown, mount, ptrace and every other kernel privilege | `docker inspect -f '{{.HostConfig.CapAdd}}' <c>`; `CapEff: 0000000000000000` in `/proc/1/status` |
| `no-new-privileges` | yes | yes | yes | yes | regaining privileges through setuid binaries | `NoNewPrivs: 1` |
| `read_only` root | yes | yes | yes | yes | writing binaries or config into the image | `docker exec <c> touch /x` fails |
| Writable paths | none | tmpfs `/etc/nginx/conf.d` 64k, `/run` 64k, `/var/cache/nginx` 16m | volume `postgres_data`; tmpfs `/run/elyrn-tls` 64k, `/var/run/postgresql` 1m | volume `tor_data` | | `grep tmpfs /proc/mounts` |
| tmpfs flags | | `noexec,nosuid,nodev` | `noexec,nosuid,nodev` | | running what was written | copy a binary there and run it: permission denied |
| `/dev/shm` (`shm_size`) | 1m | 1m | 64m (parallel query) | 1m | an unbounded writable tmpfs | `grep /dev/shm /proc/mounts` |
| Memory = memory+swap | 512m (`BACKEND_MEM_LIMIT`) | 128m | 512m | 256m | one service exhausting the host | `docker inspect -f '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}}'` |
| pids | 256 | 128 | 200 | 64 | fork bombs | `PidsLimit` |
| cpus | 1.0 | 1.0 | 1.0 | 1.0 | one service starving the rest | `NanoCpus` |
| nofile | 8192 | 4096 | 4096 | 8192 | descriptor exhaustion | `Ulimits` |
| `init` (tini) | yes | no (nginx reaps) | no (postgres reaps) | yes | zombies from interrupted healthchecks | `Init` |
| restart | unless-stopped | unless-stopped | unless-stopped | unless-stopped | staying down after a crash | `RestartPolicy` |
| healthcheck | `/internal/health` (loopback only): `SELECT 1` within 3 s and retention cycling | `/` answers | `pg_isready` | onion address published (a file; see Known limits) | starting dependents early, an unnoticed dead database link | `docker ps` |
| Logs | `local` driver, 3 × 10 MB | same | same | same | logs filling the host's disk | `docker inspect -f '{{.HostConfig.LogConfig}}' <c>` |
| Stop grace | 30 s (> 10 s requests + 5 s jobs) | default | default | default | a kill before keys are zeroized | `docker inspect -f '{{.Config.StopTimeout}}'` |
| Networks | app, data (development: also `devhost`) | edge, app | data (development: also `devhost`) | edge | lateral movement | `docker network inspect noaddx_app` |
| Published | dev only (8080) | `127.0.0.1:HTTP_PORT` → 8080 | dev only (`DB_HOST_PORT`) | none | exposure beyond loopback | `docker ps` |
| Egress | none (development: via `devhost`) | via edge | none (development: via `devhost`) | via edge (Tor) | exfiltration, callbacks | in production, a TCP connect from the backend's namespace fails |

**postgres capabilities.** Its entrypoint (`postgres/entrypoint.sh`) runs as root only to hand
the TLS key to uid 70, then the image's entrypoint drops to uid 70 with `gosu`; the server has
no effective capability. Each one was removed in turn on the dev stack and the start failed:
`CHOWN` (`install -o postgres` of the key copy), `DAC_READ_SEARCH` (read the bind-mounted key,
which belongs to the host user on Linux, and walk `PGDATA`, 0700 uid 70), `FOWNER` (set the
mode of the copy after handing it over), `SETUID`/`SETGID` (the switch to uid 70).

**Backend memory.** Argon2id's peak is `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB` = 4 × 64 MiB
= 256 MiB with the defaults; 256 MiB more covers the runtime, 20 database connections, up to
4,096 event streams and the garbage collector's headroom: 512 MiB. `GOMEMLIMIT` (448 MiB,
`BACKEND_GOMEMLIMIT`) makes the Go runtime collect harder before the container limit instead of
being killed. Raising the Argon2id settings needs `BACKEND_MEM_LIMIT` raised too;
`make check-hardening` fails when the limit is below the peak plus 128 MiB.

## nginx

| Control | Where |
|---|---|
| Unprivileged ports 8080 (clearnet) and 8081 (onion) | `nginx.conf` `listen` |
| `server_tokens off`, no access log, errors at `crit` (at `error`, nginx names the client address and path in every upstream and rate-limit line; an unreachable backend shows instead as `503 E_BACKEND_UNAVAILABLE` and in the backend's healthcheck) | `nginx-site.conf` top |
| `/api/`: the backend's answers pass through (`proxy_intercept_errors off`); nginx's own failures answer JSON with a registered code: 404 `E_EDGE_NOT_FOUND`, 405 `E_EDGE_METHOD_NOT_ALLOWED`, 413 `E_BODY_TOO_LARGE`, 429 `E_EDGE_RATE_LIMITED`, 500/502/503/504 as 503 `E_BACKEND_UNAVAILABLE`; every `error_page` to these named locations states its status (`=503`, `=404`, ...) because without `=` nginx keeps the triggering status (a 504 stayed 504), and `make check-hardening` fails when `=NNN` is missing or differs from `edge.go`; the HTML 404 page for page navigation only | [nginx-api-errors.conf](../../nginx-api-errors.conf), named locations in `nginx-site.conf` |
| Method whitelist for the whole site: GET, HEAD, POST, DELETE, OPTIONS, else 405 | `nginx-site.conf` `if ($request_method ...)` |
| Body bound 1k outside `/api/`; per API location below | `client_max_body_size` |
| Headers: 1k buffer, at most 4 × 8k | `client_header_buffer_size`, `large_client_header_buffers` |
| Timeouts: header and body 10 s, send 30 s, keepalive 30 s, upstream connect 5 s | `client_*_timeout`, `send_timeout`, `keepalive_timeout`, `proxy_connect_timeout` |
| Redirects never name the internal port | `absolute_redirect off` |
| Dotfiles never served (first regex location) | `location ~ /\.` |
| Path whitelist: `/`, static files, the one status page (the 404 page, an exact location equal to the `error_page 404` target and `STATUS_PAGES.NOT_FOUND`, checked by `make check-hardening`), the API below; everything else 404 | `location / { return 404; }` |
| Rate limit 20 r/s per client (burst 40), per Tor circuit behind the onion listener | `nginx.conf` `limit_req_zone`, [nginx-api-proxy.conf](../../nginx-api-proxy.conf) |
| Onion listener open to the tor container only, PROXY header required | `nginx.conf` `allow ${TOR_IP}; deny all;` |
| Forwarding headers set by nginx alone | [nginx-api-proxy.conf](../../nginx-api-proxy.conf) |
| CSP, Trusted Types, isolation headers | `nginx-site.conf` `add_header` (unchanged) |
| HSTS: one source, every answer of the clearnet listener in production when a listed edge proxy vouched for HTTPS (one year unless `HSTS_MAX_AGE` says otherwise; `0` off); never on the onion listener; the backend sends none | `nginx-site.conf` `add_header Strict-Transport-Security $hsts always;` (server level), `nginx.conf` map `$hsts`, rendered and validated by `nginx-hsts.sh`; `make check-hardening` pins the one directive, the map and the rendering |

**API whitelist.** `/api/` mirrors the [input contract](../api/input-contract.md): one location
per route group, exact anchored paths (`{id}`, `{note}`, `{file}` as canonical UUIDv4), the contract's
methods (HEAD passes with GET and the backend answers it; OPTIONS passes for CORS preflight), and
a body bound at the smallest round size above the contract's. Anything else under `/api/` ends
in `location /api/ { include /etc/nginx/elyrn/api-errors.conf; return 404; }`.

| Paths (`/api/v2/…`) | Methods | Body bound (contract) |
|---|---|---|
| `pow/challenge`, `conversations` | GET | 1k (none) |
| `events` | GET | 1k (none) |
| `me` | GET, DELETE | 1k (123) |
| `login`, `logout`, `invites`, `invites/redeem` | POST | 1k (≤ 292) |
| `register`, `rooms`, `rooms/join` | POST | 2k (≤ 1351) |
| `conversations/{id}/read` | POST | 1k (93) |
| `conversations/{id}/members` | GET, POST | 1k (290) |
| `conversations/{id}/messages`, `…/notes` | GET, POST | 8k (≤ 7873) |
| `conversations/{id}/files`, `…/files/{file}` | GET, POST | 342k (≤ 349695); request and response kept in memory (`client_body_buffer_size 342k`, `proxy_buffers 6 64k`, `proxy_max_temp_file_size 0`), never in a temporary file; at most 4 file requests at once per client address and 32 for all clients together (`limit_conn files_per_client 4`, `limit_conn files 32`, the backend's own bound; one more answers 503 `E_BACKEND_UNAVAILABLE`), and a body stalled 5 s between reads is cut off (`client_body_timeout 5s`); behind it every stored part spends from the account's in-memory daily budget (`FILE_ACCOUNT_DAILY_BYTES`, 429 `E_FILE_BUDGET_SPENT`) |
| `conversations/{id}`, `conversations/{id}/notes/{note}` | DELETE | 1k (none) |

A method outside the list answers 405, as the backend would; an unknown path 404; a body over
the bound 413; each as JSON, `{"success":false,"message":"<sentence>","code":"E_..."}`, the same
shape as the backend's JSON answers plus the code. The backend's gate still checks everything
again, and its own answers reach the client unchanged. `/internal/health` lies outside `/api/`,
so nginx never forwards it; the backend also answers it to loopback peers only, with a status
line and no body (any other peer gets `404`, like an unknown path): `200` when the database answers `SELECT 1` within 3 s and a retention cycle began
within 15 minutes, otherwise `503` (`E_HEALTH_UNAVAILABLE` in the backend log).

## Images

Every base image is pinned by digest (the multi-platform index, so arm64 and amd64 both
resolve). Versions are unchanged; to move one, change the tag and digest together:
`docker buildx imagetools inspect <image>:<tag>` prints the new digest.

| Image | Used by |
|---|---|
| `postgres:15-alpine@sha256:a8e04259…` | `docker-compose.yaml`, `docker-compose.test.yaml` |
| `golang:1.27.4-trixie@sha256:b54b2639…` | `dev.backend.Dockerfile` (build stage), `test.Dockerfile` |
| `debian:trixie-slim@sha256:a72b4433…` | `dev.backend.Dockerfile` (runtime), `tor.Dockerfile` |
| `nginx:1.30-alpine@sha256:583b7f2f…` | `dev.frontend.Dockerfile` |

A pinned base no longer picks up Debian or Alpine security updates by itself: move the digests
on a schedule.

## Known limits

- The backend connects to PostgreSQL as the bootstrap superuser the container creates
  (`DB_USER`, `postgres` in `.env.example`), with every right in the database, not as a role
  limited to reading and writing its tables. Open by decision (D-09 in
  [debt.md](../development/debt.md)): a separate runtime role needs a new secret that existing
  `.env` files lack, so an in-place upgrade would need a manual step.
- PostgreSQL's container can open a TCP connection to the backend over `data` (the backend
  listens on every interface). It is an untrusted client there: its address is not in
  `TRUSTED_PROXIES`. Binding the backend to its `app` address would need a configuration option
  in the backend.
- `edge` has internet access, so nginx does too; it needs none, but tor does and the published
  port needs a gateway.
- tor's healthcheck tests only that the onion address was published (a file). tor offers no
  cheap local test of reachability: proving the address answers would need a client that goes
  out through the Tor network and back (minutes, and traffic that identifies the probe).
  Check it from outside with Tor Browser after `make onion`.

---

### Next Steps:
- Every environment variable: [**Configuration & Tuning**](configuration-and-tuning.md).
- Database TLS and production mode: [**Configuration & Tuning**](configuration-and-tuning.md#database-tls-make-certs).
