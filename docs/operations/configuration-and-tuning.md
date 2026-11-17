# Configuration & Performance Tuning

This document provides a comprehensive reference for all configuration parameters, master key rotation procedures, and memory optimization profiles for production deployments.

---

## Environment Variables Reference

In the Compose stack the backend receives exactly the variables listed under `backend.environment` in `docker-compose.yaml`, each taken from `.env` (or the shell); a variable missing from that list never reaches the container, whatever `.env` says. Three are pinned there and not taken from `.env` at all: `DB_SSL_MODE` (`verify-full`), `PGSSLROOTCERT` (`/etc/elyrn/db-ca/ca.crt`) and `BACKEND_PORT` (`8080`); the database host comes from `DOCKER_DB_HOST`, not `DB_HOST`. A backend run outside Compose reads every variable below from its environment. `EDGE_TRUSTED_PROXIES` goes to nginx, not to the backend. Every value is checked at startup against a whitelist or an inclusive range; the backend refuses to start on anything outside it (nothing is silently clamped or truncated).

### 1. Cryptography & Security Secrets

| Variable | Type | Default | Description & Operational Notes |
|---|---|---|---|
| `JWT_SECRET` | string | *Generated* | HMAC-SHA256 signing secret for session tokens (must be >= `JWT_SECRET_MIN_LEN`). |
| `JWT_SECRET_MIN_LEN` | int | `32` | Minimum length for `JWT_SECRET` (32-1024; cannot be lowered below 32). |
| `JWT_ISSUER` | string | `noaddx-backend` | `iss` claim checked on every JWT validation (the `noaddx` defaults are stored names kept across the rename to elyrn.). |
| `JWT_AUDIENCE` | string | `noaddx-web` | `aud` claim checked on every JWT validation. |
| `JWT_EXPIRATION_MINUTES` | int | `43200` | Session lifespan in minutes (1-525600, i.e. up to 365 days; default 30 days). A session used past half its lifetime is re-issued, so one used at least once every half-lifetime (15 days by default) never ends; logout and account deletion end it at once. The token lives only in the HttpOnly cookie. |
| `MASTER_KEY_ACTIVE` | hex/base64 | *Generated* | Active 256-bit key: exactly 32 bytes as 64 hex characters or base64. Text passphrases are rejected. |
| `MASTER_KEY_ACTIVE_ID` | string | *Generated* | Key id stored next to every record (`[A-Za-z0-9._-]`, 1-32 chars, e.g. `key-2026-01`). |
| `MASTER_KEY_OLD` | string | *Empty* | Previous keys as `id1:key1,id2:key2`. Any malformed entry, repeated id or reuse of the active key stops startup. Records still under an old key are re-wrapped to the active key in the background; see the [rotation runbook](#master-key-rotation-runbook). |
| `ACCOUNT_LOOKUP_PEPPER` | hex/base64 | *Generated* | HMAC pepper (>= 32 bytes, hex or base64) for account lookups and pseudonymous tags. **It can never change**: every account is found through it. The database pins a commitment to it, and startup refuses any other pepper. |

At startup the backend checks these keys against the database before it serves anything: every master key id that encrypts records must be configured and must open them, and the pepper must be the one the database was created with. A regenerated `.env`, or an old key removed too early, stops startup with `E_KEY_CHECK` naming the variable to restore (see [Disaster Recovery](disaster-recovery.md)).

---

### 2. Database Connection

| Variable | Type | Default | Description |
|---|---|---|---|
| `DB_HOST` | string | `postgres` | Database host. `.env.example` sets `localhost` for host-side tools (e.g. `go test`); the Compose backend uses `DOCKER_DB_HOST` instead. |
| `DOCKER_DB_HOST` | string | `postgres` | Database host inside Docker network (resolves to PostgreSQL container). |
| `DB_PORT` | int | `5432` | PostgreSQL listening port. |
| `DB_USER` | string | `postgres` | Database user. |
| `DB_PASSWORD` | string | *Generated* | Database password (no default; `make setup` generates one; >= 16 characters in production). |
| `DB_NAME` | string | `noaddx` | Database name (a stored name, kept across the rename to elyrn). |
| `PGSSLROOTCERT` | path | *unset* | CA that verifies the database server (libpq's variable, read by the driver). The Compose backend sets `/etc/elyrn/db-ca/ca.crt`; when set, it must be a readable PEM certificate. |
| `DB_SSL_MODE` | string | `disable` | libpq sslmode. Production requires `verify-ca` or `verify-full` (an unauthenticated `require` link can be intercepted). The Compose backend ignores this value and always uses `verify-full` against the CA from `make certs` ([Database TLS](#database-tls-make-certs)); the `.env` value serves host-side tools only. |
| `APP_ENV` | string | `development` | `development` (plain `http://localhost`), `test` or `production`; see [Production Mode](#production-mode). The shell's value wins over `.env`. |
| `LOG_LEVEL` | string | `info` | `debug`, `info`, `warn` or `error`; `debug` is refused in production. |

---

### 3. Application Limits & Ephemerality

| Variable | Type | Default | Description |
|---|---|---|---|
| `BACKEND_PORT` | int | `8080` | Port the Go HTTP server listens on (1-65535). Pinned to `8080` in `docker-compose.yaml`: nginx, the healthcheck and the development port mapping all name 8080 inside the container, so the `.env` value only matters for a backend run outside Compose. |
| `MAX_REQUEST_BODY_BYTES` | int | `1048576` | Hard ceiling for HTTP request payloads (1 MiB). |
| `MAX_JSON_DEPTH` | int | `2` | Maximum JSON nesting depth to defeat recursive parsing attacks. |
| `INVITE_TTL_SEC` | int | `86400` | Lifetime of unredeemed invites (default 24 hours). |
| `MAX_ACTIVE_INVITES` | int | `5` | Maximum active, unredeemed invites allowed per account. |
| `MAX_CONVERSATIONS_PER_USER` | int | `256` | Maximum conversations allowed per account (1-4096). Lowering it only stops new conversations; accounts already above it keep, burn and delete theirs. |
| `MAX_MESSAGE_BYTES` | int | `8192` | Upper bound for one E2E ciphertext in a one-to-one conversation. Messages come in five padded sizes (284 to 4124 bytes), so values above 4124 change nothing; a lower value drops the larger sizes. Room messages are bounded by their structure instead (`ROOM_MAX_MEMBERS`). |
| `MESSAGE_PAGE_LIMIT` | int | `200` | Maximum messages returned per fetch page (1-1000). |
| `MESSAGE_TTL_DAYS` | int | `7` | Days to retain ciphertext before day-granular deletion (1-365): a message stored on UTC day D is kept until day D + `MESSAGE_TTL_DAYS` ends, so between `MESSAGE_TTL_DAYS` and `MESSAGE_TTL_DAYS` + 1 days. Lowering it also shortens what is stored: the retention run (every five minutes) caps every stored message at the new limit, counted from that run. Raising it never extends stored messages. |
| `ROOM_MAX_MEMBERS` | int | `16` | Largest room a member may create (2-32). A room message carries one 48-byte wrap per member, so this also bounds its size (5810 bytes at 32); the server refuses to start if such a message would not fit in `MAX_REQUEST_BODY_BYTES`. Lowering it affects new rooms only. |
| `ROOM_MAX_TTL_HOURS` | int | `168` | Longest room lifetime, in hours (1-720). The browser offers 1 hour, 1 day and 7 days within it. A room is deleted, with everything in it, at the hour its code names. |
| `MAX_FILE_BYTES` | int | `10485760` | Largest file one message may announce, in bytes (262144-104857600). Files are stored as sealed parts of 262144 bytes of plaintext each, so this allows `ceil(MAX_FILE_BYTES / 262144)` parts per file; `/me` reports it as `file_max_bytes`. Lowering it affects new uploads only. |
| `FILE_CONVERSATION_QUOTA_BYTES` | int | `104857600` | How many bytes of stored parts one conversation may hold (262144-10737418240), counted as stored parts × 262144, expired parts included until retention removes them. A further upload answers `507 File quota reached`. |
| `FILE_STORE_MAX_BYTES` | int | `2147483648` | How many bytes of stored parts the whole server may hold (262144-1099511627776), counted the same way against an in-process count of stored parts (taken at start, again every retention cycle, kept up to date by uploads and burns). A further upload answers `507 File store full`; so does every upload before the first count (fail closed). Parts are kept like messages (`MESSAGE_TTL_DAYS`) and go with their conversation. |
| `FILE_ACCOUNT_DAILY_BYTES` | int | `104857600` | How many bytes of parts one account may store per day (262144-10737418240, at least `MAX_FILE_BYTES`): a budget of `FILE_ACCOUNT_DAILY_BYTES / 262144` parts that every stored part spends from (an identical resend or a refused part spends nothing) and that refills continuously to full over 24 hours. It lives in memory only, keyed by the account's in-memory stream tag like the rate buckets, so nothing about an account's upload volume is stored; it resets when the server restarts, and the number of budgets is bounded by `RATE_LIMIT_MAX_BUCKETS`: a budget is dropped at cleanup only once it is full again, and when the bound is reached the budget closest to full is evicted (ties: the least recently used), so an evicted account regains at most that budget's deficit, the smallest held, and no account is refused because of others. An empty budget answers `429 File budget spent`. It keeps one account from filling the store; several accounts still can (each costs registration proofs of work). |
| `POW_DIFFICULTY` | int | `20` | Proof-of-work target leading zero bits (18-24). |
| `POW_CHALLENGE_TTL_SEC` | int | `300` | How long an issued challenge stays valid (1-3600). |

---

### 4. Build: Crypto Engine

| Variable | Type | Default | Description |
|---|---|---|---|
| `ENGINE` | `openssl` \| `native` | `openssl` | Crypto engine compiled into the backend (`make up ENGINE=native`). Both are byte-for-byte equivalent; the startup log names the engine and library version. A database written by one build is read by the other. |

### 5. Network, Proxy & Headers

| Variable | Type | Default | Description |
|---|---|---|---|
| `ALLOWED_ORIGINS` | list | `http://localhost,http://127.0.0.1` (`.env.example`; `http://localhost` when unset) | Exact origins (scheme, host, port) for CORS and the same-origin check on writes. No wildcard or prefix matching. |
| `TRUSTED_PROXIES` | list | nginx (`PROXY_IP`) | IPs/CIDRs allowed to supply the client address. Empty in Docker means "nginx only". |
| `COMPOSE_SUBNET` | CIDR | `172.29.73.0/24` | Range of the internal `app` network (nginx and the backend); change it with `PROXY_IP` and `BACKEND_IP` if it collides with another network. See [Hardening](hardening.md#networks). |
| `EDGE_SUBNET` | CIDR | `172.29.72.0/24` | Range of the `edge` network (nginx and tor, the published port); change it with `TOR_IP`. |
| `DATA_SUBNET` | CIDR | `172.29.74.0/24` | Range of the internal `data` network (the backend and PostgreSQL). |
| `PROXY_IP` | IP | `172.29.73.10` | nginx's fixed address on `app`: the address the backend trusts. |
| `BACKEND_IP` | IP | `172.29.73.12` | The backend's fixed address on `app`. nginx resolves the backend once, at start; a fixed address keeps it reachable after the backend container is recreated. |
| `TOR_IP` | IP | `172.29.72.11` | The tor container's fixed address on `edge` (`make onion`): the only peer nginx's onion listener accepts. Keep it inside `EDGE_SUBNET` (it was `172.29.73.11` before the split networks). |
| `HTTP_PORT` | int | `80` | Loopback port nginx is published on (nginx listens on 8080 inside its container). |
| `DB_HOST_PORT` | int | `5432` | Loopback port PostgreSQL is published on, in development only (`docker-compose.dev.yaml`). The backend's 8080 likewise. |
| `BACKEND_MEM_LIMIT` | size | `512m` | The backend container's memory (no swap). Keep it at least `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB` + 128 MiB; `make check-hardening` checks it. |
| `BACKEND_GOMEMLIMIT` | size | `448MiB` | Go runtime soft limit; keep it about 64 MiB under `BACKEND_MEM_LIMIT`. |
| `EDGE_TRUSTED_PROXIES` | list | *empty* | Read by nginx, not the backend: your own TLS reverse proxies in front of nginx (comma-separated IPs/CIDRs, prefix 1 or more). Only a request whose TCP peer is listed may name the client (`X-Forwarded-For`) and the protocol (`X-Forwarded-Proto`, `http` or `https`). A proxy on the same host is seen from the gateway of `EDGE_SUBNET` (`172.29.72.1` by default): list exactly that address. A malformed list stops nginx at start. See [Deployment](deployment.md#4-tls-in-front-of-the-stack). |
| `HSTS_MAX_AGE` | int | *empty* (one year in production) | Read by nginx, not the backend (`nginx-hsts.sh`, at every nginx start): the `max-age` of the `Strict-Transport-Security` header nginx sends on every answer of the clearnet listener (page, static files, API answers, its own error answers) when `APP_ENV=production` and a proxy listed in `EDGE_TRUSTED_PROXIES` said the request came over HTTPS. Empty or unset: 31536000 (one year); `0`: off; at most 63072000 (two years). Never on the onion listener, never in development. A malformed value stops nginx at start. |
| `HSTS_INCLUDE_SUBDOMAINS` / `HSTS_PRELOAD` | bool | `false` | Read by nginx with `HSTS_MAX_AGE`: add `includeSubDomains` / `preload`. `true`/`false` (`1`/`0`, `yes`/`no`, any case); anything else stops nginx at start. `docker-compose.yaml` passes `APP_ENV` and the three `HSTS_*` variables to nginx; the backend no longer reads them. The cross-origin headers of API answers are fixed (`Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, as nginx sends them), not settings; the `SEC_HEADER_*` variables of earlier releases are ignored. |

### 6. Server, Registration & Rate Limits

| Variable | Type | Default | Description |
|---|---|---|---|
| `SERVER_READ_HEADER_TIMEOUT_SEC` | int | `5` | Time to read a request's headers (1-60). |
| `SERVER_READ_TIMEOUT_SEC` | int | `15` | Time to read a whole request (1-300). |
| `SERVER_WRITE_TIMEOUT_SEC` | int | `15` | Time to write an answer (1-300); request database deadlines follow it (below). |
| `SERVER_IDLE_TIMEOUT_SEC` | int | `60` | Keep-alive idle time (1-600). |
| `SERVER_MAX_HEADER_BYTES` | int | `8192` | Largest request header block (1024-1048576). |
| `PENDING_TOKEN_TTL_SEC` | int | `300` | How long a phase-1 registration waits for its phase 2 (30-3600). |
| `PENDING_CLEANUP_INTERVAL_SEC` | int | `60` | How often expired pending registrations are dropped (1-3600). |
| `PENDING_ID_BYTES` | int | `16` | Random bytes in a pending-registration id (16-64). |
| `INTERNAL_ID_LENGTH` | int | `24` | Length of the internal user id (16-24; `users.uuid` holds 24). |
| `RATE_LIMIT_MAX_TOKENS` | int | `20` | Bucket size of the per-client and per-account rate limits (1-10000). |
| `RATE_LIMIT_REFILL_INTERVAL_SEC` | int | `3` | One token comes back every this many seconds (1-3600). |
| `RATE_LIMIT_CLEANUP_INTERVAL_SEC` | int | `300` | How often idle buckets are dropped (1-86400). |
| `RATE_LIMIT_MAX_BUCKETS` | int | `10000` | Most buckets kept at once; past it the limiter fails closed (100-1000000). |

#### Request deadlines follow `SERVER_WRITE_TIMEOUT_SEC`

`SERVER_WRITE_TIMEOUT_SEC` (default 15) is how long the backend may take to write an answer,
counted from the end of the request's headers; an answer written later is dropped with the
connection (behind nginx the client then sees a `502`/`503` from nginx instead of the
backend's own). So that a request stalled on the database still gets its `503`
(`E_STORE_UNAVAILABLE`) in time, the backend derives a request's database deadlines from it,
without any setting of their own:

| Deadline | Rule | Default config (15 s) |
|---|---|---|
| The whole request: every statement and transaction it runs, together, counted from the moment the request reaches its handler chain | write timeout - 3 s, at least 11 s | 12 s |
| One statement, including the wait for a pooled connection (backstop for work bound to no request) | min(15 s, write timeout - 3 s), at least 11 s | 12 s |
| One transaction (backstop, as above) | min(35 s, write timeout - 3 s), at least 11 s | 12 s |

The request deadline is one deadline for everything a request does with the database, so a
request that runs several statements still answers before the write deadline (a per-statement
bound alone would let three slow statements take three times as long). A client that hangs up
does not cancel its request's statements: only the deadline does, so a write is never abandoned
half-way.

The 3 s are what a request keeps for the work before its first statement and for writing the
`503`. The floor of 11 s keeps the backend's deadline above PostgreSQL's own `statement_timeout`
(10 s), so in normal operation the database cancels a slow statement first. Every value from 1
to 300 stays valid: below 14 s the deadlines stay at the floor and the backend logs a warning at
start, because there a stalled request can still outlive the write deadline. From 18 s (statement)
and 38 s (transaction) the deadlines reach their constants and stop growing. Background work
(the startup key check, re-wrapping, retention) keeps 15 s and 35 s whatever this setting is, and
retention's bulk deletes and the migration keep their own longer limits (1 and 5 minutes). The
event stream has no request deadline (it lives for minutes and sets its own write deadline for
every event); its session and member lookups run under the same one database deadline as any
request. No request's database work is cancelled by the client hanging up or by shutdown
beginning: only its deadline ends it.

---

### Startup validation: every variable and its rule

The backend checks every variable it reads, in one place (`backend/internal/database/validate.go`),
before it touches the database. A refusal is one log line with the code `E_CONFIG_INVALID`, the
variable's **name** and its rule, never its value, and the process exits with status 78:

```text
[STARTUP] E_CONFIG_INVALID: an environment variable is missing, malformed or outside its rule; ... [variable MESSAGE_TTL_DAYS] [must be an integer between 1 and 365]
```

| Variable | Rule |
|---|---|
| `APP_ENV` | `development`, `test`, `production` (`prod`) |
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error`; not `debug` in production |
| `JWT_SECRET_MIN_LEN` | 32-1024 |
| `JWT_SECRET` | at least `JWT_SECRET_MIN_LEN` characters |
| `JWT_ISSUER`, `JWT_AUDIENCE` | non-empty |
| `JWT_EXPIRATION_MINUTES` | 1-525600 |
| `MASTER_KEY_ACTIVE` | 32 bytes, hex or base64 |
| `MASTER_KEY_ACTIVE_ID` | `[A-Za-z0-9._-]{1,32}` |
| `MASTER_KEY_OLD` | `id:key` entries, ids as above, no repeat, not the active id or key |
| `ACCOUNT_LOOKUP_PEPPER` | at least 32 bytes, hex or base64 |
| `MAX_REQUEST_BODY_BYTES` | 1024-16777216, and at least 524320 (twice a sealed file part, as for a message) |
| `MAX_JSON_DEPTH` | 1-8 |
| `INVITE_TTL_SEC` | 60-604800 |
| `MAX_ACTIVE_INVITES` | 1-100 |
| `MAX_CONVERSATIONS_PER_USER` | 1-4096 |
| `MAX_MESSAGE_BYTES` | 512-65536, and fits (base64) in `MAX_REQUEST_BODY_BYTES` |
| `MESSAGE_PAGE_LIMIT` | 1-1000 |
| `MESSAGE_TTL_DAYS` | 1-365 |
| `ROOM_MAX_MEMBERS` | 2-32, and a message to a full room fits in `MAX_REQUEST_BODY_BYTES` |
| `ROOM_MAX_TTL_HOURS` | 1-720 |
| `MAX_FILE_BYTES` | 262144-104857600, and at most `FILE_CONVERSATION_QUOTA_BYTES` and `FILE_ACCOUNT_DAILY_BYTES` |
| `FILE_CONVERSATION_QUOTA_BYTES` | 262144-10737418240, and at most `FILE_STORE_MAX_BYTES` |
| `FILE_STORE_MAX_BYTES` | 262144-1099511627776 |
| `FILE_ACCOUNT_DAILY_BYTES` | 262144-10737418240 |
| `POW_CHALLENGE_TTL_SEC` | 1-3600 |
| `POW_DIFFICULTY` | 18-24 |
| `INTERNAL_ID_LENGTH` | 16-24 |
| `ARGON2_MEMORY_KIB` | 8192-1048576 (production: from 19456) |
| `ARGON2_TIME` | 1-16 |
| `ARGON2_PARALLELISM` | 1-255 |
| `ARGON2_SALT_LENGTH`, `ARGON2_HASH_LENGTH` | 16-64 |
| `ARGON2_MAX_CONCURRENT` | 1-64 |
| `PENDING_TOKEN_TTL_SEC` | 30-3600 |
| `PENDING_CLEANUP_INTERVAL_SEC` | 1-3600 |
| `PENDING_ID_BYTES` | 16-64 |
| `RATE_LIMIT_MAX_TOKENS` | 1-10000 |
| `RATE_LIMIT_REFILL_INTERVAL_SEC` | 1-3600 |
| `RATE_LIMIT_CLEANUP_INTERVAL_SEC` | 1-86400 |
| `RATE_LIMIT_MAX_BUCKETS` | 100-1000000 |
| `BACKEND_PORT`, `DB_PORT` | 1-65535 |
| `SERVER_READ_HEADER_TIMEOUT_SEC` | 1-60 |
| `SERVER_READ_TIMEOUT_SEC`, `SERVER_WRITE_TIMEOUT_SEC` | 1-300 |
| `SERVER_IDLE_TIMEOUT_SEC` | 1-600 |
| `SERVER_MAX_HEADER_BYTES` | 1024-1048576 |
| `DB_HOST`, `DB_USER`, `DB_NAME` | non-empty |
| `DB_PASSWORD` | non-empty; production: at least 16 characters |
| `DB_SSL_MODE` | a libpq sslmode; production: `verify-ca` or `verify-full` |
| `PGSSLROOTCERT` | when set: a readable file holding a PEM certificate |
| `ALLOWED_ORIGINS` | comma-separated exact origins `scheme://host[:port]` (http or https), no wildcard, path, query or credentials; at least one. A bad entry is reported by its position |
| `TRUSTED_PROXIES` | comma-separated IP addresses or CIDR ranges (may be empty); a bad entry is reported by its position |

nginx checks its own settings at every start, before it reads its configuration; a malformed
value stops the nginx container with one line naming the setting and its rule (for
`EDGE_TRUSTED_PROXIES`, also the entry it could not read):

| Variable | Rule (nginx) |
|---|---|
| `EDGE_TRUSTED_PROXIES` | comma-separated IPv4/IPv6 addresses or CIDRs, prefix from 1 to the family's width; may be empty (`nginx-edge-proxies.sh`) |
| `APP_ENV` | `development`, `test`, `production` (`prod`), any case (`nginx-hsts.sh`) |
| `HSTS_MAX_AGE` | empty (one year in production) or an integer 0-63072000 without sign or leading zero (`nginx-hsts.sh`) |
| `HSTS_INCLUDE_SUBDOMAINS`, `HSTS_PRELOAD` | empty, `true`, `false`, `1`, `0`, `yes`, `no`, any case (`nginx-hsts.sh`) |

```text
[ERROR] HSTS_MAX_AGE: must be an integer between 0 and 63072000 seconds (0 turns HSTS off; empty means 31536000)
```

`GOMEMLIMIT` is read by the Go runtime itself, which refuses a malformed value before the
backend's code runs. Every other startup failure has its own code too (`E_SELFTEST`,
`E_DB_UNREACHABLE`, `E_SECOND_INSTANCE`, `E_SCHEMA_NEWER`, `E_MIGRATE`, `E_KEY_CHECK`,
`E_LISTEN`); [Disaster Recovery](disaster-recovery.md#startup-refusals) says what to do for each.

---

### 7. Argon2id Key Derivation Tuning

Argon2id runs only in registration phase 2: it hashes the auth key into `account_hash`. Login does not run it (the keyed lookup proves the key), so these settings size sign-up capacity only.

Bounds: memory 8192-1048576 KiB (production floor 19456 KiB, the OWASP minimum), time 1-16, parallelism 1-255, salt and hash 16-64 bytes.


| Variable | Type | Default | High-Security (Default) | Low-RAM VPS (1 GB RAM) |
|---|---|---|---|---|
| `ARGON2_MEMORY_KIB` | int | `65536` | 64 MiB (`65536`) | 32 MiB (`32768`) |
| `ARGON2_TIME` | int | `3` | 3 iterations | 2 iterations |
| `ARGON2_PARALLELISM` | int | `2` (`.env.example`; `4` when unset) | 2 threads | 1 thread |
| `ARGON2_SALT_LENGTH` | int | `16` | 16 bytes | 16 bytes |
| `ARGON2_HASH_LENGTH` | int | `32` | 32 bytes | 32 bytes |
| `ARGON2_MAX_CONCURRENT` | int | `4` | 4 (256 MiB peak) | 2 (64 MiB peak) |

Each Argon2id computation allocates `ARGON2_MEMORY_KIB`; `ARGON2_MAX_CONCURRENT` (1-64) bounds how many run at once, so peak memory is `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB`. The backend container's memory limit (`BACKEND_MEM_LIMIT`, 512 MiB) must hold that peak plus at least 128 MiB. A registration phase 2 that cannot get a slot within 3 seconds is answered with `503 Service Unavailable` (its pending registration stays redeemable) instead of growing memory without limit; logins are unaffected.

---

## Production Mode

`APP_ENV=production` changes exactly this, compared with `development`:

| | development | production |
|---|---|---|
| Session cookie | `noaddx_session`, no `Secure` | `__Host-Session`, `Secure`, `HttpOnly`, `SameSite=Strict` |
| Startup checks | ranges and whitelists | the same, plus `DB_SSL_MODE` `verify-ca`/`verify-full`, `DB_PASSWORD` >= 16 characters, `LOG_LEVEL` not `debug`, `ARGON2_MEMORY_KIB` >= 19456 |
| Published ports | nginx, backend (8080) and PostgreSQL (`DB_HOST_PORT`) on loopback | nginx only ([Hardening](hardening.md#layouts)) |
| HSTS (sent by nginx) | never | on every answer of the clearnet listener whose request a proxy listed in `EDGE_TRUSTED_PROXIES` said came over HTTPS, unless `HSTS_MAX_AGE=0` (one year by default); never on the onion listener |
| Startup log | `Starting elyrn. backend (development)` | `Starting elyrn. backend (production)` and `Production mode validation passed` |

The Compose stack satisfies every production check as generated by `make setup` (the backend
always connects with `verify-full`, the password is 48 hex characters). `make onion` refuses to
start unless `APP_ENV` is `production` (or `prod`). Try it without editing `.env`:
`APP_ENV=production make up`.

Where login works in production mode: a `Secure` cookie is only accepted from a secure context.
Chromium and Firefox treat `http://localhost` as one and keep `Secure` cookies set over it, so
login works there; Safari has historically dropped `Secure` cookies on plain `http://localhost`,
so use `development` (or TLS) for local Safari testing. Tor Browser treats `.onion` as a secure
context, so login works over the onion address (confirm the first login after deploying).

---

## Database TLS (`make certs`)

The backend and the bundled PostgreSQL talk TLS 1.3 only, with both ends checked:

- `make certs` (run by `make setup`, `make up` and `make onion`) creates a private CA and a
  server certificate in `certs/` with `openssl` alone (OpenSSL or LibreSSL). `certs/` is ignored
  by git and by Docker build contexts; the keys are mode 0600 and the directory 0700.

  | File | Mounted into | Validity |
  |---|---|---|
  | `certs/ca.key` | nothing, ever | |
  | `certs/ca/ca.crt` | backend (read-only, `PGSSLROOTCERT`) | 10 years |
  | `certs/postgres/server.crt`, `server.key` | postgres (read-only; the key is copied to a postgres-owned 0600 tmpfs at start) | 2 years |

- PostgreSQL runs with `ssl=on`, `ssl_min_protocol_version=TLSv1.3` and its own read-only
  `pg_hba.conf` ([postgres/pg_hba.conf](../../postgres/pg_hba.conf)): every TCP connection without
  TLS is rejected before authentication. The Unix socket inside the container (healthcheck,
  `make shell-db`, `make backup-accounts`) is unchanged.
- The Compose backend connects with `sslmode=verify-full`: the certificate must chain to the CA
  and name `postgres`.

**Rotation.** `make certs` is idempotent: it changes nothing while both certificates are valid
for more than 30 days, and renews whatever expires sooner (a new CA also re-issues the server
certificate). `make up` passes each certificate's SHA-256 fingerprint as a container label, so
a renewal recreates exactly the container that must load it; the data volume stays. To rotate
now (for example after a leaked key), delete the material and start again:

```bash
rm -rf certs && make up      # new CA and server certificate; postgres and backend are recreated
```

Check validity at any time: `openssl x509 -noout -enddate -in certs/postgres/server.crt`.

**Renewal routine.** `make certs` warns on every run (`[WARN] certs: ... expires within 60
days`) once either certificate is that close to its end, a month before it renews it. Run
`make up` (or `make certs && make up`) at least once a month, for example from a monthly
scheduled job; between 30 days and the end, that run renews and recreates the right container.
A certificate that has expired anyway stops the backend at its next start with
`E_DB_UNREACHABLE` and the detail `TLS: the database certificate has expired`: run `make up`.
A running backend keeps its open connections, but every new one fails until then.
An existing installation needs nothing extra: its next `make up` creates `certs/`, and the
database volume, `.env` and accounts are untouched (the volume's own `pg_hba.conf` is ignored).

In development, host-side clients reach the database through its loopback-published port (`docker-compose.dev.yaml`), with TLS:
`psql "host=localhost port=$DB_HOST_PORT sslmode=verify-full sslrootcert=certs/ca/ca.crt user=postgres dbname=noaddx"`.

---

## Master Key Rotation Runbook

Rotation replaces the master key without losing any record. The backend then re-wraps every record that is still under the old key, so the old key stops protecting anything and can be removed.

### When to Rotate:
- Scheduled compliance policy (e.g., every 90 or 180 days).
- Suspected exposure of `.env` or of a copy of it.

### Step-by-Step Procedure

1. **Generate a fresh 32-byte key:**
   ```bash
   openssl rand -hex 32
   ```

2. **Update your `.env` configuration:**
   Move the current active key to `MASTER_KEY_OLD` and assign the new key to `MASTER_KEY_ACTIVE`:
   ```ini
   # PREVIOUS CONFIG:
   # MASTER_KEY_ACTIVE_ID=key-2026-01
   # MASTER_KEY_ACTIVE=<current 64-hex key>

   # UPDATED CONFIG:
   MASTER_KEY_ACTIVE_ID=key-2026-04
   MASTER_KEY_ACTIVE=<new 64-hex key from openssl rand -hex 32>
   MASTER_KEY_OLD=key-2026-01:<current 64-hex key>
   ```

3. **Restart the backend container:**
   ```bash
   docker compose up -d backend
   ```

4. **Wait for the re-wrap to finish.** New records use `key-2026-04` at once. Existing records are opened with the key named by their stored id (nothing is ever trial-decrypted under every key) and re-encrypted under the active key in batches of 100. A pass interrupted by a database error, or records that do not open, leave `E_REWRAP_INCOMPLETE` in the log and the pass retries by itself with backoff. The log says when it is done:
   ```text
   Master key rotation: 1234 records re-wrapped
   Master key rotation complete: no record uses an old key any more, MASTER_KEY_OLD can be emptied
   ```

5. **Remove the old key.** Empty `MASTER_KEY_OLD` (or drop that entry) and restart. Removing a key that records still need is refused at startup, so this step cannot lose data by mistake; the startup log also counts the old keys that encrypt nothing any more (a count only: key ids stay out of logs; `SELECT DISTINCT master_key_id FROM users` lists the ids still in use).

What rotation does not change: each account's own server key (it wraps that account's conversation list and peer keys) stays the same, only its wrapping changes. Someone who already held both the old master key and a copy of the database keeps what that copy revealed; rotation protects every copy taken afterwards.

---

## Nginx Security Headers & Trusted Types

The reverse proxy (`nginx-site.conf`, shared by the clearnet and onion listeners in `nginx.conf`) enforces strict browser isolation policies:

```nginx
# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types noaddx-worker;" always;

# Cross-Origin Isolation
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

### Trusted Types Policy
The application registers a single Trusted Types policy in JavaScript (`noaddx-worker`, a name the CSP allows and kept across the rename to elyrn.):
```javascript
window.trustedTypes.createPolicy('noaddx-worker', {
    createScriptURL: (url) => {
        if (url !== POW_WORKER_PATH) throw new TypeError('script URL not whitelisted'); // 'js/pow-worker.js'
        return url;
    }
});
```
This whitelist permits only the background Web Worker script (`js/pow-worker.js`) to be instantiated. Any other DOM sink manipulation throws a browser security exception. Styles follow the same rule: there is no `'unsafe-inline'`, and initially hidden elements are hidden by the stylesheet (`[data-hidden]`), not by inline `style` attributes.

### Who sends what

| Header | Page, static files, nginx's own answers | API answers (from the backend, through nginx) |
|---|---|---|
| `Strict-Transport-Security` | nginx, in production over HTTPS vouched for by a listed edge proxy, clearnet listener only (`nginx-hsts.sh`, `$hsts`) | the same nginx header; the backend sends none |
| `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy` | nginx (`nginx-site.conf`, server level) | nginx's copy only: the backend sets the same values (for a backend reached without nginx) and `nginx-api-proxy.conf` hides them, so each arrives exactly once; `make check-hardening` pins it |
| `Content-Security-Policy` | nginx: the site policy above | two policies, on purpose: the backend's and nginx's site policy. A browser enforces every policy it receives, so the effective one is their intersection: an API answer can load and run nothing |
| `Cache-Control` | nginx: `no-cache` on the page and static files (`expires epoch`) | the backend: `no-store` |
| `Clear-Site-Data` | never | the backend, on a successful logout and account deletion only |

API responses from the backend additionally carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`: they are data, never documents.

---

### Next Steps:
- If encountering runtime or network errors, consult the [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
- To contribute or run tests, read [**Testing & Development**](../development/testing-and-contributing.md).
