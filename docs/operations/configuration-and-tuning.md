# Configuration & Performance Tuning

This document provides a comprehensive reference for all configuration parameters, master key rotation procedures, and memory optimization profiles for production deployments.

---

## Environment Variables Reference

All settings can be configured via `.env` or injected directly as environment variables into the container runtime. Every value is checked at startup against a whitelist or an inclusive range; the backend refuses to start on anything outside it (nothing is silently clamped or truncated).

### 1. Cryptography & Security Secrets

| Variable | Type | Default | Description & Operational Notes |
|---|---|---|---|
| `JWT_SECRET` | string | *Generated* | HMAC-SHA256 signing secret for session tokens (must be >= `JWT_SECRET_MIN_LEN`). |
| `JWT_SECRET_MIN_LEN` | int | `32` | Minimum length for `JWT_SECRET` (32-1024; cannot be lowered below 32). |
| `JWT_ISSUER` | string | `elyrn-backend` | `iss` claim checked on every JWT validation. |
| `JWT_AUDIENCE` | string | `elyrn-web` | `aud` claim checked on every JWT validation. |
| `JWT_EXPIRATION_MINUTES` | int | `15` | Session lifespan (1-1440). Active sessions sliding-refresh past half-life. The token lives only in the HttpOnly cookie. |
| `MASTER_KEY_ACTIVE` | hex/base64 | *Generated* | Active 256-bit key: exactly 32 bytes as 64 hex characters or base64. Text passphrases are rejected. |
| `MASTER_KEY_ACTIVE_ID` | string | *Generated* | Key id stored next to every record (`[A-Za-z0-9._-]`, 1-32 chars, e.g. `key-2026-01`). |
| `MASTER_KEY_OLD` | string | *Empty* | Previous keys as `id1:key1,id2:key2`. Any malformed entry, repeated id or reuse of the active key stops startup. Records still under an old key are re-wrapped to the active key in the background; see the [rotation runbook](#master-key-rotation-runbook). |
| `ACCOUNT_LOOKUP_PEPPER` | hex/base64 | *Generated* | HMAC pepper (>= 32 bytes, hex or base64) for account lookups and pseudonymous tags. **It can never change**: every account is found through it. The database pins a commitment to it, and startup refuses any other pepper. |

At startup the backend checks these keys against the database before it serves anything: every master key id that encrypts records must be configured and must open them, and the pepper must be the one the database was created with. A regenerated `.env`, or an old key removed too early, stops startup with a message naming the key (see [Disaster Recovery](disaster-recovery.md)).

---

### 2. Database Connection

| Variable | Type | Default | Description |
|---|---|---|---|
| `DB_HOST` | string | `localhost` | Database host when connecting from host machine (e.g. `go test`). |
| `DOCKER_DB_HOST` | string | `postgres` | Database host inside Docker network (resolves to PostgreSQL container). |
| `DB_PORT` | int | `5432` | PostgreSQL listening port. |
| `DB_USER` | string | `postgres` | Database user. |
| `DB_PASSWORD` | string | *Generated* | Database password (no default; `make setup` generates one; >= 16 characters in production). |
| `DB_NAME` | string | `elyrn` | Database name. |
| `DB_SSL_MODE` | string | `disable` | libpq sslmode. Production requires `verify-ca` or `verify-full` (an unauthenticated `require` link can be intercepted). The Compose backend ignores this value and always uses `verify-full` against the CA from `make certs` ([Database TLS](#database-tls-make-certs)); the `.env` value serves host-side tools only. |
| `APP_ENV` | string | `development` | `development` (plain `http://localhost`), `test` or `production`; see [Production Mode](#production-mode). The shell's value wins over `.env`. |
| `LOG_LEVEL` | string | `info` | `debug`, `info`, `warn` or `error`; `debug` is refused in production. |

---

### 3. Application Limits & Ephemerality

| Variable | Type | Default | Description |
|---|---|---|---|
| `BACKEND_PORT` | int | `8080` | Port the Go HTTP server listens on. |
| `MAX_REQUEST_BODY_BYTES` | int | `1048576` | Hard ceiling for HTTP request payloads (1 MiB). |
| `MAX_JSON_DEPTH` | int | `2` | Maximum JSON nesting depth to defeat recursive parsing attacks. |
| `INVITE_TTL_SEC` | int | `86400` | Lifetime of unredeemed invites (default 24 hours). |
| `MAX_ACTIVE_INVITES` | int | `5` | Maximum active, unredeemed invites allowed per account. |
| `MAX_CONVERSATIONS_PER_USER` | int | `256` | Maximum conversations allowed per account (1-4096). Lowering it only stops new conversations; accounts already above it keep, burn and delete theirs. |
| `MAX_MESSAGE_BYTES` | int | `8192` | Upper bound for one E2E ciphertext in a one-to-one conversation. Messages come in five padded sizes (284 to 4124 bytes), so values above 4124 change nothing; a lower value drops the larger sizes. Room messages are bounded by their structure instead (`ROOM_MAX_MEMBERS`). |
| `MESSAGE_PAGE_LIMIT` | int | `200` | Maximum messages returned per fetch page (1-1000). |
| `MESSAGE_TTL_DAYS` | int | `7` | Days to retain ciphertext before day-granular deletion (1-365). Lowering it also shortens what is stored: the retention run (every five minutes) caps every stored message at the new limit, counted from that run. Raising it never extends stored messages. |
| `ROOM_MAX_MEMBERS` | int | `16` | Largest room a member may create (2-32). A room message carries one 48-byte wrap per member, so this also bounds its size (5810 bytes at 32); the server refuses to start if such a message would not fit in `MAX_REQUEST_BODY_BYTES`. Lowering it affects new rooms only. |
| `ROOM_MAX_TTL_HOURS` | int | `168` | Longest room lifetime, in hours (1-720). The browser offers 1 hour, 1 day and 7 days within it. A room is deleted, with everything in it, at the hour its code names. |
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
| `ALLOWED_ORIGINS` | list | `http://localhost,http://127.0.0.1` | Exact origins (scheme, host, port) for CORS and the same-origin check on writes. No wildcard or prefix matching. |
| `TRUSTED_PROXIES` | list | nginx (`PROXY_IP`) | IPs/CIDRs allowed to supply the client address. Empty in Docker means "nginx only". |
| `COMPOSE_SUBNET` | CIDR | `172.29.73.0/24` | Docker network range; change it (with `PROXY_IP`, `BACKEND_IP` and `TOR_IP`) if it collides with another network. |
| `PROXY_IP` | IP | `172.29.73.10` | nginx's fixed address on that network. |
| `BACKEND_IP` | IP | `172.29.73.12` | The backend's fixed address. nginx resolves the backend once, at start; a fixed address keeps it reachable after the backend container is recreated. |
| `TOR_IP` | IP | `172.29.73.11` | The tor container's fixed address (`make onion`): the only peer nginx's onion listener accepts. Keep it inside `COMPOSE_SUBNET`. |
| `HTTP_PORT` | int | `80` | Loopback port nginx is published on. |
| `DB_HOST_PORT` | int | `5432` | Loopback port PostgreSQL is published on. |
| `SEC_HEADER_COOP` / `SEC_HEADER_CORP` / `SEC_HEADER_COEP` | string | `same-origin` / `same-origin` / `require-corp` | API isolation headers; `off` disables one. |

---

### 6. Argon2id Key Derivation Tuning

Argon2id runs only in registration phase 2: it hashes the auth key into `account_hash`. Login does not run it (the keyed lookup proves the key), so these settings size sign-up capacity only.

Bounds: memory 8192-1048576 KiB (production floor 19456 KiB, the OWASP minimum), time 1-16, parallelism 1-255, salt and hash 16-64 bytes.


| Variable | Type | Default | High-Security (Default) | Low-RAM VPS (1 GB RAM) |
|---|---|---|---|---|
| `ARGON2_MEMORY_KIB` | int | `65536` | 64 MiB (`65536`) | 32 MiB (`32768`) |
| `ARGON2_TIME` | int | `3` | 3 iterations | 2 iterations |
| `ARGON2_PARALLELISM` | int | `2` | 2 threads | 1 thread |
| `ARGON2_SALT_LENGTH` | int | `16` | 16 bytes | 16 bytes |
| `ARGON2_HASH_LENGTH` | int | `32` | 32 bytes | 32 bytes |
| `ARGON2_MAX_CONCURRENT` | int | `4` | 4 (256 MiB peak) | 2 (64 MiB peak) |

Each Argon2id computation allocates `ARGON2_MEMORY_KIB`; `ARGON2_MAX_CONCURRENT` (1-64) bounds how many run at once, so peak memory is `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB`. A registration phase 2 that cannot get a slot within 3 seconds is answered with `503 Service Unavailable` (its pending registration stays redeemable) instead of growing memory without limit; logins are unaffected.

---

## Production Mode

`APP_ENV=production` changes exactly this, compared with `development`:

| | development | production |
|---|---|---|
| Session cookie | `noaddx_session`, no `Secure` | `__Host-Session`, `Secure`, `HttpOnly`, `SameSite=Strict` |
| Startup checks | ranges and whitelists | the same, plus `DB_SSL_MODE` `verify-ca`/`verify-full`, `DB_PASSWORD` >= 16 characters, `LOG_LEVEL` not `debug`, `ARGON2_MEMORY_KIB` >= 19456 |
| HSTS | never | on API responses that arrived over HTTPS (`X-Forwarded-Proto: https` from a trusted proxy) |
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
An existing installation needs nothing extra: its next `make up` creates `certs/`, and the
database volume, `.env` and accounts are untouched (the volume's own `pg_hba.conf` is ignored).

Host-side clients reach the database through its loopback-published port, with TLS:
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

4. **Wait for the re-wrap to finish.** New records use `key-2026-04` at once. Existing records are opened with the key named by their stored id (nothing is ever trial-decrypted under every key) and re-encrypted under the active key in batches of 100. The log says when it is done:
   ```text
   Master key rotation: 1234 records re-wrapped; no record uses an old key any more, MASTER_KEY_OLD can be emptied
   ```

5. **Remove the old key.** Empty `MASTER_KEY_OLD` (or drop that entry) and restart. Removing a key that records still need is refused at startup, so this step cannot lose data by mistake; the startup log also names every old key that encrypts nothing any more.

What rotation does not change: each account's own server key (it wraps that account's conversation list and peer keys) stays the same, only its wrapping changes. Someone who already held both the old master key and a copy of the database keeps what that copy revealed; rotation protects every copy taken afterwards.

---

## Nginx Security Headers & Trusted Types

The reverse proxy (`nginx-site.conf`, shared by the clearnet and onion listeners in `nginx.conf`) enforces strict browser isolation policies:

```nginx
# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types elyrn-worker;" always;

# Cross-Origin Isolation
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

### Trusted Types Policy
The application registers a single Trusted Types policy in JavaScript (`elyrn-worker`):
```javascript
window.trustedTypes.createPolicy('elyrn-worker', {
    createScriptURL: (url) => {
        if (url !== 'js/pow-worker.js') throw new TypeError('script URL not whitelisted');
        return url;
    }
});
```
This whitelist permits only the background Web Worker script (`js/pow-worker.js`) to be instantiated. Any other DOM sink manipulation throws a browser security exception. Styles follow the same rule: there is no `'unsafe-inline'`, and initially hidden elements are hidden by the stylesheet (`[data-hidden]`), not by inline `style` attributes.

API responses from the backend additionally carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`: they are data, never documents.

---

### Next Steps:
- If encountering runtime or network errors, consult the [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
- To contribute or run tests, read [**Testing & Development**](../development/testing-and-contributing.md).
