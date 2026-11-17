# Deployment

How to put an instance on a public server, in the order an operator does it. The stack is the
same one the [Quick Start](../getting-started/quickstart.md) runs; what changes is production
mode, TLS in front of it, and what you watch afterwards.

Two conditions of the design apply to every deployment: there is no forward secrecy, and a
compromised server and the address a client connects from are outside what the project can
change ([threat model](../security/threat-model.md#conditions-of-the-design)). Whoever runs the
server can serve modified client code and sees client addresses; users who need more use the
onion service or a VPN, and can check the served code with `make verify-frontend`.

---

## 1. Prerequisites

- A Linux server with **Docker Engine 28 or newer** and **Docker Compose v2** (`docker compose`):
  the internal networks need `com.docker.network.bridge.gateway_mode_ipv4=isolated`
  ([Hardening](hardening.md#networks)), and the compose files use the top-level `name:` key.
  Check with `docker version` and `docker compose version`;
  [Installation](../getting-started/installation-and-platforms.md#linux-installation-debian-ubuntu-rhel-fedora-arch)
  says how to install them.
- `git`, `make`, `openssl` (OpenSSL or LibreSSL) and `python3` (for `make check-hardening`).
- Memory for Argon2id: the backend container takes 512 MiB by default
  ([Memory sizing](../getting-started/installation-and-platforms.md#memory-sizing--vps-optimization-argon2id)).
- For a clearnet instance: a domain name pointing at the server and a reverse proxy on the host
  that terminates TLS (step 4). For an onion-only instance: nothing more; Tor Browser is the
  client.

The stack publishes one port, nginx's, on `127.0.0.1` only. Nothing in it listens on a public
interface; the public side is your reverse proxy or the onion service.

## 2. Configuration (`make setup`)

```bash
git clone <repository> elyrn && cd elyrn
make setup        # .env with fresh secrets (mode 0600) and the database TLS certificates in certs/
```

`make setup` writes every secret: `JWT_SECRET`, `ACCOUNT_LOOKUP_PEPPER`, `MASTER_KEY_ACTIVE`,
`MASTER_KEY_ACTIVE_ID` and `DB_PASSWORD`. Never type your own values for them and never reuse a
`.env` from another instance. Then set in `.env`:

| Variable | Value for a public instance |
|---|---|
| `APP_ENV` | `production`: the `__Host-Session` cookie with `Secure`, and the production startup checks ([Production Mode](configuration-and-tuning.md#production-mode)). Required by `make onion` |
| `ALLOWED_ORIGINS` | the exact origin users open, `https://` and the host name, no path and no trailing slash. For an onion-only instance, the `http://<address>.onion` origin once `make onion-address` has printed it |
| `HTTP_PORT` | the loopback port nginx is published on (default 80). Set another one (for example `8088`) when your reverse proxy itself listens on port 80 of the host |
| `LOG_LEVEL` | `info` (the default); `debug` is refused in production |
| `EDGE_TRUSTED_PROXIES` | behind your own TLS reverse proxy: that proxy's address as nginx sees it (on the same host, the gateway of `EDGE_SUBNET`, `172.29.72.1` by default); see [section 4](#4-tls-in-front-of-the-stack). Empty for an onion-only instance |

Leave `TRUSTED_PROXIES` empty: the backend trusts nginx's fixed address alone. Every other
variable has a working default ([Configuration & Tuning](configuration-and-tuning.md)); in the
Compose stack only the variables `docker-compose.yaml` lists reach the backend.

Copy `.env` to offline storage now, apart from any database backup: without it the database can
never be opened again, and together with a database copy it links accounts to their
conversations ([Disaster Recovery](disaster-recovery.md#what-must-survive)).

## 3. Start (`make up`) and what healthy looks like

```bash
make up                 # clearnet: production layout, nginx alone published on 127.0.0.1:HTTP_PORT
make onion              # instead, for an onion service (also usable together with a clearnet proxy)
make onion-address      # the .onion address, about a minute after the first start
```

Healthy:

```bash
make ps                 # every container "Up (healthy)"; tor only with make onion
make check-hardening    # [OK]: the rendered config keeps every container control
make logs               # the backend logs "Production mode validation passed" and
                        # "Server is ready to accept connections"
```

The probes of the [Quick Start](../getting-started/quickstart.md#sanity--health-checks), against
the loopback port on the server and then through the public origin:

```bash
curl -i http://127.0.0.1:8088/api/v2/me                  # your HTTP_PORT; 401, body "Unauthorized" (the backend answered)
curl -i https://chat.example.org/api/v2/me               # the same, through your proxy
curl -i https://chat.example.org/api/v2/unknown          # 404 JSON with "code":"E_EDGE_NOT_FOUND" (nginx's whitelist)
docker compose exec backend wget -q -S -O /dev/null http://127.0.0.1:8080/internal/health   # 200
make verify-frontend URL=https://chat.example.org         # against the frontend.sha256 of the release you run
```

Then open the origin in a browser, create an identity and log in once: the `Secure` cookie must
survive a reload.

## 4. TLS in front of the stack

nginx inside the stack speaks plain HTTP only. Browsers need a secure context for WebCrypto, so a
public instance is reached either through **your own TLS reverse proxy** on the host, forwarding
to `127.0.0.1:HTTP_PORT`, or through the **onion service** (`make onion`), which Tor Browser
treats as secure and which needs no certificate.

A minimal nginx on the host (certificates from your ACME client; `HTTP_PORT=8088` and
`EDGE_TRUSTED_PROXIES=172.29.72.1`, the gateway of the default `EDGE_SUBNET`, in `.env`):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name chat.example.org;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name chat.example.org;
    ssl_certificate     /etc/letsencrypt/live/chat.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    access_log off;                               # the stack keeps no access log; keep none here either

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-For $remote_addr;   # replace, never append
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;                      # the event stream (/api/v2/events) must not wait in a buffer
        proxy_read_timeout 15m;                   # a stream lives up to 10 minutes, with a ping every 10 s
    }
}
```

What the proxy must keep: one origin for the page and `/api/` (the backend refuses cross-origin
writes), no buffering of `/api/v2/events`, and request bodies (the largest is under 8 KiB). Its
own logs see every client address: switch them off or keep them as short as you can.

**The event stream must pass unbuffered.** A proxy that buffers `/api/v2/events` holds every
event until its buffer fills or the stream ends, so new messages wait. The stack's nginx answers
the stream with `X-Accel-Buffering: no`, which an nginx in front honours by itself; any other
proxy (a CDN, a cloud load balancer, a tunnel) must be told not to buffer that path in its own
settings. When a proxy holds the stream anyway, the page notices within 25 seconds of silence
(the server sends a `ping` every 10 s) and fetches its updates about every 5 seconds until the
stream delivers again, so messages arrive late rather than never.

**Client address and protocol.** nginx inside the stack takes the client address from
`X-Forwarded-For` and the protocol (`http` or `https`) from `X-Forwarded-Proto` only for a
request whose TCP peer is listed in `EDGE_TRUSTED_PROXIES` (comma-separated addresses or CIDRs
with a prefix of 1 or more; empty by default). A proxy on the same host reaches nginx from the
edge network's gateway, the first address of `EDGE_SUBNET` (`172.29.72.1` by default): list
exactly that address, never the whole subnet. From any other peer both headers are ignored and
nginx passes on the peer's address and its own `$scheme`. The list is rendered by
`nginx-edge-proxies.sh` at every nginx start; a malformed entry stops the nginx container with a
message naming the setting. The example replaces `X-Forwarded-For` with the address it sees
instead of appending to it.

> **Behind your own proxy, `EDGE_TRUSTED_PROXIES` is not optional.** Left empty, nginx cannot
> tell who the client is or that the request came over HTTPS. Then:
> - **every user shares one address**: one rate-limit bucket in nginx and in the backend (a busy
>   instance answers `429` to everyone), one per-network event-stream allowance (16 streams for
>   the whole instance, after which nobody gets live updates), and one per-address file request
>   allowance;
> - **no HSTS is sent**, because nginx never learns that the request was HTTPS.

**HSTS.** nginx is the one source of `Strict-Transport-Security`: it sends it on every answer of
the clearnet listener (the page, static files, API answers, its own error answers) when
`APP_ENV=production` and a proxy listed in `EDGE_TRUSTED_PROXIES` said the request came over
HTTPS, with `max-age` from `HSTS_MAX_AGE` (empty: one year, 31536000; `0`: off; at most
63072000) and `includeSubDomains` / `preload` from `HSTS_INCLUDE_SUBDOMAINS` / `HSTS_PRELOAD`.
It is never sent on the onion listener, in development, or for a request whose protocol no
listed proxy vouched for. The backend sends none. `nginx-hsts.sh` checks the four settings at
every nginx start; a malformed value stops nginx with a message naming it
([Configuration](configuration-and-tuning.md#5-network-proxy--headers)). If your proxy sends the
header itself, set `HSTS_MAX_AGE=0` so the browser gets one copy.

## 5. Upgrades

```bash
make backup-accounts    # first: the accounts, in case the upgrade must be rolled back
git pull
make up                 # make onion for an onion instance
make logs
```

`make up` rebuilds what changed and recreates the containers; volumes, `.env` and `certs/` stay.
What happens by itself:

- **Schema.** The backend migrates its database at start under a migration lock and logs
  `Database schema migrated from version N to M` (or `Database migrations completed (schema
  version M)` when nothing changed). A failed migration is rolled back (`E_MIGRATE`). An older
  release refuses a database a newer one migrated (`E_SCHEMA_NEWER`): rolling back the code
  means restoring the accounts backup into an empty instance, not starting the old image on the
  new database.
- **Networks.** An installation from before the split networks is stopped once and moved
  (`make up` runs `migrate-networks`; volumes stay).
- **Certificates.** `make certs` runs with every `make up` and renews what expires within 30
  days.

`make setup` never touches an existing `.env`. A release that adds a variable lists it in
`.env.example` and the changelog; add it to `.env` by hand. Read
[CHANGELOG.md](../../CHANGELOG.md) before every upgrade.

## 6. Backups and the restore drill

Back up the accounts, never the messages, and keep `.env` apart from them:

```bash
make backup-accounts    # backups/accounts-<UTC time>.sql, mode 0600
```

What is backed up, why messages are not, and how to restore onto an empty instance:
[Disaster Recovery](disaster-recovery.md#backups-accounts-only) and
[Restoring onto an empty instance](disaster-recovery.md#restoring-onto-an-empty-instance). An
onion instance also keeps its address key in the `tor_data` volume
([Onion key](onion-service.md#the-onion-address-key)). `make test-restore` runs the whole cycle
in a disposable test stack, without touching your volumes.

Never run `make clean` on a server you mean to keep: it deletes every volume, so every account,
every conversation and the onion key.

## 7. What to monitor

**Container health.** `make ps` (or `docker ps`): every service has a healthcheck and the restart
policy `unless-stopped`. The backend's (`/internal/health`) fails when the database does not
answer `SELECT 1` within 3 s or retention has not begun a cycle in 15 minutes; its log then
carries `E_HEALTH_UNAVAILABLE`. A database outage answers `503` (`E_STORE_UNAVAILABLE`) on every
route.

**Operator codes.** Failures no request answers are registered in
`backend/internal/apperr/opcode/opcode.go` and appear in the backend log as `E_...: <sentence>`.
The sentence says what to do; in short:

| Code | What it means | What to do |
|---|---|---|
| `E_SELFTEST` | The compiled crypto engine failed its known-answer self-test at start. | Do not run this binary; rebuild from a release (`make build`) and start again. |
| `E_CONFIG_INVALID` | A variable is missing, malformed or outside its rule; the line names it, never its value. | Correct it in `.env` ([rules](configuration-and-tuning.md#startup-validation-every-variable-and-its-rule)) and start again. |
| `E_DB_UNREACHABLE` | The database accepted no connection within the startup wait. | Check that PostgreSQL runs (`make ps`), the `DB_*` settings and the TLS material (`make up` renews it); the restart policy retries. |
| `E_SECOND_INSTANCE` | Another backend already runs on this database. | Exactly one may run: stop the other one. |
| `E_SCHEMA_NEWER` | A newer elyrn migrated this database. | Run that version or a newer one. |
| `E_MIGRATE` | The schema migration failed and was rolled back; nothing changed. | Read the SQLSTATE in the line, fix the database (disk space, permissions), start again. |
| `E_KEY_CHECK` | The keys in `.env` do not open this database. | Restore the `.env` that belongs to it; never start with new keys ([Disaster Recovery](disaster-recovery.md)). |
| `E_LISTEN` | The backend could not listen on its port, or the listener failed. | Another process may hold the port; the restart policy retries. |
| `E_CLOCK_JUMP` | The system clock jumped, or is behind or far ahead of the last retention pass. | Retention pauses so nothing is deleted early; fix time synchronisation (NTP). It resumes by itself. |
| `E_JOB_ABANDONED` | A critical background job kept failing; the server exits so the restart policy starts it again. | If it repeats, read the panic lines above it. |
| `E_INSTANCE_LOCK_LOST` | The connection holding the single-instance lock is gone (database restarted, network failed). | Nothing: the server stops and its restart policy starts it under a fresh lock. If it repeats, check the database and the network. |
| `E_INSTANCE_LOCK_UNREACHABLE` | The database stopped answering on the lock's open connection; the server keeps running and requests answer `503`. | If it lasts, check that PostgreSQL runs and is not paused, and the network between them. |
| `E_SHUTDOWN_LATE` | Background work outlived the shutdown deadline; keys were zeroized and the server exited anyway. | If it repeats, read the lines above it. |
| `E_REWRAP_INCOMPLETE` | Records still use an old master key after a re-wrap pass; it retries by itself. | Keep that key in `MASTER_KEY_OLD` until the line stops ([rotation](configuration-and-tuning.md#master-key-rotation-runbook)). |
| `E_PEPPER_UNVERIFIED` | Accounts exist but nothing stored proves the pepper yet; it is pinned at the first login of an existing account. | If nobody can log in, the pepper is wrong: restore the original from the `.env` backup. |

The startup codes end the process with status 78 and repeat on every restart until their cause
is fixed ([Startup refusals](disaster-recovery.md#startup-refusals)).

**Certificate expiry.** `make certs` (run by every `make up`) prints
`[WARN] certs: ... expires within 60 days` once a database certificate nears its end and renews
it within 30 days. Run `make up` at least monthly, for example from a scheduled job
([Database TLS](configuration-and-tuning.md#database-tls-make-certs)). Your public TLS
certificate is your proxy's and your ACME client's job.

**Disk.** Container logs rotate (3 × 10 MB per container); the database volume grows with
accounts and with messages until retention deletes them. Watch free space on the Docker data
directory (`docker system df -v` shows the volume sizes); a full disk stops the database, and the
backend then answers `503`.

## 8. Single instance only

Exactly one backend may run on one database: proofs of work, pending registrations, live events
and rate limits live in its memory. A second one exits at start with `E_SECOND_INSTANCE`. Scale
up (memory, CPU), not out, and do not put two stacks behind one origin
([Single-instance operation](disaster-recovery.md#single-instance-operation)).

---

### Next Steps:
- Every variable: [**Configuration & Tuning**](configuration-and-tuning.md).
- What each container may do: [**Container Hardening**](hardening.md).
- Publishing over Tor: [**Onion Service**](onion-service.md).
- When something fails: [**Disaster Recovery**](disaster-recovery.md) and the [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
