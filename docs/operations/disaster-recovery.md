# Disaster Recovery & Failure Handling

The database is useless without the keys in `.env`, and the keys are useless without the
database. Most failures heal by themselves; a few cannot be undone by design. This page lists
what each failure looks like, what the system does about it, and what is left to you.

---

## What must survive

| Asset | Where it lives | If it is lost | If it leaks |
|---|---|---|---|
| `MASTER_KEY_ACTIVE` / `MASTER_KEY_OLD` | `.env` (0600) | Every account key, conversation list and member reference is unreadable for good. No recovery exists, by design. | With a copy of the database: who talks to whom (never message content). [Rotate](configuration-and-tuning.md#master-key-rotation-runbook). |
| `ACCOUNT_LOOKUP_PEPPER` | `.env` (0600) | No account can be found again. No recovery. | With a copy of the database it links accounts to their conversations, like the master key. It **cannot be rotated**: the only remedy is a new instance. |
| `JWT_SECRET` | `.env` (0600) | Everyone is logged out once; nothing else is affected. | Sessions can be forged until it is replaced. Replace it and restart: every session ends, accounts are untouched. |
| `postgres_data` volume | Docker volume | Every account and conversation is gone; users create new identities. | See the database thief in the [threat model](../security/threat-model.md). |
| `certs/` (database CA and server key) | Host directory, 0700, outside git and images (`make certs`) | Nothing is lost: the next `make up` creates new ones and recreates postgres and the backend. | Someone on the compose network could pose as the database to the backend. Rotate: `rm -rf certs && make up`. |
| `tor_data` volume | Docker volume (`make onion`) | The onion address changes. It is **not** in `make backup-accounts`: to keep the address, copy the volume's `noaddx/hs_ed25519_secret_key` (with `docker run --rm -v noaddx_tor_data:/d ...`) offline, apart from everything else. | Someone can impersonate the onion address. See [the onion address key](onion-service.md#the-onion-address-key). |
| An account number | The user's password manager | That identity is gone. There is no recovery, by design. | Full control of that identity: its conversations and its deletion. |

The backend checks `.env` against the database at every start: every master key id that
encrypts records must be configured and must open them, and the pepper must match the one the
database pinned at its first run. A regenerated `.env` or an old key removed too early stops the
start with `E_KEY_CHECK`, naming the variable (never a key or a key id):

```text
E_KEY_CHECK: the keys in .env do not open this database ... [variable MASTER_KEY_OLD] [records are encrypted under a master key id that is not configured: restore that key as MASTER_KEY_ACTIVE or in MASTER_KEY_OLD (the ids in use: SELECT DISTINCT master_key_id FROM users)]
E_KEY_CHECK: the keys in .env do not open this database ... [variable ACCOUNT_LOOKUP_PEPPER] [is not the pepper this database was created with: restore the original (it can never change, every account is keyed by it)]
```

A database whose accounts predate the pepper check and whose conversations cannot prove the
pepper yet starts anyway, with `E_PEPPER_UNVERIFIED` at every start until they can. The first
such start stores the highest account id as the floor (`pepper-floor` in `key_checks`); only
conversations of accounts at or below it prove or contradict the pepper, because nobody can log
in to them under a wrong pepper. Accounts registered meanwhile, possibly under a wrong pepper,
can therefore neither pin it nor lock the right one out. If nobody can log in, the pepper is
wrong: restore the original.

Restore the `.env` that belongs to this database. If that `.env` is lost for good, nothing in
the database can be read again: `make clean` deletes every volume, then `make setup` starts a
new instance.

---

## Startup refusals

Every refused start is one log line, `[STARTUP] E_...: <what to do> [variable NAME] [detail]`,
and exit status 78; values, keys, user names, host names and driver error texts never appear.
The restart policy tries again, so a refusal repeats until its cause is fixed.

| Code | Cause | Your part |
|---|---|---|
| `E_SELFTEST` | The compiled crypto engine gave a wrong known answer. | Do not run this image; rebuild it (`make build`). |
| `E_CONFIG_INVALID` | A variable is missing, malformed or outside its rule (named in the line). | Correct it in `.env`; rules: [Configuration](configuration-and-tuning.md#startup-validation-every-variable-and-its-rule). |
| `E_DB_UNREACHABLE` | No connection within 60 s (retried with backoff from 1 s to 10 s), or one that waiting cannot fix: the detail says `connection refused`, `SQLSTATE 28P01` (password), `3D000` (database), or `TLS: ... expired` / `does not verify`. | Start PostgreSQL, fix the `DB_*` settings, or run `make up` (renews the certificates). |
| `E_SECOND_INSTANCE` | Another backend already holds this database (below). | Stop the other one. |
| `E_SCHEMA_NEWER` | The database was migrated by a newer elyrn (`schema-version` in `key_checks`). | Run that version or a newer one; never an older one against it. |
| `E_MIGRATE` | The migration failed and was rolled back (nothing changed); the detail is the SQLSTATE. | Fix the cause (disk, permissions), start again. |
| `E_KEY_CHECK` | The keys in `.env` do not open this database (above). | Restore the `.env` that belongs to it. |
| `E_LISTEN` | The port is in use, or the listener failed. | Free the port. |

## Single-instance operation

Exactly one backend may run on a database. Proofs of work, pending registrations, the live-event
hub and the rate limits live in the backend's memory, so two of them behind one address would
let a proof of work be spent twice and split everyone's limits. The running backend holds a
PostgreSQL advisory lock on its own connection for its whole life; a second one exits at start
with `E_SECOND_INSTANCE`. If that connection is lost (PostgreSQL restarted, the network failed),
the backend shuts down in order and exits with `E_INSTANCE_LOCK_LOST` rather than take the lock
again, because another backend may already have taken it in between; its restart policy starts
it again, and it waits up to 60 s for the database like any start. Two instances that start at
the same moment also serialise their migrations on a second, transaction-level lock.

## Backups: accounts only

Back up `.env` offline, **apart from** any copy of the database: together they reveal the
social graph.

Never back up messages, conversations or rooms. Messages expire after `MESSAGE_TTL_DAYS`, rooms
at the hour their code names, and a burned conversation must stay gone; restoring a full dump
would bring them back. What is worth keeping is the accounts, so that users keep their
identities after a lost disk:

```bash
make backup-accounts
```

This writes `backups/accounts-<UTC time>.sql` (mode 0600, ignored by git) with two tables:
`users` (account lookups, Argon2id hashes, public keys, wrapped account keys, encrypted
conversation lists, session epochs) with its id sequence `users_id_seq` and its position
(`pg_dump --table` dumps a table's owned sequence with it), and `key_checks` (the pepper
commitment and floor, the schema version, the retention mark). Keep few, short-lived copies: a
restore also brings back every account deleted after the backup was taken.

| Backed up | Not backed up (by design) |
|---|---|
| `users` and `users_id_seq`, `key_checks` | messages, conversations, memberships, invites, rooms, room notes |
| | `.env` and `certs/` (keep `.env` offline, apart; `certs/` is recreated by `make certs`) |
| | `tor_data` (the onion address key; see the table above) |

`make test-restore` proves the cycle without touching any real volume: in the disposable test
stack (`docker-compose.test.yaml`, its database on tmpfs) it registers an account, dumps with the
very command `make backup-accounts` uses, empties the database, restores the dump as below, then
starts on it (key check and migration), logs in with that account and registers a new one (the
restored sequence must not hand out an existing id).

### Restoring onto an empty instance

The tables must be restored **before the backend first starts**, so the backend checks the
restored pepper commitment instead of pinning a new one:

```bash
cp /safe/place/.env .env                     # the .env of the instance that wrote the backup
make certs                                   # database TLS material (new certificates are fine)
docker compose up -d postgres                # database only, no backend yet
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backups/accounts-<time>.sql
make up
```

Users log in with their account numbers as before. Their conversations are gone; the stale
entries in their encrypted conversation lists are dropped at their first listing.

### Rolling back the whole volume

Restoring a snapshot of the entire `postgres_data` volume (a filesystem or VM snapshot) is a
different thing, and mostly a worse one: it brings back every message, conversation and room
that existed then, including burned ones and expired ones (retention deletes them again at its
next cycle, five minutes after the start, unless the clock check pauses it: the restored
retention mark is older than the clock, which is fine). It also rewinds two counters:

- `users.session_epoch`: logging out bumps it to revoke every session. A rollback restores the
  older value, so a session token issued before a logout that happened after the snapshot is
  valid again until it expires (`JWT_EXPIRATION_MINUTES`, 15 by default). Replace `JWT_SECRET`
  after such a rollback to end every session at once.
- `users_id_seq` and each conversation's `last_seq`: they rewind with their tables, consistently,
  so ids are never reused within the restored data; clients that held newer message numbers see
  them again under the same numbers with other content and reload.

Prefer the accounts backup; roll back a full volume only to undo damage to the volume itself.

---

## What happens when…

| Failure | What users see | What the system does | Your part |
|---|---|---|---|
| PostgreSQL stops or restarts | Every request, login included, answers `503` "service unavailable" (`E_STORE_UNAVAILABLE`), never "invalid credentials", never a logout. Sending says "message not sent". A registration in progress keeps its account number. | The backend keeps running and reconnects by itself; PostgreSQL restarts itself (`restart: unless-stopped`). Connection errors, a server shutting down or out of connections, and every timeout below are all classified as an outage in one place (`backend/internal/database/errors.go`). | Usually nothing; `docker compose logs postgres`. |
| The host reboots | A short outage. | Every service comes back by itself. | Nothing. |
| The backend restarts or is upgraded | Live updates pause and reconnect (backoff up to 30 s, 8 tries; bringing the tab back to the foreground reconnects too). Sessions survive. | nginx reaches the recreated container at its fixed address (`BACKEND_IP`). In-memory state starts over: issued proofs of work, rate limits, and account numbers shown but not yet confirmed. | Nothing. A user who was between "copy" and "continue" is told the number expired and gets a new one. |
| An answer is lost while sending | The message arrives once. | The retry resends the same message id and ciphertext; the server refuses the duplicate id (409), which the client takes as delivered. A 409 on a first attempt (no earlier answer was lost) is never taken as delivered: the user is told to send again. | Nothing. |
| An answer is lost while deleting an identity | The identity is deleted, or the user is told it was not, or that it is unknown and what to do. | The browser asks `/me`: `401` means the identity is gone (the local wipe finishes), `200` means it is still there; no answer leaves it unknown. | Nothing. |
| An answer is lost while creating an account | The account opens. | The retry finds the registration used up, logs in with the number on screen, and enters the app. | Nothing. |
| Argon2id saturated (signup flood) | "server busy" on sign-up only; logins are unaffected. A registration in progress keeps its account number. | At most `ARGON2_MAX_CONCURRENT` hashes run at once; the rest wait up to 3 s, then get 503. | Tune the [Argon2id limits](configuration-and-tuning.md). |
| The backend is stopped (`make down`, an upgrade, SIGTERM) | Live updates reconnect; a request that arrives in the last moment gets `503`. | In-flight requests get 10 s, background jobs 5 s more; then the database pool and the instance lock are closed and the master keys zeroized last. A request still running then is refused (`E_SHUTTING_DOWN`, 503) instead of sealing anything under a zeroized key. Compose waits 30 s (`stop_grace_period`) before it kills. | Nothing. `E_SHUTDOWN_LATE` in the log means a job outlived its 5 s. |
| A transaction hangs on a lock, a query runs away, or the database stops answering | That request fails with `503`. | Sessions give up waiting for a lock after 5 s, cancel a statement after 10 s (`statement_timeout`) and drop a transaction left idle for 30 s. The backend itself gives up on a statement (including the wait for a pooled connection) after 15 s and on a transaction after 35 s, so neither a full pool nor an unreachable server holds a request for ever. Retention's bulk deletes may run 1 minute each. | Nothing. |
| The system clock jumps (forward or back) | Nothing: an expired message is never served, whether or not it has been deleted yet. Sessions: see below. | Retention deletes by the clock, so it checks the clock first: a cycle in which the wall clock moved differently from the time that passed, or that is behind the last retention pass, or (at startup) far ahead of it, deletes nothing and logs `E_CLOCK_JUMP`. Retention resumes once the clock is steady and has caught up with the last pass (kept in `key_checks` as `retention-clock`). The same detector pauses forgetting spent proofs of work, so none can be replayed after the clock is set back. | Fix time synchronisation (NTP). If the clock was far in the future and retention ran then, it stays paused until real time passes that moment; after fixing the clock you may delete the mark: `DELETE FROM key_checks WHERE name = 'retention-clock';` |
| A background job keeps crashing | A short outage while the backend restarts. | Retention, key re-wrapping and PoW cleanup are restarted after a panic (backoff from 1 s, at most 5 times); a job that still fails is abandoned and the backend exits with status 70 (`E_JOB_ABANDONED`) so the restart policy starts a fresh process instead of running without it. | Read the panic lines before `E_JOB_ABANDONED` in `docker compose logs backend`. |
| A request handler panics | That request answers `500` "Internal server error". | The panic is recovered (`E_PANIC`), its stack is logged without any request data, and the server keeps serving. | Report the logged stack. |
| The disk fills up | Sending fails (`503`). | PostgreSQL refuses writes (SQLSTATE `53100`); deletes need room in the write-ahead log too, so retention's cycles fail as well and are logged and retried every five minutes until there is room; a completely full disk can stop PostgreSQL itself, which then restarts. Logs cannot be the cause: every container's log rotates (3 × 10 MB, Docker's `local` driver) and repeated warnings are bounded (20 per message per minute, then one "suppressed" line). | Free space; PostgreSQL and retention recover by themselves. |
| `MAX_CONVERSATIONS_PER_USER` or `MESSAGE_TTL_DAYS` lowered | Nothing breaks. | Accounts above the new cap keep their conversations; stored messages are capped at the new retention. | Nothing. |
| The master key may have leaked | Nothing. | After rotation every record is re-wrapped under the new key in the background. A pass that a database error interrupted, or that left records it could not open, is repeated (after 1 min, doubling up to 1 h) and logs `E_REWRAP_INCOMPLETE` until no record names an old key. | Follow the [rotation runbook](configuration-and-tuning.md#master-key-rotation-runbook); remove the old key only once `E_REWRAP_INCOMPLETE` has stopped. |
| The database's TLS certificate is about to expire | Nothing yet. | `make certs` and `make up` warn 60 days ahead and renew 30 days ahead. Once expired, the next backend start fails with `E_DB_UNREACHABLE` (`TLS: ... expired`). | Run `make up` at least monthly ([renewal routine](configuration-and-tuning.md#database-tls-make-certs)). |
| The backend is unhealthy | Requests may fail. | The healthcheck (`/internal/health`, loopback only, every 30 s) answers 503 when the database does not answer `SELECT 1` within 3 s or retention has not cycled for 15 minutes; `docker compose ps` shows `unhealthy`. Docker does not restart an unhealthy container by itself. | `docker compose logs backend`; restart it if it stays unhealthy. |

### Sessions and the clock

Session tokens carry `iat`, `nbf` and `exp` from the wall clock and are checked against it, so a
clock jump affects sessions only, never data: a clock set **forward** past `exp` (15 minutes by
default) ends every session (users log in again); a clock set **back** makes newly issued tokens
look issued in the past, and tokens issued while the clock was ahead are refused as not yet
valid (`nbf`) until the clock catches up, so those users log in again. Nothing is stored by
these times, and revocation (`session_epoch`) does not depend on the clock. Fix the time
synchronisation; no other action is needed.

---

### Next Steps:
- Every environment variable: [**Configuration & Tuning**](configuration-and-tuning.md).
- What a stolen database reveals: [**Threat Model**](../security/threat-model.md).
- Symptoms and fixes: [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
