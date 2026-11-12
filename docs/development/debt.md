# Debt and Decisions

The single record of what is loose, what was decided and what is unverified. Newest first
inside each section. An entry leaves only when its fix is verified, never when it is merely
written. Ids are stable.

## State (13 Nov 2026)

- Branch `elyrn` (local, from `noaddx-dev` a3c812f), nothing pushed. Full verification passed three
  times on 12 Nov, last at dc8b15f: frontend 59/59, complete Go suite on both engines, engine
  equivalence, `make check-hardening`, gofmt, vet and staticcheck on both tag sets; race detector on
  both engines at f26b14d. First run found 53 failures (stale PoW test helper after S-03, MCP test
  setup, doc not in the test image, two real MCP bugs: arguments used before validation, `room_read`
  ignoring `before`); all fixed (5bef96f..1456cd7).
- Live tour (12 Nov, partial): robot entrance, agent identity/create/join/send/read/paging/wait over
  MCP against the running stack, browser register/join/send, hostile join codes. It found S-10.
  Not toured yet: hostile message inputs (re-run), earlier-messages button, pairing by invite,
  friend requests, delete identity, logout, lookalike and replay warnings in the browser.
- Situation-handling audit (12 Nov, two read-only auditors, by reading code): 17 server/deploy,
  17 browser, 8 agent findings below. Fixes are being written; none is verified.
- Rooms (a3c812f) are on `origin/noaddx-dev`, verified there on both engines, not merged to `main`.

## Open findings

| Id | Class | Finding | Fix | State |
|---|---|---|---|---|
| S-01 | security | Room messages name the sender by a 12-bit aura name; a code holder grinds a lookalike offline in ~4,096 tries | glyph + name + code on every message, warning on equal names | being written |
| S-02 | availability | Every login runs Argon2id in 4 global slots with no proof of work; busy slots answer 503 to everyone | verify login by the keyed lookup in constant time, no Argon2id | written, unverified |
| S-03 | availability | One global pool of 50,000 outstanding PoW challenges, filled by free requests | stateless signed challenges; store only used ones | written, unverified |
| S-04 | availability | One global cap of 4,096 event streams | per-party share: 16 streams per network (`middleware.ClientKey`) beside 4 per account | written, unverified |
| S-05 | integrity | After a reload the client forgets seen ids and counters: a malicious server can replay or reorder | persist last counters per conversation and sender in IndexedDB | written, unverified |
| S-06 | deployment | Compose cannot run `APP_ENV=production` (bundled PostgreSQL has no TLS), so onion instances run in development mode | TLS between backend and bundled PostgreSQL (`make certs`, `verify-full`, TLS-only `pg_hba.conf`); `make onion` requires production | written, verified on the dev stack (12 Nov): both backend connections TLSv1.3 `TLS_AES_256_GCM_SHA384` (`pg_stat_ssl`), plain TCP from another container refused by `pg_hba.conf`, `make certs` idempotent, `APP_ENV=production make up` starts (`Production mode validation passed`), `/` 200 and `/api/v2/me` 401 through nginx, `__Host-Session; Secure` cookie. Unverified: a browser login in production mode (Chromium on `http://localhost`, Tor Browser on an onion), `make onion` end to end, certificate renewal near expiry, Linux hosts |
| S-08 | deployment | Containers ran with default capabilities, writable roots, no resource limits, one shared network, and the backend and database published on loopback in every mode | drop all capabilities (postgres: five, each proven), read-only roots with named tmpfs, users 10001/101/70/100, memory, pids, CPU, nofile and shm limits, `init` where PID 1 reaps nothing, split `edge`/`app`/`data` networks (internal ones isolated), development-only ports, nginx limits, digest pins, `make check-hardening` | written, verified on the dev stack (OrbStack, 12 Nov): `docker inspect` and `/proc/1/status` per container, root writes fail, tmpfs `noexec`, backend and database unreachable from the host and from `edge` (also by IP), no egress from the backend, nginx reaches the backend from `PROXY_IP`, `/` 200, `/api/v2/me` 401, production-mode browser login, `users` 9 before and after, `make check-hardening` and 19 mutations of it; nginx `/api/` whitelist: `nginx -t`, 50 curl probes (each group's methods reach the backend, other methods 405, unknown paths 404, one byte over each bound 413). Unverified: Linux Docker Engine, `make onion` with tor running (config only: `--verify-config` under the restrictions), CI |
| S-07 | data | Since S-02 the stored Argon2id hash (`users.account_hash`) is read by nothing | drop: a migration removes the column and phase 2 stops hashing (no Argon2id, no slots, lighter phase 2). Keep: the column stays as a second, pepper-independent record of the key, costing one Argon2id per sign-up | open, decision needed |
| S-09 | security | Input checks were scattered (per-handler method/query/format checks, `utils.Validate*`, `parsePageCursor`, a content-type middleware, one 1 MiB body cap for all) and lax in places: duplicate and case-folded JSON keys taken, a register body with unknown fields or trailing data still served phase 1, queries ignored on the auth routes, bodies ignored on GET/DELETE/logout, `Content-Type` parameters ignored | one table (`internal/contract`): per endpoint methods, query, exact content type, body bound derived from its fields, every field with an anchored pattern and validator; one gate before every handler; `docs/api/input-contract.md` generated from it; nginx mirror pending (other agent) | written, unverified |
| S-10 | integrity | A room code is `S` plus its limits, but join checked only the id and lookup (both from `S`): a code with edited limit bytes still joined, so a member who pasted one had the verified vault replaced by one that never verifies (`E_ROOM_UNVERIFIED`, room hidden for good), and a non-member took a seat under a vault that never verifies | join carries `max_members` and `expires_at` (create's fields and bounds); the server refuses other limits exactly like a wrong lookup (`404 E_NOT_FOUND` path) before any seat or vault change; browser and agent refuse a known room pasted with other limits (`E_ROOM_CODE_INVALID`, `E_AGENT_ROOM_CODE`) and send nothing | verified 12 Nov (31882b2, a12ea80, dc8b15f): three integration tests on both engines; live on the rebuilt stack a non-member agent with +1 seat and +1 hour codes got `E_AGENT_ROOM_NOT_FOUND` and took no seat, a member agent got `E_AGENT_ROOM_CODE` and kept the room. Unverified: the browser-side refusal in a real browser |
| Q-01 | stage 1 | No error module: 78 free-text `http.Error` in the backend, 52 free-text `showError/showWarning` in the browser, no codes | one error home per program (backend, browser, agent), registered codes, one sentence each | browser, backend: written, unverified; agent: open |
| Q-02 | stage 1 | Browser: 8 direct `console` calls, 6 swallowing `catch`; backend: 8 `panic`, 2 dropped errors | decide each one: fix or justify in a comment | browser, backend: written, unverified |
| Q-03 | stage 1 | `room-crypto.js`: four functions with 7 to 9 parameters; `Rooms` module 191 lines; `setupEventListeners` 112 | named argument objects, split by purpose | written, unverified |
| Q-04 | stage 1 | Unnamed numbers: pow-worker 22, ui 17, utils 17, crypto 16, validation.go 14 (scanner counts, unread) | name the tunables, justify the rest | browser: written, unverified; backend (validation, pow, auth, cryptoengine): written, unverified; backend chat/store/realtime/agent/handlers: open |
| F-01 | function | Only the latest `MESSAGE_PAGE_LIMIT` messages are reachable; no paging backwards | `?before=seq` page, same whitelist as `after`; browser "earlier messages", agent `ReadBefore` (MCP `before` argument still to add) | written, unverified |

## Situation handling (audit of 12 Nov 2026)

Found by reading code, not reproduced unless the state says so. Severity in brackets.

### Server and deployment

| Id | Finding | Fix | State |
|---|---|---|---|
| D-01 | [high] Retention trusts the wall clock: a forward jump purges every message, invite, note and room; a backward jump caps `expires_on` early so messages die early once the clock is right | compare wall and monotonic gaps per cycle, persist the last run, pause with `E_CLOCK_JUMP` | being written |
| D-02 | [high] The supervised retention job is abandoned after 5 panics while the process stays healthy; `ListMessages` does not filter on expiry, so expired ciphertext is still served; one failing purge step starves the rest | reads never serve expired rows; an abandoned critical job exits the process (`E_JOB_ABANDONED`); purge steps independent | being written |
| D-03 | [high] No query has a context or statement timeout; an exhausted pool hangs requests without limit | `statement_timeout`, request context with a deadline into the repositories | being written |
| D-04 | [medium] A database outage answers 500 `E_INTERNAL` everywhere except login | classify driver errors once (`store.ErrUnavailable`) → 503 with one registered code, session gate included | being written |
| D-05 | [medium] Burn, room expiry or account deletion racing a send leaves orphan ciphertext until its TTL | lock the conversation row first in every delete path | being written |
| D-10 | [medium] A handler panic has no recovery and no code; net/http logs the peer address through stdlib `log` | `Recover` middleware (`E_PANIC`), `ErrorLog` through the log module | being written |
| D-06 | [medium] `AutoMigrate` on every boot: unversioned, not atomic, unguarded against a second instance or a newer schema | schema version, advisory lock, one transaction, `E_SCHEMA_NEWER` | open |
| D-07 | [medium] No log rotation on any service; free unauthenticated requests each write WARN lines; nginx `error_log crit` hides upstream failures | compose `logging` limits (checked by `make check-hardening`), per-code log rate limit, nginx `error` | open |
| D-08 | [medium] Startup failures are free-text `log.Fatal`; the pgx connect error names user, database and host; `HSTS_*`, `SEC_HEADER_*`, origins format, `PGSSLROOTCERT`, `TRUSTED_PROXIES` are not validated at start; `BACKEND_PORT` is configurable but 8080 is hardcoded in the healthcheck and nginx; no bounded wait for the database | startup codes with one exit path naming the variable only, validate all at start, bounded connect retry, pin or template the port | open |
| D-09 | [medium] The backend connects as the PostgreSQL bootstrap superuser | owner role for migrations, DML-only runtime role | open |
| D-11 | [medium] nginx `proxy_intercept_errors` replaces every registered JSON error body with an HTML page; backend down is a 502 HTML page | no intercept on `/api/`; JSON `E_BACKEND_UNAVAILABLE` for 502/504 | open |
| D-12 | [low-medium] Shutdown zeroizes keys while the rewrap goroutine or late handlers may still encrypt; compose stop timeout equals the grace period; the database is never closed | wait for supervised goroutines, refuse encryption once closing, zeroize last, `stop_grace_period`, close the pool | open |
| D-13 | [low-medium] A second backend instance starts (PoW secret and spent set, pending store, hub and limiters are per process) | advisory lock at start, `E_SECOND_INSTANCE`, documented | open |
| D-14 | [low-medium] Database TLS certificate expiry is silent; the healthcheck never touches the database | healthcheck runs `SELECT 1` with a timeout; `make certs` warns early | open |
| D-15 | [low] Spent PoW eviction and JWT times follow the wall clock | covered by the D-01 detector | open |
| D-16 | [low] No restore test; `tor_data` onion key and full-volume restore undocumented; tor healthcheck only tests a file | `make test-restore`, document exclusions, real tor check | open |
| D-17 | [low] Rewrap runs one pass per boot and stops silently on a database error; a database with users but no members pins any pepper | retry until no old-key rows, `E_REWRAP_INCOMPLETE` | open |

Doc drift to fix with them: `disaster-recovery.md` (retention on a full disk), `configuration-and-tuning.md` (`DB_HOST`, `DB_NAME` defaults).

### Browser

| Id | Finding | Fix | State |
|---|---|---|---|
| C-01 | [high] No request times out: a hung POST disables send for good, a hung GET blocks the conversation's sync chain | one abort timeout in the request function, `E_REQUEST_TIMEOUT` | being written |
| C-02 | [high] Registration clears the account number from screen, clipboard and memory before `/me` succeeds; a failure then shows the menu silently | clear only after entering; `E_ACCOUNT_CREATED_NOT_ENTERED` | being written |
| C-03 | [high, security] Any 401 (and `/me` 0/5xx at load) wipes the whole IndexedDB, replay counters included: a hostile server answers 401 once and replays undetected (S-05 bypass); offline at load logs the device out | `wipeIdentity` for server-driven paths keeps counters; `wipeAll` only for the user's logout or delete; `E_SERVER_UNREACHABLE` with retry | being written |
| C-04 | [high] One composer for all conversations: a draft for A is sent to B; a send for A clears text typed for B | in-memory draft per conversation | being written |
| C-05 | [medium-high] Browser PoW accepts difficulty 32 and 2^31 hashes, no timeout, no cancel, locks held | cap at the server maximum 24, wall-clock timeout, terminate on stop, `E_POW_TIMEOUT` | being written |
| C-06 | [medium] Login and register phase 1 leave the page on ordinary errors: a wrong number wipes the keystore and shows the session-expired page | `apiCall` with inline codes | being written |
| C-07 | [medium] No global error handler; a failed sync shows "say hello" over a conversation that did not load | one handler (`E_UNEXPECTED`), sync failure shown with retry | being written |
| C-08 | [medium] Two tabs of one account reuse counters; peers hide a message as a replay | Web Lock around counter allocation, fresh read, write-ahead | open |
| C-09 | [medium] Overlapping list refreshes can drop a just-joined conversation (false `W_CONVERSATION_BURNED`) | single-flight refresh with a generation | open |
| C-10 | [medium] A room hidden by `E_ROOM_UNVERIFIED` is not named and cannot be left; the seat stays held | list it as unverified with a leave action | open |
| C-11 | [medium-low] Re-entrancy: Enter bypasses the disabled login button; join, accept, logout unguarded; send awaits the roster before disabling | one busy flag per action before the first await | open |
| C-12 | [low-medium] Storage failures (private mode, quota, downgrade, blocked upgrade) are log-only | `W_STORAGE_UNAVAILABLE` shown once | open |
| C-13 | [low] Misleading codes: roster 5xx as `E_ROSTER_UNVERIFIED`, limits out of range as `E_IDENTITY_MISMATCH`, challenge 429 as `E_ROOM_NOT_CREATED`, free-text `unsupportedNotice` | the right code each | open |
| C-14 | [low] Delete identity with a lost answer reports not deleted | probe `/me` on 0/5xx | open |
| C-15 | [low] A first-attempt 409 on send counts as stored | accept 409 only after a lost answer, as the agent does | open |
| C-16 | [low] A fast client clock gives a false expired room with no hint | name the clock in the sentence | open |
| C-17 | [low] A new room code is auto-copied and left in the clipboard | best-effort clear as for the account number | open |

Undetermined: back-forward cache after logout, blocked IndexedDB upgrade, an unbounded JSON body from a hostile server.

### Agent

| Id | Finding | Fix | State |
|---|---|---|---|
| A-01 | [high] Message counters live in memory and two processes may share one identity: counters are reused, browser peers hide the messages as replays while the agent reports `stored: true` | exclusive lock file (`E_AGENT_IDENTITY_IN_USE`), atomic per-room counter state raised before each POST | open |
| A-02 | [high] A failed registration confirm leaves an identity file that can never log in (`E_AGENT_IDENTITY_UNKNOWN` forever) | keep the pending token and retry confirm | open |
| A-03 | [high] A failed `/me` check leaves the session set: the mismatch is fail-open on the next call and `room_create` panics on nil limits | drop the session on any check error, guard limits | open |
| A-04 | [medium-high] The agent detects no replay or reordering; a re-served message reaches the model as new | mirror the browser's counter judgement | open |
| A-05 | [medium-low] `room_wait` re-opens a dying stream four times without backoff and reports a timeout early | backoff, read fallback, `CodeNetwork` if no stream held | open |
| A-06 | [low-medium] `room_create` with a lost answer orphans the room and its code | settle by listing rooms | open |
| A-07 | [low] Signal shutdown does not wait for the call in flight (map write after close, temp link may remain) | cancel, then wait with a bound | open |
| A-08 | [low] `E_AGENT_IDENTITY_FILE` suggests moving the only copy of the account away; TLS failure reads as unreachable | clearer sentences, a TLS code | open |

Decided exception (Q-01): `Errors.format()` in `frontend/js/errors.js` throws two `TypeError`s with fixed
texts for the module's own misuse (unknown code, missing parameter); the user-facing path `message()`
maps them to `E_UNKNOWN_CODE` and `E_BAD_PARAMS`, and the tests pin both texts.

## Order of work (the snowball)

1. Robot entrance (in progress), S-01 (in progress).
2. Stage 1: Q-01 error modules per program, then Q-02, Q-03, Q-04; S-02..S-05 and F-01 each in its own commit.
3. One full verification at the end: `make test-engines`, `make test-equivalence`, frontend tests, race detector, then a live tour of every screen in two browsers plus one agent.
4. Stage 2 (prove by attack) and stage 3 (fuzz) start only after stage 1 is verified.

## Decisions

- D-2026-11-12-a: design of the robot entrance, D1 to D8 in `docs/architecture/agents.md`.
- D-2026-11-12-b: stored and wire names keep the `noaddx` protocol namespace after the rename.
- D-2026-11-12-c: the agent accepts `http://*.onion` through the environment's SOCKS proxy; plain http elsewhere only on loopback.

## Scanner baseline (12 Nov 2026, before stage 1)

clones 3 · identical functions 0 · tool-made names 0 · 7+ parameter functions 6 · panics 8 ·
direct console 8 · swallowing catch 6 · dropped errors 2.
