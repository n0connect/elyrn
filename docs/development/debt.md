# Debt and Decisions

The single record of what is loose, what was decided and what is unverified. Newest first
inside each section. An entry leaves only when its fix is verified, never when it is merely
written. Ids are stable.

## State (13 Nov 2026, evening)

- `main` and `elyrn-dev` are on GitHub at 41669b0 with a green CI run (both engines with the race
  detector and every fuzz target, equivalence, frontend, images, govulncheck, gitleaks): the first
  verification on Linux. Local `elyrn-dev` is ahead of it and **not pushed**.
- **Local head, every exit code read:** frontend 161/161; complete Go suite on both engines (the
  integration package now ends with a connection guard: open sessions return to the baseline);
  engine equivalence; `make check-hardening`; gitleaks; govulncheck; staticcheck on both tag sets;
  gofmt; `go mod tidy -diff`, all at eb9b17e. Race detector on both engines at eb9b17e. After it
  only the frontend changed (e2643e4): frontend tests rerun, 161/161.
- **Fuzz campaign at eb9b17e:** all 76 Go targets, 45 s each on the native engine and 15 s each on
  the OpenSSL engine, no failure; the seven browser fuzz files at 20 times their iteration count.
- **`make test-restore`:** passed on both engines (dump, drop, restore, key check, the restored
  account logs in, a new one registers); the development database was not touched.
- **Negative use:** suites generated from the route table (108 refusals without a session, 50
  byte-equal "not yours" versus "never existed" answers, order and repetition, limits, cross-protocol
  confusion, the agent) and for the browser (inputs, a hostile server, auth flows). They found and
  fixed: an existence oracle on message send, the agent creating an account before parsing a join
  code, account numbers sent as messages or taken as invites, a listing whose limits changed, a
  duplicate id answered as stored, and more (commits a901490..e2643e4).
- **Seen in a real browser on the rebuilt stack:** the ways back from login and registration,
  Escape, a left registration and a closed room panel leaving nothing behind, wrong pastes into
  every field, an account number refused as a message, six Enter presses sending once, favicon.
- **Not verified:** `make onion` end to end; production-mode browser login after these changes;
  clock-jump and job-abandon exits (no honest test, no drill); friend requests, two tabs, storage
  warnings and the id-taken redraw in a real browser (tests only).

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
| D-01 | [high] Retention trusts the wall clock: a forward jump purges every message, invite, note and room; a backward jump caps `expires_on` early so messages die early once the clock is right | compare wall and monotonic gaps per cycle, persist the last run, pause with `E_CLOCK_JUMP` | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-02 | [high] The supervised retention job is abandoned after 5 panics while the process stays healthy; `ListMessages` does not filter on expiry, so expired ciphertext is still served; one failing purge step starves the rest | reads never serve expired rows; an abandoned critical job exits the process (`E_JOB_ABANDONED`); purge steps independent | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-03 | [high] No query has a context or statement timeout; an exhausted pool hangs requests without limit | `statement_timeout`, request context with a deadline into the repositories | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-04 | [medium] A database outage answers 500 `E_INTERNAL` everywhere except login | classify driver errors once (`store.ErrUnavailable`) → 503 with one registered code, session gate included | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-05 | [medium] Burn, room expiry or account deletion racing a send leaves orphan ciphertext until its TTL | lock the conversation row first in every delete path | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-10 | [medium] A handler panic has no recovery and no code; net/http logs the peer address through stdlib `log` | `Recover` middleware (`E_PANIC`), `ErrorLog` through the log module | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-06 | [medium] `AutoMigrate` on every boot: unversioned, not atomic, unguarded against a second instance or a newer schema | schema version, advisory lock, one transaction, `E_SCHEMA_NEWER` | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-07 | [medium] No log rotation on any service; free unauthenticated requests each write WARN lines; nginx `error_log crit` hides upstream failures | compose `logging` limits (checked by `make check-hardening`), per-template log rate limit; nginx stays at `crit` on purpose (at `error` every line carries the client address), a down backend shows as 503 `E_BACKEND_UNAVAILABLE` and in the healthcheck | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-08 | [medium] Startup failures are free-text `log.Fatal`; the pgx connect error names user, database and host; `HSTS_*`, `SEC_HEADER_*`, origins format, `PGSSLROOTCERT`, `TRUSTED_PROXIES` are not validated at start; `BACKEND_PORT` is configurable but 8080 is hardcoded in the healthcheck and nginx; no bounded wait for the database | startup codes with one exit path naming the variable only, validate all at start, bounded connect retry, pin or template the port | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-09 | [medium] The backend connects as the PostgreSQL bootstrap superuser | owner role for migrations, DML-only runtime role | open: not done on purpose. A real split needs a one-shot migrator service and a new runtime-password secret that existing `.env` files lack, so an in-place upgrade would need a manual step; design recorded in the report of cffb279 (Makefile adds `DB_APP_PASSWORD` idempotently, a `migrate` service creates role `elyrn_app` with DML only, the backend keeps only the app credentials) |
| D-11 | [medium] nginx `proxy_intercept_errors` replaces every registered JSON error body with an HTML page; backend down is a 502 HTML page | no intercept on `/api/`; JSON `E_BACKEND_UNAVAILABLE` for 502/504 | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-12 | [low-medium] Shutdown zeroizes keys while the rewrap goroutine or late handlers may still encrypt; compose stop timeout equals the grace period; the database is never closed | wait for supervised goroutines, refuse encryption once closing, zeroize last, `stop_grace_period`, close the pool | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-13 | [low-medium] A second backend instance starts (PoW secret and spent set, pending store, hub and limiters are per process) | advisory lock at start, `E_SECOND_INSTANCE`, documented | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-14 | [low-medium] Database TLS certificate expiry is silent; the healthcheck never touches the database | healthcheck runs `SELECT 1` with a timeout; `make certs` warns early | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-15 | [low] Spent PoW eviction and JWT times follow the wall clock | covered by the D-01 detector | verified by the suite at a3c4007 (see State for what was also seen live) |
| D-16 | [low] No restore test; `tor_data` onion key and full-volume restore undocumented; tor healthcheck only tests a file | `make test-restore` (run on both engines, 13 Nov), exclusions documented; the tor healthcheck still only tests the hostname file (tor offers no cheap local reachability check): documented limit, open | verified except the tor check |
| D-17 | [low] Rewrap runs one pass per boot and stops silently on a database error; a database with users but no members pins any pepper | retry until no old-key rows, `E_REWRAP_INCOMPLETE` | verified by the suite at a3c4007 (see State for what was also seen live) |

Doc drift to fix with them: `disaster-recovery.md` (retention on a full disk), `configuration-and-tuning.md` (`DB_HOST`, `DB_NAME` defaults).

### Browser

| Id | Finding | Fix | State |
|---|---|---|---|
| C-01 | [high] No request times out: a hung POST disables send for good, a hung GET blocks the conversation's sync chain | one abort timeout in the request function, `E_REQUEST_TIMEOUT` | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-02 | [high] Registration clears the account number from screen, clipboard and memory before `/me` succeeds; a failure then shows the menu silently | clear only after entering; `E_ACCOUNT_CREATED_NOT_ENTERED` | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-03 | [high, security] Any 401 (and `/me` 0/5xx at load) wipes the whole IndexedDB, replay counters included: a hostile server answers 401 once and replays undetected (S-05 bypass); offline at load logs the device out | `wipeIdentity` for server-driven paths keeps counters; `wipeAll` only for the user's logout or delete; `E_SERVER_UNREACHABLE` with retry | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-04 | [high] One composer for all conversations: a draft for A is sent to B; a send for A clears text typed for B | in-memory draft per conversation | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-05 | [medium-high] Browser PoW accepts difficulty 32 and 2^31 hashes, no timeout, no cancel, locks held | cap at the server maximum 24, wall-clock timeout, terminate on stop, `E_POW_TIMEOUT` | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-06 | [medium] Login and register phase 1 leave the page on ordinary errors: a wrong number wipes the keystore and shows the session-expired page | `apiCall` with inline codes | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-07 | [medium] No global error handler; a failed sync shows "say hello" over a conversation that did not load | one handler (`E_UNEXPECTED`), sync failure shown with retry | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-08 | [medium] Two tabs of one account reuse counters; peers hide a message as a replay | Web Lock around counter allocation, fresh read, write-ahead | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-09 | [medium] Overlapping list refreshes can drop a just-joined conversation (false `W_CONVERSATION_BURNED`) | single-flight refresh with a generation | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-10 | [medium] A room hidden by `E_ROOM_UNVERIFIED` is not named and cannot be left; the seat stays held | list it as unverified with a leave action | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-11 | [medium-low] Re-entrancy: Enter bypasses the disabled login button; join, accept, logout unguarded; send awaits the roster before disabling | one busy flag per action before the first await | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-12 | [low-medium] Storage failures (private mode, quota, downgrade, blocked upgrade) are log-only | `W_STORAGE_UNAVAILABLE` shown once | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-13 | [low] Misleading codes: roster 5xx as `E_ROSTER_UNVERIFIED`, limits out of range as `E_IDENTITY_MISMATCH`, challenge 429 as `E_ROOM_NOT_CREATED`, free-text `unsupportedNotice` | the right code each | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-14 | [low] Delete identity with a lost answer reports not deleted | probe `/me` on 0/5xx | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-15 | [low] A first-attempt 409 on send counts as stored | accept 409 only after a lost answer, as the agent does | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-16 | [low] A fast client clock gives a false expired room with no hint | name the clock in the sentence | verified by the suite at a3c4007 (see State for what was also seen live) |
| C-17 | [low] A new room code is auto-copied and left in the clipboard | best-effort clear as for the account number | verified by the suite at a3c4007 (see State for what was also seen live) |

Undetermined: back-forward cache after logout, blocked IndexedDB upgrade, an unbounded JSON body from a hostile server.

### Agent

| Id | Finding | Fix | State |
|---|---|---|---|
| A-01 | [high] Message counters live in memory and two processes may share one identity: counters are reused, browser peers hide the messages as replays while the agent reports `stored: true` | exclusive lock file (`E_AGENT_IDENTITY_IN_USE`), atomic per-room counter state raised before each POST | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-02 | [high] A failed registration confirm leaves an identity file that can never log in (`E_AGENT_IDENTITY_UNKNOWN` forever) | keep the pending token and retry confirm | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-03 | [high] A failed `/me` check leaves the session set: the mismatch is fail-open on the next call and `room_create` panics on nil limits | drop the session on any check error, guard limits | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-04 | [medium-high] The agent detects no replay or reordering; a re-served message reaches the model as new | mirror the browser's counter judgement | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-05 | [medium-low] `room_wait` re-opens a dying stream four times without backoff and reports a timeout early | backoff, read fallback, `CodeNetwork` if no stream held | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-06 | [low-medium] `room_create` with a lost answer orphans the room and its code | settle by listing rooms | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-07 | [low] Signal shutdown does not wait for the call in flight (map write after close, temp link may remain) | cancel, then wait with a bound | verified by the suite at a3c4007 (see State for what was also seen live) |
| A-08 | [low] `E_AGENT_IDENTITY_FILE` suggests moving the only copy of the account away; TLS failure reads as unreachable | clearer sentences, a TLS code | verified by the suite at a3c4007 (see State for what was also seen live) |

### Found after the audit

| Id | Finding | Fix | State |
|---|---|---|---|
| A-09 | [high, security] The agent pruned a room's counter record when one listing omitted the room: a hostile server hides the room once and replays undetected | prune only on the room's own expiry or the agent's own leave | verified by the suite at a3c4007 (8008614) |
| A-10 | [medium] History pages in the agent skip the browser's ceiling rule | mirror `counters.js` | verified by the suite at a3c4007 (8008614) |
| C-18 | [medium] The browser ignores the edge codes nginx now answers (`E_BACKEND_UNAVAILABLE` and four more) | map `data.code` to registered codes; unknown codes fall back to the status | verified by the suite at a3c4007 (9b0546c) |
| C-19 | [medium] Found in the live tour: the nonce, the agent command and the open room's code sat in boxes an animation rule kept at opacity 0 (never visible, before the two doors too) | boxes carry the `show` class; robot-side colours | written, seen fixed in a real browser (e6d0b89) |
| D-18 | [low] `nginx-site.conf` was changed without `nginx -t` (since run: passes, and the config serves live); `docker-compose.test.yaml` has no log limits; `HSTS_*` and `SEC_HEADER_*` are not passed through compose; the retention heartbeat marks a cycle begun, not finished | check each in the final verification, fix or justify | open |

### Found by fuzz, drills and the tour (13 Nov)

| Id | Finding | Fix | State |
|---|---|---|---|
| L-01 | [high] A stopped backend answered 504 with the 503 code: an `error_page` to a named location keeps the trigger's status | every edge `error_page` states `=NNN`; check-hardening enforces it | verified live (a7de107) |
| L-02 | [high] A database paused 20 s cost the single-instance lock: the watcher's own deadline closed the lock session, the server exited and lost its in-memory state | no deadline on the lock ping; lost only when the connection is closed; `E_INSTANCE_LOCK_UNREACHABLE` once per outage | verified by the suite and live (6e6b21a) |
| L-03 | [medium] A request stalled on the database lost its 503: statement deadline equal to the HTTP write timeout | one deadline per request from `SERVER_WRITE_TIMEOUT_SEC` minus a margin (the event stream exempt); background work keeps its limits | verified by the suite (a3c4007, a6889fe) |
| L-04 | [medium] The agent reported an outage as a wrong-shaped answer | any 5xx is a passing failure | verified by the suite and live (6e6b21a) |
| L-05 | [low] The agent warned `E_AGENT_STATE_REBUILT` on every start of an identity that never sent | counter file written with the identity | verified by the suite and live |
| L-06 | [medium] JWT signatures could be re-spelled (unused bits, inserted line ends) and still verify | strict decoding, exact three base64url segments | verified by the suite (c18f3c6) |
| L-07 | [low] Agent and browser trimmed message text differently (U+0085, U+FEFF) | one explicit trim set, pinned on both sides | verified by the suite (c18f3c6) |
| L-08 | [low] The registration screen showed no way back (a CSS rule hid the button, Escape did nothing); `favicon.ico` answered 404; startup logged the active master-key id | one visible exit and Escape on every pre-login screen, a second confirmation once the account may exist; a favicon; counts only in the log | verified by the suite and in a real browser (a901490, a6889fe, e2643e4) |
| N-01 | [high] Existence oracle: a non-member sending a well-formed message to a live room got 400, to a missing id 404 | membership first; always 404 | verified by the suite (a6889fe) |
| N-02 | [medium] An account number could be sent as a message (browser and agent) or was not recognised in the join field in fullwidth form | refused with its own code on both sides, one shared sample table | verified by the suite and in a real browser |
| N-03 | [medium] Any duplicate message or note id answered "stored" | "stored" only for the sender's own identical resend; `E_ID_TAKEN` otherwise, one automatic redraw in both clients | verified by the suite (22ca108). The browser's redraw path: tests of the mapping only |
| N-04 | [medium] Driver error text (database user, name, host) reached the log from repository loggers; panic values were logged as-is | one reducer for every repository log line; panics by type, stack without argument words | verified by the suite (eb9b17e) |
| N-05 | [medium] The integration package opened one database pool per test and closed none (about 130 against a limit of 100); a helper then exited the test binary | one pool at a time, no exiting path reachable from tests, a connection guard in `TestMain` | verified by the suite (eb9b17e) |
| N-06 | [low] The agent created an account (two proofs of work) before parsing a join code; it echoed a cursor past the room's end | parse first; cursor capped at the real end | verified by the suite |
| L-09 | [low] Open: `frontend.sha256` is stale since the rename; `docker-compose.test.yaml` has no log limits; `HSTS_*` and `SEC_HEADER_*` are not passed through compose; the retention heartbeat marks a cycle begun, not finished | `make manifest` at release; fix or justify the rest | open |

Feature (13 Nov): two doors. The main menu is the white human side; `robot` is a black door that
judges whoever presses it in the page (pointer trail, or a SHA-256 question), walks a human back and
lets a robot in. Theatre: it gates nothing, measures in memory only, sends and stores nothing
(`frontend/js/robot-door.js`, `docs/architecture/agents.md`). Seen working in a real browser on
both paths; its unit tests are written, not run.

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
- D-2026-11-13-a (owner): no forward secrecy, by design. The identity is one number from which
  everything is derived again on any device, with no secret kept on a device; a ratchet needs
  exactly such a kept, underivable, deleted secret, and brings per-device state, key upload and
  new linkable surfaces with it. This is a condition of the system, not a debt. It stays stated
  in the security documents.
- D-2026-11-13-b (owner): threat model boundary. A compromised server and the network address a
  client connects from are outside what the project can change (onion and VPN are the answer for
  the address). The measure is that the server cannot read messages or tell who an account is.
- D-2026-11-12-c: the agent accepts `http://*.onion` through the environment's SOCKS proxy; plain http elsewhere only on loopback.

## Scanner baseline (12 Nov 2026, before stage 1)

clones 3 · identical functions 0 · tool-made names 0 · 7+ parameter functions 6 · panics 8 ·
direct console 8 · swallowing catch 6 · dropped errors 2.
