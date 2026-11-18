# Debt and Decisions

The single record of what is loose, what was decided and what is unverified. Newest first
inside each section. An entry leaves only when its fix is verified, never when it is merely
written. Ids are stable.

## State (13 Nov 2026, evening)

- `main` and `elyrn-dev` are on GitHub at the same commit with a green CI run (both engines with
  the race detector and every fuzz target, equivalence, frontend, images, govulncheck, gitleaks).
  Nothing is unpushed. Every document was checked against the code on 13 Nov (0dd8fac).
- **Last full local verification, every exit code read:** frontend 161/161; complete Go suite on both engines (the
  integration package now ends with a connection guard: open sessions return to the baseline);
  engine equivalence; `make check-hardening`; gitleaks; govulncheck; staticcheck on both tag sets;
  gofmt; `go mod tidy -diff`, all at eb9b17e. Race detector on both engines at eb9b17e. After it
  only the frontend, documents and the Makefile changed: frontend tests rerun, 162/162; CI ran the rest.
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
- **14 Nov, committed and pushed (`ba687d9`, `9f80e60`, `0c2b4c1`; `main` = `elyrn-dev`):** the
  changes recorded under *Found 14 Nov* below and the documents that describe them. Verified
  once on the whole tree: frontend 173 of 173, the containerized suite on both engines, engine
  equivalence, `make check-hardening`, gitleaks, govulncheck, staticcheck on both tag sets,
  gofmt; CI green on both commits' runs. The run found one defect in the round's own code
  (`Counters.retention` listed whole records, not ids, for rooms expired long ago, so the
  browser's prune would have failed); fixed before the commit. Tried in a real browser behind
  the Cloudflare quick tunnel: messages arrive without leaving the tab (0.7 to 5 s), the
  session cookie lives 30 days, a reload with the session answer delayed 3 s never shows the
  main menu.
- **Not verified:** `make onion` end to end; production-mode browser login after these changes;
  clock-jump and job-abandon exits (no honest test, no drill); friend requests, two tabs, storage
  warnings and the id-taken redraw in a real browser (tests only).

## Open findings

| Id | Class | Finding | Fix | State |
|---|---|---|---|---|
| S-01 | security | Room messages name the sender by a 12-bit aura name; a code holder grinds a lookalike offline in ~4,096 tries | glyph + name + code on every message, warning on equal names | committed (ba751e3, 44a1b39); in the tree of the full verification at eb9b17e (State) |
| S-02 | availability | Every login runs Argon2id in 4 global slots with no proof of work; busy slots answer 503 to everyone | verify login by the keyed lookup in constant time, no Argon2id | committed (1c8f95a, 7938ecc); in the tree of the full verification at eb9b17e (State) |
| S-03 | availability | One global pool of 50,000 outstanding PoW challenges, filled by free requests | stateless signed challenges; store only used ones | committed (bd0e0c9, 743a409); in the tree of the full verification at eb9b17e (State) |
| S-04 | availability | One global cap of 4,096 event streams | per-party share: 16 streams per network (`middleware.ClientKey`) beside 4 per account | committed (f5efb72); in the tree of the full verification at eb9b17e (State) |
| S-05 | integrity | After a reload the client forgets seen ids and counters: a malicious server can replay or reorder | persist last counters per conversation and sender in IndexedDB | committed (2817a33, 649dfdc); in the tree of the full verification at eb9b17e (State). When a record may be dropped: C-20 |
| S-06 | deployment | Compose cannot run `APP_ENV=production` (bundled PostgreSQL has no TLS), so onion instances run in development mode | TLS between backend and bundled PostgreSQL (`make certs`, `verify-full`, TLS-only `pg_hba.conf`); `make onion` requires production | written, verified on the dev stack (12 Nov): both backend connections TLSv1.3 `TLS_AES_256_GCM_SHA384` (`pg_stat_ssl`), plain TCP from another container refused by `pg_hba.conf`, `make certs` idempotent, `APP_ENV=production make up` starts (`Production mode validation passed`), `/` 200 and `/api/v2/me` 401 through nginx, `__Host-Session; Secure` cookie. Unverified: a browser login in production mode (Chromium on `http://localhost`, Tor Browser on an onion), `make onion` end to end, certificate renewal near expiry, Linux hosts |
| S-08 | deployment | Containers ran with default capabilities, writable roots, no resource limits, one shared network, and the backend and database published on loopback in every mode | drop all capabilities (postgres: five, each proven), read-only roots with named tmpfs, users 10001/101/70/100, memory, pids, CPU, nofile and shm limits, `init` where PID 1 reaps nothing, split `edge`/`app`/`data` networks (internal ones isolated), development-only ports, nginx limits, digest pins, `make check-hardening` | written, verified on the dev stack (OrbStack, 12 Nov): `docker inspect` and `/proc/1/status` per container, root writes fail, tmpfs `noexec`, backend and database unreachable from the host and from `edge` (also by IP), no egress from the backend, nginx reaches the backend from `PROXY_IP`, `/` 200, `/api/v2/me` 401, production-mode browser login, `users` 9 before and after, `make check-hardening` and 19 mutations of it; nginx `/api/` whitelist: `nginx -t`, 50 curl probes (each group's methods reach the backend, other methods 405, unknown paths 404, one byte over each bound 413). Unverified: Linux Docker Engine, `make onion` with tor running (config only: `--verify-config` under the restrictions), CI |
| S-07 | data | Since S-02 the stored Argon2id hash (`users.account_hash`) is read by nothing | drop: a migration removes the column and phase 2 stops hashing (no Argon2id, no slots, lighter phase 2). Keep: the column stays as a second, pepper-independent record of the key, costing one Argon2id per sign-up | decided 18 Nov 2026 (D-2026-11-18-a): drop. Removed: registration stores no hash, the schema-2 migration drops `users.account_hash` idempotently, Argon2id is gone from both crypto engines with every `ARGON2_*` setting, the slots and `E_ARGON2_BUSY`; `make check-hardening` sizes the backend by the file-request pool. Written, compiled; not yet run |
| S-09 | security | Input checks were scattered (per-handler method/query/format checks, `utils.Validate*`, `parsePageCursor`, a content-type middleware, one 1 MiB body cap for all) and lax in places: duplicate and case-folded JSON keys taken, a register body with unknown fields or trailing data still served phase 1, queries ignored on the auth routes, bodies ignored on GET/DELETE/logout, `Content-Type` parameters ignored | one table (`internal/contract`): per endpoint methods, query, exact content type, body bound derived from its fields, every field with an anchored pattern and validator; one gate before every handler; `docs/api/input-contract.md` generated from it; nginx `/api/` mirrors it as a default-deny whitelist | committed (ed5d87f..029a542; nginx mirror e3da3e5, probed live as recorded under S-08); in the tree of the full verification at eb9b17e (State) |
| S-10 | integrity | A room code is `S` plus its limits, but join checked only the id and lookup (both from `S`): a code with edited limit bytes still joined, so a member who pasted one had the verified vault replaced by one that never verifies (`E_ROOM_UNVERIFIED`, room hidden for good), and a non-member took a seat under a vault that never verifies | join carries `max_members` and `expires_at` (create's fields and bounds); the server refuses other limits exactly like a wrong lookup (`404 E_NOT_FOUND` path) before any seat or vault change; browser and agent refuse a known room pasted with other limits (`E_ROOM_CODE_INVALID`, `E_AGENT_ROOM_CODE`; the agent's code is `E_AGENT_ROOM_CODE_ALTERED` since A-11) and send nothing | verified 12 Nov (31882b2, a12ea80, dc8b15f): three integration tests on both engines; live on the rebuilt stack a non-member agent with +1 seat and +1 hour codes got `E_AGENT_ROOM_NOT_FOUND` and took no seat, a member agent got `E_AGENT_ROOM_CODE` and kept the room. Unverified: the browser-side refusal in a real browser |
| Q-01 | stage 1 | No error module: 78 free-text `http.Error` in the backend, 52 free-text `showError/showWarning` in the browser, no codes | one error home per program (backend, browser, agent), registered codes, one sentence each | committed: browser 9ab953d, backend 8cab927, agent with the agent itself (registry in `backend/internal/agent/errors.go` since c1e7ae6); in the tree of the full verification at eb9b17e (State) |
| Q-02 | stage 1 | Browser: 8 direct `console` calls, 6 swallowing `catch`; backend: 8 `panic`, 2 dropped errors | decide each one: fix or justify in a comment | committed (54e38c3, f461429); in the tree of the full verification at eb9b17e (State) |
| Q-03 | stage 1 | `room-crypto.js`: four functions with 7 to 9 parameters; `Rooms` module 191 lines; `setupEventListeners` 112 | named argument objects, split by purpose | committed (363b90e, 87dd961, 630050b); in the tree of the full verification at eb9b17e (State) |
| Q-04 | stage 1 | Unnamed numbers: pow-worker 22, ui 17, utils 17, crypto 16, validation.go 14 (scanner counts, unread) | name the tunables, justify the rest | committed: browser 00fbe7b; backend 2b12a3c (validation, pow, auth, cryptoengine), 6253e17 (store, chat), f878896 (handlers, middleware, server), 7bcf825 (agent, mcp); in the tree of the full verification at eb9b17e (State). No Q-04 commit names `realtime`: unchecked |
| F-01 | function | Only the latest `MESSAGE_PAGE_LIMIT` messages are reachable; no paging backwards | `?before=seq` page, same whitelist as `after`; browser "earlier messages", agent `ReadBefore`, MCP `room_read` `before` | committed (5825789, e111fd5, fe690de, 5bef96f); in the tree of the full verification at eb9b17e (State) |

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

The doc drift found with them (`disaster-recovery.md` on a full disk, the `DB_HOST` and `DB_NAME` defaults in `configuration-and-tuning.md`) is fixed: both now match the code.

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
| D-18 | [low] `nginx-site.conf` was changed without `nginx -t`; `docker-compose.test.yaml` has no log limits; `HSTS_*` and `SEC_HEADER_*` are not passed through compose; the retention heartbeat marks a cycle begun, not finished; `frontend.sha256` (ignored by git, written by `make manifest`) is stale since the rename | check each, fix or justify; `make manifest` at release | `nginx -t`: run, passes, the config serves live. HSTS and `SEC_HEADER_*`: D-20. Open: test-stack log limits, the retention heartbeat, `frontend.sha256` |

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
| L-09 | [low] Duplicate of D-18 | - | merged into D-18 |

### Found 14 Nov

| Id | Finding | Fix | State |
|---|---|---|---|
| C-20 | [high, security] The browser twin of A-09: a conversation left out of one listing, or a burn or leave answered `404`, removed its counter record, so a hostile server could hide a conversation once and replay it undetected | a record is dropped only on the user's own burn or leave answered `204`, or a day after the room's own expiry (the room is then never shown); at most `MAX_RECORDS` (1024), least recently used first, `W_COUNTER_RECORDS_EVICTED` once per page load (`counters.js`, `keystore.js`, `chat.js`) | verified 14 Nov (`ba687d9`) |
| C-21 | [medium-high] Found behind a Cloudflare quick tunnel: the browser had no fallback when the event stream cannot be held (a proxy buffers it or keeps dropping it), so new messages appeared only on a tab switch, and after 8 failed reconnects updates stopped | the server sends a named `ping` event right after the preamble and every 25 s; a watchdog in `chat.js` polls about every 5 s while the tab is visible and the stream showed no event (5 s for a new stream, 60 s after one), decided by `streamNeedsPolling` in `utils.js`; `W_LIVE_STREAM_SILENT`, `W_LIVE_STREAM_GAVE_UP` | verified 14 Nov (`ba687d9`) |
| C-22 | [medium] The owner saw the login screen after a reload. Cause found once he described it exactly: the session was not lost; `#mainMenu` was the one view painted by markup, so it showed until `/me` answered, and behind a slow link that read as a logout followed by a login | the page opens on a start view holding the brand line only; the main menu appears only when there is no stored identity, the session is refused, or the server cannot be reached (`leaveStartView`, `ui.js`; `boot`, `app.js`); without scripting the stylesheet shows the menu | verified 14 Nov (`0c2b4c1`), in a real browser behind the tunnel |
| D-19 | [medium] Behind the operator's own TLS proxy, nginx saw every request from that proxy: all users shared one rate-limit bucket (`429` for everyone on a busy instance) and the backend never saw HTTPS | `EDGE_TRUSTED_PROXIES`: `nginx-edge-proxies.sh` renders realip and a geo list at nginx start (a malformed list stops nginx); `X-Forwarded-For` and `X-Forwarded-Proto` are taken only from a listed peer (`$forwarded_proto`); `check-hardening.py` checks both | verified 14 Nov (`ba687d9`) |
| D-20 | [low] `HSTS_*` never reached the backend in the Compose stack; `SEC_HEADER_*` could only disagree with nginx's fixed cross-origin headers | compose passes `HSTS_MAX_AGE`, `HSTS_INCLUDE_SUBDOMAINS`, `HSTS_PRELOAD` (off by default); `SEC_HEADER_*` removed, the backend's three headers fixed and hidden by nginx on `/api/` | verified 14 Nov (`ba687d9`) |
| D-21 | [low] An invite's or a room note's stored expiry was creation time plus TTL to the second, so it told the second the row was made | expiry rounded up to the next whole hour (`expiryAfter`, `service.go`, `rooms.go`, `expiry_test.go`); rows stored earlier keep their exact expiry | verified 14 Nov (`ba687d9`) |
| D-22 | [low] A login lookup the server could not compute (pepper, crypto engine) answered `401 Invalid credentials`, telling the user their only key was worthless | `E_LOGIN_LOOKUP_FAILED` is `500`; computed from the key alone before any account is read, so it tells no account from another | verified 14 Nov (`ba687d9`) |
| D-23 | [low] `make shell-db` used fixed names (`postgres`, `noaddx`); `make agent` with the OpenSSL engine did not check for the OpenSSL headers before building; no target built an agent for another system | `shell-db` uses the container's `POSTGRES_USER` and `POSTGRES_DB`; `agent` checks OpenSSL >= 3.2 through `pkg-config` first; `agent-cross GOOS= GOARCH=` builds a static native-engine binary | verified 14 Nov (`ba687d9`) |
| D-24 | [medium] Sessions ended after 15 minutes by default (`JWT_EXPIRATION_MINUTES` allowed 1 to 1440) | default 43200 minutes (30 days), range 1 minute to 365 days, sliding refresh after half the lifetime unchanged (D-2026-11-14-a) | verified 14 Nov (`ba687d9`) |
| A-11 | [low] The agent answered a known room pasted with other limits with `E_AGENT_ROOM_CODE`, whose sentence says the code is malformed | its own code `E_AGENT_ROOM_CODE_ALTERED` and sentence (`roomentry.go`) | verified 14 Nov (`ba687d9`) |

Feature (13 Nov): two doors. The main menu is the white human side; `robot` is a black door that
judges whoever presses it in the page (pointer trail, or a SHA-256 question), walks a human back and
lets a robot in. Theatre: it gates nothing, measures in memory only, sends and stores nothing
(`frontend/js/robot-door.js`, `docs/architecture/agents.md`). Seen working in a real browser on
both paths; its unit and fuzz tests (`frontend/tests/robot-door*.test.mjs`) ran in the frontend
suite of the full verification at eb9b17e.

Decided exception (Q-01): `Errors.format()` in `frontend/js/errors.js` throws two `TypeError`s with fixed
texts for the module's own misuse (unknown code, missing parameter); the user-facing path `message()`
maps them to `E_UNKNOWN_CODE` and `E_BAD_PARAMS`, and the tests pin both texts.

### Found 17 and 18 Nov

Everything below is in the tree of the full verification at `ce2c588` (State). "Audit" rows are the
22 records of the security audit of 18 Nov (`needs_validation` there: no target code was executed);
each fix came with a test that fails without it, and those tests ran in that verification.

| Id | Finding | Fix | State |
|---|---|---|---|
| C-23 | [high] In Safari (WebKit) a reload opened the main menu: the engine cannot read an X25519 `CryptoKey` back from IndexedDB, so `Keystore.load()` found no identity. The 14 Nov fix (C-22) had been tried in Chromium only | `Keystore.keepsKeys()` probes the engine; only where the key does not survive, the identity is kept as PKCS#8 wrapped under a non-extractable AES-GCM device key (AAD `"NAID"`, version, public key); `W_IDENTITY_NOT_KEPT`, `W_IDENTITY_UNREADABLE` | verified 18 Nov; reproduced and fixed in the real WKWebView engine, 0.15 s to the app after a reload |
| C-24 | [high] New messages did not appear without a tab switch: `onMessageEvent` dropped events while the page was hidden, and a proxy holding the stream delayed the rest | a hidden page syncs but marks read only when visible; heartbeat 10 s, silence limit 25 s, hidden polling 30 s with back-off on 5xx; nginx passes `X-Accel-Buffering` (`live-updates.js`) | verified 18 Nov; hidden page 0.27 s, behind a holding proxy first message within 27 s, then 5 s, both engines |
| F-02 | [feature] Member roles (`#tag`), set by the room owner for anyone or by a member for itself | sealed 93-byte blob under a key derived from the room secret, bound to room and card; the server stores it unread; owner-or-self, `E_ROLE_NOT_ALLOWED`; reserved words compared after NFKC and case fold ([rooms](../architecture/rooms.md)) | verified 18 Nov |
| F-03 | [feature] Files in a conversation | delivery only (D-2026-11-17-f): 256 KiB sealed parts, one key per part, the server relays bytes; no cleaning, no viewing; the name sent is `file-<8 hex>[.ext]`; a standing notice says a file can fingerprint its sender; limits 10 MiB a file, 100 MiB a conversation, a share per member, 100 MiB an account a day (memory only), 2 GiB a store ([files](../architecture/files.md)) | verified 18 Nov |
| F-04 | [feature] Alerts without content | Notification API only, title `elyrn.`, body `new message`, one tag, off by default; no Web Push, no service worker (`alerts.js`) | verified 18 Nov |
| D-25 | [medium] HSTS never reached a browser and had two homes; API answers carried two copies of some security headers; logout left site data to the browser | HSTS from nginx alone (`nginx-hsts.sh`, one year by default in production); one copy of each header on API answers; `Clear-Site-Data: "cookies", "storage"` on logout and account deletion | verified 18 Nov (`check-hardening`); the live instance's settings are the owner's to confirm (State) |
| S-11 | [audit] A room message's header card was not bound to the sending member | the header card must be the sender's stored card (`400 Sender card mismatch`) | verified 18 Nov |
| S-12 | [audit] A member could register a second card under another member's key and shadow it | a key under more than one card is a disputed seat: no role, no friend request, shown as disputed; the safety number counts seats when they differ from keys | verified 18 Nov |
| S-13 | [audit] A burned room could be created again by anyone holding its code | `burned_rooms` keeps the id until the room's original expiry. Limit: after that expiry the id is free again, as for any expired room | verified 18 Nov |
| S-14 | [audit] A friend request (an invite in a room note) was not bound to the member who sent the note | a binder derived from the requester's account key and the room keys; a relayed request is refused (`E_FRIEND_REQUEST_RELAYED`). Limit: a build before binders drops such a note unread | verified 18 Nov |
| S-15 | [audit] A refused clipboard clear was silent | the clear is bounded and a failure is said (`W_CLIPBOARD_NOT_CLEARED`) | verified 18 Nov |
| S-16 | [audit] The login mask branch could show the real account number | login never shows the number | verified 18 Nov |
| S-17 | [audit] A login left midway kept running | the run is taken before the first wait and every wait is followed by the leave check | verified 18 Nov |
| S-18 | [audit] A rate-limited or failed `/me` wiped the stored identity | only a `401` or another public key ends the stored session | verified 18 Nov |
| S-19 | [audit] The per-sender counter record had no bound a member could not abuse | at most 4,096 senders (agent 256); a full record refuses new off-roster senders and always records roster members (see A-12 to A-15, C-25) | verified 18 Nov |
| S-20 | [audit] An event stream outlived the revocation of its session | a revocation generation ends streams at once; each heartbeat checks the session again (one indexed lookup per stream per 10 s) | verified 18 Nov |
| S-21 | [audit] Deleting an account or burning a conversation deleted every row in one statement, which other members could make exceed the request budget | access ends at once; rows are purged in batches by the retention job (`orphaned_conversations`) | verified 18 Nov |
| S-22 | [audit] Retention deleted in one statement and rolled back whole on a timeout | batches | verified 18 Nov |
| S-23 | [audit] One member could use up a room's file quota | a share per member (`507 File share reached`) | verified 18 Nov |
| S-24 | [audit] The proof-of-work issuer refused everyone once its tracked-client table was full | an overflow bucket shared by untracked clients | verified 18 Nov |
| S-25 | [audit] nginx had no share of connections per client: slow bodies and streams could hold the pool | per-client and whole-pool shares for the API, the event stream, pages and files; `worker_connections` sized from them (`check-hardening` proves the sum) | verified 18 Nov |
| S-26 | [audit] The file pool had no per-client share | `files_per_client`; a file slot is taken only after authentication | verified 18 Nov |
| S-27 | [audit] Proxied bodies were spooled to a tmpfs | no spooling on the API locations | verified 18 Nov |
| S-28 | [audit] The agent reached an onion origin through any proxy the environment named | an onion origin is used only through a `socks5h` `ALL_PROXY` | verified 18 Nov |
| S-29 | [audit] The agent named a sender by its 12-bit name alone | name and code, `left` when the key is off the roster, `same_name` when another key shows the name | verified 18 Nov |
| S-30 | [audit] Go's JSON reader took keys in any case and repaired invalid UTF-8 where the browser refused | exact keys and strict UTF-8 for every sealed payload (`e2e/strictjson.go`) and for the agent's state file | verified 18 Nov |
| S-31 | [audit] A public instance could run in development mode | startup refuses development mode with an `https` or `.onion` origin | verified 18 Nov |
| S-32 | [audit] The release workflow signed the frontend of any pushed tag | only a commit on `main`. Limit: who may push a tag is the hosting service's rule | verified 18 Nov |
| D-26 | [low, audit hardening notes] `SendNote` 500 on a vanished conversation; `MarkRead` on an expired room; no rate bucket on conversation delete; `TRUSTED_PROXIES` took `/0`; received file names took invisible format characters; the restore runbook did not say to replace `JWT_SECRET`; `.gitignore` gaps; logout reported success after a partial revocation; seconds settings became durations unchecked; a key byte was logged | each fixed in its own commit | verified 18 Nov |
| A-12 | [medium, commit review] In the agent a flood of made-up senders in one loaded sequence stopped a roster member from being tracked | a kept sender (own key, roster) is always tracked; an untracked sender is reported and its messages say `unrecorded` | verified 18 Nov |
| A-13, C-25 | [medium, commit review] A roster member arriving at a full record displaced the oldest off-roster entry silently | it displaces the off-roster entry recorded most recently (a long-held entry is a real former member; a flood is recorded later), and the displaced sender is marked unrecorded; agent and browser alike | verified 18 Nov |
| A-14, C-26 | [medium, commit review] The bounded set of unrecorded senders failed open when full | once a key does not fit, a flag that never clears marks every sender that is neither kept nor in the record | verified 18 Nov |
| A-15 | [medium] An earlier page in the agent did not report the senders its ledger left untracked | every ledger reports them | verified 18 Nov |
| A-16 | [medium, found by the first full run] The MCP `join` tool checked a room code's prefix only; the agent parsed it. A refused call could reach the agent | one rule, `agent.ValidateRoomCode`, used by the tool and the agent | verified 18 Nov (`FuzzToolArguments`) |
| A-17 | [low, found by fuzz] The agent's state file did not load identically after a save (an empty `order`) | one load rule; keys matched byte for byte | verified 18 Nov (`FuzzDecodeCounterRooms`, seed kept) |
| C-27 | [low] Sealing a room message with an invalid file description threw before returning its promise | it rejects | verified 18 Nov |
| C-28 | [low] After a friend request was accepted the notes panel kept showing it | accept and every refusal redraw through `refreshRoomPanels` | verified 18 Nov |
| Q-05 | [tests, found by the first full run] A test helper that called itself (`holdHub`) took the integration package down; seven browser tests were wrong in themselves (two files built from the same bytes compared as different, order pins that read comments, a limit the server accepts listed as refused); a roles test looked a rejoined member up under its earlier card; `check-hardening` held an older rule for `pages_all` | each fixed at its cause; no assertion was loosened | verified 18 Nov |
| D-27 | [decided] The Argon2id hash of the auth key (S-07) | removed with its column (D-2026-11-18-a); schema version 2: a binary of version 1 refuses the migrated database (`E_SCHEMA_NEWER`), so going back means restoring the backup taken before the update | verified 18 Nov |

Known limits recorded in this round (none is a regression):

- **Open, S-33 (audit, deferred unit):** stored message volume has no bound per conversation or per
  instance beyond retention and the request limits; a member can grow the database until the
  retention period ends. Not hunted to the end in the audit; no fix yet.
- `RedeemInvite` maps a retired conversation id to `409` like `CreateRoom`; no test, because the id
  is drawn at random and forcing a collision would need a stand-in, which the tests do not use.
- The per-account daily file allowance is held in memory and is per account: many accounts and
  many addresses can still fill the store up to `FILE_STORE_MAX_BYTES`.
- Unrecorded senders are remembered per process (agent) and per tab (browser), not across restarts;
  a refused sender is refused and marked again on its next message.
- The audit run is closed as incomplete (60 agent invocations, 33 units, 22 records, five checked
  twice); its report is kept outside the repository.

## Order of work (the snowball)

1. Stage 1 (Q-01..Q-04, S-01..S-05, S-09, F-01), the negative-use suites and the fuzz campaign
   are committed and were run at eb9b17e (State).
2. Done 14 Nov: one full verification of the 14 Nov tree, its fallout fixed, committed and
   pushed (State).
3. Then: the items still open above (S-07 decision, D-09, D-18 remainder) and what State
   lists as not verified.

## Decisions

- D-2026-11-18-a: the stored Argon2id hash of the auth key is removed (closes S-07). Nothing read
  `users.account_hash` since login moved to the keyed lookup (S-02), yet every registration ran
  Argon2id to write it. Data nobody reads is not stored, and the memory-heavy step, its slots and
  its settings go with it. The migration drops the column inside the migration transaction.
- D-2026-11-17-a (owner): pending engineering and security decisions are analysed and taken by
  the lead through these lenses: cybersecurity, edge cases, disaster scenarios, situation
  handling, consistency, logic, continuity. They are recorded here and reported as taken.
- D-2026-11-17-b: where a browser cannot read an X25519 key back from IndexedDB (WebKit, proven
  in the Safari 27 engine), the identity is kept wrapped under a non-extractable device key, and
  only there; an engine that keeps the key keeps today's direct form and never produces the
  wrapped one. Decided by what the engine proves at login, never by its name. Cost, stated in
  the threat model: in the wrapped form, script running in the origin could unwrap an
  extractable copy. The alternative (asking for the account number after every reload) exposes
  the root secret each time and was judged weaker against the same threat.
- D-2026-11-17-c: the open conversation is synced while the page is hidden; nothing is marked
  read until the page is visible. A hidden page behind a held event stream polls every 30 s.
- D-2026-11-17-d: the event stream's heartbeat is 10 s and a silent stream is noticed after
  25 s; nginx passes `X-Accel-Buffering: no` through so an outer nginx does not buffer it.
- D-2026-11-17-e: member roles (`#text` beside a room member). The owner sets anyone's, a member
  only their own (server-enforced, 403 otherwise). The text is sealed under a key derived from
  the room secret and bound to the member's stored card; the server never reads it. A role
  grants nothing. Reserved words are compared after NFKC and case folding. Known limits: a
  cross-script lookalike of a reserved word is not caught, and a lying server can serve an
  older role of the same member.
- D-2026-11-17-f: file sharing. A file is sealed in the browser into equal 256 KiB parts; its
  key travels inside an ordinary message. Limits: 10 MiB per file, 100 MiB per conversation,
  100 MiB per account per day (held in memory only, so nothing about an account's volume is
  stored), 2 GiB in total; a full store refuses uploads and nothing else. elyrn. delivers a file
  exactly as it is and never reads, interprets, cleans or displays its content; the only thing it
  sets is the name a file is sent under (`file-<8 random hex>` plus a short plain extension), and
  the sender is told at every chosen file that the file goes with whatever it carries. No CSP
  change. (18 Nov 2026: the owner decided delivery only, replacing the re-encoding of images:
  decoding files in the page is attack surface, and cleaning a few formats teaches people to
  trust it with the ones it does not clean.)
  Not in this round: deleting an uploaded file, download by the Go agent.
- D-2026-11-17-g: the per-account file budget evicts the fullest budget when its table is full
  rather than refusing new accounts. Many accounts can fill the store either way (each costs
  registration proofs of work); refusing would only add a way to lock honest accounts out.
- D-2026-11-17-h: at most 32 file requests are handled at once, counted only for an
  authenticated caller; nginx admits 4 per address and 32 in total on the files location.
  Known limit: many addresses can occupy that pool; messages do not use it.
- D-2026-11-17-i: content-free alerts are the browser's own notification with a fixed text,
  off by default. No Web Push and no service worker: a push service is a third party that
  would learn when an account receives messages. Consequence: alerts work only while elyrn is
  open in a tab.
- D-2026-11-17-j: the open conversation is not remembered across a reload, neither in the
  address nor in storage: it would leave a trace on the device.
- D-2026-11-17-k: HSTS has one home, nginx, and covers every HTTPS answer of the clearnet
  listener; in production it defaults to one year and `0` turns it off. `Clear-Site-Data` is
  sent on a successful logout and account deletion. API answers carry one copy of each
  security header (two CSPs stay: the browser enforces both).
- D-2026-11-17-l: a message whose payload carries keys this build does not know is shown as
  sent by a newer elyrn, with the advice to reload, not as a tampered message.
- D-2026-11-17-m: not built in this round: renaming a room, delivery and read ticks, a typing
  indicator.
- D-2026-11-14-a (owner): sessions last 30 days by default (`JWT_EXPIRATION_MINUTES=43200`),
  configurable from 1 minute to 365 days, with the sliding refresh after half the lifetime, so a
  session in use does not end; logout and account deletion still end every session at once.
- D-2026-11-12-a: design of the robot entrance, D1 to D9 in `docs/architecture/agents.md`.
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
