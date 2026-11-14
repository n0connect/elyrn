# Changelog

All notable changes to elyrn. are recorded here. Security fixes are always listed explicitly
(see [SECURITY.md](SECURITY.md)). The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- **Go 1.27.4.** Builds use Go 1.27.4 (GO-2026-6859, net/http HTTP/1 server crash in the
  MaxBytesReader header race); it also carries the fix of Go 1.27.3 (GO-2026-6809).
- **Existence oracle on send (N-01).** A non-member sending a well-formed message to a live room
  got `400` where a missing id got `404`. Membership is now checked first: both answer `404`.
  Negative-use suites generated from the route table pin it (108 refusals without a session,
  50 byte-equal "not yours" and "never existed" answers).
- **An account number is never sent (N-02).** The browser and the agent refused nothing that
  looked like an account number: it could be sent as a message or pasted as an invite. Both now
  refuse it with their own code (`E_MESSAGE_IS_ACCOUNT_NUMBER`, `E_INVITE_IS_ACCOUNT_NUMBER`,
  `E_AGENT_MESSAGE_IS_ACCOUNT_NUMBER`), fullwidth look-alikes included, from one shared sample
  table; a room code in the login field says what it is.
- **"Stored" only for one's own resend (N-03).** Any duplicate message or note id answered
  `409 Conflict`, which clients read as "stored". `409 Conflict` now means only the caller's own
  identical earlier attempt; any other holder of the id answers `409` JSON `Id taken`
  (`E_ID_TAKEN`), nothing is stored, and the browser and the agent send once more under a fresh id.
- **A join is bound to its code's limits (S-10).** The room id and lookup derive from the secret
  alone, so a code with edited limit bytes still joined and replaced the member's vault with one
  that never verifies (the room was hidden for good). Join now carries `max_members` and
  `expires_at` and the server refuses other limits like a wrong code (`404`) before any seat or
  vault changes; the browser and the agent refuse a known room pasted with other limits.
- **Replay records survive a server-ended session (C-03).** Any `401` wiped the whole browser
  storage, replay counters included, so a hostile server could answer `401` once and replay
  undetected. A session the server ends now removes the identity only; the user's own logout or
  deletion removes everything. The agent no longer drops a room's counter record because a
  listing omitted it or the server answered `404` (A-09); only the room's own expiry or the
  agent's own leave does.
- **Strict session tokens (L-06).** A JWT signature re-spelled with unused bits or inserted line
  ends still verified; only the exact three base64url segments verify now.
- **No identifiers in logs (N-04, D-08).** Repository loggers and startup failures printed driver
  error text (database user, name, host); every database error is now reduced to its class,
  startup failures name the variable and never its value, panics are logged by type, the
  peer-address scrubber catches bare and zoned IPv6 and glued IPv4, and the active master key id
  is no longer logged.
- **nginx mirrors the input contract.** `/api/` was one prefix proxied whole, with a 1 MiB body
  limit. nginx now admits only the contract's routes (exact paths, canonical UUIDv4 segments),
  their methods and a body bound per route group at the smallest round size above the
  contract's (1k, 2k or 8k), and refuses everything else under `/api/` itself: 404 for another
  path, 405 for another method, 413 for an oversized body before it reaches the backend. These
  refusals are nginx's own JSON answers with registered `E_EDGE_*` codes (see "JSON answers from
  nginx (D-11, C-18, L-01)" under Added).
- **Restricted containers (S-08).** Every service now drops all capabilities (PostgreSQL keeps
  `CHOWN`, `DAC_READ_SEARCH`, `FOWNER`, `SETUID`, `SETGID` for its start as root, then runs as
  uid 70), runs with a read-only root, `no-new-privileges`, Docker's default seccomp profile and
  bounded memory without swap, pids, CPU, open files and `/dev/shm`; writable paths are named
  tmpfs mounts with `noexec,nosuid,nodev`. nginx runs as uid 101 on unprivileged ports and the
  backend gets 512 MiB (Argon2id peak 256 MiB plus headroom, `BACKEND_MEM_LIMIT`). The single
  network is split into `edge` (nginx, tor), `app` (nginx, backend) and `data` (backend,
  PostgreSQL); `app` and `data` are internal with no bridge address, so in production the backend
  and the database have no internet and neither the host nor a container on another network reaches
  them, even where the runtime routes between bridges. The backend still trusts nginx alone at
  `PROXY_IP`. Production publishes nginx only; the backend and PostgreSQL ports moved to
  `docker-compose.dev.yaml`, which `make up` adds in development. nginx gained header, timeout,
  dotfile and method limits; base images are pinned by digest. `make check-hardening` fails when
  the rendered config loses a control. Upgrading: `make up` stops the old stack once (volumes
  stay); an `.env` with `TOR_IP=172.29.73.11` needs `172.29.72.11` before `make onion`.
- **One input contract, default deny.** Input checks were spread over handlers, utils and a
  content-type middleware, and some inputs slipped through: duplicate JSON keys (the last won),
  keys in any letter case, a registration body with unknown fields or trailing data (read as an
  empty phase 1 request yet still served with a valid proof of work), query strings on the auth
  routes, bodies on GET, DELETE and logout, and `Content-Type` parameters. Every route now
  passes one gate (`internal/contract`) that admits exactly what its table declares: methods,
  query parameters, `Content-Type: application/json` exactly, a body bound derived from each
  endpoint's largest legitimate body (123 bytes for login instead of 1 MiB), and every field by
  an anchored pattern plus a validator where a pattern cannot say everything. An input already
  refused for one reason keeps its status and body (a request with several faults may now get
  the gate's answer before a 401 or 429); the whole whitelist is
  [docs/api/input-contract.md](docs/api/input-contract.md), generated from the table.
- **TLS to the bundled database; production mode for Compose and onion instances.** The backend
  reached the bundled PostgreSQL in plain text, so the Compose stack could not pass the
  production checks and onion instances ran in development mode (unprefixed cookie without
  `Secure`). `make certs` (run by `make setup`, `make up` and `make onion`) now creates a private
  CA and a server certificate in the git- and Docker-ignored `certs/` (keys 0600); PostgreSQL
  accepts TCP only over TLS 1.3 and the backend verifies its certificate and name
  (`verify-full`). Certificates renew within 30 days of expiry and a renewal recreates exactly
  the container that loads them. `make onion` refuses to start unless `APP_ENV=production`.
  Existing installations get the certificates at their next `make up`; data and `.env` are
  untouched.
- **Live updates held by one network.** The event stream hub allowed 4 streams per account and
  4,096 in all, first come first served, and accounts cost only a proof of work: a few hundred
  accounts from one network could hold every stream, and nobody else got live updates. Each
  network (the client key the rate limiter uses: an IPv4 address, IPv6 /64 or Tor circuit) now
  holds at most 16 streams, four accounts at their full cap, so filling the hub takes 256
  networks. Over its share a stream is refused with the usual `429`.
- **Proof-of-work challenge pool.** Every issued challenge was kept in one global pool of
  50,000 until it expired, and `GET /api/v2/pow/challenge` is free, so anyone could fill the pool
  and registration, invites and rooms answered 503 for everyone. Issuing now stores nothing: the
  salt is an HMAC over the challenge, timestamp, ttl and difficulty under a per-boot secret, and
  the server verifies a solution from the echoed fields alone. Only solved challenges are kept
  (single use, until they expire, at most 50,000), so filling that set costs a full proof of work
  per entry. The wire format is unchanged; challenges issued before a restart are refused (403).
- **Login lockout through Argon2id.** Every login with a well-formed auth key ran a full Argon2id
  verification (a decoy one for unknown keys) in `ARGON2_MAX_CONCURRENT` global slots, with no
  proof of work, so anyone could keep the slots busy and every login answered 503. Login now
  proves the key by its keyed lookup alone (`HMAC(pepper, auth key)`, compared in constant time,
  the same work for known and unknown keys): a 256-bit key gains nothing from a memory-hard hash.
  Argon2id runs only in registration phase 2, behind its proof of work; existing accounts and the
  stored hash format are unchanged.
- **Replay and reorder after a reload.** The client kept seen message ids and sender counters in
  memory only, so after a reload a malicious server could serve an old authentic message again
  as new, reorder messages, or withhold a device's own last messages so its next send reused a
  counter. Each device now remembers, per conversation, the highest seq it processed and each
  sender's highest counter (IndexedDB; no text, ids or times): a message with a used counter is
  shown as "replayed or reordered by the server" instead of its text, and a counter is never
  reused. Detection stays per device; a device's first open of a conversation is not covered.
- **Lookalike room members.** A room message from someone else was labelled with the sender's
  name alone, which carries 12 bits: anyone holding the room code could grind an account offline
  (about 4,096 tries) until its member key bore a member's name, join, and write as them. Every
  room message now shows the sender's glyph, name and code (43 bits to match), gap warnings name
  the sender with its code, and two keys under one name are tagged "same name as another member"
  in the member list and on their messages, with one warning per session.
- **Shared rate limits behind nginx.** `TRUSTED_PROXIES` was empty in the Docker stack, so the
  backend saw every user as nginx's address: about 20 failed logins locked everyone out, and
  five PoW challenges per minute were shared by all clients. nginx now has a fixed address that
  the backend trusts, and only it.
- **Session revocation.** A token revoked by an earlier logout could log out the sessions created
  after it, and a failed revocation still answered "logged out". Logout now uses the same gate as
  every protected route and reports failure.
- **Session token exposure.** Login and registration returned the session token in the JSON body,
  and the API accepted it as a Bearer header. It now lives only in the HttpOnly cookie.
- **CSRF from same-site origins.** `SameSite=Strict` still sends cookies from other ports and
  sibling subdomains. State-changing requests now require `Sec-Fetch-Site: same-origin` (or an
  exactly whitelisted `Origin`).
- **CORS prefix match.** `http://localhost:3000.evil.example` was accepted when `http://localhost`
  was listed. Origins are now matched exactly.
- **Spoofable client address.** `X-Forwarded-For` was read from the left (client-controlled); it
  is now read from the right. IPv6 clients are keyed by /64, so address rotation no longer
  escapes rate limits.
- **Unbounded memory.** The rate limiter grew without bound between cleanups and sorted with an
  O(n²) loop under its global lock; PoW challenges and pending registrations had no cap. All are
  bounded now and fail closed.
- **Weak key material accepted.** A 32-character passphrase was accepted as a master key, and a
  short string as the lookup pepper. Only 32+ bytes of hex or base64 are accepted now; a malformed
  `MASTER_KEY_OLD` stops startup instead of being skipped; records decrypt only under their
  stored key id.
- **Crash on stored parameters.** An Argon2id hash with parallelism 0 or 256 panicked the server;
  stored parameters are range-checked before use.
- **Configuration ranges.** Every numeric setting is range-checked at startup. Production requires
  `verify-ca`/`verify-full` TLS to PostgreSQL and a non-default database password. The
  PostgreSQL URL is built with escaping (no DSN injection).
- **Dependencies.** golang-jwt 5.3.1 (GO-2025-3553), pgx 5.11.0 (GO-2026-5004, SQL injection),
  x/text 0.43.0 (GO-2026-5970, GO-2026-6629). The Go toolchain is in the Go 1.27.4 entry.
- **Browser hardening.** The page CSP no longer allows inline styles or `data:` images; API
  responses are inert (`default-src 'none'`, `no-store`); text from a peer has bidi overrides
  and control characters neutralized before display.
- **Containers.** Every published port binds to loopback; the backend runs as an unprivileged
  user on a read-only filesystem without capabilities.
- **AccountNumber exposure window.** Phase 1 of registration kept the AccountNumber (which also
  seeds the user's E2E identity) in server memory for up to five minutes; it now keeps only the
  derived auth key and public key, and the AccountNumber leaves memory with the phase-1 response.
- **Argon2id memory bound.** Unlimited concurrent Argon2id hashes could allocate 64 MiB each until
  the process died; at most `ARGON2_MAX_CONCURRENT` run at once and the rest get 503 after 3 s.
  Argon2id ran at login then; since "Login lockout through Argon2id" (above) it runs only in
  registration phase 2, behind its proof of work, and the bound applies there.
- **OpenSSL error queue** is cleared on the thread that filled it (cgo calls can change OS
  threads), so no failure detail lingers between calls.
- **Master key rotation left the old key in charge.** Rotating only changed the key for new
  records; every existing account key and member reference stayed under the old (possibly
  exposed) key for good. Records are now re-wrapped under the active key in the background, and
  the old key can be removed once the log says none remain.
- **Mismatched `.env` started a broken server.** A regenerated `.env`, a wrong pepper or an old
  master key removed too early started a server that answered every account with errors. The
  backend now opens sample records with every key id in use and compares the pepper with a
  commitment pinned at the first run, and refuses to start on a mismatch.

### Added

- **Two doors.** The main menu is the human door (login, new identity); `robot`, captioned
  "the other door", is the black robot door that judges whoever presses it in the page (pointer
  trail, or a SHA-256 question), walks a human back and lets a robot in to the agent command. It gates nothing, measures in
  memory only, and sends and stores nothing. Every screen before login has a way back
  (`← back to main menu`, the brand title, Escape); leaving registration ends its proof of work
  and asks twice once the account may exist. A favicon.
- **Operations (D-06, D-07, D-13, D-14, D-16).** A schema version with a migration lock
  (`E_SCHEMA_NEWER` refuses a database migrated by a newer binary); a single-instance advisory
  lock (`E_SECOND_INSTANCE`); a loopback-only health endpoint (`/internal/health`: `SELECT 1`
  within 3 s and retention cycling) behind the compose healthcheck; log rotation on every service
  and a per-code log flood bound; `make certs` warns 60 days before a certificate expires;
  `make test-restore`, a restore drill entirely inside the disposable test stack. Every startup
  and lifecycle failure has a registered operator code (`backend/internal/apperr/opcode`) and one
  exit path (status 78).
- **JSON answers from nginx (D-11, C-18, L-01).** nginx no longer replaces the backend's coded
  answers with HTML pages; its own refusals answer JSON with a registered code
  (`E_EDGE_NOT_FOUND`, `E_EDGE_METHOD_NOT_ALLOWED`, `E_BODY_TOO_LARGE`, `E_EDGE_RATE_LIMITED`,
  and `503 E_BACKEND_UNAVAILABLE` for a backend that is down or slow, which used to answer 502 or
  504). The browser and the agent map them by code. Five status pages nothing pointed to are gone.
- **Fuzz stage.** 76 Go fuzz targets (47 new on the server, plus the agent and MCP), each asserting
  invariants, not only "no panic"; one list in CI checked by `scripts/check-fuzz-targets.py`;
  `make fuzz` and `make fuzz-js`; seven seeded browser fuzz files whose failures carry their seed.
- **Negative-use suites.** Generated from the route table for the server and the agent, and for
  the browser (inputs, a hostile server, auth flows).
- **MCP `room_read` pages back** with `before` (F-01); every tool argument is validated before
  the agent is touched.

- **Earlier messages.** Only the latest `MESSAGE_PAGE_LIMIT` messages of a conversation were
  reachable. `GET /api/v2/conversations/{id}/messages?before=seq` returns the page just below
  `seq` (never below a room member's join), `/me` reports `message_page_limit`, and the browser
  shows an "earlier messages" control above the list while more may exist. Earlier pages are
  checked for replay and reorder on their own and never change what the device remembers.

- **Robot entrance.** AI agents join rooms through `elyrn-agent`, a Go program that speaks the
  same end-to-end protocol as the browser and exposes it as MCP tools over stdio (`make agent`;
  `elyrn-agent mcp --server https://host`). An agent is an ordinary account: same proofs of work,
  rate limits and encryption, no server-side flag. Its identity lives in one file the program
  refuses to use with permissions wider than 0600. The main menu has a `robot` entry that shows
  the command with the instance's origin filled in. See
  [Agents](docs/operations/agents.md) and [Robot Entrance](docs/architecture/agents.md).
- **Rooms.** Code-based group conversations for 2 to `ROOM_MAX_MEMBERS` (default 16, up to 32)
  people, living 1 hour to `ROOM_MAX_TTL_HOURS` (default 7 days). The 256-bit room code never
  reaches the server: it stores an HMAC of a derived lookup and checks seats, lifetime and order.
  Every message has its own key, wrapped for each member the sender saw with an ephemeral and a
  static X25519 secret (which also authenticates the sender, deniably), committed against key
  substitution, and bound to a roster digest the server checks (`412` on a stale roster). Late
  joiners read only what was sent after they joined. Members carry a different key and name in
  every room, compare a room safety number, and can send each other friend requests: an invite
  sealed for one member, accepted through the usual fingerprint check. Go (`internal/e2e`) and
  the browser open each other's vectors. See [docs/architecture/rooms.md](docs/architecture/rooms.md).
- **Two byte-for-byte equivalent crypto engines.** The OpenSSL engine (libcrypto >= 3.2 through
  cgo, now with HKDF and X25519) returns alongside the native Go engine; `ENGINE=openssl|native`
  picks one at build time and OpenSSL is the default. Input validation is shared, known-answer
  tests run on both, a differential suite proves identical outputs and rejections
  (`make test-equivalence`), and the server runs a known-answer self-test before it starts.
- Release tags per engine (`elyrn-openssl-vX.Y.Z`, `elyrn-native-vX.Y.Z`), moving dev tags
  (`elyrn-openssl-dev`, `elyrn-native-dev`) and `make build-ref REF=<tag>` to rebuild any of them.
- **Verifiable client.** Each release tag gets the SHA-256 of every frontend file, signed with
  Sigstore keyless by the release workflow; `make verify-frontend URL=…` checks that any
  instance, onion included, serves exactly those bytes.
- **Five padding sizes.** Messages are padded to a power of two from 256 to 4096 bytes, so a
  ciphertext's length reveals one of five size classes (it was one of 24), and the server
  accepts no other size. The longest message drops from 6000 to 4094 bytes of payload, still
  above the 2000-character composer limit; messages stored before the change still open.
- **Delete identity.** `DELETE /api/v2/me` erases the account, its invites and every
  conversation it is in, for both sides; peers are told at once and every session ends. It
  takes the account number again (as its auth key), and the browser checks the number belongs
  to this identity before sending, so the server never sees a second account's key. A `DELETE`
  that carries a body must now declare JSON, like every other write.
- **Onion service (`make onion`).** An opt-in tor container publishes the app as a Tor v3
  onion service with Tor's own PoW and introduction DoS defenses. Abuse control keeps working
  without client IPs: tor names each circuit in a PROXY header, nginx's onion listener accepts
  only the tor container, and the backend rate-limits each circuit separately (it used to group
  Tor's whole address range like one IPv6 subscriber, which would have put every Tor user in
  one bucket). A circuit holding more than 32 open connections is torn down, and the PoW
  issuer forgets idle clients after one window instead of an hour, so a flood of circuits
  cannot fill its client cap and refuse challenges to everyone.
- **Invites cost a proof of work.** `POST /api/v2/invites` now takes `{"pow": …}` with a fresh,
  single-use solution, like each registration phase: missing → 412, invalid or replayed → 403,
  empty body → 415. While the browser solves it, the invite code scrambles, masks and reveals
  exactly like a new account number; the invite panel's "done" button is gone.
- Fuzz tests for every parser that faces the network (stored hash format, E2E ciphertext and its
  AAD bindings, UUID/invite/ciphertext whitelists, PoW solutions, JSON bodies).
- GitHub Actions: both engines with the race detector and fuzzers, the equivalence suite,
  frontend interop tests, govulncheck, gitleaks over the full history, and both Docker images
  booting as the unprivileged user with the self-test passing.

- `docs/operations/disaster-recovery.md`: what each failure does, what to back up (accounts only,
  never messages) and how to restore; `make backup-accounts`.

### Fixed

- **Server situation handling (D-01..D-05, D-10, D-12, D-15, D-17).** Retention compares wall and
  monotonic time and pauses on a clock jump (`E_CLOCK_JUMP`), so a jump never purges early; reads
  never serve expired rows; an abandoned critical job exits the process (`E_JOB_ABANDONED`) so the
  restart policy starts a fresh one; statements, waits and transactions have deadlines; a
  database outage answers `503 E_STORE_UNAVAILABLE` on every route, the session check included;
  deletes lock the conversation before its children, so a racing send leaves no orphan
  ciphertext; handler panics answer `500 E_PANIC`; shutdown stops requests, then jobs, then the
  database, and zeroizes keys last, refusing to seal afterwards (`E_SHUTTING_DOWN`); re-wrapping
  retries until no record uses an old key (`E_REWRAP_INCOMPLETE`).
- **One deadline per request (L-03).** A request's whole database work runs under one deadline
  derived from `SERVER_WRITE_TIMEOUT_SEC`, so a request stalled on the database still writes its
  `503` before the write deadline; background work keeps its own limits.
- **A slow database no longer costs the instance lock (L-02).** The lock watcher's own deadline
  closed the lock's session when the database paused, and the server exited with its in-memory
  state. A database that stops answering now logs `E_INSTANCE_LOCK_UNREACHABLE` once and the
  server keeps running; only a closed connection is `E_INSTANCE_LOCK_LOST`.
- **Browser situation handling (C-01..C-17).** Requests time out (`E_REQUEST_TIMEOUT`); the
  account number stays until the app opens (`E_ACCOUNT_CREATED_NOT_ENTERED`); a draft per
  conversation; a bounded, cancellable proof of work (`E_POW_TIMEOUT`); inline login and
  registration errors; one global error handler and a retry for failed loads; counters allocated
  under a Web Lock with write-ahead, so two tabs never reuse one; single-flight list refresh;
  rooms that fail verification are listed with a leave action; one busy flag per action; storage
  failures shown; delete with a lost answer probes `/me`; a first-attempt `409` is never taken as
  stored; clock hints; the room code cleared from the clipboard; bounded answer bodies; a
  back-forward cache check. A left registration, invite or room panel leaves nothing behind.
- **Agent situation handling (A-01..A-08, A-10, L-04, L-05, N-06).** One process per identity
  (`E_AGENT_IDENTITY_IN_USE`); send and seen counters persisted write-ahead, and replays detected
  and listed without text; an interrupted registration is finished by the next run; a failed `/me`
  check leaves no session; `room_wait` outlives a dying stream; a lost create answer is settled;
  shutdown waits for the call in flight; a TLS code; history pages follow the browser's ceiling
  rule; any `5xx` is a passing failure; one canonical server origin; the join code is parsed
  before an account is created; the cursor never runs past the room's end.
- **Agent and browser trim message text alike (L-07).** One explicit trim set on both sides.
- **Code boxes never visible (C-19).** The nonce, the agent command and the open room's code sat
  in boxes an animation rule kept at opacity 0 (also before the two doors). They are shown now;
  Enter in the door's challenge field no longer reaches the copy button.
- **Plain backend refusals under their own codes.** A backend `503` (plain text, "Service
  unavailable"), `405`, `413` and `415` reached the user as a generic failure; the browser now maps
  them to `E_API_UNAVAILABLE`, `E_API_METHOD_NOT_ALLOWED`, `E_API_BODY_TOO_LARGE` and
  `E_API_INVALID_REQUEST`.
- **Invites cleared from the clipboard (C-18),** like the room code and the account number.
- **A client leaving while its event stream starts** no longer turns the stream's database lookup
  into an internal error: the stream's database work runs under its own deadline, and any
  remaining cancelled work is `E_REQUEST_CANCELLED` (logged at INFO, never as an error).
- **One origin per server.** A server address with an empty port or another spelling of the same
  origin made a second origin for one server (a false `E_AGENT_SERVER_MISMATCH`); the agent keeps
  one canonical origin. Pointer coordinates near the floating-point limit no longer make the
  robot door draw an endless detour.
- `make` declares as `.PHONY` only targets that exist.
- **The integration package exhausted PostgreSQL's connections (N-05).** One pool at a time, no
  exiting path reachable from tests, and a connection guard in `TestMain`.

- **"Copied" shown when the copy failed.** Without the async clipboard API (older browsers,
  insecure contexts) a failed copy was logged and then reported as a success. It now fails, and
  the user is told to copy by hand ("copy it manually", or the account-number warning at signup).
- **Login during a database outage said "invalid credentials".** It now answers 503, so a user is
  never told that a valid account number is worthless.
- **A failed signup burned the account number.** Phase 2 used the pending registration up even
  when it then failed (database outage, saturated Argon2id), so the number the user had just
  saved never worked. It now stays redeemable until the account exists; the browser stays on the
  page, says the number is still valid, and on a lost answer logs in with it instead.
- **Lowering `MAX_CONVERSATIONS_PER_USER` locked accounts out.** Accounts above the new cap could
  not list, burn or delete their conversations, or delete themselves. The cap now only limits new
  conversations.
- **Lowering `MESSAGE_TTL_DAYS` did not shorten stored messages.** Retention now caps every
  stored message at the new limit.
- **nginx answered 502 after a backend upgrade** when the recreated container got a new address
  (nginx resolves it once). The backend now has a fixed address (`BACKEND_IP`).
- **PostgreSQL did not come back after a crash or reboot** (no restart policy) while the rest of
  the stack did.
- **A retried send could deliver a message twice.** A retry after a lost answer reuses the
  message id and ciphertext, so the server refuses the duplicate; the sender's counter never
  repeats within a session, so a withheld message shows up as a gap.
- Database sessions give up on a lock after 5 s and drop transactions idle for 30 s, so a stuck
  request cannot hold the connection pool.

### Changed

- **Sessions last 30 days and slide.** `JWT_EXPIRATION_MINUTES` defaults to 43200 (30 days)
  instead of 15 and accepts 1 to 525600 (365 days) instead of 1 to 1440. A session used past
  half its lifetime is re-issued, so it ends only at logout, account deletion or after 15-30
  days without use. A stolen session cookie is therefore useful for that long unless the account
  logs out or is deleted. The pending-registration token keeps its own `PENDING_TOKEN_TTL_SEC`.
- The browser reports every failure and warning by a registered code from one module
  (`js/errors.js`) and logs only through `js/log.js`, which keeps a code, an error's name and a
  status number and nothing else; five messages now say what to do next.
- The browser's wide crypto calls (`sealMessage`, `sealNote`, `encryptMessage` and the helpers
  under them) take one named-argument object; event wiring, the conversation refresh, message
  sync, roster loading and the account-number copy are split into one function per job; and its
  timeouts, limits, sizes and repeated strings are named constants, each with one home. No
  behaviour, wire format or stored data changes.
- The server answers every failure through one registry (`backend/internal/apperr`): each cause
  has a code, status, sentence and log level, and is logged once by code and operation. Status
  and body text are unchanged on the wire. A failed client-key secret or HMAC now answers 500
  instead of a panic that dropped the connection. Login's JSON-shaped failures
  (`{"success":false,"message":...}`) are registered codes too (`E_LOGIN_*`), written in the same
  bytes; registration is split into its two phases in the code. The MCP in-flight tests run the
  real agent against the real server instead of a stand-in backend.
- The project is now **elyrn.** (formerly noaddx.): the brand, the Go module, binaries, images,
  containers, release tags (`elyrn-openssl-*`, `elyrn-native-*`) and the prefixes of new codes
  (`elyrn:` invites, `elyrn#` rooms). Stored and wire names do not change (the `noaddx` HKDF
  labels, the IndexedDB and database names, the development cookie), so identities, rooms and
  sessions carry over, and `noaddx:` and `noaddx#` codes are still accepted.
- The retention run purges every five minutes instead of hourly, so expired rooms do not linger.
- nginx revalidates the page and its assets on every load (`Cache-Control: no-cache`, mostly
  `304`): with a one-hour cache, browsers ran a new page with old scripts after an upgrade.
- Sessions saved before rooms ask for the account number once more, to derive the rooms key.
- The delete button sits on the same line as logout and turns red on hover; one red token
  (`--danger`) is used for every destructive or failed state.
- The project is now **noaddx.** (formerly noaddress.). Protocol labels changed with the name, so
  identities created under the old name do not carry over.
- `make setup` generates the database password and works with any `openssl`; `make test` runs the
  complete suite, database and integration tests included.
- Go 1.26 or newer is required to build.
- `setup.sh` and `run.sh` are gone; they only forwarded to `make setup` / `make up` / `make test`.
