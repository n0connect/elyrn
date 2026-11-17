# Testing & Development Guide

This guide covers running test suites across Go backend units, database migrations, integration scenarios, and frontend WebCrypto cryptographic verification.

---

## Test Architecture Overview

```text
+-------------------------------------------------------------+
| 1. Frontend WebCrypto Verification                          |
|    node --test frontend/tests/*.test.mjs                    |
|    (Checks byte-for-byte derivation matches Go)             |
+-------------------------------------------------------------+
| 2. Backend Unit & Cryptographic Tests                       |
|    go test -tags=test ./internal/...                        |
|    (either ENGINE, runs without external database)          |
+-------------------------------------------------------------+
| 3. Database Migration & Integration E2E Tests               |
|    Requires PostgreSQL (containerized or local)             |
|    make test                                                |
+-------------------------------------------------------------+
```

---

## Running Tests

### Option A: Fully Containerized (Recommended)

Run all tests inside an isolated Docker container with a disposable tmpfs PostgreSQL instance:

```bash
make test
```

**What this does:**
1. Starts `postgres-test` with temporary in-memory storage (`tmpfs`).
2. Builds `test.Dockerfile` for `ENGINE` (OpenSSL by default, with the equivalence suite; `ENGINE=native` for the Go engine).
3. Executes unit and integration test packages.
4. Shuts down and cleans up test containers.
5. Emits output to `test-results/output-<engine>.log`.

---

### Option B: Local Native Go Tests

If developing natively on your host machine:

#### 1. Non-DB Unit Tests (Instant, No Postgres Required)
```bash
make test-unit                 # OpenSSL engine (needs OpenSSL >= 3.2 headers + pkg-config)
make test-unit ENGINE=native   # Go standard library engine
# Direct command: cd backend && go test -tags=test ./internal/... ./tests/auth/... ./tests/encryption/... ./tests/identity/... ./tests/middleware/... ./tests/utils/...
```

#### 2. Full Suite (Requires Local Postgres running on 5432)
```bash
# Step 1: Database and integration tests against a separate local PostgreSQL (TEST_DB_* overrides);
# never the bundled one: it holds live data and accepts TLS connections only
make test-db

# Step 2: Full Suite with Race Condition Detector
cd backend
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=noaddx_test go test -p 1 -race -tags=test ./...   # add openssl to -tags for that engine; noaddx_test: the stored name kept across the rename
```

Every database test brings the database up through `testutil.StartDatabase`: the error-returning `database.Start` (a database that cannot be reached fails that test, it never ends the test binary), with the previous test's pool closed first and its own pool closed when it ends, so one pool is open at a time whatever the number of tests. The integration package runs between two counts of the test database's sessions (`tests/integration/connections_test.go`, from `TestMain`): sessions left open by the tests (a pool, a server, a transaction not released) fail the run, listed by `application_name` (`elyrn-backend` for the backend's own), state and the first word of their statement.

---

### Option C: Frontend WebCrypto Derivation Tests

Verify that JavaScript's native W3C WebCrypto produces identical cryptographic keys, fingerprints, and AAD ciphertexts as Go's internal packages:

```bash
make test-crypto
# Direct command: node --test frontend/tests/*.test.mjs
```

To run both unit tests and frontend crypto tests with a single command:
```bash
make test-all
```

**Requirements:** Node.js 20+ (utilizes native `node:crypto` and built-in test runner, zero npm dependencies).

`frontend/tests/` holds 22 test files with 199 tests: twelve unit files (`crypto`, `room-crypto`,
`rooms`, `counters`, `errors`, `utils`, `validation`, `pow-worker`, `robot-door`, `start-view`,
`alerts`, `role-control`) and the three negative-use files (Option E), plus seven seeded fuzz
files (`*.fuzz.test.mjs`, Option D). What only a real browser shows is driven by hand, never
faked: the IndexedDB round trip of `Keystore.keepsKeys` (which form an engine keeps), the
permission prompt and the notification of `alerts.js`, and typing in the role control.
`crypto.test.mjs` alone checks, among others:
- `auth key matches Go derivation`
- `identity public key matches Go derivation; private key is not extractable`
- `strict base64url rejects malformed account numbers`
- `both peers derive the same conversation key and round-trip a message`
- `ciphertext length is one of five power-of-two buckets`
- `opens a message encrypted by the Go implementation (interop)`
- `AAD binding: wrong message id, sender, conversation, or tampered bytes fail`
- `invite code carries a fingerprint the redeemer can verify`
- `safety number and aura are symmetric and deterministic`
- `payload limit is enforced before encryption`

### Counts

| Suite | Count (13 Nov 2026) | How to count |
|---|---|---|
| Go test functions | 378 (137 in `tests/integration`), plus one `TestMain` | `grep -rhE '^func Test[A-Z_]' --include='*_test.go' backend \| grep -vc '^func TestMain'` |
| Go fuzz targets | 76 | `python3 -I scripts/check-fuzz-targets.py --list \| wc -l` |
| Frontend tests | 199 in 22 files (17 Nov 2026) | `grep -hcE '^test\(' frontend/tests/*.test.mjs` (summed), or the `tests` line of `node --test frontend/tests/*.test.mjs` |

---

### Option D: Fuzzing the Parsers

Every module of the server that parses, decodes, validates or classifies attacker-influenced bytes has a fuzz target, and so does every surface of the agent (`elyrn-agent`, its MCP server) that judges bytes it does not control (86 Go targets in all, none needs a database). A target asserts invariants, not only "no panic": whatever is accepted is canonical (re-encoding gives the input back), a mutated or forged blob, token, record or proof of work fails closed, every refusal is a registered `apperr` answer below 500, and state machines (spent proofs, log throttle, event hub) stay within their bounds and agree with a model.

| Package | Targets |
|---|---|
| `internal/agent` | the nine targets below |
| `internal/apperr` | `FuzzWriteError`, `FuzzWriteCode`, `FuzzEdgeBody` |
| `internal/chat` | `FuzzParseRoomInput`, `FuzzRosterDigestMatchesClient`, `FuzzMessageWindow`, `FuzzClockTrusted` |
| `internal/contract` | `FuzzGateRequest`, `FuzzGateLoginBody`, `FuzzPattern*` (12), `FuzzIntegerLiteral` |
| `internal/database` | `FuzzClassify` |
| `internal/e2e` | `FuzzDecrypt`, `FuzzDecryptBindings`, `FuzzParseRoomCode`, `FuzzRoomCodeBuild`, `FuzzOpenRoomMessage`, `FuzzMutateRoomMessage`, `FuzzOpenRoomNote`, `FuzzOpenRoomCard`, `FuzzOpenRoomVault`, `FuzzRosterDigest`, `FuzzAura`, `FuzzRoomSafetyNumber` |
| `internal/handlers` | `FuzzHealthLoopback` |
| `internal/mcp` | the three targets below |
| `internal/pow` | `FuzzValidateSolution`, `FuzzTagMutation`, `FuzzCheckSolutionWindow`, `FuzzSpentSet` |
| `internal/realtime` | `FuzzHubOperations` |
| `internal/server` | `FuzzRouteChain` (the production chain, differential against the mux) |
| `internal/utils` | `FuzzScrubPeerAddresses`, `FuzzAdmitLine`, `FuzzClockSteady`, `FuzzParseProxyList`, `FuzzParseOrigins`, `FuzzDecodeExact`, `FuzzParseRoomBlob` |
| `tests/auth` | `FuzzVerifyToken`, `FuzzVerifyPendingToken`, `FuzzAccountLookup` |
| `tests/database` | `FuzzValidateStartupConfig` |
| `tests/encryption` | `FuzzOpenWithKeyID`, `FuzzSealRoundTrip` |
| `tests/identity` | `FuzzDeriveFromAccountNumber`, `FuzzValidateEncodedKey` |
| `tests/middleware` | `FuzzClientKey`, `FuzzCORS`, `FuzzRecover` |
| `tests/utils` | `FuzzParseCanonicalUUIDv4`, `FuzzValidateInviteToken`, `FuzzValidateCiphertext` |

The agent and its MCP server, one invariant each:

- `FuzzClassifyServerURL`: an accepted server address yields a canonical origin that classifies again to itself; a refused one yields no origin.
- `FuzzParseIdentity`: a loaded identity file holds a canonical origin and a well-formed secret, and saved again loads identically.
- `FuzzDecodeCounterRooms`: a loaded counter file stays within its rooms and senders bounds with canonical keys and safe sequence numbers, round-trips through save, and keeps no long-expired room.
- `FuzzServerAnswer`: a bounded answer is read as served; a refused one never hands its status to the caller, and nginx's own edge answers never pass as the backend's status (never as 404 "room gone").
- `FuzzEventStream`: the event stream never ends a wait by itself, wakes it only for a `msg` or `conv` event, and never drops the roster without a `conv` event.
- `FuzzSolveChallenge`: a malformed challenge is a server-answer failure, one above the difficulty bound a proof-of-work failure, and every solution is canonical and really has the leading zero bits.
- `FuzzReceivedText`: received text is neutralized one for one and idempotently; sent text is exactly the CRLF-normalized input trimmed of the shared trim set (`messageTrimChars`, the browser's `MESSAGE_TRIM_CHARS`, pinned by one sample table on both sides), within 1..2000 characters, with no forbidden character.
- `FuzzRoomPages`: pages served withheld, repeated, reordered or mutated are judged as an independent model judges them (a lower counter after a higher one, or one above its history ceiling, is a replay; the same page served again is history, not a replay).
- `FuzzOpenServedMessage`: arbitrary ciphertext under a real message id opens only to that message's own text, sender and "mine", else it is broken with no text.
- `FuzzServe` (MCP): every input line gets at most one answer, stdout never ends inside a line, and every protocol error is a registered code with its number and sentence.
- `FuzzToolArguments` (MCP): arguments refused by validation give the same answer with no backend at all (nothing reaches the backend before validation), and a backend that refuses everything never yields success.
- `FuzzRoomCodeArgument` (MCP): every code `JoinRoom` can parse is accepted as an argument, and what is accepted is canonical and round-trips.

The Go list lives in one place, the CI step "Fuzz targets (short run)" in `.github/workflows/ci.yml` (sorted by package, then target). `scripts/check-fuzz-targets.py` fails unless every `func Fuzz...` in `backend/` is listed there exactly once under its own package and every listed target exists; CI runs it in the frontend job and `make check-hardening` runs it first. `make fuzz` reads that list through the same script and runs every target locally:

```bash
make fuzz                         # every Go target, 20 s each, ENGINE=openssl
make fuzz ENGINE=native FUZZTIME=2m
```

Run one target at a time (both engines: add `openssl` to the tags for the OpenSSL build):

```bash
cd backend
go test -tags test -run '^$' -fuzz '^FuzzGateRequest$' -fuzztime 60s ./internal/contract
go test -tags 'test openssl' -run '^$' -fuzz '^FuzzOpenRoomMessage$' -fuzztime 60s ./internal/e2e
```

CI runs every target for 10 seconds per engine (`.github/workflows/ci.yml`, "Fuzz targets (short run)"); a new target is registered there (the check above fails until it is) and in the table above.

Any input that fails is written to `testdata/fuzz/` next to the package and becomes a permanent regression test; commit it with the fix.

#### Frontend fuzz files

Each browser module that judges untrusted input has a seeded fuzz file under `frontend/tests/`, loaded as the browser loads it (helpers in `fuzz-helpers.mjs`); CI runs them with the other frontend tests:

| File | Module and invariant |
|---|---|
| `validation.fuzz.test.mjs` | `validation.js`: accepted message text is clean, bounded, trimmed of exactly `MESSAGE_TRIM_CHARS` (equal to the agent's `messageTrimChars`, read from the Go source) and re-validates to itself; codes and ids are never laxer than the server's patterns; the role rule agrees with an independent model |
| `room-crypto.fuzz.test.mjs` | `crypto.js`, `room-crypto.js`: codes round-trip; tampered cards, vaults, messages, notes and roles never open to anything but their genuine plaintext; a role moved to another card or room never opens |
| `counters.fuzz.test.mjs` | `counters.js`: the replay judgement agrees with an independent model (the invariants `FuzzRoomPages` asserts for the agent) |
| `errors.fuzz.test.mjs` | `errors.js`: arbitrary answers always yield a registered code and a registry sentence, never the server's text |
| `utils.fuzz.test.mjs` | `utils.js`: `apiCall` reads answers of random status, type, size and chunking from a real local server; `once` and `singleFlight` hold under random interleavings; `streamNeedsPolling` (visible and hidden pages) agrees with an independent model |
| `pow-worker.fuzz.test.mjs` | `pow-worker.js`: task shapes judged against the server's hex patterns, SHA-256 against Node's, low-difficulty answers verified |
| `robot-door.fuzz.test.mjs` | `robot-door.js`: total, deterministic and finite |

```bash
make fuzz-js                      # node --test frontend/tests/*.fuzz.test.mjs
FUZZ_SCALE=20 make fuzz-js        # twenty times the iterations of every target
```

A failing JS target prefixes its assertion with `[fuzz seed=0x... iteration=N]`. Every target draws all its inputs from one generator started at that seed, so the same seed replays the same inputs in the same order: pass it back, with enough iterations to reach N (`FUZZ_SCALE` only changes how many are drawn, not which), and narrow the run to the failing test by name, e.g. `FUZZ_SEED=0x5eed0001 node --test --test-name-pattern='validateMessageText' frontend/tests/validation.fuzz.test.mjs` (decimal or `0x` hex; `FUZZ_SEED` replaces every target's seed in that run). Each file's targets have fixed seeds, so a CI failure also reproduces with the plain command. Turn the input into a plain test next to the fix.

### Option E: Negative Use (careless, confused or hostile users and servers)

Beyond edge cases and disasters, the browser client is checked by what a user does wrong at the UI and what a hostile server sends. Three files load the real modules in a `vm` context (no module under test is mocked); a real `node:http` server plays the hostile elyrn server (`negative-helpers.mjs`). Every scenario asserts the exact registered code or the exact refusal, never only "does not throw". They run with the other frontend tests (`node --test frontend/tests/*.test.mjs`).

| File | Scenarios |
|---|---|
| `negative-input.test.mjs` | login field (`validation.js parseAccountNumber`, also read by the delete field): blank, non-string, over-length, wrong alphabet, padding, multi-line, zero-width, homoglyph, markup → `E_LOGIN_EMPTY` / `E_LOGIN_FORMAT`; fullwidth and padded numbers read as the same number; an invite or room code under every prefix → `E_LOGIN_INVITE_PASTED`. Join field: blank → `E_JOIN_CODE_EMPTY` / `E_INVITE_EMPTY`; an account number (padded, fullwidth) → `E_INVITE_IS_ACCOUNT_NUMBER`; a room code where only an invite is read → `E_INVITE_INVALID`; broken invites → `E_INVITE_INVALID`, broken room codes → `E_ROOM_CODE_INVALID`; own invite recognised by fingerprint; an expired room code parses (its expiry is judged by `chat.js`). Composer: blank → `E_MESSAGE_EMPTY`, over-length → `E_MESSAGE_TOO_MANY_CHARS` (with its limit) or `E_MESSAGE_TOO_LONG`, controls and bidi → `E_MESSAGE_CONTROL_CHARS`, an account number anywhere (fullwidth too) → `E_MESSAGE_IS_ACCOUNT_NUMBER`, and every row of the agent's `accountNumberSamples` (read from `backend/internal/agent/fuzz_test.go`) refused or sent exactly as the agent's `ValidateMessageText` does; invites, room codes, near-misses and markup are sent as text. Door answer: blank, junk, look-alike, account number never pass |
| `negative-server.test.mjs` | markup, header text and odd types in error bodies map to registered codes; an HTML body is no data; a success body on an error status is a failure; no file in `frontend/js` writes HTML into the DOM, and nginx's CSP requires Trusted Types. Listed rooms with wrong types (`malformed room`), limits other than the code's or another account's vault are refused; limits that change between two listings are refused (`E_ROOM_DATA_CHANGED` in `chat.js`). Member lists of the wrong shape (`malformed roster`, a missing or mistyped `role` included), roles that do not open, are moved to another card or room, or break the role rule (shown as no role), a role posted sealed for the target card and a `403 Role not allowed` mapped to `E_ROLE_NOT_ALLOWED`, an error status (by `Errors.fromResult`), `mine` flags that lie, cards that are invites / room codes / account numbers / markup / duplicates (skipped and counted), more cards than seats, members dropped and added between reads. Notes: wrong shapes dropped, a note listed twice shown once, a note holding a room code / account number / markup refused when accepted. Join and create: a 2xx naming another room, a 2xx error body, a success body on an error status take no seat; a join request carries no code and no account number. Messages: a flipped `mine` does not open a pair message; a room message names its real sender; a friend request answered `409` "Id taken" is sealed and sent again once under a fresh id, a plain `409` is returned as it came |
| `negative-auth.test.mjs` | proof-of-work challenge that is not an object, on a 2xx error body or an error status → no challenge, by code; a difficulty over the cap → `E_POW_TOO_HARD` before any worker. `/me` (`auth.js judgeMe`): any other or missing key → `E_IDENTITY_MISMATCH`; settings of the wrong type or out of range → `E_SERVER_LIMITS_INVALID`; extra fields ignored. Registration left mid-way: number, token and flags dropped, proofs of work ended, the clipboard cleared only if it still holds the number, a left run never holds the next registration's lock; where the account may exist the way back asks once (`W_REGISTRATION_LEAVE_CONFIRM`). Every guarded action pressed twice runs once |

#### Negative-use tour (manual, real browser)

What lives in DOM-bound code (`app.js`, `auth.js`'s screens, `chat.js`, `ui.js`) is checked by hand in a real browser, against a local stack, with the console open: no line may carry a secret, and each expected code must appear in the console's `[elyrn]` line. Each line is screen · action · expected.

Pre-login screens:
- Main menu · open the page · no `404` for `/favicon.ico` or `/favicon.svg` in the network panel; the tab shows a black square with a white dot (also on the 404 page).
- Login · press `← back to main menu`, click the brand title, press Escape (each in turn) · the main menu; opening login again shows an empty field; the eye icon reveals nothing.
- Login · type a number, press login, press Escape before it answers · the main menu stays; the app never opens behind it.
- Login · paste a room code · `that is an invite or a room code — log in first, then use join` (`E_LOGIN_INVITE_PASTED`); nothing is sent (network panel).
- Login · paste the number in fullwidth characters · logs in as the same account.
- Login · hold Enter down · one `POST /login`.
- Login · log in, log out · the login field and the eye animation hold nothing (open login again, hover the eye).
- New identity (before copy) · `← back to main menu` is visible; press it, click the brand title, press Escape · the main menu.
- New identity · press copy, press Escape while the proof of work runs · the main menu; the CPU drops (worker ended); open new identity again and press copy: it runs (not blocked by the left run).
- New identity · press copy, press back about 700 ms later (the masking animation still running, the number not yet revealed) · the main menu; in the elements panel `#generatedAccountNumber` stays empty (text length 0) and its class list holds none of `generating`, `masking`, `revealed`, also a few seconds later.
- New identity · press copy, press back while the number is being revealed · the same: text empty, class list clean; the clipboard unchanged.
- New identity · press copy, leave while `POST /register` (confirm false) is in flight (throttle the network) · the main menu; no number is shown or copied afterwards; the clipboard is unchanged.
- New identity (number shown) · press back · the main menu; the number element is empty; the clipboard no longer holds the number (if nothing else was copied since).
- New identity (number shown) · press continue, then back while `POST /register` (confirm true) is in flight · the warning `your account may already exist and this number is the only way into it — save it now (leaving clears it from the clipboard), then press back again to leave` (`W_REGISTRATION_LEAVE_CONFIRM`); a second press leaves; the app does not open behind the menu.
- New identity · make `/me` fail after the account is created (stop the backend between the two calls) · `E_ACCOUNT_CREATED_NOT_ENTERED`; back asks first (`W_REGISTRATION_LEAVE_CONFIRM`); pressing continue in between makes the next back ask again.
- New identity · double-click copy, double-click continue · one challenge request and one `POST /register` each.

Inside the app:
- Composer · paste your account number (alone, in a sentence, fullwidth) and send · `E_MESSAGE_IS_ACCOUNT_NUMBER`; nothing is posted; the composer is emptied and no draft keeps it (switch conversation and back).
- Composer · hold Enter down on a message · one message posted.
- Composer · type while a send is in flight (throttle) · the new text stays in the composer after the send settles.
- Join · paste your own invite · `W_OWN_INVITE`; nothing posted.
- Join · paste an expired room code · `E_ROOM_CODE_EXPIRED`; nothing posted.
- Join · paste a room code of a full room · `W_ROOM_FULL`.
- Join · paste a spent invite · `E_INVITE_SPENT`.
- Join · press join twice fast · one request.
- Join · paste a room code you are in, with its limit byte edited · `E_ROOM_CODE_INVALID`; nothing posted.
- Conversation · have the server return `seq` going backwards, duplicate message ids, or a message whose `mine` is flipped (a proxy rewriting `/messages`) · each such message is skipped, or shown unreadable, never twice.
- Conversation · a peer (modified client) sends a message with `sentAt` beyond what a Date holds · the message shows with no time, not `Invalid Date`.
- Room · a member list missing yourself or marking another card `mine` (proxy) · `E_ROSTER_UNVERIFIED`; sending is refused.
- Room · a friend request whose text is a room code or an account number · accept gives `E_FRIEND_REQUEST_MALFORMED` and the note is dismissed.
- Any screen · log out while an invite or a room is being created · the panels close; no code is revealed or copied afterwards.
- App home · press `+ invite`, then during the mask or reveal animation log out, or open `join` (closing the invite panel) · `#inviteCode` stays empty with none of `generating`, `masking`, `revealed`, a few seconds later too; the clipboard is unchanged; pressing `+ invite` again works.
- App home · press `+ room`, then `open room`, then during the mask or reveal animation press `cancel`, or `+ room` again (reopening the form), or log out · `#roomCode` stays empty with a clean class list, a few seconds later too; the clipboard is unchanged; after `cancel` or `+ room` the room still appears in the list (its `code` button shows the code).
- Any screen · back, then the browser's forward (bfcache) · the session is checked again (`/me`); a revoked one goes to login with `W_SESSION_ENDED`.

### Option F: Restore Drill

```bash
make test-restore                 # ENGINE=openssl; ENGINE=native for the other engine
```

Entirely inside the disposable test stack (`docker-compose.test.yaml`, project `noaddx-test`, its
database on tmpfs), so no development or production volume is touched: it registers an account
(`TestRestoreDrill` with `RESTORE_DRILL=seed`), dumps `users` and `key_checks` with the very
command `make backup-accounts` uses, drops and recreates the test database, restores the dump with
`psql -v ON_ERROR_STOP=1`, then starts on it (`RESTORE_DRILL=verify`: key check and migration),
logs in with the seeded account and registers a new one (the restored `users_id_seq` must not hand
out an existing id). The drill's keys are drawn once per run and passed to the containers by name.
See [Disaster Recovery](../operations/disaster-recovery.md#backups-accounts-only).

### Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and `elyrn-dev`, on tags and on pull requests: the complete suite with the race detector for **both crypto engines**, the engine **equivalence** suite, short fuzz runs, the frontend interop tests, `govulncheck`, `gitleaks` over the full history, and the Docker images: the backend must boot as the unprivileged user and pass the startup self-test, nginx must render and accept its config (`nginx -t`), and tor must accept its config with the onion defenses compiled in.

`.github/workflows/release.yml` runs on each `elyrn-{openssl,native}-vX.Y.Z` tag: it signs the frontend manifest with Sigstore keyless and attaches it to the release ([Verifying the Client](../security/verifying-the-client.md)). Every action in that job is pinned to a commit, since it holds the signing and publishing permissions.

---

## Code Rules & Concurrency Compliance

All code modifications must strictly comply with project policies:

### 1. Cryptography Whitelist (`RULES.md Section 1`)
- Symmetric encryption: **AES-256-GCM** only.
- Asymmetric keys: **X25519** only.
- Hashing: **SHA-256** only.
- Key derivation: **HKDF-SHA256** only.
- Sensitive key material in memory must be zeroized upon deallocation (`cryptoengine.Zeroize`).

### 2. Lock Ordering & Concurrency (`LOCK_HIERARCHY.md`)
To prevent deadlocks, locks are acquired from lowest to highest priority. [LOCK_HIERARCHY.md](../../LOCK_HIERARCHY.md) lists every lock with its level; in short:

- **Priority Level 1 (Application State):** the rate limiter map, the PoW per-client limiters and spent set, `realtime.Hub.mu` (leaf), `pendingStore.mu` (leaf).
- **Priority Level 2 (Per-Resource Locks):** `TokenBucket.mu` and the per-client PoW limiters.
- **Priority Level 3 (Highest):** database row locks in one order per transaction (`invites` → `users` → `rooms` → `conversations`), the advisory locks, `masterKeyOnce` and the master key use lock.
- **The agent:** the identity lock file before the call lock; the MCP write lock nests with neither.

**Rule:** never acquire a lower-priority lock while holding a higher-priority lock. A new lock is listed in `LOCK_HIERARCHY.md` with its level.

### 3. Input Triple Validation (`RULES.md Section 5.1`)
Every external client input must pass:
1. **Type validation** (e.g. UUIDv4 struct, exact byte slice).
2. **Range validation** (min and max byte length).
3. **Whitelist validation** (regex character set, e.g. `^[A-Za-z0-9_-]+$`).

---

### Next Steps:
- Review the [**Threat Model & Security**](../security/threat-model.md).
- Explore the [**REST API Reference**](../api/rest-api.md).
