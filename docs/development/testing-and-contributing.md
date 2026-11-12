# Testing & Development Guide

This guide covers running test suites across Go backend units, database migrations, integration scenarios, and frontend WebCrypto cryptographic verification.

---

## Test Architecture Overview

```text
+-------------------------------------------------------------+
| 1. Frontend WebCrypto Verification                          |
|    node --test frontend/tests/*.test.mjs                              |
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
5. Emits output to `test-results/output.log`.

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
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=elyrn_test go test -p 1 -race -tags=test ./...
```

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

**Tests Verified:**
- `auth key matches Go derivation`
- `identity public key matches Go derivation; private key is not extractable`
- `strict base64url rejects malformed account numbers`
- `both peers derive the same conversation key and round-trip a message`
- `AAD binding: wrong message id, sender, conversation, or tampered bytes fail`
- `invite code carries a fingerprint the redeemer can verify`
- `safety number and aura are symmetric and deterministic`
- `payload limit is enforced before encryption`

---

### Option D: Fuzzing the Parsers

Every module of the server that parses, decodes, validates or classifies attacker-influenced bytes has a fuzz target, and so does every surface of the agent (`elyrn-agent`, its MCP server) that judges bytes it does not control (76 Go targets in all, none needs a database), plus the stored Argon2id hash format (its verifier is test-only since login stopped reading the hash, S-02; it stays while the hash does, S-07). A target asserts invariants, not only "no panic": whatever is accepted is canonical (re-encoding gives the input back), a mutated or forged blob, token, record or proof of work fails closed, every refusal is a registered `apperr` answer below 500, and state machines (spent proofs, log throttle, event hub) stay within their bounds and agree with a model.

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
| `tests/auth` | `FuzzVerifyAccountNumberHash`, `FuzzVerifyToken`, `FuzzVerifyPendingToken`, `FuzzAccountLookup` |
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
| `validation.fuzz.test.mjs` | `validation.js`: accepted message text is clean, bounded, trimmed of exactly `MESSAGE_TRIM_CHARS` (equal to the agent's `messageTrimChars`, read from the Go source) and re-validates to itself; codes and ids are never laxer than the server's patterns |
| `room-crypto.fuzz.test.mjs` | `crypto.js`, `room-crypto.js`: codes round-trip; tampered cards, vaults, messages and notes never open to anything but their genuine plaintext |
| `counters.fuzz.test.mjs` | `counters.js`: the replay judgement agrees with an independent model (the invariants `FuzzRoomPages` asserts for the agent) |
| `errors.fuzz.test.mjs` | `errors.js`: arbitrary answers always yield a registered code and a registry sentence, never the server's text |
| `utils.fuzz.test.mjs` | `utils.js`: `apiCall` reads answers of random status, type, size and chunking from a real local server; `once` and `singleFlight` hold under random interleavings |
| `pow-worker.fuzz.test.mjs` | `pow-worker.js`: task shapes judged against the server's hex patterns, SHA-256 against Node's, low-difficulty answers verified |
| `robot-door.fuzz.test.mjs` | `robot-door.js`: total, deterministic and finite |

```bash
make fuzz-js                      # node --test frontend/tests/*.fuzz.test.mjs
FUZZ_SCALE=20 make fuzz-js        # twenty times the iterations of every target
```

A failing JS target prefixes its assertion with `[fuzz seed=0x... iteration=N]`. Every target draws all its inputs from one generator started at that seed, so the same seed replays the same inputs in the same order: pass it back, with enough iterations to reach N (`FUZZ_SCALE` only changes how many are drawn, not which), and narrow the run to the failing test by name, e.g. `FUZZ_SEED=0x5eed0001 node --test --test-name-pattern='validateMessageText' frontend/tests/validation.fuzz.test.mjs` (decimal or `0x` hex; `FUZZ_SEED` replaces every target's seed in that run). Each file's targets have fixed seeds, so a CI failure also reproduces with the plain command. Turn the input into a plain test next to the fix.

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
- Key derivation: **HKDF-SHA256** or **Argon2id** only.
- Sensitive key material in memory must be zeroized upon deallocation (`cryptoengine.Zeroize`).

### 2. Lock Ordering & Concurrency (`LOCK_HIERARCHY.md`)
To prevent deadlocks, all mutex acquisitions must strictly proceed from lowest to highest priority:

- **Priority Level 1 (Application State):** Rate limiter maps, PoW challenge maps, `realtime.Hub.mu` (leaf lock), `pendingStore.mu` (leaf lock).
- **Priority Level 2 (Per-Resource Locks):** `TokenBucket.mu`.
- **Priority Level 3 (Highest):** Database transaction locks (GORM), `masterKeyOnce`.

**Rule:** Never acquire a lower-priority lock while holding a higher-priority lock!

### 3. Input Triple Validation (`RULES.md Section 5.1`)
Every external client input must pass:
1. **Type validation** (e.g. UUIDv4 struct, exact byte slice).
2. **Range validation** (min and max byte length).
3. **Whitelist validation** (regex character set, e.g. `^[A-Za-z0-9_-]+$`).

---

### Next Steps:
- Review the [**Threat Model & Security**](../security/threat-model.md).
- Explore the [**REST API Reference**](../api/rest-api.md).
