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

Every module of the server that parses, decodes, validates or classifies attacker-influenced bytes has a fuzz target (64, none needs a database), plus the stored Argon2id hash format (its verifier is test-only since login stopped reading the hash, S-02; it stays while the hash does, S-07). A target asserts invariants, not only "no panic": whatever is accepted is canonical (re-encoding gives the input back), a mutated or forged blob, token, record or proof of work fails closed, every refusal is a registered `apperr` answer below 500, and state machines (spent proofs, log throttle, event hub) stay within their bounds and agree with a model.

| Package | Targets |
|---|---|
| `internal/apperr` | `FuzzWriteError`, `FuzzWriteCode`, `FuzzEdgeBody` |
| `internal/chat` | `FuzzParseRoomInput`, `FuzzRosterDigestMatchesClient`, `FuzzMessageWindow`, `FuzzClockTrusted` |
| `internal/contract` | `FuzzGateRequest`, `FuzzGateLoginBody`, `FuzzPattern*` (12), `FuzzIntegerLiteral` |
| `internal/database` | `FuzzClassify` |
| `internal/e2e` | `FuzzDecrypt`, `FuzzDecryptBindings`, `FuzzParseRoomCode`, `FuzzRoomCodeBuild`, `FuzzOpenRoomMessage`, `FuzzMutateRoomMessage`, `FuzzOpenRoomNote`, `FuzzOpenRoomCard`, `FuzzOpenRoomVault`, `FuzzRosterDigest`, `FuzzAura`, `FuzzRoomSafetyNumber` |
| `internal/handlers` | `FuzzHealthLoopback` |
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

Run one target at a time (both engines: add `openssl` to the tags for the OpenSSL build):

```bash
cd backend
go test -tags test -run '^$' -fuzz '^FuzzGateRequest$' -fuzztime 60s ./internal/contract
go test -tags 'test openssl' -run '^$' -fuzz '^FuzzOpenRoomMessage$' -fuzztime 60s ./internal/e2e
```

CI runs every target for 10 seconds per engine (`.github/workflows/ci.yml`, "Fuzz targets (short run)"); a new target is registered there and in the table above.

Any input that fails is written to `testdata/fuzz/` next to the package and becomes a permanent regression test; commit it with the fix.

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
