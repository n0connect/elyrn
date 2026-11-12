# Debt and Decisions

The single record of what is loose, what was decided and what is unverified. Newest first
inside each section. An entry leaves only when its fix is verified, never when it is merely
written. Ids are stable.

## State (12 Nov 2026)

- Branch `elyrn` (local, from `noaddx-dev` a3c812f): rename to elyrn., robot entrance, fixes
  below. Compiled only. **No test has run on this branch.** Nothing pushed.
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
| S-07 | data | Since S-02 the stored Argon2id hash (`users.account_hash`) is read by nothing | drop: a migration removes the column and phase 2 stops hashing (no Argon2id, no slots, lighter phase 2). Keep: the column stays as a second, pepper-independent record of the key, costing one Argon2id per sign-up | open, decision needed |
| Q-01 | stage 1 | No error module: 78 free-text `http.Error` in the backend, 52 free-text `showError/showWarning` in the browser, no codes | one error home per program (backend, browser, agent), registered codes, one sentence each | browser, backend: written, unverified; agent: open |
| Q-02 | stage 1 | Browser: 8 direct `console` calls, 6 swallowing `catch`; backend: 8 `panic`, 2 dropped errors | decide each one: fix or justify in a comment | browser, backend: written, unverified |
| Q-03 | stage 1 | `room-crypto.js`: four functions with 7 to 9 parameters; `Rooms` module 191 lines; `setupEventListeners` 112 | named argument objects, split by purpose | written, unverified |
| Q-04 | stage 1 | Unnamed numbers: pow-worker 22, ui 17, utils 17, crypto 16, validation.go 14 (scanner counts, unread) | name the tunables, justify the rest | browser: written, unverified; backend (validation, pow, auth, cryptoengine): written, unverified; backend chat/store/realtime/agent/handlers: open |
| F-01 | function | Only the latest `MESSAGE_PAGE_LIMIT` messages are reachable; no paging backwards | `?before=seq` page, same whitelist as `after`; browser "earlier messages", agent `ReadBefore` (MCP `before` argument still to add) | written, unverified |

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
