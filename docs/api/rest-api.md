# REST API Reference

All API endpoints are mounted under the base prefix `/api/v2`.
Every request passes one input contract before any handler runs; the complete whitelist (each
endpoint's methods, query parameters, body bound and every field with its pattern and refusal
answer) is generated from the code in [input-contract.md](input-contract.md). In short:
- **Request Body Size:** each endpoint's own bound, derived from its largest legitimate body (123 bytes for login, a few KiB for messages, 349695 bytes for a file part), never above `MAX_REQUEST_BODY_BYTES` (1 MiB).
- **Content Type:** exactly `application/json`, no parameters (`415` otherwise).
- **JSON:** one object, declared keys only (exact case), each once, each of its declared type; nesting only where declared (at most 2 levels); nothing after it.
- **Query Parameters:** only the whitelisted ones (`?after=seq` or `?before=seq` on the messages route, the required `?part=n` on a file read), raw and canonical; anything else, or a required one missing, is rejected with `400 Bad Request`.

---

## Error Answers

Every failure the backend answers comes from one registry (`backend/internal/apperr`): a stable
code (logged by the server, never sent), a status and one sentence. Several causes deliberately
share one public answer, so a client cannot tell them apart (an unknown room from a wrong code,
an expired session from none). Three shapes reach the wire:

| Shape | Used by | Body |
|---|---|---|
| text | almost every failure | `<sentence>\n`, `text/plain` |
| JSON | login's failures, `409 Id taken`, and the role and file answers below (each shares its status with another answer of its route) | `{"success":false,"message":"<sentence>"}` |
| empty | `HEAD` on register, login and the PoW challenge (`405`); the health endpoint | status line only |

| Status | Sentence | Codes (server side) | Meaning |
|---|---|---|---|
| 400 | `Invalid request` | `E_INVALID_REQUEST`, `E_INVALID_INPUT`, `E_LOGIN_BODY_INVALID` (JSON) | the input contract or the service refused the input |
| 400 | `Pending token required` | `E_PENDING_TOKEN_REQUIRED` | registration phase 2 without its token |
| 401 | `Unauthorized` | `E_NO_SESSION`, `E_SESSION_CONTEXT_MISSING`, `E_MEMBER_NOT_FOUND`, `E_PENDING_TOKEN_INVALID`, `E_ACCOUNT_EXISTS` | no session, a revoked or expired one, an account that is gone, a spent or expired pending token |
| 401 | `Invalid credentials` (JSON) | `E_LOGIN_KEY_MALFORMED`, `E_LOGIN_NO_ACCOUNT`, `E_LOGIN_LEGACY_ACCOUNT` | login: no account for this key, whatever the reason |
| 403 | `Forbidden` | `E_CROSS_ORIGIN`, `E_IDENTITY_UNSET`, `E_FORBIDDEN` | a cross-origin write, or an action the caller may not take |
| 403 | `Invalid proof of work` | `E_POW_INVALID` | forged, expired, already used, below the issued difficulty, or issued before a restart |
| 403 | `Role not allowed` (JSON) | `E_ROLE_NOT_ALLOWED` | a member who does not own the room set another member's role |
| 404 | `Not Found` | `E_ROUTE_NOT_FOUND` | no such route (a malformed id answers the same) |
| 404 | `Not found` | `E_NOT_FOUND` | no such conversation, room, invite, note, member card or file part *for the caller*: unknown, expired, burned, a wrong room code, or one the caller is not a member of |
| 405 | `Method not allowed` | `E_METHOD_NOT_ALLOWED`, `E_HEAD_NOT_ALLOWED` (empty) | another method |
| 409 | `Conflict` | `E_CONFLICT` | the id holds the caller's own identical earlier attempt (stored); a room id that exists |
| 409 | `Id taken` (JSON) | `E_ID_TAKEN` | a message or note id, or a file part, held by anything else: nothing stored, send again under a fresh id |
| 409 | `File part out of order` (JSON) | `E_FILE_PART_OUT_OF_ORDER` | a later part of a file whose live part 0 the caller has not stored |
| 409 | `Room full` | `E_ROOM_FULL` | no free seat |
| 412 | `Proof of work required` | `E_POW_REQUIRED` | a PoW-gated request without `pow` |
| 412 | `Roster changed` | `E_ROSTER_CHANGED` | a room message for a member list that is no longer current |
| 415 | `Unsupported Media Type` | `E_UNSUPPORTED_MEDIA_TYPE` | a body not declared as exactly `application/json` |
| 429 | `Too many requests` | `E_RATE_LIMITED`, `E_POW_RATE_LIMITED`, `E_SUBSCRIBER_LIMIT`, `E_LIMIT_REACHED` | any rate limit, stream share or per-account cap |
| 429 | `File budget spent` (JSON) | `E_FILE_BUDGET_SPENT` | the account stored `FILE_ACCOUNT_DAILY_BYTES` of file parts within the last day |
| 500 | `Internal server error` | `E_INTERNAL`, `E_PANIC`, `E_ACCOUNT_COLLISION`, `E_INPUT_UNCHECKED`, `E_LOGIN_LOOKUP_FAILED` (JSON) | a server fault; on login, a lookup the server could not compute |
| 503 | `Service unavailable` | `E_STORE_UNAVAILABLE`, `E_POW_CAPACITY`, `E_PENDING_STORE_FULL`, `E_SHUTTING_DOWN`, `E_REQUEST_CANCELLED`, `E_FILE_REQUESTS_BUSY` | the database is unreachable, restarting, out of connections or too slow (every route, the session check included), or a bounded resource is full (for files: 32 file part requests handled at once); retry later |
| 507 | `File quota reached` (JSON) | `E_FILE_QUOTA_REACHED` | the conversation holds `FILE_CONVERSATION_QUOTA_BYTES` of file parts |
| 507 | `File store full` (JSON) | `E_FILE_STORE_FULL` | the server holds `FILE_STORE_MAX_BYTES` of file parts, or has not counted them yet |

`503 E_STORE_UNAVAILABLE` never means a key, session or conversation is gone: clients retry
instead of logging out. A request's whole database work runs under one deadline derived from
`SERVER_WRITE_TIMEOUT_SEC` ([the rule](../operations/configuration-and-tuning.md#request-deadlines-follow-server_write_timeout_sec)),
so a stalled request still gets its `503` before the write deadline.

### Answers from nginx

nginx (`nginx-site.conf`) admits only the contract's routes and methods, each with a body bound,
and answers its own refusals without the backend, in JSON with a code
(`backend/internal/apperr/edge.go`):

```json
{"success":false,"message":"Not Found","code":"E_EDGE_NOT_FOUND"}
```

| Status | Code | When |
|---|---|---|
| 404 | `E_EDGE_NOT_FOUND` | a path outside the whitelist |
| 405 | `E_EDGE_METHOD_NOT_ALLOWED` | a method the route does not take |
| 413 | `E_BODY_TOO_LARGE` (`Request entity too large`) | a body over the route group's bound (1k, 2k, 8k, or 342k for file parts) |
| 429 | `E_EDGE_RATE_LIMITED` | over 20 requests per second per client (burst 40) |
| 503 | `E_BACKEND_UNAVAILABLE` | the backend is down, failed or too slow (also for 500, 502 and 504 from upstream) |

The backend's own answers pass through unchanged. `GET /internal/health` (the container
healthcheck) is outside `/api/`; nginx never forwards it and the backend answers it to loopback
peers only (`200` or `503 E_HEALTH_UNAVAILABLE`, no body; any other peer gets `404`).

---

## Authentication & Sessions

- **Session Delivery:** The only credential is an HttpOnly, `SameSite=Strict` cookie: `noaddx_session` in development (a name kept from the project's former name, so sessions survived the rename), `__Host-Session` (Secure, host-only) in production. The token never appears in a response body and the `Authorization` header is ignored, so page script can never read or replay it.
- **Same-Origin Writes:** `POST`/`PUT`/`PATCH`/`DELETE` requests are refused with `403` unless the browser marks them `Sec-Fetch-Site: same-origin` (or, without that header, sends an `Origin` listed exactly in `ALLOWED_ORIGINS`). Clients that send neither header are not browsers and hold no ambient cookies.
- **Sliding Expiration:** Sessions expire after `JWT_EXPIRATION_MINUTES` (default 43200 minutes, 30 days; accepted range 1 to 525600 minutes, 365 days). A session used after half its lifetime has passed is re-issued as a fresh cookie, so one used at least once every half-lifetime (15 days by default) does not expire; logout and account deletion end it at once.
- **Saturation and outages:** `POST /api/v2/login` answers `503` while the database is unreachable, so an outage is never reported as an unknown account. When the server cannot compute the account lookup from a well-formed key (a missing or short pepper, or a crypto engine failure), login answers `500 Internal server error` (`E_LOGIN_LOOKUP_FAILED`), never `401`: the lookup is computed from the key alone before any account is read, so it fails alike for every key, and `401` always means the key matches no usable account. The `503` and `500` answers do not depend on whether the account exists; retry with backoff. Every other route answers a database outage (unreachable, restarting, out of connections, or a statement past its timeout) the same way, `503 Service Unavailable`, the session check included, so an outage never logs a client out.
- **Global Invalidation:** `POST /api/v2/logout` with a live session increments the user's `session_epoch`, instantly invalidating every JWT issued for that account on every device. A token revoked earlier cannot trigger this (it no longer authenticates); if revocation fails the endpoint answers `500` instead of reporting success. The cookie is cleared in every case.

---

## Endpoints Summary

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/v2/pow/challenge` | Public | Request SHA-256 hashcash puzzle (registration, invites and rooms) |
| `POST` | `/api/v2/register` | Public | Phase 1 (generate account number) & Phase 2 (confirm account) |
| `POST` | `/api/v2/login` | Public | Authenticate with derived `auth_key` |
| `POST` | `/api/v2/logout` | Session | Revoke all active sessions and wipe cookies |
| `GET` | `/api/v2/me` | Session | Fetch user public key, retention policy and room limits |
| `DELETE` | `/api/v2/me` | Session + auth key | Erase the account, its invites and every conversation (both sides); leave joined rooms |
| `POST` | `/api/v2/invites` | Session | Generate single-use pairing token (requires PoW) |
| `POST` | `/api/v2/invites/redeem` | Session | Redeem pairing token and start conversation |
| `POST` | `/api/v2/rooms` | Session | Create a room from client-derived values (requires PoW) |
| `POST` | `/api/v2/rooms/join` | Session | Take a seat in a room whose code the caller holds |
| `GET` | `/api/v2/conversations` | Session | List active conversations and rooms |
| `DELETE` | `/api/v2/conversations/{id}` | Session | Burn a conversation (a room: owner burns, others leave) |
| `GET` | `/api/v2/conversations/{id}/messages` | Session | Fetch encrypted messages (supports `?after=seq` or `?before=seq`) |
| `POST` | `/api/v2/conversations/{id}/messages` | Session | Send E2E encrypted message ciphertext |
| `POST` | `/api/v2/conversations/{id}/read` | Session | Update read sequence marker |
| `GET` | `/api/v2/conversations/{id}/members` | Session | A room's member cards and sealed roles |
| `POST` | `/api/v2/conversations/{id}/members` | Session | Store a member's sealed role (owner: anyone; member: itself) |
| `POST` | `/api/v2/conversations/{id}/files` | Session | Store one sealed part of a file |
| `GET` | `/api/v2/conversations/{id}/files/{file}` | Session | Fetch one stored part (`?part=n`, required) |
| `GET` / `POST` | `/api/v2/conversations/{id}/notes` | Session | Sealed notes (friend requests) to / from a room member |
| `DELETE` | `/api/v2/conversations/{id}/notes/{note}` | Session | Remove a note addressed to the caller |
| `GET` | `/api/v2/events` | Session | Server-Sent Events (SSE) realtime poke stream |

---

## 1. Identity & Authentication

### `GET /api/v2/pow/challenge`
Issues a single-use hashcash proof-of-work challenge. The server stores nothing per issued
challenge: `salt` is an HMAC tag over `challenge`, `timestamp`, `ttl` and `difficulty` under a
per-boot secret, so a solution must echo all five fields exactly as issued (see
[cryptography.md](../security/cryptography.md#stateless-issuing)). A solution answers 403 when
forged, expired, already used, or issued before a server restart, and 503 while the set of used,
unexpired challenges is full.

- **Rate Limit:** 5 requests per minute per client key (an IPv4 address, an IPv6 /64, or one Tor circuit on the onion service), shared by every proof of work (registration, invites, rooms): `429` beyond it. The server tracks at most 50,000 clients; while that table is full, clients not in it share one bucket of 500 challenges per minute (`429` beyond it), and tracked clients keep their own limit.
- **Response (200 OK):**
```json
{
  "success": true,
  "message": "PoW challenge generated successfully",
  "challenge": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```

---

### `POST /api/v2/register`
Two-phase registration process to protect against bot accounts.

#### Phase 1: Request Account Number Preview
- **Request Body:**
```json
{
  "confirm": false,
  "pow": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "solution": "1048576",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```
- **Response (200 OK):**
```json
{
  "success": true,
  "message": "Account number generated - click continue to create account",
  "account_number": "k8x9F...43-character-base64url-string...",
  "pending_token": "eyJhbGciOi...",
  "confirmed": false
}
```

#### Phase 2: Confirm Account Creation
Requires solving a fresh, single-use PoW challenge.
- **Request Body:**
```json
{
  "confirm": true,
  "pending_token": "eyJhbGciOi...",
  "pow": {
    "challenge": "new_challenge_hex",
    "salt": "new_salt_hex",
    "solution": "524288",
    "difficulty": 20,
    "timestamp": 1729731230,
    "ttl": 300
  }
}
```
- **Response (201 Created):** Sets the HttpOnly session cookie; the body never carries the token.
```json
{
  "success": true,
  "message": "Account created successfully",
  "confirmed": true
}
```
- **Retries:** the user has already saved the account number, so a phase 2 that fails for a passing reason (`5xx`, `503` saturation, a lost connection) leaves the pending registration in place: send phase 2 again with the same `pending_token` and a fresh PoW until `PENDING_TOKEN_TTL_SEC` runs out. Once the account exists the token is spent and phase 2 answers `401`. A client that gets `401` should log in with the account number it holds: that succeeds when an earlier attempt created the account and only its answer was lost, and fails when the registration expired (or the server restarted) before it was confirmed.

---

### `POST /api/v2/login`
Authenticates a user via their derived `auth_key`. The `AccountNumber` is **never** sent.

The key is proven by its keyed lookup: the server computes `HMAC(pepper, auth_key)`, finds the account by it and compares the two in constant time. No slow hash runs at login (and none at registration either), so a flood of registrations cannot lock existing accounts out. Answers: `200` (logged in), `400` (body is not JSON), `401` (no account for this key, whatever the reason), `429` (per-client or per-account rate limit), `500` (the lookup could not be computed, `E_LOGIN_LOOKUP_FAILED`), `503` (database unreachable).

- **Request Body:**
```json
{
  "auth_key": "43-character-base64url-derived-key"
}
```
- **Response (200 OK):** Sets the HttpOnly session cookie; the body never carries the token.
```json
{
  "success": true,
  "message": "Login successful"
}
```

---

### `POST /api/v2/logout`
Revokes all active sessions for this account across all devices by bumping `session_epoch`.

- **Response (200 OK):** Clears session cookie and carries `Clear-Site-Data: "cookies", "storage"`, so the browser drops this origin's cookies and stored data (the identity and its records in IndexedDB) even if the page's own wipe failed.
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### `GET /api/v2/me`
Retrieves caller's public key and server retention policy.

- **Response (200 OK):**
```json
{
  "public_key": "X25519-public-key-base64url",
  "message_ttl_days": 7,
  "room_max_members": 16,
  "room_max_ttl_hours": 168,
  "message_page_limit": 200,
  "file_max_bytes": 10485760
}
```
`file_max_bytes` is `MAX_FILE_BYTES`, the largest file one message may announce.

---

### `DELETE /api/v2/me`
Erases the caller's account: pending invites, every conversation it belongs to (all ciphertext, for both sides; peers get a `conv` event), every room it owns, its seat in every room it joined (its messages there stay readable to the others) and the account row. Every session of the account ends and the cookie is cleared.

A live session is not enough: the request re-proves the account number with its derived auth key, exactly as login does. The client checks that the number derives this identity's public key before sending anything, so the server never sees a second account's key.

- **Request Body** (`Content-Type: application/json`, required for any `DELETE` that carries a body):
```json
{
  "auth_key": "HKDF(AccountNumber, \"noaddx/auth\") base64url"
}
```
- **Errors:** `400` malformed body or key, `403` the key belongs to another account (`E_FORBIDDEN`), `415` body not declared as JSON, `429` too many attempts.
- **Response (200 OK):** carries `Clear-Site-Data: "cookies", "storage"`, as a successful logout does. No other answer, a refused deletion included, carries it.
```json
{
  "success": true,
  "message": "Account deleted"
}
```

---

## 2. Pairing & Invites

### `POST /api/v2/invites`
Creates a single-use pairing token. Every invite costs a fresh, single-use PoW challenge, exactly like each registration phase.

- **Request Body:**
```json
{
  "pow": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "solution": "1048576",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```
- **Errors:** `415` without a JSON body, `412` without `pow` (`E_POW_REQUIRED`), `403` for a solution that is unknown, expired, already used or below the issued difficulty (`E_POW_INVALID`).
- **Rate Limit:** Bounded by `MAX_ACTIVE_INVITES` (default: 5 concurrent unredeemed invites). Returns `429 Too Many Requests` when limit is exceeded. Challenges themselves are limited to 5 per minute per client key, shared with registration.
- **Response (201 Created):**
```json
{
  "token": "16-byte-base64url-token",
  "expires_at": 1729817600
}
```

---

### `POST /api/v2/invites/redeem`
Redeems an invite token and creates an isolated two-party conversation.

- **Request Body:**
```json
{
  "token": "16-byte-base64url-token"
}
```
- **Response (201 Created):**
```json
{
  "conversation": {
    "id": "e9b2c3d4-5678-4abc-9def-0123456789ab",
    "peer_public_key": "peer-X25519-public-key-base64url",
    "last_seq": 0,
    "read_seq": 0
  }
}
```
*Note: Returns `404 Not Found` (`E_NOT_FOUND`) if the token is invalid, expired, already redeemed, or created by the caller; `429` when the caller holds `MAX_CONVERSATIONS_PER_USER` conversations or redeems too often.*

---

## 3. Conversations & Messages

### `GET /api/v2/conversations`
Lists the caller's conversations, newest first (the server keeps no recency across conversations). A room carries `room` and an empty `peer_public_key`; an expired room is no longer listed.

- **Response (200 OK):**
```json
{
  "conversations": [
    {
      "id": "e9b2c3d4-5678-4abc-9def-0123456789ab",
      "peer_public_key": "peer-public-key-base64url",
      "last_seq": 14,
      "read_seq": 14
    },
    {
      "id": "bcde36b2-87a3-43c6-8748-ee62ca2f2939",
      "peer_public_key": "",
      "last_seq": 3,
      "read_seq": 2,
      "room": {
        "vault": "the room code, sealed for the caller's account (65 bytes, base64url)",
        "max_members": 5,
        "expires_at": 1793559600,
        "owner": false,
        "members": 3,
        "notes": 1
      }
    }
  ]
}
```
*The client opens the vault, recomputes the room id from the code inside, and hides the room if the id, `max_members` or `expires_at` differ from the code.*

---

### `DELETE /api/v2/conversations/{id}`
**Burn:** Bilaterally deletes the conversation, all memberships, and all stored ciphertexts from the database. In a room only the owner burns (for everyone); any other member **leaves**: their seat goes, their messages stay readable to the others, notes to and from them go. Members get a `conv` event either way. Every request takes a token
from the caller's rate bucket `burn` before the conversation is looked up (a `404` spends one
too): `429` (`E_RATE_LIMITED`) once it is empty.

- **Response:** `204 No Content`

---

### `GET /api/v2/conversations/{id}/messages[?after=seq | ?before=seq]`
Fetches encrypted messages for a conversation, at most `MESSAGE_PAGE_LIMIT` (`message_page_limit` in `/me`) per page, always in ascending `seq`. A conversation the caller is not in answers `404`, exactly like one that does not exist. Expired messages are never served, whether or not retention has deleted them yet.
- With no query, returns the latest page.
- With `?after=seq` (`seq` >= 0), returns the oldest page of messages with sequence numbers greater than `seq`: catching up.
- With `?before=seq` (`seq` >= 1), returns the newest page of messages with sequence numbers lower than `seq`: paging back. A page shorter than the limit is the beginning.
- At most one of the two, each once, as decimal digits; anything else is `400`.
- In a room, only messages sent after the caller joined are returned, on every page: nothing earlier was encrypted for them.

- **Response (200 OK):**
```json
{
  "messages": [
    {
      "id": "7b1a2c3d-4e5f-4678-890a-bcdef0123456",
      "seq": 15,
      "mine": false,
      "ciphertext": "base64url-encoded-nonce-ciphertext-tag"
    }
  ]
}
```

---

### `POST /api/v2/conversations/{id}/messages`
Sends an end-to-end encrypted message ciphertext.

- **Request Body:**
```json
{
  "id": "7b1a2c3d-4e5f-4678-890a-bcdef0123456",
  "ciphertext": "base64url-encoded-nonce-ciphertext-tag"
}
```
- **Response (201 Created):**
```json
{
  "seq": 15
}
```
*Note: message ids are unique on the whole server. A duplicate `id` answers one of two `409`s, and stores nothing either way:*
- *`409 Conflict` (plain text, `E_CONFLICT`): the id holds the caller's own message in this conversation with byte for byte this `ciphertext`. That makes sending safe to retry: a client whose answer was lost resends the same `id` and `ciphertext`, and this `409` means the first attempt was stored. It is judged before the roster digest, so a resend after someone joined or left still answers it (not `412`).*
- *`409` `{"success":false,"message":"Id taken"}` (JSON, `E_ID_TAKEN`): the id is held by anything else (another conversation, another member, or other content under it). Nothing was stored: send again under a fresh `id` (the browser and the agent do so once, automatically) and never take it as stored.*

*Both are answered only to a member of the conversation, after the membership check (a non-member gets `404` first), and the split reveals only whether the holder is the caller's own identical send; that some message holds the id was already told by any `409` (`backend/internal/chat/duplicates.go`).*

A conversation the caller is not a member of (or that does not exist, expired or was burned) answers `404` before the ciphertext is judged against its format, so the answer never tells a non-member whether the id is a room, or how large. In a room the ciphertext must have the room format (`NADR`, docs/architecture/rooms.md), with at most one wrap per member, and its roster digest must match the current members. A member who joined or left since the sender fetched the roster makes it `412 Precondition Failed`: fetch `/members` again, re-encrypt under the same `id`, and send again.

---

### `POST /api/v2/conversations/{id}/read`
Advances the caller's read marker. Cannot be moved backwards or past `last_seq`.

- **Request Body:**
```json
{
  "seq": 15
}
```
- **Response:** `204 No Content`

---

## 4. Rooms

Every value below is derived on the client from a room secret the server never sees ([Rooms](../architecture/rooms.md)). Binary values are unpadded base64url.

### `POST /api/v2/rooms`
Stores a new room. Costs a fresh proof of work, like an invite.

- **Request Body:**
```json
{
  "id": "UUIDv4 derived from the room secret",
  "lookup": "32 bytes derived from the room secret",
  "max_members": 5,
  "expires_at": 1793559600,
  "card": "the creator's member card (60 bytes)",
  "vault": "the room code, sealed for the creator's account (65 bytes)",
  "pow": { "challenge": "…", "salt": "…", "solution": "…", "difficulty": 20, "timestamp": 1729731200, "ttl": 300 }
}
```
- `max_members` is 2 to `ROOM_MAX_MEMBERS`. `expires_at` is on the hour, at least 50 minutes and at most `ROOM_MAX_TTL_HOURS` + 1 hours (plus 10 minutes of clock skew) ahead.
- **Errors:** `400` any field out of shape or range, `412` / `403` proof of work missing or invalid, `409` the id exists (`E_CONFLICT`: draw a new secret), `429` too many conversations or requests.
- **Response (201 Created):** `{"conversation": { … "room": { … "owner": true, "members": 1 } }}`

---

### `POST /api/v2/rooms/join`
Takes a seat. A wrong lookup, limits other than the room's, an unknown room and an expired room all answer `404`, so the answer says nothing about which. Joining a room the caller is already in refreshes their vault and answers `200`.

- **Request Body:**
```json
{
  "id": "UUIDv4 derived from the room secret",
  "lookup": "32 bytes derived from the room secret",
  "card": "the caller's member card (60 bytes)",
  "vault": "the room code, sealed for the caller's account (65 bytes)",
  "max_members": "the code's member limit, as on create",
  "expires_at": "the code's expiry in Unix seconds, as on create"
}
```
- **Errors:** `400` out of shape (or a copy of a member's card), `404` no such room for this code (`E_NOT_FOUND`, also for limits other than the room's), `409` the room is full (`E_ROOM_FULL`), `429` too many conversations or requests.
- **Response:** `201 Created` (new seat) or `200 OK` (already a member), with the room as in the listing.

---

### `GET /api/v2/conversations/{id}/members`
The room's members, sorted by card so the order does not reveal who joined first.

- **Response (200 OK):**
```json
{
  "members": [
    { "card": "60 bytes, base64url", "mine": true, "owner": true, "role": "" },
    { "card": "60 bytes, base64url", "mine": false, "owner": false, "role": "93 bytes, base64url" }
  ]
}
```
Each entry has exactly these four fields. `role` is `""` for a member that never had one, else
the sealed role the server stored without opening it.

### `POST /api/v2/conversations/{id}/members`
Stores a sealed role for the member whose card is `card`. The room's owner may set any member's
role, any other member only its own. The server checks the blob's size only (93 bytes, 124
base64url characters); it is sealed for the room and bound to `card`, so the server can neither
read nor move it. A cleared role is the sealed empty role, never an empty string. Runs under the
conversation's row lock; rate bucket `role`.

- **Request Body:**
```json
{
  "card": "the target's stored card, 80 base64url characters",
  "role": "the sealed role, 124 base64url characters"
}
```
- **Errors:** `400` out of shape; `403` `{"success":false,"message":"Role not allowed"}` (`E_ROLE_NOT_ALLOWED`) a member who does not own the room set another member's role; `404` (`E_NOT_FOUND`) the caller is not a member of this live room, the conversation is one-to-one or does not exist, or no current member has that card (one answer for all); `429` too many requests.
- **Response:** `204 No Content`. Every member gets a `conv` event, the caller's other devices included.

---

### `POST /api/v2/conversations/{id}/notes`
Delivers a sealed note (a friend request carrying an invite) to the one member whose card is `to`. At most one note waits per sender and addressee; it expires with the invite or the room.

- **Request Body:**
```json
{
  "id": "client-generated UUIDv4, bound into the note's encryption",
  "to": "the addressee's card",
  "blob": "NADN note: exactly one wrap, roster digest over the addressee's card"
}
```
- **Errors:** `400` malformed, sealed for someone else, or addressed to the caller; `404` no member has that card; `409 Conflict` a note from the caller already waits for them (or this very note, same `id` and `blob`, is the one waiting); `409` `{"success":false,"message":"Id taken"}` the `id` is held by another note (another room, sender, addressee or `blob`): nothing stored, seal again under a fresh `id`.
- **Response:** `201 Created`. The addressee gets a `conv` event.

### `GET /api/v2/conversations/{id}/notes`
The notes waiting for the caller in this room: `{"notes": [{"id": "…", "blob": "…"}]}`.

### `DELETE /api/v2/conversations/{id}/notes/{note}`
Removes a note addressed to the caller (after accepting or ignoring it). `204`, or `404` if no such note is addressed to them.

---

## 4a. Files

A file is encrypted on the client and stored as equal parts: 262144 bytes of plaintext each,
sealed to exactly 262160 bytes (349547 base64url characters), so the server learns a file's size
only in whole parts and never its name, type or bytes. The file's key travels in an ordinary
message, so exactly the members who can read that message can open the file. Works in one-to-one
conversations and rooms. Parts expire by the messages' day rule (`MESSAGE_TTL_DAYS`, day-granular,
capped like messages) and go with their conversation (burn, room expiry, the owner's or a pair
member's account deletion); leaving a room keeps the leaver's parts, like their messages.

### `POST /api/v2/conversations/{id}/files`
Stores one part. Part 0 opens the file for its uploader (and takes one token of the caller's `file`
rate bucket; later parts take none); a later part needs that live part 0 stored by the same
uploader and takes its deletion day, so a file expires as one. Parts after part 0 may come in any
order. Runs under the conversation's row lock. Nothing is published: the announcing message is. Every
stored part also spends one part of the caller's daily budget (`FILE_ACCOUNT_DAILY_BYTES`, one budget
per account across all its conversations, refilled over 24 hours, held in memory only and reset when
the server restarts); an identical resend or a refused part spends nothing.

- **Request Body:**
```json
{
  "id": "the file's client-generated UUIDv4",
  "part": 0,
  "data": "the sealed part, 349547 base64url characters"
}
```
`part` is below `ceil(MAX_FILE_BYTES / 262144)` (the contract admits up to 399, the bound's last
part).
- **Errors:**
  - `400` out of shape, or a part number past `MAX_FILE_BYTES`;
  - `404` (`E_NOT_FOUND`) the caller is not a member, the conversation does not exist, or the room expired;
  - `409 Conflict` the caller's own identical part is already stored (the earlier attempt succeeded);
  - `409` `{"success":false,"message":"Id taken"}` (`E_ID_TAKEN`) the part is stored with other bytes or by another member: nothing stored, upload the file again under a fresh `id`;
  - `409` `{"success":false,"message":"File part out of order"}` (`E_FILE_PART_OUT_OF_ORDER`) a later part before the caller stored part 0 (or after part 0 expired);
  - `507` `{"success":false,"message":"File quota reached"}` (`E_FILE_QUOTA_REACHED`) the conversation holds `FILE_CONVERSATION_QUOTA_BYTES` of parts;
  - `507` `{"success":false,"message":"File store full"}` (`E_FILE_STORE_FULL`) the server holds `FILE_STORE_MAX_BYTES` of parts (or has not counted them yet: fail closed);
  - `429` `{"success":false,"message":"File budget spent"}` (`E_FILE_BUDGET_SPENT`) the account's daily budget is spent (checked right after membership, before the part's other checks);
  - `429` too many new files.
  - `503` (`E_FILE_REQUESTS_BUSY`, or `E_BACKEND_UNAVAILABLE` from nginx) 32 file part requests are being handled already; retry.
- **Response:** `201 Created`, no body.

### `GET /api/v2/conversations/{id}/files/{file}?part=n`
One stored part, to a member of the conversation. `part` is required.

- **Response (200 OK):** `{"data": "the sealed part, 349547 base64url characters"}`
- **Errors:** `400` no or a malformed `part`; `404` (`E_NOT_FOUND`) the part is missing or past its deletion day, the room expired, or the caller is not a member (one answer for all). `503` as for an upload: too many file requests at once.

---

## 5. Realtime Server-Sent Events (SSE)

### `GET /api/v2/events`
Opens an unbuffered, content-free SSE stream.

- **Headers:** `Accept: text/event-stream`
- **Response headers:** `Content-Type: text/event-stream` and `X-Accel-Buffering: no`, which the stack's nginx passes on so an nginx in front of it does not buffer the stream either ([Deployment](../operations/deployment.md)).
- **Stream Events:**
  - `event: msg` with `data: {"c": "<conversation_id>"}` (signals a new message arrived).
  - `event: conv` with `data: {}` (signals the conversation list, a room's members, or the caller's notes changed).
  - `event: ping` with `data: {}` (heartbeat: sent once right after the `retry: 3000` / `: ready` preamble, which always comes first, then every 10 seconds). It is a named event, not an SSE comment, so the browser can see that the stream is being delivered. The web client treats a stream as held by a proxy when a new connection shows no event within 5 seconds, or a stream that already delivered one then goes 25 seconds without any; it then fetches its updates about every 5 seconds while the tab is visible and every 30 seconds while it is hidden (nothing is marked read while hidden), until an event arrives again (`frontend/js/live-updates.js`: `STREAM_FIRST_PROOF_MS`, `STREAM_SILENCE_LIMIT_MS`, `POLL_INTERVAL_MS`, `HIDDEN_POLL_INTERVAL_MS`). Clients must ignore event names they do not know.
- **Authentication:** Validated via session cookie. If session is revoked, the stream closes with `401 Unauthorized`.
- **Limits:** `429` when the account already holds 4 streams, the caller's network (IPv4 address, IPv6 /64 or Tor circuit) holds 16, or the server holds 4,096.

---

### Next Steps:
- Learn how to tune server memory and rotation in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
- Resolve any client/server errors in [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
