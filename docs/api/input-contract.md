# Input Contract

<!-- Generated from backend/internal/contract (go generate ./internal/contract). Do not edit. -->

The server accepts exactly what this document lists and refuses everything else, before any
handler runs (`contract.Gate`). Checks run in this order and the first failure answers:

1. Path: one of the templates below; `{id}`, `{note}` and `{file}` are canonical
   UUIDv4. A percent-encoded path is refused. Refusal: 404.
2. Method: one of the listed methods. Refusal: 405 (a bare 405 for HEAD where noted).
3. Query: only the listed parameters, raw (never percent-decoded), each once, at most as many
   as listed, every required one present. Refusal: 400.
4. Content type: a request with a body, and every POST to an operation that requires one, sends
   exactly one `Content-Type: application/json` (no parameters). Refusal: 415. A body sent
   to an operation that takes none: 400.
5. Body: at most the listed bytes (never above `MAX_REQUEST_BODY_BYTES`); exactly one JSON
   object; only the listed keys, each once, each of its type; nesting only where listed (and
   never beyond `MAX_JSON_DEPTH`); nothing after it. Refusal: the body's shape answer.
6. Fields, in the listed order: presence, then pattern, length and validator. A `null` value
   counts as absent. Refusal: the field's answer.

Every pattern is an anchored RE2 expression (linear time, no backtracking), compiled once from
named constants. Integers are canonical JSON integer literals (no fraction, exponent or `-0`).

## Patterns

| Name | Expression | Length | Validator |
|---|---|---|---|
| base64url-16 | `^[A-Za-z0-9_-]{21}[AQgw]$` | 22 | utils.DecodeExact(16) |
| base64url-32 | `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$` | 43 | utils.DecodeExact(32) |
| file-part | `^[A-Za-z0-9_-]+$` | 349547 | utils.DecodeExact(262160) |
| hex-challenge | `^[0-9a-f]{32}$` | 32 | - |
| hex-salt | `^[0-9a-f]{32}$` | 32 | - |
| message-ciphertext | `^[A-Za-z0-9_-]+$` | 379..7747 | utils.ValidateCiphertext, or utils.ParseRoomBlob(NADR, up to 32 wraps) |
| note-blob | `^[A-Za-z0-9_-]+$` | 643..5763 | utils.ParseRoomBlob(NADN, 1 wrap) |
| part-query | `^(?:0\|[1-9][0-9]*)$` | 1..3 | - |
| pending-token | `^(?:[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)?$` | 0..1024 | - |
| pow-solution | `^(?:0\|[1-9][0-9]*)$` | 1..20 | canonical uint64 |
| room-card | `^[A-Za-z0-9_-]{80}$` | 80 | utils.DecodeExact(60) |
| room-role | `^[A-Za-z0-9_-]{124}$` | 124 | utils.DecodeExact(93) |
| room-vault | `^[A-Za-z0-9_-]{86}[AEIMQUYcgkosw048]$` | 87 | utils.DecodeExact(65) |
| seq-query | `^(?:0\|[1-9][0-9]*)$` | 1..19 | - |
| uuid-v4 | `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` | 36 | utils.ParseCanonicalUUIDv4 |

## Integer ranges

| Name | Minimum | Maximum | Validator |
|---|---|---|---|
| after | 0 | 9223372036854775807 | - |
| file-part-number | 0 | 399 | - |
| pow-difficulty | 1 | 256 | - |
| pow-ttl | 1 | 9223372036854775807 | - |
| room-expiry | 1 | 9223372036854775807 | a multiple of 3600 |
| room-size | 2 | 32 | - |
| seq | 1 | 9223372036854775807 | - |
| unix-seconds | 1 | 9223372036854775807 | - |

## `/api/v2/pow/challenge`

HEAD: bare 405 (`E_HEAD_NOT_ALLOWED`).

### GET

- Query: none.
- Body: none.

## `/api/v2/register`

HEAD: bare 405 (`E_HEAD_NOT_ALLOWED`).

### POST

- Query: none.
- Body: optional (empty means `{}`), at most 1351 bytes; shape refused with 412 `E_POW_REQUIRED`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `pow` | object | true | object (members below) | 412 `E_POW_REQUIRED` | - |
| `pow.challenge` | string | true | hex-challenge | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.solution` | string | true | pow-solution | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.timestamp` | integer | true | unix-seconds | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.ttl` | integer | true | pow-ttl | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.difficulty` | integer | true | pow-difficulty | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.salt` | string | true | hex-salt | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `confirm` | boolean | false | true or false | - | - |
| `pending_token` | string | false | pending-token | - | 401 `E_PENDING_TOKEN_INVALID` |

## `/api/v2/login`

HEAD: bare 405 (`E_HEAD_NOT_ALLOWED`).

### POST

- Query: none.
- Body: required, at most 123 bytes; shape refused with 400 `E_LOGIN_BODY_INVALID`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `auth_key` | string | true | base64url-32 | 401 `E_LOGIN_KEY_MALFORMED` | 401 `E_LOGIN_KEY_MALFORMED` |

## `/api/v2/logout`

### POST

- Query: none.
- Body: none.

## `/api/v2/me`

### GET

- Query: none.
- Body: none.

### DELETE

- Query: none.
- Body: required, at most 123 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `auth_key` | string | true | base64url-32 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/events`

### GET

- Query: none.
- Body: none.

## `/internal/health`

### GET

- Query: none.
- Body: none.

## `/api/v2/invites`

### POST

- Query: none.
- Body: required, at most 292 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `pow` | object | true | object (members below) | 412 `E_POW_REQUIRED` | - |
| `pow.challenge` | string | true | hex-challenge | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.solution` | string | true | pow-solution | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.timestamp` | integer | true | unix-seconds | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.ttl` | integer | true | pow-ttl | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.difficulty` | integer | true | pow-difficulty | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.salt` | string | true | hex-salt | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |

## `/api/v2/invites/redeem`

### POST

- Query: none.
- Body: required, at most 99 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `token` | string | true | base64url-16 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/rooms`

### POST

- Query: none.
- Body: required, at most 648 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `id` | string | true | uuid-v4 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `lookup` | string | true | base64url-32 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `card` | string | true | room-card | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `vault` | string | true | room-vault | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `pow` | object | true | object (members below) | 412 `E_POW_REQUIRED` | - |
| `pow.challenge` | string | true | hex-challenge | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.solution` | string | true | pow-solution | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.timestamp` | integer | true | unix-seconds | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.ttl` | integer | true | pow-ttl | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.difficulty` | integer | true | pow-difficulty | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `pow.salt` | string | true | hex-salt | 403 `E_POW_INVALID` | 403 `E_POW_INVALID` |
| `max_members` | integer | true | room-size | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `expires_at` | integer | true | room-expiry | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/rooms/join`

### POST

- Query: none.
- Body: required, at most 422 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `id` | string | true | uuid-v4 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `lookup` | string | true | base64url-32 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `card` | string | true | room-card | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `vault` | string | true | room-vault | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `max_members` | integer | true | room-size | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `expires_at` | integer | true | room-expiry | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations`

### GET

- Query: none.
- Body: none.

## `/api/v2/conversations/{id}`

### DELETE

- Query: none.
- Body: none.

## `/api/v2/conversations/{id}/messages`

### GET

- Query: at most 1 of `after` (seq-query, after), `before` (seq-query, seq).
- Body: none.

### POST

- Query: none.
- Body: required, at most 7873 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `id` | string | true | uuid-v4 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `ciphertext` | string | true | message-ciphertext | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations/{id}/read`

### POST

- Query: none.
- Body: required, at most 93 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `seq` | integer | true | seq | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations/{id}/members`

### GET

- Query: none.
- Body: none.

### POST

- Query: none.
- Body: required, at most 290 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `card` | string | true | room-card | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `role` | string | true | room-role | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations/{id}/notes`

### GET

- Query: none.
- Body: none.

### POST

- Query: none.
- Body: required, at most 5971 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `id` | string | true | uuid-v4 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `to` | string | true | room-card | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `blob` | string | true | note-blob | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations/{id}/notes/{note}`

### DELETE

- Query: none.
- Body: none.

## `/api/v2/conversations/{id}/files`

### POST

- Query: none.
- Concurrency: at most 32 requests at once, shared by every operation of this bound (checked before the body is read); one more: 503 `E_FILE_REQUESTS_BUSY`.
- Body: required, at most 349695 bytes; shape refused with 400 `E_INVALID_REQUEST`.

| Field | Type | Required | Whitelist | Missing | Invalid |
|---|---|---|---|---|---|
| `id` | string | true | uuid-v4 | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `part` | integer | true | file-part-number | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |
| `data` | string | true | file-part | 400 `E_INVALID_REQUEST` | 400 `E_INVALID_REQUEST` |

## `/api/v2/conversations/{id}/files/{file}`

### GET

- Query: at most 1 of `part` (part-query, file-part-number, required).
- Concurrency: at most 32 requests at once, shared by every operation of this bound (checked before the body is read); one more: 503 `E_FILE_REQUESTS_BUSY`.
- Body: none.
