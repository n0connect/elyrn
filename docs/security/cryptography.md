# Cryptography Specification

This document details the exact cryptographic standards, key derivation functions, wire framing, and authenticated encryption employed by **elyrn.**

The project was called noaddx. before; `noaddx` remains the protocol namespace. Every HKDF salt
and info label (`noaddx.v1`, `noaddx/...`), every hash prefix and the stored names keep it and
never change, so keys and records made before the rename stay valid. Only the code prefixes the
app emits changed (`elyrn:`, `elyrn#`); `noaddx:` and `noaddx#` codes are still accepted.

---

## Cryptographic Standards & Primitives

All cryptographic operations strictly adhere to well-vetted, modern standards:

| Primitive | Standard | Purpose |
|---|---|---|
| **X25519** | RFC 7748 | Elliptic-curve Diffie-Hellman key exchange |
| **HKDF-SHA256** | RFC 5869 | Extract-and-expand key derivation |
| **AES-256-GCM** | NIST SP 800-38D | Authenticated encryption with associated data |
| **HMAC-SHA256** | RFC 2104 | Database lookups, member tagging, and proxy client keys |
| **PKCS#8 for X25519** | RFC 8410 | Encoding private keys for WebCrypto import |
| **Base64URL** | RFC 4648 Section 5 | URL-safe string encoding (no padding `=` characters) |

### Two Equivalent Crypto Engines

Every server-side primitive goes through one internal API (`backend/internal/cryptoengine`), implemented twice and selected at build time:

| Engine | Build | Library |
|---|---|---|
| `openssl` *(default)* | `make up` / `ENGINE=openssl` (Go tag `openssl`, CGO on) | libcrypto >= 3.2: `EVP_Digest`, `EVP_Q_mac`, `EVP_KDF` (`HKDF`), `EVP_aes_256_gcm`, `EVP_PKEY` X25519, `RAND_bytes`, `CRYPTO_memcmp` |
| `native` | `make up ENGINE=native` (CGO off, static binary) | Go `crypto/*` + `golang.org/x/crypto/hkdf` |

The engines are **byte-for-byte equivalent**, and this is enforced, not assumed:

1. **One validation layer.** Lengths and ranges are checked once, before an engine is called, so both engines always see the same well-formed input and refuse the same bad input.
2. **Known-answer tests** (FIPS 180-4, RFC 4231, RFC 5869, GCM test case 16, RFC 7748) run against whichever engine is compiled in.
3. **Differential tests** (`make test-equivalence`) link both engines into one binary and compare every primitive on random inputs and edge cases: non-canonical and low-order X25519 points, empty AAD and plaintext, each engine opening what the other sealed, and identical rejection of tampered ciphertext.
4. **Startup self-test.** The server runs the known-answer vectors on its engine before touching keys or data and refuses to start on any mismatch; the log names the engine and library version.

Accounts, stored records and messages are therefore portable between the two builds: a database written by one engine is read by the other.

---

## Key Derivation Hierarchy

### 1. Account Number & Derivations

The account number is a 32-byte (256-bit) cryptographically secure random value generated server-side via `crypto/rand` and encoded in 43 Base64URL characters.

```text
                      AccountNumber (32 raw bytes)
                                   |
         +-------------------------+-------------------------+
         v                                                   v
   HKDF-Extract                                        HKDF-Extract
(Salt: "noaddx.v1")                             (Salt: "noaddx.v1")
         |                                                   |
         v                                                   v
    HKDF-Expand                                         HKDF-Expand
(Info: "noaddx/auth", L: 32)            (Info: "noaddx/identity/x25519", L: 32)
         |                                                   |
         v                                                   v
      auth_key                                       X25519 Private Key
 (Sent at login only)                               (Stays in browser WebCrypto)
```

Both Go (`backend/internal/identity`) and JavaScript (`frontend/js/crypto.js`) implement this exact derivation and are verified byte-for-byte in test suites.

**How the server proves the auth key.** The server stores `account_lookup = HMAC-SHA256(pepper, auth_key)` and finds the account by it. At login it computes the lookup from the presented key, reads the account by it and compares the computed and stored lookups in constant time; an unknown key is compared against a fixed-length stand-in, so both outcomes do the same work. No Argon2id runs at login and no decoy hash is needed: `auth_key` is 256 bits of HKDF output from a 256-bit random AccountNumber, so there is no low-entropy secret for a memory-hard hash to slow down, and whether an account exists for a key can be learned only by holding the key. No hash of the auth key is stored at all: registration used to keep an Argon2id hash of it (`account_hash`) that nothing read, and it was removed with its column (S-07 in [debt.md](../development/debt.md), decision D-2026-11-18-a).

### 2. Browser Key Import (WebCrypto Non-Extractable)

In JavaScript, raw 32-byte X25519 private keys cannot be imported directly into `SubtleCrypto` without PKCS#8 framing.
The browser prepends the RFC 8410 `PrivateKeyInfo` header (OID `1.3.101.110`):

```javascript
const PKCS8_X25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
]);

const pkcs8Key = new Uint8Array(PKCS8_X25519_PREFIX.length + 32);
pkcs8Key.set(PKCS8_X25519_PREFIX, 0);
pkcs8Key.set(rawPrivateKeyBytes, PKCS8_X25519_PREFIX.length);

const cryptoKey = await window.crypto.subtle.importKey(
    "pkcs8",
    pkcs8Key,
    { name: "X25519" },
    false, // extractable = false (MANDATORY)
    ["deriveKey", "deriveBits"]
);
```
**Security Property:** `extractable: false` means that once imported, no script on the page can export the raw private key bytes. It can still *use* the key while it runs, and the account number itself passes through the page when it is typed: a page that runs hostile code (a modified client, a malicious extension) is not protected by this. See [Verifying the Client](verifying-the-client.md).

### 3. The Identity Kept Across Reloads (IndexedDB)

So that a reload does not ask for the account number again, the browser keeps the identity in IndexedDB (`frontend/js/keystore.js`), in one of two forms. Which one is decided by what this browser proves, never by its name. Before the identity is derived at login, `Keystore.keepsKeys` (once per page load) stores a throwaway non-extractable X25519 key, reads it back in a new transaction and deletes it; a storage failure counts as "cannot" (`W_KEY_PROBE_FAILED`, logged). Only where the throwaway key does not come back is the sealed form made at all: in an engine that keeps X25519 keys the wrapped form never exists, not even in memory. `Keystore.save` then still stores the form, reads it back through the same code the next page load uses, and keeps the first form that gives the identity back.

| Form | Kept | Engines (Nov 2026) | At rest |
|---|---|---|---|
| direct | the non-extractable X25519 `CryptoKey`, its public key, the rooms root | Chromium (checked Nov 2026), and any engine that reads an X25519 key back | No script, not even one running in this origin, can obtain the private key bytes from what is stored. |
| sealed | a device key (AES-256-GCM, generated non-extractable, usages `wrapKey` and `unwrapKey` only), the identity's PKCS#8 wrapped under it (`wrapKey`, a random 12-byte IV, AAD = `"NAID"` ‖ version `0x01` ‖ the identity's 32-byte public key), its public key, the rooms root | WebKit (Safari): it stores an X25519 `CryptoKey` without error and cannot read it back, while AES keys round-trip | The honest page unwraps straight into a non-extractable X25519 key (`ElyrnCrypto.unsealIdentity`), so the private key bytes never reach its script. Script running in this origin could call `unwrapKey` itself with `extractable: true` and read the key. |

The wrapped form is made at login, from the one moment the identity key is extractable (`crypto.js` `x25519FromSeed` reads the public key from it), and only for a session the browser keeps in an engine that failed the throwaway-key test; no plaintext PKCS#8 or seed is ever stored or logged, and the buffers that held them are overwritten. The AAD binds a wrapped blob to one public key, so it cannot be opened as another identity. When neither form reads back, nothing is kept and the page says so once (`W_IDENTITY_NOT_KEPT`): the account number is needed after a reload. A record that is stored but gives no identity at load (an engine that cannot read it back, a damaged record) is logged (`W_IDENTITY_UNREADABLE`) and the page opens logged out; the next login replaces it.

---

## Pairwise Messaging Encryption

### 1. Conversation Key Agreement

```text
Shared Secret = X25519(myPrivateKey, peerPublicKey)

Conversation Key = HKDF-SHA256(
    IKM:   Shared Secret (32 bytes),
    Salt:  Conversation ID (16 bytes UUID raw binary),
    Info:  "noaddx/conv/v1",
    L:     32 bytes
)
```

### 2. Message Framing & Bucket Padding

To thwart traffic analysis based on message length, every frame is padded to a **power-of-two size from 256 to 4096 bytes**, so the ciphertext reveals one of five size classes. The server accepts no other size, so even a client that skipped the padding could not store a message's length. Frames written before these classes (any multiple of 256, payloads up to 6000 bytes) still open.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length (2B)     |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    JSON UTF-8 Payload                         |
|       {"t": "Hello world", "ts": 1729731200000, "n": 1}       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Zero Padding (0x00 bytes)                     |
|     Padded to the next of 256, 512, 1024, 2048, 4096 bytes    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3. Client-Side Authenticated Associated Data (AAD)

The AES-256-GCM cipher authenticates a 69-byte context binding:

```text
AAD = "NADM" (4 bytes: Magic ASCII)
    || 0x01   (1 byte: Version)
    || Conversation ID (16 bytes: UUIDv4 binary)
    || Message ID      (16 bytes: UUIDv4 binary, client-generated)
    || SHA-256(Sender Public Key) (32 bytes)
```

### 4. Wire Output

```text
Wire Format = base64url( Nonce [12 bytes] || Ciphertext [N bytes] || GCM Tag [16 bytes] )
```

---

## Room Messaging Encryption

Rooms ([design](../architecture/rooms.md)) use the same primitives and frame padding, with no shared group key: every message gets a fresh 32-byte key `mk`, wrapped for each member the sender sees.

### 1. From the room code

```text
code = "elyrn#" || base64url( S (32 random bytes) || max_members (1) || expires_hour (4, big-endian) )
(codes made before the rename carry "noaddx#" and are still accepted)

room id  = UUIDv4 bits over HKDF(S, salt "noaddx.v1", info "noaddx/room/id",     16)
lookup   =                  HKDF(S, salt "noaddx.v1", info "noaddx/room/lookup", 32)   → server stores HMAC(pepper subkey "noaddx/room-lookup", lookup)
card key =                  HKDF(S, salt "noaddx.v1", info "noaddx/room/card",   32)   → never leaves members' devices
role key =                  HKDF(S, salt "noaddx.v1", info "noaddx/room/role",   32)   → never leaves members' devices
```

### 2. From the account

```text
rooms root = HKDF(AccountNumber, salt "noaddx.v1", info "noaddx/rooms", 32)          (browser: non-extractable HKDF key)
vault key  = HKDF(rooms root, salt "noaddx.v1", info "noaddx/rooms/vault", 32)
member key = X25519 scalar HKDF(rooms root, salt = room id (16), info "noaddx/rooms/member/x25519", 32)

card  = nonce || AES-256-GCM(card key,  member public key, AAD "NADC" || 0x01 || room id)   (60 bytes)
vault = nonce || AES-256-GCM(vault key, S || max_members || expires_hour, AAD "NADV" || 0x01 || room id)   (65 bytes)
```

The member key differs per room, so nothing links an account's presence in two rooms. A client keeps using the card stored when it joined: cards are sealed under a random nonce, so a re-derived card differs in bytes. A card proves the code, not the key it carries: two served cards that open to one key make that key *disputed* (no role, no friend request, counted in the room safety number; [rooms](../architecture/rooms.md#disputed-seats)).

### 3. Message (`NADR` v1; a note is the same with `NADN` and exactly one wrap)

```text
header = "NADR" || 0x01 || sender card (60) || E (32, fresh ephemeral X25519) || SHA-256("noaddx/room/commit/v1" || mk) (32)
         || roster digest (32) || n (1)
body   = AES-256-GCM(mk, nonce 0^12, frame(payload), AAD = room id || message id || header)

for each recipient R (sender member key a, public A):
  KEK_R  = HKDF(X25519(e, R) || X25519(a, R), salt = message id,
                info = "noaddx/room/wrap/v1" || room id || E || A || R, 32)
  wrap_R = AES-256-GCM(KEK_R, nonce 0^12, mk, AAD = SHA-256(room id || message id || header || body))   (48 bytes)

wire   = base64url( header || shuffled wraps || body )
roster digest = SHA-256("noaddx/room/roster/v1" || cards as served, sorted by bytes)
```

- `X25519(a, R)` authenticates the sender to each recipient (and only to them: messages are deniable).
- The wrap's AAD hashes header and body, so a member who learned `mk` cannot swap the body under genuine wraps.
- The commitment makes `mk` binding: AES-GCM alone is not key-committing.
- Every AES-GCM key in a message seals exactly one plaintext, hence the zero nonces.
- The server checks only the structure (magic, version, 1 to 32 wraps, one of the five frame sizes), the roster digest, and that the sender card in the header is byte for byte the sending member's stored card (`400 Sender card mismatch`); it opens nothing.

### 3a. Friend request binder (in a note's payload, `"b"`)

```text
binder = HKDF-SHA256(ikm  = X25519(requester account private key, addressee room public key),
                     salt = room id (16),
                     info = "noaddx/room/befriend/v1" || invite token (16) || requester room public key (32)
                            || addressee room public key (32),
                     32 bytes)
note payload = {"t": invite code, "ts": sender clock, "n": 1, "b": base64url(binder)}
```

The addressee recomputes it as `HKDF(X25519(own room private key, C), ...)` once the redeem answer
names the invite's creator account key `C` (already checked against the invite's fingerprint), with
the note's authenticated sender room key as the requester's, and accepts only on equality
(constant time). A member relaying another account's invite cannot produce it. On a mismatch the
new conversation is burned (`E_FRIEND_REQUEST_RELAYED`). `"b"` is accepted only by a note's
reader: anywhere else, and to a build from before binders, it is a key of a newer elyrn. The
browser only (the agent has no friend requests); the X25519 private keys stay non-extractable
WebCrypto keys used for `deriveBits` only.

Both implementations (`frontend/js/room-crypto.js`, `backend/internal/e2e/room.go`) open each other's vectors in their test suites.

### 4. Member role (`NADL` v1)

```text
plain = len (1 byte, 0..64) || utf8(role, NFC) || zero padding          (65 bytes)
role  = nonce (12, random) || AES-256-GCM(role key, nonce, plain,
                                          AAD = "NADL" || 0x01 || room id (16) || target card (60))   (93 bytes)
```

- The role key derives from the room secret: every code holder can open and seal roles, the server
  can do neither. Who may store one for whom is the server's rule (owner: anyone; member: itself).
- The target card in the AAD binds a role to one member: moved to another member's card it does
  not open. A cleared role is the sealed empty text, the same size as any other.
- Opening refuses a length over 64, a non-zero padding byte, bytes that are not UTF-8, and text
  outside the role rule ([rooms](../architecture/rooms.md#member-roles)); such a role is shown as
  none. Each role is sealed under a fresh random nonce; the browser and Go reproduce each other's
  vectors byte for byte from a fixed nonce.

---

## File Encryption

A file ([design](../architecture/files.md)) is sealed in the browser as equal parts and announced
by an ordinary message whose payload carries `"f"`: the file id, its key, its size, its SHA-256 and
its name. The message's own encryption is the only key distribution.

```text
fk     = 32 random bytes; file id = a random UUIDv4; parts = ceil(size / 262144)
K_i    = HKDF-SHA256(fk, salt = file id (16), info = "noaddx/file/part/v1" || u32be(i) || u32be(parts), 32)
part_i = AES-256-GCM(K_i, nonce 0^12, P_i (262144 bytes, the last zero-padded),
                     AAD = "NADF" || 0x01 || conversation id (16) || file id (16) || u32be(i) || u32be(parts))
h      = SHA-256(the file's size bytes)
```

- Each `K_i` seals exactly one plaintext, hence the zero nonce.
- The index and the part count are in both the key and the AAD: a part cannot be moved to another
  place, file, conversation or a file of another length.
- Opening requires every part to verify, the padding past `size` to be zero and the reassembled
  bytes to hash to `h`; anything else is unreadable and nothing is kept.
- Every sealed part is 262160 bytes: the server learns a file's size in 256 KiB steps only.
- The browser opens the Go-made file message and the Go side pins a browser-made one (shared
  vectors); `FILE_PART_BYTES` and the size bound are pinned against the Go sources by a test.

---

## Proof of Work (PoW) Hashcash

To prevent registration floods, registration requires solving a SHA-256 hashcash puzzle in a client Web Worker (`frontend/js/pow-worker.js`). Creating an invite or a room costs one fresh puzzle as well, so mass-producing pairing tokens or rooms stays expensive even for a logged-in client.

### Challenge Structure
- **Challenge:** 16 random bytes (hex-encoded string, 32 chars).
- **Salt:** the challenge's authentication tag (hex-encoded string, 32 chars), see below.
- **Difficulty:** Target number of leading zero bits (`POW_DIFFICULTY`, default `20`; startup refuses a value outside `18`-`24`).
- **Timestamp:** issue time, Unix seconds.
- **TTL:** `POW_CHALLENGE_TTL_SEC`, default 300 seconds (5 minutes). Single-use only.

The browser runs no challenge harder than the server's maximum (24 bits): a harder one is refused before the worker starts, and the worker refuses it too. A proof of work still running after 5 minutes is abandoned (`E_POW_TIMEOUT`; `POW_TIMEOUT_MS` in `frontend/js/auth.js`, a fixed constant equal to the default `POW_CHALLENGE_TTL_SEC` of 300 seconds: an instance with another challenge lifetime does not change it), and logging out or leaving registration stops it; the worker is terminated either way.

### Stateless Issuing
Issuing a challenge stores nothing on the server, so the free, unauthenticated challenge endpoint
cannot fill server memory. The salt authenticates every field the client echoes back:

`salt = hex(HMAC-SHA256(secret, "elyrn/pow-challenge/v1" || challenge || be64(timestamp) || be64(ttl) || be64(difficulty))[:16])`

`secret` is 32 bytes drawn from the crypto engine's CSPRNG at first use and never leaves memory;
a failed draw answers 500 and is never retried with a weaker source. The challenge is fixed-length
hex and the integers are fixed-width, so the MAC input is unambiguous. To verify, the server
recomputes the tag from the echoed `challenge`, `timestamp`, `ttl` and `difficulty` and compares
it with the echoed salt in constant time; any changed field, or a challenge issued under another
secret, fails. The difficulty checked is therefore the issued one, never a client choice. A
challenge expires at `timestamp + ttl` (its real lifetime is between `ttl - 1` and `ttl` seconds,
since the timestamp is whole seconds).

Single use is kept by remembering **solved** challenges only, each until it expires, in a set of
at most 50,000 entries; a full set answers 503. Every entry costs its sender a full proof of work
(about 2^20 SHA-256 evaluations at the default difficulty), so filling the set takes about
5 × 10^10 hashes within one TTL, plus 50,000 issued challenges, which the per-client issue limit
(5 per minute) spreads over at least 2,000 client keys. A restart draws a new secret: challenges
issued before it no longer verify (403), and the client asks for a fresh one on its next try.

### Solution Verification
The client increments an integer `nonce` starting at `0`:
`hash = SHA-256(challenge || str(nonce) || salt)` (the three as text: hex, decimal, hex)
The solution is valid if and only if `hash` contains at least `Difficulty` leading zero bits.

### Two-Phase Registration Security Flow
1. **Phase 1 (`confirm: false`):**
   - Client requests challenge `GET /api/v2/pow/challenge`.
   - Solves PoW #1.
   - Posts solution to `POST /api/v2/register`.
   - Server returns generated `account_number` preview + signed `pending_token`.
2. **Phase 2 (`confirm: true`):**
   - Client requests a **fresh, second challenge**.
   - Solves PoW #2.
   - Posts `pending_token` + PoW #2 solution.
   - Server validates PoW #2, verifies pending token, and creates the account.

---

## Visual Identity Verification (Aura & Safety Numbers)

Because users have no usernames, `elyrn.` shows display values derived from public keys
(`frontend/js/crypto.js`, `frontend/js/room-crypto.js`, twin `backend/internal/e2e/display.go`):

1. **Aura:** `d = SHA-256("noaddx/aura" || public key)`.
   - Name: adjective `d[0] mod 64` and noun `d[1] mod 64`, e.g. *silent-ember* (12 bits).
   - Code: `hex(d[2] d[3])`, four hex digits (16 bits).
   - Glyph: a 5x5 grid mirrored around its middle column, from the bits of `d[4..]` (15 bits).
   - In a room the aura is that of the member's room key, so the same account has another aura in every room. Every room message shows the sender's glyph, name and code (43 bits to imitate), and two keys under one name are tagged as such.
   - A room's own aura is the aura of `SHA-256("noaddx/room-aura" || room id)`.
2. **Safety number (one-to-one):** `SHA-256(first key || second key)`, the two raw keys ordered by
   their base64url text, read as six groups of five decimal digits (each group: five digest bytes
   as a big-endian number, mod 100000). Both sides see the same 30 digits; compare them on another
   channel, then **mark as verified**.
3. **Room safety number:** the same six groups over `SHA-256("noaddx/room/safety/v1" || every
   distinct member key, sorted by bytes [|| "noaddx/room/seats/v1" || u32be(seats)])`, where
   `seats` is the number of cards served (every row of the member list) and the bracketed part is
   appended only when it differs from the number of distinct keys. Equal digits mean equal member
   lists, seats included: a room where a code holder took a seat under another member's key shows
   other digits than the room without that seat, while a room with one card per key keeps the
   digits it always had.

---

## What the Design Does Not Provide

- **No forward secrecy, by design.** Every key derives again from the account number (identity,
  conversation keys, room member keys) or from a room code (room id, lookup, card key), so any
  device can recreate an identity from the number alone. Room messages use a fresh message key and
  a fresh ephemeral key each, but the wrap also needs the recipient's static member key, which the
  account number recreates. Whoever holds an account number opens every message for that account
  that is still stored or was recorded. A ratchet would need a kept, underivable secret, per-device
  state and uploaded keys; the reasoning is in the [threat model](threat-model.md#conditions-of-the-design).
- **No protection against a client that is not genuine.** A server that serves modified code can
  read the account number as it is typed ([Verifying the Client](verifying-the-client.md)).

---

### Next Steps:
- Review the [**REST API Reference**](../api/rest-api.md).
- Learn how to manage keys in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
