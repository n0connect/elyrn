# Rooms: Code-Based Group Conversations

A **room** is a conversation for two or more people who do not need to know each other. Its creator picks how many people it holds and how long it lives; whoever has the **room code** can join until it is full, and nobody else can. Rooms sit next to the existing one-to-one conversations (pairing by single-use invite), and a member of a room can send another member a **friend request**: an invite delivered end-to-end inside the room, so the two can continue in a one-to-one conversation.

This document is the design of record: what is stored, what is computed where, and why.

<p align="center">
  <img src="../../assets/room.png" alt="A room with three members: names exist in this room only, every message is sealed for exactly its members" width="48%" />
  <img src="../../assets/room-members.png" alt="The member list and the room safety number every member compares" width="48%" />
</p>

---

## Goals

1. **Only code holders get in.** The code never reaches the server. The server stores a keyed hash of a value derived from it and cannot join, read, or forge anything a code holder can.
2. **Content stays end to end.** Every message is encrypted on the sender's device for exactly the members it saw. A member who joins later cannot read what was sent before; a member who left cannot read what is sent after.
3. **No member can impersonate another.** Each recipient authenticates the sender with a key only the sender and that recipient can compute.
4. **Nothing links a member across rooms.** In every room an account appears under a different key and a different storage pseudonym. Neither the server nor other members can tell that two rooms share a person.
5. **The creator's limits hold.** The member limit and the lifetime are carried in the code itself; clients check them against what the server reports and refuse a room that breaks them.
6. **Same engine, same rules.** The server adds no new primitive: rooms use X25519, HKDF-SHA256, AES-256-GCM and SHA-256 only (RULES.md §1.4). The browser and the Go client (`internal/e2e`) implement the protocol byte for byte, pinned by interop vectors.

Non-goals: moderation (kicking a member), editing a room's limits after creation, server-side search, and forward secrecy, which the design does not have by decision (see *Limitations* and the [threat model](../security/threat-model.md#conditions-of-the-design)).

---

## The Room Code

<p align="center">
  <img src="../../assets/room-created.png" alt="A new room: its code is shown once to its creator, who passes it on over a channel they trust" width="60%" />
</p>

```text
code = "elyrn#" || base64url( S (32) || max_members (1) || expires_hour (4, big-endian) )
(codes made before the rename carry "noaddx#" and are still accepted)
```

- `S` is 32 bytes from the creator's platform CSPRNG (`crypto.getRandomValues`). It is the room's only secret.
- `max_members` is 2 to 32. `expires_hour` is the room's deletion time in hours since the Unix epoch.
- The code is 56 characters (57 with the legacy `noaddx#` prefix). Anyone holding it holds everything needed to join, so it is handled like an invite: shown once on creation, copyable again from inside the room by its members.

### Values derived from S

All with HKDF-SHA256, salt `"noaddx.v1"` (`noaddx` is the protocol namespace kept from the project's former name; every label below keeps it):

| Value | Info | Length | Where it goes |
|---|---|---|---|
| Room id | `noaddx/room/id` | 16 | Formatted as a UUIDv4 (version and variant bits set). Public routing id; the server cannot choose it. |
| Lookup `L` | `noaddx/room/lookup` | 32 | Sent to the server on create and join. The server stores only `HMAC(pepper subkey "noaddx/room-lookup", L)`. |
| Card key `K_card` | `noaddx/room/card` | 32 | Never leaves members' devices. Seals member cards. |

Because the room id is derived from `S`, a client always recomputes it and refuses a server that presents a room under another id.

---

## Per-Account Room Keys

At login the browser derives, from the AccountNumber, a non-extractable HKDF key:

```text
rooms_root = HKDF(AccountNumber, salt "noaddx.v1", info "noaddx/rooms", 32)
```

It is stored in IndexedDB beside the identity key and, like it, cannot be exported by script. From it:

| Value | Salt | Info | Use |
|---|---|---|---|
| Vault key | `"noaddx.v1"` | `noaddx/rooms/vault` | AES-256-GCM key that seals each room's code for this account |
| Member key | room id (16 bytes) | `noaddx/rooms/member/x25519` | X25519 private key this account uses in that room only |

The member key differs per room and cannot be linked to the account's identity key or to its key in any other room without the AccountNumber. It is deterministic, so every device that logs in to the account recovers the same key for the same room.

A browser that kept a session from before rooms existed has no rooms root in its keystore; it asks for the account number once more and derives it.

### Card

A member's card announces their member public key to the room and proves they hold the code:

```text
card = nonce (12) || AES-256-GCM(K_card, nonce, member_public_key (32), AAD = "NADC" || 0x01 || room_id (16))   // 60 bytes
```

The server cannot open or forge a card. It stores each member's card and serves the roster as the list of cards, sorted by their bytes (no join order). Cards are sealed under a random nonce, so the card a device derives at login differs in bytes from the one stored when the account joined; clients use the stored one, because others address notes to it, and the server refuses a message or note whose header card is not the sender's stored card (`400 Sender card mismatch`).

#### Disputed seats

A card proves the code, not the key it announces: every code holder has `K_card`, so a code holder can take a seat with a card carrying **another member's** key. The server cannot see keys, so both clients neutralise it the same way (browser `frontend/js/rooms.js` `verifyMembers` and `disputed`, the agent's roster):

- A key that more than one served card opens to is **disputed**. Its member is listed once, with its name and code, tagged *"two seats claim this identity"* (in the members panel and on each of its messages), and shows **no role**; nobody can set its role and no friend request can be sent to it (which of its cards is the member's own nobody can tell). The room warns once per session; the member whose own key is disputed is told so plainly.
- Its `owner` is true when **any** of its cards is flagged owner: only the server flags the owner, and an impostor's seat is never the owner's, so the badge cannot be taken away.
- Messages stay attributed by key, as they always are (the wraps authenticate the sender).
- A member who left and joined again holds one card (the server drops a card when its seat is left): that is not a dispute. Two cards both flagged as the viewer's own are the server lying, and the member list is refused.
- The room safety number counts the seats too ([Limitations](#limitations)), so members comparing it see a room with a duplicated seat differ from one without.

### Vault

So that the room survives logout and works on every device, each membership stores the code, sealed for its own account:

```text
vault = nonce (12) || AES-256-GCM(vault_key, nonce, S || max_members || expires_hour (37), AAD = "NADV" || 0x01 || room_id (16))   // 65 bytes
```

On login the client opens the vault, recomputes the room id from `S` and compares it, and compares `max_members` and `expires_hour` with what the server reports. Any mismatch hides the room.

---

## Room Messages

Each message has its own random 32-byte message key `mk`, encrypted once for every member the sender sees (including the sender, so its other devices can read it). There is no shared group key to rotate, so membership changes need no coordination: who can read a message is fixed by who was in the roster when it was sent.

### Wire format (`NADR` v1)

```text
offset  size    field
0       4       "NADR"
4       1       version 0x01
5       60      sender card
65      32      ephemeral X25519 public key (fresh per message)
97      32      commitment = SHA-256("noaddx/room/commit/v1" || mk)
129     32      roster digest (below)
161     1       n = number of wraps, 1..32
162     48·n    wraps, in random order
162+48n F+16    body = AES-256-GCM(mk, nonce 0^12, frame(payload), AAD = room_id || message_id || bytes[0:162])
```

`F` is the padded frame: 256, 512, 1024, 2048 or 4096 bytes, exactly as in one-to-one messages. The payload is the same `{"t": text, "ts": sender clock, "n": sender's counter in this room}`.

### Wraps

For each recipient `r` with member public key `R`, sender member key `a` (public `A`) and ephemeral key `e` (public `E`):

```text
ikm   = X25519(e, R) || X25519(a, R)
KEK_r = HKDF(ikm, salt = message_id (16), info = "noaddx/room/wrap/v1" || room_id || E || A || R, 32)
wrap  = AES-256-GCM(KEK_r, nonce 0^12, mk, AAD = SHA-256(room_id || message_id || bytes[0:162] || body))   // 48 bytes
```

The recipient computes the same `ikm` as `X25519(r, E) || X25519(r, A)` and tries its key on every wrap (there are at most 32, and no wrap says whom it is for).

Why each piece is there:

- **`X25519(a, R)` authenticates the sender.** Only the sender and this recipient can compute it, so another member who learned `mk` cannot build a wrap that opens for this recipient. It also makes messages deniable: a recipient cannot prove to anyone else who wrote them, because the recipient could have computed that value too.
- **`X25519(e, R)` with a fresh `e`** keeps a later leak of the sender's member key from opening messages the sender wrote.
- **The wrap's AAD hashes the whole header and body**, so a member who holds `mk` cannot keep a genuine wrap and swap the body underneath it.
- **The commitment** stops a malicious sender from building a body that decrypts to different texts under different keys (AES-GCM is not key-committing): every recipient checks that the `mk` it unwrapped matches the one the header commits to.
- **Nonces are zero** because every AES-GCM key here encrypts exactly one plaintext: `mk` is fresh per message and each `KEK_r` mixes a fresh ephemeral key and the unique message id.
- **The card in every message** lets members verify messages from people who have since left: the sender's key comes from a card only a code holder could make. Every member is a code holder, so the server also checks that the card is the sending member's stored card (`400 Sender card mismatch`): a member cannot send under keys of its own making.

### Roster digest

```text
digest = SHA-256("noaddx/room/roster/v1" || card_1 || ... || card_k)    // cards sorted by their raw bytes
```

It covers the roster as the server served it to the sender. The server recomputes it over the room's current members when the message arrives and refuses the message with `412` if a member joined or left in between. The sender then fetches the roster again and re-encrypts, so no message is ever encrypted for a stale member list. Cards that fail to open or carry an invalid key count in the digest but get no wrap, so a code holder who joins with a broken card cannot stop the room from working.

### Receiving

A client accepts a message only if every check passes, in this order: the size is one of the allowed classes and `n` is in range; the card opens under `K_card`; both X25519 computations succeed; one wrap opens; the commitment matches; the body opens and its payload has exactly the three fields. Anything else is shown as *unreadable*. Counters are checked per sender, by the same rule as in one-to-one conversations (`frontend/js/counters.js`): a gap is flagged, and a counter at or below the sender's last one, within one load or (for a message with a seq above the one this device remembers) across reloads, is shown as a replayed or reordered message instead of its text. The record is per device; a device's first open of the room, another device's view, and a replay placed at or below the remembered seq are not covered ([threat model](../security/threat-model.md)).

---

## Server Behaviour

### Storage

| Table | Columns | A database thief learns |
|---|---|---|
| `rooms` | `id`, `lookup` (HMAC), `max_members`, `expires_at` (hour), `owner_tag` | That a room exists, its limit and its deletion hour. Not the code, not who is in it. |
| `conversation_members` | as today, plus `card`, `vault`, `joined_seq`, `role` | Per-room pseudonyms, client-sealed cards, vaults and roles (a role's text is not readable, and a set role looks like a cleared one), and from which message each member can read. |
| `messages` | as today | Ciphertext; `n` reveals how many members a message was sent to. |
| `room_notes` | `id`, `conversation_id`, `recipient_tag`, `sender_tag`, `blob`, `expires_at` | That one member sent another a sealed note in that room. |

`owner_tag` is the creator's member pseudonym in that room, so it joins nothing outside it.

### Operations

| Operation | Rule |
|---|---|
| Create | Costs a proof of work (as invites do). The client sends the derived id, `L`, the limit, the hour-aligned expiry (1 hour to `ROOM_MAX_TTL_HOURS` ahead), its card and its vault. |
| Join | The room must exist, be unexpired, have a free seat, `HMAC(L)` must match in constant time, and the `max_members` and `expires_at` the client read from its code must equal the stored room's; otherwise `404`, without saying which. The limits are checked before any seat is taken or vault replaced: the room id and `L` derive from `S` alone, so a code whose limit bytes were edited would otherwise pass and store a vault that can never verify, hiding the room from that account. A full room answers `409`. Joining again with the same account and the same code refreshes the vault and is harmless; the browser and the agent refuse to send a join for a room they are in when the pasted code carries other limits (`E_ROOM_CODE_INVALID`, `E_AGENT_ROOM_CODE_ALTERED`). The member can read messages sent after it joined (`joined_seq`), and paging back (`?before=seq`) stops there too; leaving and joining again starts from the new join. |
| Send | As in one-to-one conversations, plus the structure check and the roster digest check (`412`). |
| Leave | Any member except the owner leaves: their membership goes, their messages stay readable to the others. |
| Burn | The owner burns the room for everyone, as in one-to-one conversations. |
| Expire | At `expires_at` the room stops answering at once; the retention task deletes it and everything in it within five minutes. |
| Delete account | Rooms the account owns are burned, rooms it joined are left. |

Lock order (LOCK_HIERARCHY.md): `invites` → `users` → `rooms` → `conversations`. Join, leave and send all take the conversation row lock, so a message is always checked against the roster it is stored under.

---

## Friend Requests

A member can ask another member of the same room to become friends without revealing anything until the other side accepts:

1. The requester W creates an ordinary single-use invite (a proof of work, counted against `MAX_ACTIVE_INVITES`). Its code carries the fingerprint of W's account key.
2. The invite code travels as a **note**: the room message format with magic `NADN`, exactly one wrap (for the addressee V), and a roster digest over V's card only. The server delivers it to the member whose card it names and to nobody else, at most one pending note per pair, until the invite expires. Beside the code the note carries a **binder** (below).
3. V sees *"silent-ember wants to be friends"*. Accepting redeems the invite, checks the fingerprint against the account key the redeem answer names (the invite's creator C), then checks the binder; ignoring deletes the note.

**The binder** ties the invite to the member who sent it. Without it, a member X who received W's request could seal W's code into a note of its own to V: V would believe it befriended X and be paired with W (a misbinding; X learns no plaintext). W computes, and V recomputes after the redeem answer named C:

```text
binder = HKDF-SHA256(ikm  = X25519(W_account_private, V_room_public),       // W's side
                     salt = room_id (16 bytes),
                     info = "noaddx/room/befriend/v1" || invite_token (16) || W_room_public (32) || V_room_public (32),
                     32 bytes)
check  = HKDF-SHA256(ikm  = X25519(V_room_private, C),                        // V's side; C from the redeem answer
                     same salt, info with the note's authenticated sender room key for W_room_public
                     and V's own room key for V_room_public)
```

V accepts only when `check` equals the binder (compared in constant time). A relayed invite fails: the relaying member's room key sent the note, and it cannot compute a binder under the creator's account key for its own room key. On a mismatch V burns the new conversation exactly as on a fingerprint mismatch and is told *"this request did not come from the member who sent it"* (`E_FRIEND_REQUEST_RELAYED`); the note is deleted (its invite is spent). The account key is used inside WebCrypto for `deriveBits` only; nothing is exported.

**The note payload** is the frame every message uses, holding `{"t": invite code, "ts": sender clock, "n": 1, "b": base64url(binder)}` (no padding, 43 characters). Only a note's reader accepts `"b"`; a room or one-to-one message carrying it, and a build from before binders reading a note that carries it, treat it as a key a newer elyrn wrote. A build before binders drops such a note unread (it never showed a note it could not open), so it never offers it as a valid request; this build shows a note whose payload carries keys it does not know as *"sent by a newer elyrn; reload this page to read it"*, with ignore only. A note with no `"b"` (sent by a build from before binders, or still pending from one) is shown as *"sent by an older elyrn and cannot be checked"* with ignore only: its invite is never redeemed, so nothing half-happens. Pasting an invite code into the join field is unchanged (no binder there).

Because the invite code arrives authenticated by the requester's room key, the server cannot substitute the requester's account key in the new one-to-one conversation, and the binder stops another member from relaying it. Accounts are revealed to each other only when the addressee accepts.

---

## Member Roles

A role is a short label shown beside a member of a room, `#komutan` or `#lider`, so members can
say who is who in this room. It grants nothing: moderation stays a non-goal, and a role proves
nothing about anyone.

**Who may set it.** The room's owner sets or clears any member's role; every other member sets or
clears its own only. The server enforces this (`403 Role not allowed` otherwise); the browser
shows the control only where it can be used: the owner sees it on every member, any other member
on its own row only.

**The text rule** (one home per program: `frontend/validation.js` `validateRoleText`, and the Go
side's own): after the `#`, 1 to 16 Unicode code points, each a letter (`\p{L}`), a digit
(`\p{N}`), `-` or `_`; stored NFC-normalised; at most 64 bytes of UTF-8; case kept as typed. The
words `owner` and `you` are reserved: a role is refused when its NFKC form, case-folded, equals
one of them (the browser lowercases the NFKC form; the Go side uses full Unicode case folding; for
these two words they agree), so `OwNeR`, fullwidth `ｏｗｎｅｒ` and `ＹＯＵ` are refused. The rule is
applied to what is typed (the reason is shown as it is typed) and again to every role that is
opened; one that breaks it is shown as no role.

**Sealed form.**

```text
K_role = HKDF(S, salt "noaddx.v1", info "noaddx/room/role", 32)        (S = the room secret)
plain  = len (1 byte, 0..64) || utf8(role) || zero padding             (exactly 65 bytes)
role   = nonce (12, random) || AES-256-GCM(K_role, nonce, plain,
                                           AAD = "NADL" || 0x01 || room id (16) || target card (60))
         93 bytes; base64url without padding: 124 characters
```

The target card is the member's stored card as the member list serves it, so a role cannot be
moved to another member. A cleared role is the sealed empty role, never an empty string, so the
server cannot tell a set role from a cleared one; a member that never had a role has `""`. On
opening, the tag must verify, the length must be at most 64, every padding byte must be zero, the
bytes must be UTF-8 and the text must pass the rule; anything else is shown as no role and logged
under a code only (`W_ROLE_UNREADABLE`), never its text.

**Display.** The role is shown as `#text` beside the member in the members panel and beside the
sender's name on room message bubbles (a member who left has none), always inserted as text. It
is drawn as plain italic text, while the built-in `you` and `owner` badges are framed tags: a
role never looks like a badge, and only the badge marks the owner.

**Server behaviour.** `POST /api/v2/conversations/{id}/members` with `{"card", "role"}` stores the
blob for the current member whose stored card is `card`, under the conversation row lock and its
own rate bucket (`role`), and publishes `conv` to every member (the caller's other devices
included), so every open members panel and every bubble updates without a reload. The server
checks only the blob's alphabet and exact length; it never opens it. The member list serves
`{"card", "mine", "owner", "role"}`. The role is a column of the membership: it goes when the
membership goes (leave, burn, expiry, account deletion).

**Known limits.** A lying server can serve an older role blob of the same member: it cannot forge
one or move one to another member, but it can show a role that was since changed or cleared. Any
holder of the code can seal a role (the key derives from the room secret); it is the server that
stops a member who does not own the room from storing one for someone else. A role is free text:
a lookalike from another script (a Cyrillic `о` in `оwner`) passes the reserved-word check and
proves nothing; only the built-in badge marks the owner.

---

## Limitations

- **The code is the trust anchor.** Anyone who obtains the code can join while a seat is free and read what is sent from then on. Members see every join in the member list and can compare the room's safety number on another channel; that comparison also exposes a malicious server that shows different members different rosters, which only matters if the server also holds the code.
- **The room safety number** covers the distinct member keys and, when they differ in number, the seats:

  ```text
  digest = SHA-256("noaddx/room/safety/v1" || distinct member keys (32 bytes each, ascending by bytes)
                   [ || "noaddx/room/seats/v1" || u32be(seats) ])
  digits = six groups of five: for g = 0..5, the big-endian integer of digest[5g .. 5g+5) mod 100000, zero-padded
  ```

  `seats` is the number of cards the server serves (every row of the member list, duplicates and cards that do not open included). The bracketed part is appended only when `seats` differs from the number of distinct keys, so a room where every card opens to its own key keeps the digits it always had, and a room with a disputed seat (above) shows other digits. `frontend/tests/room-trust.test.mjs` pins the vector the Go side reproduces.
- **No forward secrecy (a condition of the design).** As with one-to-one conversations, whoever later obtains a member's AccountNumber can open the messages still stored for that member (until the room expires or retention deletes them, `MESSAGE_TTL_DAYS` to `MESSAGE_TTL_DAYS` + 1 days after they were sent). The fresh ephemeral key protects a sender only against the leak of their room key, not of the recipient's.
- **Names are short labels, not identities.** An aura name carries 12 bits, and a member key is derived from an account secret and the room id, so a holder of the code can grind account secrets offline (about 4,096 tries, no server contact) until their key is named like a member's. The client therefore shows the glyph, name and code on every message, tags members and senders whose names equal another key's ("same name as another member") and warns once per session. A determined holder of the code can still grind a full visual match (glyph, name and code: 2^43 X25519 derivations); the room safety number covers every member key and exposes it.
- **Metadata the server sees.** Member count, join and leave times, message sizes and timing, and who sent each message (as a per-room pseudonym). Over the onion service the server does not see addresses.
- **Lifetime is enforced by the server.** A compromised server can keep data past expiry; honest clients stop using a room at the hour its code names.
