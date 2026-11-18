# Threat Model & Security Architecture

This document formalizes the security guarantees, adversary capabilities, and cryptographic boundaries of **elyrn.**

---

## Security Objectives

1. **Confidentiality:** No entity other than the verified participants in a conversation can decrypt message contents. In a room that means the members the sender saw when sending: nobody who joins later, nobody who left before.
2. **Pseudonymity & Unlinkability:** The server and database observers cannot link a user's presence across different conversations.
3. **Bounded Storage:** Ciphertext is kept by UTC day: a message stored today gets the deletion day today + `MESSAGE_TTL_DAYS` and is served and stored until that day ends, so it lives more than `MESSAGE_TTL_DAYS` and at most `MESSAGE_TTL_DAYS` + 1 days (a room's messages at most until its expiry hour). **Burn** removes a conversation's ciphertext from the server for both sides. This bounds what is stored; it is not forward secrecy, which the design does not have (see [Conditions of the design](#conditions-of-the-design)).
4. **Resilience to Database Dumps:** A stolen database snapshot reveals no plaintext, no user credentials, and no direct social graph linkages.
5. **Zero Telemetry:** The platform records no client IP addresses, access timestamps or user activity logs. It cannot hide the address a client connects from; that is the network's job (see [Conditions of the design](#conditions-of-the-design)).

---

## Database Storage Analysis

What an adversary learns if they obtain a full SQL database dump (`noaddx/...` labels are the protocol namespace kept from the project's former name):

| Table | Sensitive Columns | Protection Mechanism | Readable Without Master Key / Pepper? |
|---|---|---|---|
| `users` | `id`<br>`uuid`<br>`account_lookup`<br>`public_key`<br>`session_epoch`<br>`encrypted_key`<br>`conv_index_enc` | Serial integer (`backend/internal/models/user.go`)<br>Random internal id<br>HMAC-SHA256 of the auth key (`ACCOUNT_LOOKUP_PEPPER`)<br>Plaintext X25519 Public Key<br>Integer<br>AES-256-GCM wrapped user key (master key)<br>AES-256-GCM encrypted room list (user key) | **The public key, the order in which accounts registered (the serial `id`), and how often each account logged out (`session_epoch`)**.<br>The AccountNumber cannot be reversed. Account IDs cannot be linked to rooms without master key. |
| `invites` | `lookup`<br>`creator_tag`<br>`creator_ref_enc`<br>`expires_at` | HMAC-SHA256 under a pepper subkey (`noaddx/invite-lookup`)<br>HMAC-SHA256 under a pepper subkey (`noaddx/invite-creator`)<br>AES-256-GCM creator UUID (master key)<br>Timestamp, rounded up to the whole hour (UTC) | **The expiration hour (and with `INVITE_TTL_SEC` the hour of creation, not the second), and how many unredeemed invites one (unnamed) creator holds**.<br>Invite token and creator identity are unreadable. |
| `conversations` | `id`<br>`last_seq` | Random UUIDv4 (derived from the code for a room)<br>Integer | **That a conversation exists and how many messages it has had**; participants are unknown. |
| `conversation_members` | `member_tag`<br>`member_ref_enc`<br>`peer_key_enc`<br>`read_seq`<br>`card`, `vault`<br>`joined_seq` | HMAC-SHA256 per conversation under a pepper subkey (`noaddx/conversation-tag`) of `uuid \|\| conversation id`<br>AES-256-GCM user UUID (master key)<br>AES-256-GCM peer pub key (user key; empty in rooms)<br>Integer<br>AES-256-GCM under keys derived from the room code / the account (client-side)<br>Integer | **The read and join sequence numbers**.<br>The member tag is isolated to this room. A user in Room A has a completely different tag in Room B. Cards and vaults open only with the room code or the AccountNumber. |
| `rooms` | `id`<br>`lookup`<br>`max_members`, `expires_at`<br>`owner_tag` | Derived from the room code<br>HMAC-SHA256 under a pepper subkey (`noaddx/room-lookup`) of a value derived from the code<br>Plain (hour-granular expiry)<br>The creator's member tag in that room | **That a room exists, its seat limit and its deletion hour**. Not the code, not the members. |
| `room_notes` | `sender_tag`, `recipient_tag`<br>`blob`<br>`expires_at` | Per-room member tags<br>Sealed for the addressee's room key<br>Timestamp, rounded up to the whole hour (UTC) | **That one member sent another a note** (a friend request) in that room, and in which hour (its expiry is the first whole hour at or after `INVITE_TTL_SEC` from sending, or the room's expiry if sooner). Invites and notes stored before this rounding keep their exact expiry. |
| `messages` | `ciphertext`<br>`sender_tag`<br>`seq`<br>`expires_on` | AES-256-GCM E2E browser encryption<br>Per-room member tag<br>Per-room sequence number<br>Date (UTC, truncated to day) | **Nothing about content**.<br>Sequence numbers are scoped to this room. Expiry dates reveal only the day of deletion, and so the UTC day a message was sent. |
| `conversation_members.role` | `role` | AES-256-GCM under a key derived from the room code, bound to the member's card (client-side); `""` when never set | **Whether a member ever had a role set** (a cleared role is a sealed empty role, so set and cleared look alike). Not the role's text. A lying server can serve an older role blob of the same member; it cannot forge one or move it to another member. |
| `file_parts` | `file_id`, `part`<br>`uploader_tag`<br>`data`<br>`expires_on` | Client-generated UUIDv4, part number<br>Per-room member tag<br>AES-256-GCM, every part exactly 262160 bytes<br>Date (UTC, truncated to day) | **That a member stored N parts of a file in a conversation, and on which UTC day** (so a file's size in 256 KiB steps). Not its name, type, exact size or bytes. A file id is a random UUIDv4 chosen by the uploader; the server never lists file ids, and a member learns one only from the message that announces the file, which it can read only if the message was encrypted for it. A member who joined a room later therefore cannot ask for files sent before it joined in practice; one who guessed an id would learn only that file's size in 256 KiB steps, never its key. |
| `burned_rooms` | `id`<br>`expires_at` | The burned room's id (derived from its code)<br>The room's own expiry, on the hour | **That a room with this id existed and was burned by its owner (or the owner's account deletion) before it expired, and when it would have expired.** Nothing else: no owner, no members, no lookup. Kept until that expiry passes. |
| `orphaned_conversations` | `id`<br>`orphaned_on` | A deleted conversation's id<br>Date (UTC, truncated to day) | **That a conversation with this id was deleted (burned, expired or with an account) on that UTC day and its rows are not yet purged.** Kept only until retention deleted its messages and file parts (normally the next cycle). |
| `key_checks` | `pepper`, `pepper-floor`, `schema-version`, `retention-clock` | A keyed commitment to the pepper; an account id; integers; a time | **The schema version, the last retention pass and the highest account id at the pepper check**. The pepper commitment reveals nothing about the pepper. |

**The database account.** The backend connects to PostgreSQL as the bootstrap superuser the
container creates (`DB_USER`, `postgres` in `.env.example`), not as a role limited to reading and
writing its own tables. Whoever takes over the backend process therefore holds every right in the
database, not only those the application uses. This is open by decision (D-09 in
[debt.md](../development/debt.md)): a separate runtime role needs a new secret that existing
`.env` files lack, so an in-place upgrade would need a manual step. See
[Hardening](../operations/hardening.md#known-limits).

---

## Adversary Capabilities Matrix

| Adversary Model | What is Protected | What is NOT Protected |
|---|---|---|
| **Passive Network Observer (ISP, Wi-Fi snooper)** | - Message plaintext (E2E AES-256-GCM)<br>- Account numbers & credentials<br>- Message length (one of five padded sizes, 256 to 4096 bytes) | - Connection timing & packet frequency<br>- IP address connecting to Nginx (hidden from the server over the onion service)<br>- Total bytes transferred |
| **Database Thief (Stolen SQL backup)** | - Message contents (encrypted client-side)<br>- Account numbers (HMAC under the pepper; no other hash of the key is stored)<br>- Cross-conversation user linkage (per-room HMAC tags)<br>- Fine-grained send timestamps (server stores no seconds/minutes) | - Total message count per room<br>- Internal message ordering within a single room<br>- Coarse day of scheduled message deletion |
| **Curious Server Operator (Has DB + `.env` + Master Keys)** | - Message plaintext (Keys are derived in browser WebCrypto; server never has private X25519 keys)<br>- Room codes and room member keys: the server only ever sees values derived from the code | - Social graph: operator can decrypt `member_ref_enc` to link users to conversations and rooms, and so see who sent a friend request to whom<br>- Active connection presence via realtime hub |
| **Malicious Server at Runtime (Compromised backend, genuine client)** | - Message plaintext and the account number: the server only relays ciphertext and derived values.<br>- Forged messages: every message is authenticated by its sender's key.<br>- Undetected key substitution and room tampering, by the checks in [What a lying server can and cannot do](#what-a-lying-server-can-and-cannot-do). | - Withholding, delaying, replaying or reordering messages (detected per device, never prevented), refusing service, hiding conversations.<br>- Metadata: who talks to whom (it holds the master key), when, how much, from which address; which member stored how many parts of a file and when, and which member fetched which part and when.<br>- **Web Security Limit:** a server that serves modified JavaScript reads the account number when it is typed and with it every stored message of that account (no forward secrecy). See [Verifying the Client](verifying-the-client.md). |
| **Session Cookie Interceptor** | - Cookie is `HttpOnly` and `SameSite=Strict`; in production also `Secure` and `__Host-` prefixed (development: `noaddx_session`, no `Secure`); the token never appears in a response body and no header can carry it.<br>- Cross-origin and same-site writes (other ports, sibling subdomains) are refused via `Sec-Fetch-Site`/`Origin`.<br>- Logout immediately invalidates all sessions via `session_epoch` bump; an already revoked token cannot trigger it.<br>- Logout and account deletion close the account's live event streams; a stream that checked its session just before the revocation is refused when it subscribes (a per-account revocation generation read before the check), and every stream re-checks its session at each heartbeat (10 s). When the streams cannot be closed at once, the answer is `503`, never success, and a stream left open ends within one heartbeat.<br>- A successful logout or account deletion also answers `Clear-Site-Data: "cookies", "storage"`, so the browser drops the origin's cookies and stored identity even when the page's own wipe failed. | - Access to the authenticated account until logout, account deletion or expiry (30 days by default, sliding, so a stolen cookie that is used keeps itself alive). This is the price of a session that does not end: the cookie is `HttpOnly`, `SameSite=Strict` and, in production, `__Host-` prefixed and `Secure`. |
| **User Loses AccountNumber** | - High security: zero backdoor access. | - **Unrecoverable:** By cryptographic design, no admin reset, SMS code, or email recovery exists. |

---

## What the Server Cannot Learn

With the genuine client, whatever the server stores or sees in transit:

- **Message and note content.** Messages are encrypted in the browser (or in `elyrn-agent`); the server holds ciphertext of one of five padded sizes and opens nothing.
- **The account number.** Registration shows it once from phase 1's answer; afterwards only the derived auth key (as `HMAC(pepper, auth key)`) and the public key reach the server.
- **Who an account is.** There is no email, phone number, name or password; an account is a random number and a public key.
- **Room codes.** The server sees only values derived from a code (room id, an HMAC of the lookup, sealed cards and vaults); it cannot make a card, so it cannot add a member to a room.
- **Which conversations one account is in, from the database alone.** Members appear under a different HMAC tag in every conversation, and under a different key and name in every room. With `.env` (master key and pepper) the operator can link them; see the matrix above.

## What a Lying Server Can and Cannot Do

A server that runs modified backend code but serves the genuine client can refuse, withhold, delay,
replay, hide and lie about metadata. Each lie about keys, rooms or order is detected by the client:

| The server … | The client detects it by … |
|---|---|
| swaps the peer key behind an invite | the invite code's fingerprint over the token and the creator's key: the redeemer's browser burns the conversation (`E_PEER_KEY_SUBSTITUTED`); the creator is protected once both compare the **safety number** (30 digits) on another channel |
| answers `/me` with another public key | the client derives its own key from the account number and refuses a different one (`E_IDENTITY_MISMATCH`, `E_AGENT_IDENTITY_MISMATCH`) |
| lists a room under another id or other limits | the room code sealed in the member's vault: the id and limits must match the code, or the room is hidden and can only be left (`E_ROOM_UNVERIFIED`, `E_AGENT_ROOM_VERIFY`) |
| seats someone under a doctored code | joins carry the code's limits and the server refuses other limits like a wrong code; a client refuses a known room pasted with other limits (`E_ROOM_CODE_INVALID`, `E_AGENT_ROOM_CODE_ALTERED`) |
| adds a card nobody announced, or drops the member's own card | every card must open under the room's card key, the member's own card must be present and the count may not exceed the code's limit (`E_ROSTER_UNVERIFIED`, `E_AGENT_ROSTER`) |
| shows members different rosters | the **room safety number** (30 digits over the sorted member keys, and the seat count when it differs from their number): different digits on another channel mean different rooms |
| serves a second seat whose card carries a member's key (a code holder made it) | the key is **disputed**: shown once, with no role, no role control and no friend request; its owner badge kept; the room warns, and the safety number differs from the room without that seat (`W_ROOM_SEATS_DISPUTED`, `W_OWN_SEAT_DISPUTED`; [rooms](../architecture/rooms.md#disputed-seats)) |
| answers `/me` with a refusal that is not a `401` (a `429`, a `404`, any `5xx`) | the browser keeps the stored identity and offers a retry under that answer's code; only a `401`, or a `/me` naming another public key, ends the session on this device, at page load, on a stream reconnect and on a return from the back-forward cache |
| withholds, replays or reorders messages | the encrypted per-sender counter: gaps are named per sender, a replayed or reordered message is shown as a warning without its text (per device; see the limits below) |
| hides a room to reset the agent's replay record | the agent drops a room's counter record only on the room's own expiry or its own leave, never on the server's word |
| hides a conversation or room to reset the browser's replay record | the browser drops a counter record only on the user's own burn or leave that the server confirmed (`204`), or a day after the room's own expiry from its code (the room is then never shown again); a listing that omits the conversation or a `404` keeps the record |

It cannot read messages, forge a member's message (every message key is wrapped with
`X25519(sender, recipient)`), add a member to a room without its code, or make one client accept a
peer key that the safety number does not confirm. Every message also carries a roster digest the
server checks (`412` on a stale roster), which keeps honest senders from encrypting for an outdated
member list; it is a consistency check, not a defence against the server. The server also checks
that the card in a room message's or note's header is, byte for byte, the sending member's stored
card (`400 Sender card mismatch`): every member holds the code and could seal cards for keys of its
own making, and this keeps each member to the one identity on the roster. It guards members
against each other, not against the server, which stores whatever card a member joined with.

## Conditions of the Design

Two limits are decided properties of the system, not open debts (decisions D-2026-11-13-a and -b in
[debt.md](../development/debt.md)):

- **No forward secrecy.** An identity is one account number from which every key is derived
  again, on any device, with nothing kept on a device that the number cannot recreate (a room
  member key derives from the account number and the room id; a room's id, lookup and card key
  from its code). Forward secrecy needs exactly such a kept, underivable secret that is later
  deleted (a ratchet), and with it per-device state, keys uploaded to the server and new surfaces
  that link devices and sessions. So whoever obtains an account number can open every message of
  that account, one-to-one or wrapped for it in a room, still stored or recorded in transit.
  Retention and **burn** bound what is stored.
- **A compromised server and the client's network address are outside what the project can
  change.** The measure is that the server cannot read messages or tell who an account is. A
  server that serves modified client code defeats any browser application; checking the code is
  described in [Verifying the Client](verifying-the-client.md). The address a client connects
  from is visible to whoever runs the server or watches the network; the answer is the
  [onion service](../operations/onion-service.md) or a VPN, not the application.

---

## Stored-Record AAD Specification (v2)

To prevent ciphertext swapping across rows, tables, or identities, the server-side AES-256-GCM records named under the registered field codes below bind to an authenticated header (`backend/internal/encryption/aad.go`). `users.encrypted_key`, each account's server key wrapped under the master key, carries no header (`encryption.EncryptWithMasterKey`, no AAD): a database writer who moves it to another row gains nothing, since every record that key opens (`peer_key_enc`, `conv_index_enc`) is bound below to its own member tag or user UUID and fails to open under another account's key or row.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       MAGIC "PXAD"                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER (0x02)   |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                  SHA-256(Subject Tag) (32 bytes)              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Record ID (16 bytes UUID)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Field (1)   |  Purpose (1)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total Length = 55 bytes
```

### Registered Field Codes:
- `0x01` (`FieldPeerPublicKey`): Encrypted peer public key (`conversation_members.peer_key_enc`).
- `0x02` (`FieldInviteCreator`): Encrypted invite creator reference (`invites.creator_ref_enc`).
- `0x03` (`FieldMemberRef`): Encrypted member reference (`conversation_members.member_ref_enc`).
- `0x04` (`FieldConversationIndex`): Encrypted conversation ID index (`users.conv_index_enc`).

---

## Memory Zeroization on Shutdown

To protect against cold-boot attacks and post-termination RAM dumps, `backend/cmd/server/main.go`
stops in order on `SIGINT` or `SIGTERM`:
- In-flight requests get 10 s, then are cut off; open Server-Sent Events streams end.
- Background jobs (retention, re-wrapping, PoW cleanup) get 5 s more.
- The database pool and the single-instance lock are closed.
- The master keys (`MASTER_KEY_ACTIVE`, `MASTER_KEY_OLD`) are overwritten with `0x00` last (`encryption.Close`). A request still running then is refused (`503`, `E_SHUTTING_DOWN`) instead of sealing anything under a zeroized key.

---

## What the Server Holds in Memory, and for How Long

- **The AccountNumber:** only inside the phase-1 registration request. The response shows it to the user once; what waits for phase 2 (up to `PENDING_TOKEN_TTL_SEC`) is the derived auth key and X25519 public key, from which the AccountNumber cannot be recovered. Login sends the derived auth key, never the AccountNumber.
- **Master keys:** for the process lifetime, zeroized on shutdown (above).
- **Per-user server keys and conversation indexes:** only while a request that needs them runs.
- **Stream tags and rate-limit keys:** HMACs under per-boot secrets, never persisted.
- **File upload budgets:** how many file parts each account stored in the last day (`FILE_ACCOUNT_DAILY_BYTES`) is counted in memory only, keyed by the stream tag, never written to the database, and resets when the process restarts.

## Login Cost and Availability

Login costs one HMAC, one indexed query and one constant-time compare, for known and unknown keys alike; it does not run Argon2id. Earlier, every syntactically valid key ran a full Argon2id verification (a decoy for unknown keys) in `ARGON2_MAX_CONCURRENT` global slots without proof of work, so anyone could keep the slots busy and every login answered 503 (S-02). Argon2id no longer runs anywhere: registration stopped storing a hash of the key (D-2026-11-18-a). Response time still does not reveal whether an account exists, and the question has no attacker value: a 256-bit auth key cannot be guessed. Per-client and per-account rate limits stay.

---

## Known Limitations

These are properties of the design, stated so nobody relies on a guarantee that is not there:

- **No forward secrecy (a condition of the design, above).** Each account has one static X25519 identity key derived from its AccountNumber, and each conversation one key derived from the two identities; room member keys derive from the account and the room id. Whoever obtains an AccountNumber can decrypt every message of that account that is still stored (up to `MESSAGE_TTL_DAYS` + 1 days, by UTC day) or was recorded in transit. Retention and **Burn** bound the exposure; treat the AccountNumber like a master key.
- **The invite creator trusts the server for the peer key.** The fingerprint in the invite code protects the *redeemer* against a substituted creator key. The creator learns the redeemer's key from the server and is protected only after both compare safety numbers.
- **A friend request is bound to the member who sent it, not to a person.** Its binder ([rooms](../architecture/rooms.md#friend-requests)) proves that the account which created the invite also holds the room key that sent the note, so another member cannot relay someone else's invite (the addressee burns the conversation, `E_FRIEND_REQUEST_RELAYED`). It proves nothing about who stands behind that room key. A request still pending from a build before binders carries none: it can only be ignored, never accepted. A build before binders drops a request that carries a binder unread, so a requester on this build whose addressee runs an older one is told the request was sent while the addressee never sees it, until the addressee reloads.
- **Clipboard clears are attempts.** The page copies the account number, invite codes and room codes for the user to paste, and later tries to clear the clipboard if it still holds them (on continue for the account number, two minutes later for a code). A browser can refuse that write or never settle it (a tab without focus): the page then says so (`W_CLIPBOARD_NOT_CLEARED`, "copy something else to overwrite it"). Clipboard histories and cross-device clipboard sync may have kept a copy either way; the page cannot see or clear them.
- **Code delivery is trust in the server (outside what the project can change, above).** A browser application runs the JavaScript it is served; a malicious or compromised deployment can serve code that leaks the account number (see the matrix above). Each release signs the list of frontend file hashes, and `make verify-frontend` proves what an instance serves ([Verifying the Client](verifying-the-client.md)), but only to the verifier: a server can still target one user.
- **Withheld-, replayed- and reordered-message detection is per device.** The encrypted sender counter reveals gaps in what one device has seen; it is not a cross-device delivery guarantee. Each device keeps, per conversation, a record in IndexedDB (the highest seq it processed, its own highest counter, and each sender's highest counter, a use stamp that only counts up, and for a room its own expiry from its code; no text, ids or the time of any activity), so across reloads it detects an old message served again under a new seq, messages served out of order, and gaps; such a message is shown as a warning, not as text. A device never reuses a counter, even after a reload in which the server withholds its own last messages, and a send whose answer was lost spends its counter too. A session the server ends (a 401) keeps the records. The user's own logout or identity deletion, or logging in with another account on the device, removes them all; one record is removed by the user's own burn or leave that the server confirmed (`204`), or once its room's own expiry is more than 24 hours past. It does not detect: anything on a device with no record (its first open of the conversation, after logout, or with storage wiped or refused, where only order within one load is checked); what another device was shown; a replay given a seq at or below the remembered one (it shows as history, at its original time); a server rolling its seqs back below the remembered one; a conversation whose record was evicted; a sender first seen after its room's record was full. A browser record names at most 4096 senders (`Counters.MAX_SENDERS`). What a record holds is never given up to a newcomer that is not a member: at the bound a new sender that is not on the current roster is not recorded (its messages are shown, each tagged *"replay protection is not kept for this sender on this device"*, and the room warns once per session that its record is full), so such a sender has no replay detection across reloads on that device; a new roster member is always recorded and displaces the off-roster entry recorded most recently (logged `W_COUNTER_RECORDS_EVICTED`; the displaced sender is marked unrecorded and tagged the same way, since a long-held entry is a real former member while a flood of made-up keys is recorded after it); this device's own entry, its own counter, the remembered seq and the roster's entries are never displaced. A record an older build wrote above the bound is read keeping this device's own entry, the roster's, then the earliest-recorded others, instead of being discarded (which forgot the device's own counter). What stops made-up senders in the first place is the server: it refuses a room message or note whose header card is not the sender's stored card (`400 Sender card mismatch`), so a member cannot send under keys of its own making, and the bound only matters against a server that does not enforce that. The agent applies the same rule at 256 senders (`maxTrackedSenders`), within one loaded sequence as in its record: its own key and the roster are always tracked and recorded, and a newcomer off the roster at the bound is not (its messages carry `unrecorded: true`). A server that leaves a conversation out of a listing, or answers `404` for it, and later lists it again does not reset the record: the browser keeps it, and the agent drops one only on the room's own expiry or its own leave (see the table above). A browser keeps at most 1024 records: past that, on the first listing of each session, it drops the least recently used (a use is a message seen or sent; the conversations listed at that moment go last) and logs `W_COUNTER_RECORDS_EVICTED` once per page load; the agent, at the same bound, drops the records of the rooms that expire soonest (`E_AGENT_STATE_EVICTED`). A device that has never sent in a conversation (a second browser of the account, a new profile) learns its account's highest counter there before its first send: each own message it opens raises its counter, whatever its verdict, and when its own latest message is not on the latest page it reads earlier pages until it meets one or the history ends; the send waits for that, and if a read fails it is not sent (*"message not sent — press send again"*), never sent with a guessed counter (`counters.js` THE OWN COUNTER). The agent reads every visible message forward before its first send, up to 64 pages. What stays: two devices of one account that send at the same moment, or a device that sends while it is offline from, or has not yet read, the other's latest message, can take the same counter; the other members then see one of the two messages in place of its text as *"⚠ a message from {name} was replayed or reordered by the server"*, also after a reload, and its sender sees nothing wrong on its own device. Two tabs of one browser cannot: each counter is taken under a lock the tabs share (Web Locks), from the record as stored at that moment, and the raised record is stored before the message is posted; a counter whose send the server refused outright is reused by the next send. A browser without Web Locks still reads fresh and writes ahead, without the lock.
- **The pepper cannot be rotated.** `ACCOUNT_LOOKUP_PEPPER` keys every account lookup and every per-conversation pseudonym. Together with a copy of the database it links accounts to their conversations without the master key (internal user ids are stored in clear). The master key can be rotated and old records re-wrapped; the pepper cannot, so its exposure calls for a new instance. Startup refuses a pepper other than the one the database was created with, so it cannot change by accident either.
- **Master key rotation keeps account keys.** Re-wrapping replaces the master key around each account's server key, not the account key itself. A copy of the database taken while an attacker also held the old master key stays readable to them; every later copy does not.
- **A room's code is its trust anchor.** Whoever obtains the code can join while a seat is free and read what is sent from then on; members see every join and can compare the room safety number. A server that also holds the code could show members different rosters; comparing the room safety number exposes it. See [Rooms](../architecture/rooms.md#limitations).
- **Rooms leak their size and churn.** The server sees how many members a room has, when members join and leave (`joined_seq`), and how many members each message was encrypted for.
- **An agent's identity is a file on disk.** `elyrn-agent` keeps its AccountNumber in `~/.config/elyrn/agent.json` (mode 0600, directory 0700) on the machine that runs it; whoever reads that file is that agent. Full-disk encryption and file permissions are the protection. See [Agents](../operations/agents.md).
- **Room text reaching a model is untrusted input.** An agent sees what its room sees, and any member can write text meant to steer the model behind it. Tool results label room messages as data, not instructions, but prompt injection is a property of language models that no transport can remove: putting an agent in a room is trusting its operator with that room, and the room with what the agent can do.
- **Network metadata.** The server sees connection addresses and timing in transit. It does not log them (`access_log off`; rate-limit keys are HMACs of the address under a per-boot secret), but an operator could capture them at runtime. Over the [onion service](../operations/onion-service.md) there is no client address to see, only a per-circuit number.
- **Behind the onion listener a client is a Tor circuit, and a party can open many.** nginx and the backend count every per-client share (rate limits, connection shares, event streams, file and page slots) per circuit, so one party with many circuits holds many shares. What bounds it are the global shares, sized so the worker pool and the frontend container's memory always hold them (`nginx-main.conf`), and Tor's own introduction defences; a party that holds a global share blocks those requests for everyone until it lets go. See [Onion Service](../operations/onion-service.md#zero-trust-behind-tor).
- **Leaving the login screen mid-login leaves an unused session cookie.** When the way back from the login screen is taken after `/login` succeeded (or while it was in flight and it then succeeds) but before the app opened, the page abandons that login (`auth.js` `leaveLogin`): nothing is shown, no key is derived or stored, the app does not open. The `HttpOnly` session cookie that `/login` set stays in that browser, valid until it expires (`JWT_EXPIRATION_MINUTES`, 30 days by default; only an authenticated request would slide it, and the page makes none with it), until a later login in that browser replaces it, or until the account logs out anywhere. It is not revoked because sessions are revoked per account, not per session: a session token carries the account, its `session_epoch`, and its issue and expiry times, and no session id, and `/logout` bumps the epoch, ending every session of the account on every device. Ending only this one would need a per-session record the server deliberately does not keep. Whoever can use that browser's cookie jar in that window holds a session of the account, without its keys (the account number never left the page and messages stay end-to-end encrypted).
- **In Safari the identity is kept wrapped, not as a key.** Browsers that can read an X25519 `CryptoKey` back from IndexedDB (Chromium, checked Nov 2026) keep the identity as a non-extractable key: script running in the origin can use it while the page runs but can never obtain the private key bytes from what is stored. WebKit (Safari, as of Nov 2026) cannot read such a key back, so there the identity is kept sealed: its PKCS#8 wrapped under a non-extractable AES-256-GCM device key that may only wrap and unwrap. The page itself unwraps it straight into a non-extractable key, but script running in the origin (a modified client, a malicious extension, an injection) could unwrap an extractable copy and read the identity private key, which lets it decrypt that account's stored messages after the page is gone. The account number passes through the same page at login, so this weakens only what is at rest between logins. Which form a browser gets is decided by what it proves: before the identity is derived, the page stores a throwaway X25519 key and reads it back, and only where that fails is the wrapped form made at all ([Cryptography](cryptography.md#3-the-identity-kept-across-reloads-indexeddb)); logout or identity deletion removes either form.
- **Files are delivered exactly as they are.** elyrn. never reads, interprets, cleans or displays a file's content ([Files](../architecture/files.md)): decoding a file in the page would be attack surface for bytes written by strangers, and cleaning some formats would teach people to trust it with the ones it cannot clean. A photo or document reaches every member with whatever its maker put in it (location, device, author, time), and the file itself is a fingerprint: the same file elsewhere can be matched to it. The sender is told so at every chosen file, and a member who ignores that can send a photo's location, which cannot be undone once it was saved. Only the name is set by elyrn.: every file goes out as `file-<8 random hex>` plus a short plain extension, so the chosen name never leaves the device. A received file is untrusted: it is only ever handed to the browser as a download, never opened or previewed by the page. The server learns how many 256 KiB parts a member stored in a conversation and when, and which member fetched which part and when; never a file's name, type, exact size or bytes. Parts of an upload cancelled half-way stay until their day rule (no deletion this round).
- **Content-free alerts tell a looker that a message came.** When the user turns alerts on (off by default, per device), the page raises the browser's own notification while it is hidden: title `elyrn.`, body `new message`, one at a time under one tag, nothing again until the page was seen. It never names a sender, a room, a count or any content, but whoever sees the screen (or the operating system's notification history) learns that this device uses elyrn. and when a message arrived. Nothing leaves the device for it: no push service, no service worker, no request (`frontend/js/alerts.js`), so it works only while a tab is open. The choice is kept in IndexedDB with the identity and goes with it.
- **Deletion is logical, not forensic.** Deleting an identity or burning a conversation ends access at once; the conversation's messages and file parts stay on disk, unreachable, until the next retention cycles delete them in batches (`orphaned_conversations` names the conversation meanwhile, with the UTC day of the deletion). Even then PostgreSQL keeps dead row versions until autovacuum reuses the space and keeps the WAL until it is recycled. A disk image taken soon after can still hold them: ciphertext, HMAC tags and encrypted references, never plaintext.

---

### Next Steps:
- Review the low-level math and algorithms in [**Cryptography Specification**](cryptography.md).
- Examine configuration parameters in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
