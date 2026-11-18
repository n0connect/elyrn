# Files: Sharing a File Inside a Conversation

Design of record for file sharing in one-to-one conversations and rooms. The server stays
blind: it never sees a file's bytes, name, type or exact size, and no third party is contacted.
No new primitive: X25519 (through the existing message keys), HKDF-SHA256, AES-256-GCM, SHA-256.

## Purpose

A member sends a file the way it sends a message. The file is encrypted in the browser and stored
as equal-sized opaque parts; an ordinary message announces it and carries its key. Because that
message is encrypted like every message, exactly the people who can read the message can open the
file, with no new key distribution: in a room the message is wrapped for the roster at the moment
it is sent, in a pair for the two peers.

## Formats

### Parts

```text
FILE_PART_BYTES = 262144                                  (256 KiB of plaintext per part)
fk      = 32 random bytes (the file key); file id = a random UUIDv4
size    = the byte length of the file as sent (1 .. file_max_bytes); parts = ceil(size / 262144)
K_i     = HKDF-SHA256(ikm = fk, salt = file id (16), info = "noaddx/file/part/v1" || u32be(i) || u32be(parts), 32)
P_i     = bytes [i * 262144, (i + 1) * 262144) of the file; the last part zero-padded to 262144
part_i  = AES-256-GCM(K_i, nonce 0^12, P_i, AAD = "NADF" || 0x01 || conversation id (16) || file id (16) || u32be(i) || u32be(parts))
h       = SHA-256(the file's size bytes)
```

A sealed part is 262160 bytes (349547 base64url characters), whatever the file: the server learns a
file's size only in steps of 256 KiB. Each part key seals exactly one plaintext, so the zero nonce is
safe. The index and the part count are bound into both the key and the AAD, so a part opens in no
other place, file, conversation or file length. Opening checks that every part verifies, that the
padding past `size` is zero and that the whole file hashes to `h`; any failure shows the file as
unreadable and keeps nothing (`frontend/js/file-crypto.js`, `frontend/js/file-transfer.js`).

### The announcing message

The payload of a message (one-to-one and rooms alike) is exactly `{"t","ts","n"}` or exactly
`{"t","ts","n","f"}`:

```text
"f": {"i": "<file id, canonical UUIDv4>", "k": "<fk, base64url, 43 chars>", "s": <size, integer 1..104857600>,
      "h": "<SHA-256, base64url, 43 chars>", "n": "<display name>"}
```

`f` has exactly these five keys, each checked for shape and range (`frontend/js/crypto.js`
`decodePayload`; `backend/internal/e2e/file.go` reads it the same way). With `f` the caption `t` may
be empty; without it `t` keeps the message rules. The whole payload must still fit the 4094-byte
frame (`payloadFits` reserves room for the description). There is no type field, and the client
never looks at the bytes to find one: a file is delivered, never interpreted. An invalid `f`
makes the message unreadable; a payload with keys other than these four is a newer elyrn's
("sent by a newer elyrn; reload this page to read it").

**The name rule** (`frontend/validation.js` `isFileName`, the same as Go's `fileNameValid`): NFC as it
is (never normalised on reading), 1 to 128 code points, at most 512 bytes of UTF-8, no leading dot,
no `/` or `\`, no control character (Unicode Cc: C0, DEL, C1), no bidirectional control (U+061C,
U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), no lone surrogate. A received name that
fails it makes the message unreadable. A file is saved under its name with `<>:"|?*` replaced
(`saveName`). Received names and captions are other people's data: shown as text only.

**The name a file is sent under** (`frontend/validation.js` `outgoingFileName`): every file goes
out as `file-<8 random hex>` plus the chosen file's extension when that extension, lowercased,
is 1 to 8 characters of `[a-z0-9]` (`holiday photo.JPG` becomes `file-3fa2c19e.jpg`); otherwise
with no extension. The chosen name never leaves the device, and the composer shows the name that
will be sent, not the chosen one. This is the only thing elyrn. sets about a file.

## The browser: delivery only

**elyrn. delivers a file exactly as it is; it never reads, interprets, cleans or displays file
content** (the owner's decision of 18 Nov 2026). The server's only job is to relay sealed bytes and
the client's only job is to deliver them, as with messages. Decoding or parsing a file in the page
is attack surface, on the receiving side for bytes written by strangers and on the sending side
for whatever the user picked up elsewhere. Cleaning could only ever cover a couple of formats, and
a tool that cleans some files teaches people to trust it with the ones it does not clean (HEIC,
PDF, office documents, video). So nothing is cleaned and the user is told so every time.

| Module | One job |
|---|---|
| `js/file-crypto.js` | part keys, sealing and opening of parts, the file's hash |
| `js/file-transfer.js` | parts to and from the server, in order, with retries; nothing else |
| `js/file-composer.js` | the one chosen file of the open conversation, from choosing to its message being stored |
| `js/file-card.js` | a received file in its bubble: its name, its size and `save` |

**Choosing.** The attach control (`+`), pasting a file, or dropping one on the open conversation.
One file per message (more is refused). It is checked before it is read: empty, or over this
server's `file_max_bytes` (from `/me`, validated like the other limits: one part to the bound),
with the limit in the sentence. It is read once and left as it is; a file that changed or vanished
while it was read is refused. The composer shows the name it will be sent under, its size and a way
to remove it; send stays off while it is being read or uploaded.

**The notice.** At every chosen file, for as long as it is chosen, never dismissible and never
"once per session", the composer says (`Errors.NOTICE.FILE_SENT_AS_IS`): *this file is delivered
exactly as it is. photos and documents usually carry hidden data — where, when and on what device
they were made, who wrote them — and the file itself can be recognised wherever the same file turns
up. elyrn. removes none of it.* The cost is stated plainly: a user who ignores the notice can send
a photo with the place it was taken in it, and that cannot be undone once a member has saved it.

**Sending.** Pressing send uploads the parts in order (progress: parts done / total), then sends the
announcing message through the one send path, so a roster that changed meanwhile (412) re-encrypts
the message for the new roster, a lost answer is retried under the same id (409 "Conflict" means
stored) and the counters hold. A part whose request gets no answer or a server error is tried 3
times with a pause that doubles from 1 s; then the upload stops and says so, and the next send
continues under the same file id from the first part not stored, while the page lives. The
server's request limit (a `429` without a file sentence) is waited out past part 0 and on every
download: the transfer pauses 3 s (the server's default refill) and asks again, at most 120
times per transfer. Leaving the conversation, removing the file, logging out or the session ending
(401) cancels the upload between parts; nothing is sent, and the composer is empty.

**Receiving.** The bubble shows a card: the name the file was sent under (as text), its size, one
control, `save`, and a fixed line (`Errors.NOTICE.FILE_FROM_MEMBER`): *sent by another member,
exactly as they sent it — opening it is your own decision.* Nothing is fetched until `save` is
pressed; then the parts are fetched and opened, the hash is checked, and the bytes are handed to
the browser as a download under the saved name (an object URL, revoked shortly after; the bytes
are not kept). There is no preview of any kind. Recipients must treat a received file as
untrusted: it is whatever another member chose to send. No CSP change: a download is not a fetch
directive.

**Memory.** The sender holds the chosen file once plus one sealed part; the receiver holds the one
buffer the file is assembled in plus one served part, and `save` makes the one copy the browser's
download needs.

## Server behaviour as seen by the client

([API](../api/rest-api.md#4a-files))

| Request | Answer the client acts on |
|---|---|
| `POST /conversations/{id}/files` `{id, part, data}` | `201` stored; `409` "Conflict" = already stored (counts as stored); `409` "Id taken" or "File part out of order": the next send uploads afresh under a new id; `429` "File budget spent" (daily budget) or `429` (too many new files); `507` "File quota reached" (conversation) or "File store full" (server); `503` busy; `404` the conversation is gone (burned, expired, left) |
| `GET /conversations/{id}/files/{file}?part=n` | `200 {"data"}` exactly one sealed part; `404` "no longer available" (expired, burned, missing) |

Every answer maps to a registered code and a sentence that says what to do next
(`frontend/js/errors.js`; [Troubleshooting](../troubleshooting/troubleshooting-guide.md)).
Nothing is published on the event stream for a part: the announcing message is.

## What the server learns

That a member stored N parts of a file in a conversation and on which UTC day (so its size in 256
KiB steps), and which member fetched which part and when. Not the file's name, type, exact size or
bytes, nor which message announced it. See the [threat model](../security/threat-model.md).

## Limits

`MAX_FILE_BYTES` (default 10 MiB, at most 100 MiB) per file; `FILE_CONVERSATION_QUOTA_BYTES` per
conversation; `FILE_STORE_MAX_BYTES` per server; `FILE_ACCOUNT_DAILY_BYTES` per account and day
([configuration](../operations/configuration-and-tuning.md)). Parts expire by the messages' day rule.

## Known limits

- **A file carries whatever its maker put in it.** Location, device, author and time in photos and
  documents reach every member who saves the file, and the file itself is a fingerprint: the same
  file found elsewhere can be matched to it. elyrn. removes nothing and says so at every chosen
  file; once a member has saved a file, nothing can take it back.
- **A received file is untrusted.** elyrn. never opens it; what the receiver's own programs do with
  it after `save` is outside elyrn.
- **File ids** are random and chosen by the client; the server sees the same id for every part of
  a file, and a member who re-sends a file under a new id is not linked to the earlier upload.
- **No deletion this round.** A file's parts live until their day rule or their conversation ends.
  An upload cancelled or refused half-way leaves the parts already stored until then (no message
  announces them).
- **Agents read metadata only.** The Go agent shows a file message as its caption plus the file's
  name and size; it cannot fetch the bytes, and its own sends never carry `f`.
- **Everyone who could read the message can open the file**, for as long as its parts live: a
  member who leaves a room keeps what it already received the key for.
