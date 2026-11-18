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
frame (`payloadFits` reserves room for the description). There is no type field: the receiver
decides what the bytes are from the bytes (magic numbers), never from the name. An invalid `f`
makes the message unreadable; a payload with keys other than these four is a newer elyrn's
("sent by a newer elyrn; reload this page to read it").

**The name rule** (`frontend/validation.js` `isFileName`, the same as Go's `fileNameValid`): NFC as it
is (never normalised on reading), 1 to 128 code points, at most 512 bytes of UTF-8, no leading dot,
no `/` or `\`, no control character (Unicode Cc: C0, DEL, C1), no bidirectional control (U+061C,
U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069), no lone surrogate. A chosen file is sent
under a name that passes it (`fileNameForSending`: NFC, refused characters replaced by `_`,
leading dots dropped, cut to the bounds keeping the extension); a received name that fails it
makes the message unreadable. A file is saved under its name with `<>:"|?*` replaced
(`saveName`). Received names and captions are other people's data: shown as text only.

## The browser

| Module | One job |
|---|---|
| `js/file-crypto.js` | part keys, sealing and opening of parts, the file's hash |
| `js/file-transfer.js` | parts to and from the server, in order, with retries; nothing else |
| `js/image-clean.js` | an image's hidden data stays behind; images recognised and decoded for viewing |
| `js/file-composer.js` | the one chosen file of the open conversation, from choosing to its message being stored |
| `js/file-card.js` | a received file in its bubble: view and save |

**Choosing.** The attach control (`+`), pasting a file, or dropping one on the open conversation.
One file per message (more is refused). It is checked before it is read: empty, or over this
server's `file_max_bytes` (from `/me`, validated like the other limits: one part to the bound),
with the limit in the sentence. It is read once; a file that changed or vanished while it was
read is refused. The composer shows its name and size and a way to remove it; send stays off while
it is being prepared or uploaded.

**Images lose their metadata before they leave.** PNG, JPEG and WebP, recognised by their first
bytes, are decoded with their orientation applied and encoded again from the pixels through a
canvas: PNG stays PNG, JPEG stays JPEG (quality 0.92), WebP becomes PNG. EXIF, GPS, device, time,
comments and text chunks stay behind, and the name becomes `image-<4 random hex>.<ext>`. What the
engine's own encoder writes beside the pixels is dropped as well (WebKit writes an Exif segment of
its own into a canvas JPEG): JPEG APP1 to APP15 and comment segments, PNG `tEXt`, `zTXt`, `iTXt`,
`eXIf` and `tIME` chunks; an encoded image that does not parse is not sent. An image
whose header declares, or whose pixels have, more than 4096 x 4096 is refused (the largest canvas
every engine draws). An image that cannot be decoded or encoded here is refused with a sentence
that says so and what to do; it is never sent as it was. A cleaned image that grew past the limit
is refused. Anything else (GIF, PDF, archives, text) is sent as it is, and the user is told once per
session that its hidden data goes along.

**Sending.** Pressing send uploads the parts in order (progress: parts done / total), then sends the
announcing message through the one send path, so a roster that changed meanwhile (412) re-encrypts
the message for the new roster, a lost answer is retried under the same id (409 "Conflict" means
stored) and the counters hold. A part whose request gets no answer or a server error is tried 3
times with a pause that doubles from 1 s; then the upload stops and says so, and the next send
continues under the same file id from the first part not stored, while the page lives. The
server's request limit (a `429` without a file sentence) is waited out past part 0 and on every
download: the transfer pauses 3 s (the server's default refill) and asks again, at most 120
times per transfer. Leaving the
conversation, removing the file, logging out or the session ending (401) cancels the upload between
parts; nothing is sent, and the composer is empty.

**Receiving.** The bubble shows a card: the name (text), the size, `view` and `save`. Nothing is
fetched until one is pressed; a double click fetches once. `view` draws the opened bytes on a
`<canvas>` only when they are PNG, JPEG or WebP by their first bytes and within the pixel limit;
SVG, HTML and everything else are never rendered, only saved. `save` hands the bytes to the browser
as a download (an object URL, revoked shortly after). One opened file is kept at a time. No CSP
change: a canvas needs no `blob:` image source, and a download is not a fetch directive.

**Memory.** The sender holds the chosen file once (the cleaned copy replaces the original) plus
one sealed part; the receiver holds the one buffer the file is assembled in plus one served part,
and `save` makes the one copy the browser's download needs.

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

- **A recipient can tell the sender's browser engine** from how an image was re-encoded (encoder
  tables, chunk order, quality behaviour): cleaning removes what the camera wrote, not the trace
  of the encoder that wrote the new file. Colour profiles are not kept either.
- **File ids** are random and chosen by the client; the server sees the same id for every part of
  a file, and a member who re-sends a file under a new id is not linked to the earlier upload.
- **No deletion this round.** A file's parts live until their day rule or their conversation ends.
  An upload cancelled or refused half-way leaves the parts already stored until then (no message
  announces them).
- **Agents read metadata only.** The Go agent shows a file message as its caption plus the file's
  name and size; it cannot fetch the bytes, and its own sends never carry `f`.
- **Everyone who could read the message can open the file**, for as long as its parts live: a
  member who leaves a room keeps what it already received the key for.
