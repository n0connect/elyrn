// ========================================
// ELYRN CRYPTO (WebCrypto only — no third-party code)
// ========================================
// Mirrors backend/internal/identity byte-for-byte. Algorithms are restricted to
// RULES.md §1.4: X25519, HKDF-SHA-256, AES-256-GCM, SHA-256.
//
// AccountNumber ──HKDF "noaddx/auth"──────────────▶ auth key (sent at login)
//               └─HKDF "noaddx/identity/x25519"──▶ X25519 identity (never leaves the browser)
// identity × peer ──X25519──HKDF(conv id)────────▶ per-conversation AES-256-GCM key

const ElyrnCrypto = (() => {
    'use strict';

    // "noaddx" in these labels is the protocol namespace, not the product name: it never changes.
    const SALT = 'noaddx.v1';
    const INFO_AUTH = 'noaddx/auth';
    const INFO_IDENTITY = 'noaddx/identity/x25519';
    const INFO_CONVERSATION = 'noaddx/conv/v1';
    const INFO_AURA = 'noaddx/aura';
    const INFO_INVITE_FP = 'noaddx/invite-fp';
    const KEY_BYTES = 32;
    const BITS_PER_BYTE = 8;
    const KEY_BITS = KEY_BYTES * BITS_PER_BYTE;
    const NONCE_BYTES = 12;
    const TAG_BYTES = 16;
    const TAG_BITS = TAG_BYTES * BITS_PER_BYTE;
    const UUID_BYTES = 16;
    const INVITE_TOKEN_BYTES = 16;
    const INVITE_FP_BYTES = 16;
    // Invites are emitted with INVITE_PREFIX; codes made before the rename carry the legacy one
    // and are still accepted.
    const INVITE_PREFIX = 'elyrn:';
    const LEGACY_INVITE_PREFIX = 'noaddx:';
    const INVITE_PREFIXES = Object.freeze([INVITE_PREFIX, LEGACY_INVITE_PREFIX]);
    // Plaintext is framed as len(2) || json || zero padding to a power-of-two size from
    // PAD_BLOCK to MAX_FRAME_BYTES, so ciphertext length reveals one of five size classes.
    // json = {"t": text, "ts": sender clock (ms), "n": sender's per-conversation counter}, and for
    // a file message also "f" (docs/architecture/files.md); gaps in a peer's "n" reveal messages
    // the server withheld or deleted.
    const PAD_BLOCK = 256;
    const MAX_FRAME_BYTES = 4096;
    const FRAME_LENGTH_BYTES = 2;
    const MAX_PAYLOAD_BYTES = MAX_FRAME_BYTES - FRAME_LENGTH_BYTES;
    const PAYLOAD_KEYS = Object.freeze(['t', 'ts', 'n']);
    // A file message's payload also carries FILE_KEY, an object of exactly FILE_FIELDS:
    // {"i": file id (canonical UUIDv4), "k": file key (32 bytes, base64url), "s": size in bytes
    // (1..MAX_FILE_BYTES_BOUND), "h": SHA-256 of the file (32 bytes, base64url), "n": display name
    // (validation.js isFileName)}, written in that order as backend/internal/e2e/file.go reads it
    const FILE_KEY = 'f';
    const FILE_FIELDS = Object.freeze(['i', 'k', 's', 'h', 'n']);
    const KNOWN_KEYS = Object.freeze([...PAYLOAD_KEYS, FILE_KEY]);
    // The largest file any server may allow (backend/internal/config MaxFileBytesBound): a size
    // past it is refused whatever this server's file_max_bytes says
    const MAX_FILE_BYTES_BOUND = 104857600;
    const FILE_HASH_BYTES = 32;
    // The error name of a payload a newer elyrn wrote (decodePayload): valid t, ts and n plus
    // keys this build does not know. Told apart from tampering, never read.
    const NEWER_PAYLOAD = 'NewerPayload';
    // RFC 8410 PrivateKeyInfo header for an X25519 key (OID 1.3.101.110)
    const PKCS8_X25519_PREFIX = new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    ]);
    const AAD_MAGIC = [0x4e, 0x41, 0x44, 0x4d]; // "NADM"
    const AAD_VERSION = 0x01;
    // The sealed identity (sealIdentity): the identity's PKCS#8 wrapped under a device key with
    // AES-256-GCM, its AAD binding the blob to one identity public key
    const SEAL_MAGIC = [0x4e, 0x41, 0x49, 0x44]; // "NAID"
    const SEAL_VERSION = 0x01;
    const X25519 = Object.freeze({ name: 'X25519' });
    const SEALED_IDENTITY_BYTES = PKCS8_X25519_PREFIX.length + KEY_BYTES + TAG_BYTES;
    // Safety numbers: groups of decimal digits, each read from a run of digest bytes
    const SAFETY_GROUPS = 6;
    const SAFETY_GROUP_BYTES = 5;
    const SAFETY_GROUP_DIGITS = 5;
    // Aura over SHA-256("noaddx/aura" || key): byte 0 picks the adjective, byte 1 the noun, bytes
    // 2..3 are the code, and the bits from byte 4 on fill the drawn columns of the square grid
    const AURA_GRID_SIZE = 5;
    const AURA_DRAWN_COLUMNS = 3;  // the rest of each row mirrors these
    const AURA_CODE_OFFSET = 2;
    const AURA_GRID_OFFSET = 4;
    const B64URL_RE = /^[A-Za-z0-9_-]+$/;
    const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const subtle = globalThis.crypto && globalThis.crypto.subtle;

    // ---------- encoding ----------

    function b64urlEncode(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Strict decode: alphabet whitelist + exact length + canonical re-encoding
    function b64urlDecode(text, expectedBytes) {
        if (typeof text !== 'string' || text.length === 0 || !B64URL_RE.test(text)) {
            throw new Error('invalid encoding');
        }
        // base64 comes in groups of four characters: restore the padding the URL form drops
        const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        if ((expectedBytes !== undefined && bytes.length !== expectedBytes) || b64urlEncode(bytes) !== text) {
            throw new Error('invalid encoding');
        }
        return bytes;
    }

    function uuidBytes(uuid) {
        if (!UUID_V4_RE.test(uuid)) {
            throw new Error('invalid id');
        }
        const hex = uuid.replace(/-/g, '');
        const out = new Uint8Array(UUID_BYTES);
        for (let i = 0; i < UUID_BYTES; i++) {
            // two hex digits per byte
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function concat(...parts) {
        const total = parts.reduce((n, p) => n + p.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const p of parts) {
            out.set(p, offset);
            offset += p.length;
        }
        return out;
    }

    function wipe(bytes) {
        if (bytes && bytes.fill) {
            bytes.fill(0);
        }
    }

    async function sha256(bytes) {
        return new Uint8Array(await subtle.digest('SHA-256', bytes));
    }

    async function hkdf(ikm, salt, info, length) {
        const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: encoder.encode(info) },
            base,
            length * BITS_PER_BYTE
        );
        return new Uint8Array(bits);
    }

    // ---------- identity ----------

    function accountBytes(accountNumber) {
        return b64urlDecode(accountNumber, KEY_BYTES);
    }

    async function deriveAuthKey(accountNumber) {
        const raw = accountBytes(accountNumber);
        try {
            const key = await hkdf(raw, encoder.encode(SALT), INFO_AUTH, KEY_BYTES);
            const encoded = b64urlEncode(key);
            wipe(key);
            return encoded;
        } finally {
            wipe(raw);
        }
    }

    // Turns a 32-byte X25519 scalar into a NON-extractable private key plus its public key
    // (base64url). withSealed: the identity also gets its sealed form (sealIdentity), made from
    // the same moment of extractability, for a browser that cannot keep the key itself. The
    // caller wipes the seed.
    async function x25519FromSeed(seed, withSealed) {
        const pkcs8 = concat(PKCS8_X25519_PREFIX, seed);
        try {
            // Extractable only long enough to read the public coordinate (x) and, for the
            // identity, to wrap it
            const temp = await subtle.importKey('pkcs8', pkcs8, X25519, true, ['deriveBits']);
            const jwk = await subtle.exportKey('jwk', temp);
            const publicKey = jwk.x;
            jwk.d = '';
            b64urlDecode(publicKey, KEY_BYTES);
            const privateKey = await subtle.importKey('pkcs8', pkcs8, X25519, false, ['deriveBits']);
            if (withSealed !== true) {
                return { privateKey: privateKey, publicKey: publicKey };
            }
            return { privateKey: privateKey, publicKey: publicKey, sealed: await sealIdentity(temp, publicKey) };
        } finally {
            wipe(pkcs8);
        }
    }

    // Returns a NON-extractable private key plus the public key (base64url); withSealed adds the
    // sealed form (x25519FromSeed), which only a session kept by an engine that cannot keep the
    // key itself needs (Keystore.keepsKeys)
    async function deriveIdentity(accountNumber, withSealed) {
        const raw = accountBytes(accountNumber);
        let seed = null;
        try {
            seed = await hkdf(raw, encoder.encode(SALT), INFO_IDENTITY, KEY_BYTES);
            return await x25519FromSeed(seed, withSealed);
        } finally {
            wipe(raw);
            wipe(seed);
        }
    }

    // ---------- sealed identity ----------
    // Some engines (WebKit, Nov 2026) store an X25519 CryptoKey in IndexedDB without error and
    // cannot read it back, while AES keys round-trip (Keystore.keepsKeys finds out by trying a
    // throwawayKey). Only for them is the sealed form made at all, and the identity kept sealed: its
    // PKCS#8 wrapped under a non-extractable AES-256-GCM device key that may only wrap and unwrap,
    // opened at load straight into a non-extractable key. The honest path never shows the private
    // key to script, but script running in this origin could unwrap an extractable copy, which it
    // cannot do with a kept CryptoKey (docs/security/threat-model.md).

    function sealAAD(publicKey) {
        return concat(SEAL_MAGIC, [SEAL_VERSION], b64urlDecode(publicKey, KEY_BYTES));
    }

    function sealParams(iv, publicKey) {
        return { name: 'AES-GCM', iv: iv, additionalData: sealAAD(publicKey), tagLength: TAG_BITS };
    }

    // { deviceKey, iv, wrapped } for temp, the identity key while it is extractable
    async function sealIdentity(temp, publicKey) {
        const deviceKey = await subtle.generateKey({ name: 'AES-GCM', length: KEY_BITS }, false, ['wrapKey', 'unwrapKey']);
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
        const wrapped = new Uint8Array(await subtle.wrapKey('pkcs8', temp, deviceKey, sealParams(iv, publicKey)));
        return Object.freeze({ deviceKey: deviceKey, iv: iv, wrapped: wrapped });
    }

    // A non-extractable X25519 private key that protects nothing: Keystore stores and reads one
    // back to learn whether this engine keeps such keys, before any identity is derived
    async function throwawayKey() {
        return (await subtle.generateKey(X25519, false, ['deriveBits'])).privateKey;
    }

    // Whether key came back from storage as the kind throwawayKey makes (WebKit gives back null)
    function isThrowawayKey(key) {
        return typeof CryptoKey !== 'undefined' && key instanceof CryptoKey && key.type === 'private' &&
            !key.extractable && key.algorithm.name === X25519.name;
    }

    function isDeviceKey(key) {
        return typeof CryptoKey !== 'undefined' && key instanceof CryptoKey && !key.extractable &&
            key.algorithm.name === 'AES-GCM' && key.usages.includes('unwrapKey');
    }

    // The non-extractable identity key a stored sealed form opens to. Rejects anything that is not
    // exactly a sealed identity of publicKey: a malformed record, another identity's blob.
    async function unsealIdentity(sealed, publicKey) {
        if (!sealed || typeof sealed !== 'object' || !isDeviceKey(sealed.deviceKey) ||
            !(sealed.iv instanceof Uint8Array) || sealed.iv.length !== NONCE_BYTES ||
            !(sealed.wrapped instanceof Uint8Array) || sealed.wrapped.length !== SEALED_IDENTITY_BYTES) {
            throw new Error('invalid sealed identity');
        }
        return subtle.unwrapKey('pkcs8', sealed.wrapped, sealed.deviceKey, sealParams(sealed.iv, publicKey),
            X25519, false, ['deriveBits']);
    }

    async function conversationKey(privateKey, peerPublicKey, conversationId) {
        const peer = await subtle.importKey('raw', b64urlDecode(peerPublicKey, KEY_BYTES), X25519, false, []);
        const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, KEY_BITS));
        try {
            const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
            return await subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: uuidBytes(conversationId), info: encoder.encode(INFO_CONVERSATION) },
                base,
                { name: 'AES-GCM', length: KEY_BITS },
                false,
                ['encrypt', 'decrypt']
            );
        } finally {
            wipe(shared);
        }
    }

    // ---------- messages ----------

    // AAD = "NADM" || v1 || conversation(16) || message(16) || SHA-256(sender public key)(32)
    async function messageAAD(conversationId, messageId, senderPublicKey) {
        const senderTag = await sha256(b64urlDecode(senderPublicKey, KEY_BYTES));
        return concat(new Uint8Array(AAD_MAGIC), new Uint8Array([AAD_VERSION]),
            uuidBytes(conversationId), uuidBytes(messageId), senderTag);
    }

    function frame(payloadBytes) {
        if (payloadBytes.length === 0 || payloadBytes.length > MAX_PAYLOAD_BYTES) {
            throw new Error('message too long');
        }
        let size = PAD_BLOCK;
        while (size < payloadBytes.length + FRAME_LENGTH_BYTES) {
            size *= 2;
        }
        const out = new Uint8Array(size);
        // The length is a big-endian uint16
        out[0] = payloadBytes.length >> 8;
        out[1] = payloadBytes.length & 0xff;
        out.set(payloadBytes, FRAME_LENGTH_BYTES);
        return out;
    }

    // Opens any multiple of PAD_BLOCK, so frames written before the power-of-two sizes
    // (payloads up to 6000 bytes) stay readable
    function unframe(framed) {
        if (framed.length < FRAME_LENGTH_BYTES || framed.length % PAD_BLOCK !== 0) {
            throw new Error('bad frame');
        }
        const length = (framed[0] << 8) | framed[1];
        if (length === 0 || length + FRAME_LENGTH_BYTES > framed.length) {
            throw new Error('bad frame');
        }
        for (let i = length + FRAME_LENGTH_BYTES; i < framed.length; i++) {
            if (framed[i] !== 0) {
                throw new Error('bad frame');
            }
        }
        return framed.subarray(FRAME_LENGTH_BYTES, FRAME_LENGTH_BYTES + length);
    }

    const MAX_COUNTER = Number.MAX_SAFE_INTEGER;

    // The wire form of a file description ({ id, key, size, hash, name }), checked: an invalid one
    // is never written
    function fileWire(file) {
        const wire = { i: file.id, k: file.key, s: file.size, h: file.hash, n: file.name };
        if (!fileFrom(wire)) {
            throw new Error('invalid file');
        }
        return wire;
    }

    // The file description an "f" value gives ({ id, key, size, hash, name }), or null: exactly the
    // five fields, each of its shape and range. The name rule is validation.js's isFileName (the
    // one home of it); without that rule loaded nothing is accepted.
    function fileFrom(raw) {
        if (raw === null || typeof raw !== 'object' || Array.isArray(raw) ||
            Object.keys(raw).length !== FILE_FIELDS.length ||
            !FILE_FIELDS.every(key => Object.prototype.hasOwnProperty.call(raw, key))) {
            return null;
        }
        if (!UUID_V4_RE.test(raw.i) || !isEncoded(raw.k, KEY_BYTES) || !isEncoded(raw.h, FILE_HASH_BYTES) ||
            !Number.isSafeInteger(raw.s) || raw.s < 1 || raw.s > MAX_FILE_BYTES_BOUND ||
            typeof isFileName !== 'function' || !isFileName(raw.n)) {
            return null;
        }
        return Object.freeze({ id: raw.i, key: raw.k, size: raw.s, hash: raw.h, name: raw.n });
    }

    function isEncoded(text, bytes) {
        try {
            b64urlDecode(text, bytes);
            return true;
        } catch (e) {
            return false;
        }
    }

    function payloadBytes({ text, sentAt, counter, file }) {
        const payload = { t: text, ts: sentAt, n: counter };
        if (file) payload[FILE_KEY] = fileWire(file);
        return encoder.encode(JSON.stringify(payload));
    }

    // The framed payload both conversation kinds encrypt: { text, sentAt, counter, file? }
    function encodePayload({ text, sentAt, counter, file }) {
        if (!Number.isSafeInteger(counter) || counter < 1 || typeof text !== 'string') {
            throw new Error('invalid payload');
        }
        return frame(payloadBytes({ text, sentAt, counter, file }));
    }

    // Accepts exactly {t, ts, n} or exactly {t, ts, n, f} with a valid f; the caller wipes
    // `plain`. A well-formed frame holding an object with valid t, ts and n plus keys this build
    // does not know was written by a newer elyrn: it throws a NEWER_PAYLOAD error
    // (isNewerPayload); anything else that fails, an invalid f included, throws 'bad payload'.
    // Returns { text, sentAt, counter, file } (file null when there is none).
    function decodePayload(plain) {
        const parsed = JSON.parse(decoder.decode(unframe(plain)));
        const has = (key) => Object.prototype.hasOwnProperty.call(parsed, key);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || !PAYLOAD_KEYS.every(has) ||
            typeof parsed.t !== 'string' || !Number.isSafeInteger(parsed.ts) || parsed.ts <= 0 ||
            !Number.isSafeInteger(parsed.n) || parsed.n < 1 || parsed.n > MAX_COUNTER) {
            throw new Error('bad payload');
        }
        if (Object.keys(parsed).some(key => !KNOWN_KEYS.includes(key))) {
            const newer = new Error('payload from a newer elyrn');
            newer.name = NEWER_PAYLOAD;
            throw newer;
        }
        const file = has(FILE_KEY) ? fileFrom(parsed[FILE_KEY]) : null;
        if (has(FILE_KEY) && !file) {
            throw new Error('bad payload');
        }
        return { text: parsed.t, sentAt: parsed.ts, counter: parsed.n, file: file };
    }

    // Whether error is decodePayload's verdict on a payload a newer elyrn wrote
    function isNewerPayload(error) {
        return error instanceof Error && error.name === NEWER_PAYLOAD;
    }

    async function encryptMessage({ key, conversationId, messageId, senderPublicKey, text, sentAt, counter, file }) {
        const plain = encodePayload({ text, sentAt, counter, file });
        const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
        try {
            const aad = await messageAAD(conversationId, messageId, senderPublicKey);
            const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: TAG_BITS }, key, plain));
            return b64urlEncode(concat(nonce, sealed));
        } finally {
            wipe(plain);
        }
    }

    // Throws on any tampering (wrong conversation, message id, sender, or modified bytes)
    async function decryptMessage({ key, conversationId, messageId, senderPublicKey, ciphertext }) {
        const data = b64urlDecode(ciphertext);
        if (data.length < NONCE_BYTES + TAG_BYTES + PAD_BLOCK) {
            throw new Error('ciphertext too short');
        }
        const aad = await messageAAD(conversationId, messageId, senderPublicKey);
        const plain = new Uint8Array(await subtle.decrypt(
            { name: 'AES-GCM', iv: data.subarray(0, NONCE_BYTES), additionalData: aad, tagLength: TAG_BITS },
            key,
            data.subarray(NONCE_BYTES)
        ));
        try {
            return decodePayload(plain);
        } finally {
            wipe(plain);
        }
    }

    // Whether text (with a file named fileName, if given) fits one frame at the longest ts, counter
    // and file size; the file's id, key and hash have fixed lengths
    function payloadFits({ text, fileName }) {
        const file = fileName === undefined ? null : {
            id: '00000000-0000-4000-8000-000000000000', key: b64urlEncode(new Uint8Array(KEY_BYTES)),
            size: MAX_FILE_BYTES_BOUND, hash: b64urlEncode(new Uint8Array(FILE_HASH_BYTES)), name: fileName
        };
        try {
            return payloadBytes({ text, sentAt: Date.now(), counter: MAX_COUNTER, file }).length <= MAX_PAYLOAD_BYTES;
        } catch (e) {
            return false;
        }
    }

    // ---------- pairing & verification ----------

    // Bound to the token so two invites from the same person share no bytes (unlinkable)
    async function inviteFingerprint(token, publicKey) {
        const digest = await sha256(concat(encoder.encode(INFO_INVITE_FP),
            b64urlDecode(token, INVITE_TOKEN_BYTES), b64urlDecode(publicKey, KEY_BYTES)));
        return digest.subarray(0, INVITE_FP_BYTES);
    }

    // Invite code = "elyrn:" + base64url(token(16) || SHA-256("noaddx/invite-fp" || token || creator key)[0:16]).
    // The fingerprint never goes to the server; it lets the redeemer detect key substitution.
    async function buildInviteCode(token, creatorPublicKey) {
        const fp = await inviteFingerprint(token, creatorPublicKey);
        return INVITE_PREFIX + b64urlEncode(concat(b64urlDecode(token, INVITE_TOKEN_BYTES), fp));
    }

    // codeBody returns what follows the first of prefixes that text starts with, or null.
    function codeBody(text, prefixes) {
        const prefix = prefixes.find((p) => text.startsWith(p));
        return prefix === undefined ? null : text.slice(prefix.length);
    }

    function parseInviteCode(code) {
        const body = codeBody(String(code || '').trim(), INVITE_PREFIXES);
        if (body === null) {
            throw new Error('not an invite');
        }
        const raw = b64urlDecode(body, INVITE_TOKEN_BYTES + INVITE_FP_BYTES);
        return {
            token: b64urlEncode(raw.subarray(0, INVITE_TOKEN_BYTES)),
            fingerprint: raw.slice(INVITE_TOKEN_BYTES)
        };
    }

    async function fingerprintMatches(invite, publicKey) {
        const fingerprint = invite.fingerprint;
        const actual = await inviteFingerprint(invite.token, publicKey);
        let diff = actual.length ^ fingerprint.length;
        for (let i = 0; i < actual.length && i < fingerprint.length; i++) {
            diff |= actual[i] ^ fingerprint[i];
        }
        return diff === 0;
    }

    // Order-independent: both peers compute the same 30 digits
    async function safetyNumber(publicKeyA, publicKeyB) {
        const [first, second] = [publicKeyA, publicKeyB].sort();
        return digitGroups(await sha256(concat(b64urlDecode(first, KEY_BYTES), b64urlDecode(second, KEY_BYTES))));
    }

    // Six groups of five digits from the first 30 bytes of a digest
    function digitGroups(digest) {
        const groups = [];
        for (let g = 0; g < SAFETY_GROUPS; g++) {
            let value = 0;
            for (let i = 0; i < SAFETY_GROUP_BYTES; i++) {
                // the group's bytes as one big-endian number
                value = value * 256 + digest[g * SAFETY_GROUP_BYTES + i];
            }
            groups.push(String(value % 10 ** SAFETY_GROUP_DIGITS).padStart(SAFETY_GROUP_DIGITS, '0'));
        }
        return groups;
    }

    // ---------- aura (local, key-derived display identity) ----------

    const AURA_ADJECTIVES = [
        'silent', 'hollow', 'velvet', 'ashen', 'lunar', 'feral', 'gilded', 'frozen',
        'quiet', 'hidden', 'solar', 'obsidian', 'pale', 'wild', 'ivory', 'misty',
        'stark', 'radiant', 'sable', 'cinder', 'distant', 'faded', 'gentle', 'hushed',
        'iron', 'jade', 'kindred', 'lucid', 'mellow', 'nimble', 'opal', 'polar',
        'quartz', 'rusted', 'saffron', 'tidal', 'umbral', 'vivid', 'woven', 'zephyr',
        'amber', 'briar', 'cobalt', 'dusk', 'eerie', 'frost', 'ghost', 'hazel',
        'indigo', 'jasper', 'karst', 'lilac', 'marble', 'neon', 'onyx', 'prism',
        'quill', 'raven', 'slate', 'thorn', 'ultra', 'vesper', 'winter', 'xenon'
    ];
    const AURA_NOUNS = [
        'ember', 'fox', 'moth', 'wren', 'lynx', 'comet', 'echo', 'harbor',
        'iris', 'kite', 'lotus', 'mist', 'nova', 'orbit', 'pike', 'quasar',
        'reef', 'sage', 'tide', 'umbra', 'vale', 'willow', 'yarrow', 'zenith',
        'atlas', 'bloom', 'crane', 'delta', 'ether', 'fern', 'glade', 'heron',
        'isle', 'jackal', 'koi', 'lark', 'mesa', 'nomad', 'oak', 'petal',
        'quail', 'river', 'spire', 'thistle', 'urchin', 'viper', 'wolf', 'yew',
        'aspen', 'birch', 'cedar', 'dune', 'elk', 'flint', 'grove', 'hawk',
        'ibis', 'juniper', 'kestrel', 'lichen', 'marsh', 'newt', 'owl', 'pine'
    ];

    // { name: "silent-ember", code: "7f3a", grid: 5x5 booleans (mirrored) }
    async function aura(publicKey) {
        const digest = await sha256(concat(encoder.encode(INFO_AURA), b64urlDecode(publicKey, KEY_BYTES)));
        const grid = [];
        let bit = 0;
        for (let row = 0; row < AURA_GRID_SIZE; row++) {
            const cells = new Array(AURA_GRID_SIZE);
            for (let col = 0; col < AURA_DRAWN_COLUMNS; col++) {
                // bit `bit` of the grid bits, least significant first within each byte
                const byte = digest[AURA_GRID_OFFSET + (bit >> 3)];
                cells[col] = ((byte >> (bit & 7)) & 1) === 1;
                cells[AURA_GRID_SIZE - 1 - col] = cells[col];
                bit++;
            }
            grid.push(cells);
        }
        const code = Array.from(digest.subarray(AURA_CODE_OFFSET, AURA_GRID_OFFSET), b => b.toString(16).padStart(2, '0')).join('');
        return {
            name: AURA_ADJECTIVES[digest[0] % AURA_ADJECTIVES.length] + '-' + AURA_NOUNS[digest[1] % AURA_NOUNS.length],
            code: code,
            grid: grid
        };
    }

    // ---------- capability check ----------

    async function isSupported() {
        if (!subtle || !globalThis.crypto.randomUUID) {
            return false;
        }
        try {
            await subtle.generateKey(X25519, false, ['deriveBits']);
            return true;
        } catch (e) {
            return false;
        }
    }

    function newMessageId() {
        return globalThis.crypto.randomUUID();
    }

    return Object.freeze({
        BITS_PER_BYTE,
        KEY_BYTES,
        NONCE_BYTES,
        TAG_BYTES,
        UUID_BYTES,
        PAD_BLOCK,
        MAX_FRAME_BYTES,
        MAX_FILE_BYTES_BOUND,
        INVITE_PREFIX,
        INVITE_PREFIXES,
        // base64 spends four characters per three bytes
        INVITE_BODY_CHARS: Math.ceil((INVITE_TOKEN_BYTES + INVITE_FP_BYTES) * 4 / 3),
        AURA_GRID_SIZE,
        codeBody,
        b64urlDecode,
        b64urlEncode,
        uuidBytes,
        concat,
        sha256,
        wipe,
        x25519FromSeed,
        encodePayload,
        decodePayload,
        isNewerPayload,
        digitGroups,
        deriveAuthKey,
        deriveIdentity,
        unsealIdentity,
        throwawayKey,
        isThrowawayKey,
        conversationKey,
        encryptMessage,
        decryptMessage,
        payloadFits,
        buildInviteCode,
        parseInviteCode,
        fingerprintMatches,
        safetyNumber,
        aura,
        isSupported,
        newMessageId,
        isUuidV4: (id) => typeof id === 'string' && UUID_V4_RE.test(id)
    });
})();
