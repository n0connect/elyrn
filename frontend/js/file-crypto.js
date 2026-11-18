// ========================================
// ELYRN FILE CRYPTO (WebCrypto only — no third-party code)
// ========================================
// A file is sealed as equal parts (docs/architecture/files.md, docs/security/cryptography.md):
//
//   fk  = 32 random bytes (the file key), file id = a random UUIDv4
//   K_i = HKDF-SHA256(fk, salt = file id (16), info = "noaddx/file/part/v1" || u32be(i) || u32be(parts), 32)
//   P_i = the file's bytes [i * FILE_PART_BYTES, (i + 1) * FILE_PART_BYTES), the last zero-padded
//   part_i = AES-256-GCM(K_i, nonce 0^12, P_i, AAD = "NADF" || 0x01 || conversation id (16) ||
//            file id (16) || u32be(i) || u32be(parts))
//   h   = SHA-256 of the file's bytes
//
// Each K_i seals exactly one plaintext, hence the zero nonce. Binding the index and the count
// into both the key and the AAD means no part opens in another place, another file, another
// conversation or a file of another length. Opening checks the padding is zero; the whole file
// must hash to h. The file key travels only inside the encrypted message that announces the file.

const ElyrnFileCrypto = (() => {
    'use strict';

    const C = ElyrnCrypto;
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    const encoder = new TextEncoder();

    // Plaintext per part (backend/internal/utils FilePartBytes): the server learns a file's size
    // only in steps of this
    const FILE_PART_BYTES = 262144;
    const SEALED_PART_BYTES = FILE_PART_BYTES + C.TAG_BYTES;
    // base64 spends four characters per three bytes
    const SEALED_PART_CHARS = Math.ceil(SEALED_PART_BYTES * 4 / 3);
    const MAX_PARTS = Math.ceil(C.MAX_FILE_BYTES_BOUND / FILE_PART_BYTES);
    const KEY_BYTES = C.KEY_BYTES;
    const KEY_BITS = KEY_BYTES * 8;
    const TAG_BITS = C.TAG_BYTES * 8;
    const U32_BYTES = 4;
    const VERSION = 0x01;
    // "noaddx" in these labels is the protocol namespace, not the product name: it never changes.
    const INFO_PART = encoder.encode('noaddx/file/part/v1');
    const MAGIC_PART = encoder.encode('NADF');
    const ZERO_NONCE = new Uint8Array(C.NONCE_BYTES);

    // Realm-independent (bytes from another frame or a test context are still bytes)
    function isBytes(value, length) {
        return Object.prototype.toString.call(value) === '[object Uint8Array]' && value.length === length;
    }

    function u32be(value) {
        const out = new Uint8Array(U32_BYTES);
        new DataView(out.buffer).setUint32(0, value, false);
        return out;
    }

    // How many parts a file of size bytes takes (1..MAX_PARTS), or throws
    function partCount(size) {
        if (!Number.isSafeInteger(size) || size < 1 || size > C.MAX_FILE_BYTES_BOUND) {
            throw new Error('invalid file size');
        }
        return Math.ceil(size / FILE_PART_BYTES);
    }

    // A new file's id and key: { id, key (base64url) }
    function newFile() {
        const key = globalThis.crypto.getRandomValues(new Uint8Array(KEY_BYTES));
        try {
            return { id: C.newMessageId(), key: C.b64urlEncode(key) };
        } finally {
            C.wipe(key);
        }
    }

    // Checks one part's place: index below parts, parts as size gives it
    function place({ size, index }) {
        const parts = partCount(size);
        if (!Number.isSafeInteger(index) || index < 0 || index >= parts) {
            throw new Error('invalid part');
        }
        return parts;
    }

    async function partKey({ key, fileId, index, parts }) {
        const raw = C.b64urlDecode(key, KEY_BYTES);
        try {
            const base = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
            return await subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: C.uuidBytes(fileId), info: C.concat(INFO_PART, u32be(index), u32be(parts)) },
                base, { name: 'AES-GCM', length: KEY_BITS }, false, ['encrypt', 'decrypt']);
        } finally {
            C.wipe(raw);
        }
    }

    function partAAD({ conversationId, fileId, index, parts }) {
        return C.concat(MAGIC_PART, new Uint8Array([VERSION]), C.uuidBytes(conversationId), C.uuidBytes(fileId),
            u32be(index), u32be(parts));
    }

    // The bytes of part index of a file held in bytes (a view, never a copy)
    function partOf(bytes, index) {
        return bytes.subarray(index * FILE_PART_BYTES, Math.min(bytes.length, (index + 1) * FILE_PART_BYTES));
    }

    // Seals part index of the file whose bytes are `bytes` (the whole file, size bytes long):
    // the sealed part as base64url, SEALED_PART_CHARS long
    async function sealPart({ conversationId, file, bytes, index }) {
        if (!isBytes(bytes, file.size)) {
            throw new Error('invalid file bytes');
        }
        const parts = place({ size: file.size, index });
        const plain = new Uint8Array(FILE_PART_BYTES);
        plain.set(partOf(bytes, index));
        try {
            const k = await partKey({ key: file.key, fileId: file.id, index, parts });
            const sealed = new Uint8Array(await subtle.encrypt(
                { name: 'AES-GCM', iv: ZERO_NONCE, additionalData: partAAD({ conversationId, fileId: file.id, index, parts }), tagLength: TAG_BITS },
                k, plain));
            return C.b64urlEncode(sealed);
        } finally {
            C.wipe(plain);
        }
    }

    // Opens part index of file and writes its real bytes into `into` (the whole file's buffer,
    // size bytes long) at their place. Throws unless the part is exactly one sealed part that
    // opens for this conversation, file, place and count, with every padding byte zero.
    async function openPart({ conversationId, file, index, data, into }) {
        const parts = place({ size: file.size, index });
        if (!isBytes(into, file.size)) {
            throw new Error('invalid file buffer');
        }
        const sealed = C.b64urlDecode(data, SEALED_PART_BYTES);
        const k = await partKey({ key: file.key, fileId: file.id, index, parts });
        const plain = new Uint8Array(await subtle.decrypt(
            { name: 'AES-GCM', iv: ZERO_NONCE, additionalData: partAAD({ conversationId, fileId: file.id, index, parts }), tagLength: TAG_BITS },
            k, sealed));
        try {
            const length = Math.min(FILE_PART_BYTES, file.size - index * FILE_PART_BYTES);
            for (let i = length; i < plain.length; i++) {
                if (plain[i] !== 0) throw new Error('bad padding');
            }
            into.set(plain.subarray(0, length), index * FILE_PART_BYTES);
        } finally {
            C.wipe(plain);
        }
    }

    // h: SHA-256 of the file's bytes, base64url
    async function hashOf(bytes) {
        return C.b64urlEncode(await C.sha256(bytes));
    }

    // Whether bytes hash to the file's h (compared without an early exit)
    async function matches(file, bytes) {
        const want = C.b64urlDecode(file.hash, KEY_BYTES);
        const got = await C.sha256(bytes);
        let diff = 0;
        for (let i = 0; i < KEY_BYTES; i++) diff |= want[i] ^ got[i];
        return diff === 0;
    }

    return Object.freeze({
        FILE_PART_BYTES,
        SEALED_PART_BYTES,
        SEALED_PART_CHARS,
        MAX_PARTS,
        partCount,
        newFile,
        sealPart,
        openPart,
        hashOf,
        matches
    });
})();
