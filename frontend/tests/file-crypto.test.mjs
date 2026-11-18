// frontend/js/file-crypto.js, loaded as the browser loads it (after crypto.js), with the shared
// constants read from the Go sources. Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load } from './fuzz-helpers.mjs';

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../js/file-crypto.js', '../validation.js']);
const C = get('ElyrnCrypto');
const F = get('ElyrnFileCrypto');
const goSource = (path) => readFileSync(new URL('../../backend/' + path, import.meta.url), 'utf8');

const CONV = '3b241101-e2bb-4255-8caf-4136c566a962';
const OTHER_CONV = '9b2c1101-e2bb-4255-8caf-4136c566a962';
const PART = 262144;

// A file of size bytes with recognisable content, its description and its sealed parts
async function sealed(size, conversationId = CONV) {
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) bytes[i] = (i * 31 + 7) & 0xff;
    const { id, key } = F.newFile();
    const file = { id, key, size, hash: await F.hashOf(bytes), name: 'f.bin' };
    const parts = [];
    for (let index = 0; index < F.partCount(size); index++) {
        parts.push(await F.sealPart({ conversationId, file, bytes, index }));
    }
    return { bytes, file, parts };
}

// Opens every part into a fresh buffer: the file's bytes when everything verifies
async function openAll({ file, parts, conversationId = CONV }) {
    const into = new Uint8Array(file.size);
    for (let index = 0; index < parts.length; index++) {
        await F.openPart({ conversationId, file, index, data: parts[index], into });
    }
    if (!(await F.matches(file, into))) throw new Error('hash mismatch');
    return into;
}

test('the part size and the size bound are the Go side\'s own', () => {
    const utils = goSource('internal/utils/validation.go');
    const config = goSource('internal/config/config.go');
    const shift = (source, name) => {
        const found = source.match(new RegExp(`${name}\\s+(?:int64\\s+)?=\\s+(\\d+)\\s*<<\\s*(\\d+)`));
        assert.ok(found, `${name} moved or changed form`);
        return Number(found[1]) * 2 ** Number(found[2]);
    };
    assert.equal(F.FILE_PART_BYTES, shift(utils, 'FilePartBytes'));
    assert.equal(F.FILE_PART_BYTES, PART);
    assert.equal(C.MAX_FILE_BYTES_BOUND, shift(config, 'MaxFileBytesBound'));
    assert.equal(F.SEALED_PART_BYTES, PART + 16);
    assert.equal(F.SEALED_PART_CHARS, 349547);
    assert.equal(F.MAX_PARTS, 400);
    // The name bounds are the Go rule's
    const file = goSource('internal/e2e/file.go');
    assert.match(file, /FileNameMaxChars = 128\b/);
    assert.match(file, /fileNameMaxBytes = 512\b/);
    assert.equal(get('MAX_FILE_NAME_CHARS'), 128);
    assert.equal(get('MAX_FILE_NAME_BYTES'), 512);
});

test('files of every shape round-trip: one byte, a part less one, a whole part, a part and one, several parts', async () => {
    for (const size of [1, 19, PART - 1, PART, PART + 1, 3 * PART + 5]) {
        const one = await sealed(size);
        assert.equal(one.parts.length, Math.ceil(size / PART));
        for (const part of one.parts) assert.equal(part.length, F.SEALED_PART_CHARS);
        assert.deepEqual(await openAll(one), one.bytes, String(size));
    }
});

test('part count and sizes outside the bound are refused', () => {
    assert.equal(F.partCount(1), 1);
    assert.equal(F.partCount(PART), 1);
    assert.equal(F.partCount(PART + 1), 2);
    assert.equal(F.partCount(C.MAX_FILE_BYTES_BOUND), F.MAX_PARTS);
    for (const size of [0, -1, 1.5, C.MAX_FILE_BYTES_BOUND + 1, '5', NaN, undefined]) {
        assert.throws(() => F.partCount(size), String(size));
    }
});

test('a part opens only in its own place, file, conversation and length', async () => {
    const one = await sealed(2 * PART + 3);
    const into = () => new Uint8Array(one.file.size);
    const open = (over) => F.openPart({ conversationId: CONV, file: one.file, index: 0, data: one.parts[0], into: into(), ...over });
    await open({});
    // Reordered or duplicated parts: part 1 served as part 0, part 0 as part 2
    await assert.rejects(open({ data: one.parts[1] }));
    await assert.rejects(open({ index: 2 }));
    // Another conversation, another file id, another key, another length (part count)
    await assert.rejects(open({ conversationId: OTHER_CONV }));
    await assert.rejects(open({ file: { ...one.file, id: C.newMessageId() } }));
    await assert.rejects(open({ file: { ...one.file, key: F.newFile().key } }));
    await assert.rejects(open({ file: { ...one.file, size: 3 * PART + 3 }, into: new Uint8Array(3 * PART + 3) }));
    // An index past the file, a buffer of another length
    await assert.rejects(open({ index: 3 }));
    await assert.rejects(open({ index: -1 }));
    await assert.rejects(open({ into: new Uint8Array(5) }));
});

test('an altered or truncated part never opens; neither does one sealed for a shorter file (padding)', async () => {
    const one = await sealed(PART + 10);
    const raw = C.b64urlDecode(one.parts[1]);
    for (const at of [0, 9, 10, 4000, raw.length - 17, raw.length - 1]) {
        const altered = raw.slice();
        altered[at] ^= 1;
        await assert.rejects(F.openPart({ conversationId: CONV, file: one.file, index: 1, data: C.b64urlEncode(altered), into: new Uint8Array(one.file.size) }), String(at));
    }
    for (const data of [one.parts[1].slice(1), one.parts[1] + 'A', '', C.b64urlEncode(raw.subarray(0, raw.length - 16))]) {
        await assert.rejects(F.openPart({ conversationId: CONV, file: one.file, index: 1, data, into: new Uint8Array(one.file.size) }));
    }
    // A sender that declares fewer bytes than it sealed: the extra bytes are padding that is not zero
    const longer = await sealed(PART + 20);
    const shorter = { ...longer.file, size: PART + 10 };
    await assert.rejects(F.openPart({ conversationId: CONV, file: shorter, index: 1, data: longer.parts[1], into: new Uint8Array(shorter.size) }));
});

test('a declared hash that disagrees with the bytes is caught', async () => {
    const one = await sealed(100);
    const other = await sealed(100);
    await assert.rejects(openAll({ ...one, file: { ...one.file, hash: other.file.hash } }));
    assert.equal(await F.matches(one.file, one.bytes), true);
    const flipped = one.bytes.slice();
    flipped[0] ^= 1;
    assert.equal(await F.matches(one.file, flipped), false);
});

test('each file gets a fresh id and key; sealing refuses bytes that are not the declared file', async () => {
    const a = F.newFile();
    const b = F.newFile();
    assert.notEqual(a.id, b.id);
    assert.notEqual(a.key, b.key);
    assert.equal(C.isUuidV4(a.id), true);
    assert.equal(C.b64urlDecode(a.key, 32).length, 32);
    const one = await sealed(10);
    await assert.rejects(F.sealPart({ conversationId: CONV, file: one.file, bytes: new Uint8Array(11), index: 0 }));
    await assert.rejects(F.sealPart({ conversationId: CONV, file: one.file, bytes: [1, 2], index: 0 }));
    await assert.rejects(F.sealPart({ conversationId: CONV, file: one.file, bytes: one.bytes, index: 1 }));
});
