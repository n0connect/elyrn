// Fuzz: frontend/js/file-crypto.js, loaded as the browser loads it. A served part, mutated at
// random, served at a random place, for a random file id, conversation or length, opens to the
// genuine bytes or not at all; nothing that did not open is ever written into the file's buffer.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load } from './fuzz-helpers.mjs';

const SEED = 0x5eed0010;
const ITERATIONS = 150;
const PART = 262144;
// File sizes drawn: up to three parts, often near a part boundary
const MAX_PARTS_DRAWN = 3;
const NEAR_BOUNDARY = 3;

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../js/file-crypto.js', '../validation.js']);
const C = get('ElyrnCrypto');
const F = get('ElyrnFileCrypto');
const CONV = '3b241101-e2bb-4255-8caf-4136c566a962';

function drawSize(r) {
    const parts = r.int(1, MAX_PARTS_DRAWN);
    return r.bool(0.5) ? Math.max(1, (parts - 1) * PART + r.int(-NEAR_BOUNDARY, NEAR_BOUNDARY)) : r.int(1, parts * PART);
}

test('file parts: a mutated or misplaced part opens to the genuine bytes or not at all', async () => {
    await fuzz(SEED, ITERATIONS, async (r) => {
        const size = drawSize(r);
        const bytes = r.bytes(size);
        const { id, key } = F.newFile();
        const file = { id, key, size, hash: await F.hashOf(bytes), name: 'x' };
        const index = r.int(0, F.partCount(size) - 1);
        const genuine = await F.sealPart({ conversationId: CONV, file, bytes, index });
        // One of: a mutated part, another place, another file, another conversation, another length
        let data = genuine;
        let at = { conversationId: CONV, file, index };
        const kind = r.int(0, 4);
        if (kind === 0) {
            const raw = C.b64urlDecode(genuine);
            raw[r.int(0, raw.length - 1)] ^= 1 << r.int(0, 7);
            data = r.bool(0.2) ? r.mutate(genuine) : C.b64urlEncode(raw);
        } else if (kind === 1) {
            at = { ...at, index: r.int(0, F.partCount(size)) };
        } else if (kind === 2) {
            at = { ...at, file: { ...file, id: C.newMessageId() } };
        } else if (kind === 3) {
            at = { ...at, conversationId: C.newMessageId() };
        } else {
            const other = Math.max(1, size + r.int(-PART, PART));
            at = { ...at, file: { ...file, size: other } };
        }
        const into = new Uint8Array(at.file.size);
        let opened = true;
        try {
            await F.openPart({ ...at, data, into });
        } catch (error) {
            opened = false;
        }
        const same = data === genuine && at.index === index && at.file.id === file.id && at.conversationId === CONV &&
            F.partCount(at.file.size) === F.partCount(size) && at.file.size >= Math.min(size, (index + 1) * PART);
        if (opened) {
            assert.ok(same || (data === genuine && at.file.size < size && F.partCount(at.file.size) === F.partCount(size) &&
                bytes.subarray(at.file.size, Math.min(size, (index + 1) * PART)).every((b) => b === 0)), `opened kind ${kind}`);
            const start = index * PART;
            // Only the genuine bytes are written; a longer declared size reads zeros past them,
            // which the whole file's hash refuses later (FileTransfer.download)
            const end = Math.min(at.file.size, size, start + PART);
            assert.deepEqual(into.subarray(start, end), bytes.subarray(start, end));
        } else {
            assert.ok(into.every((b) => b === 0), 'a part that did not open wrote bytes');
            if (same && at.file.size === size) assert.fail('the genuine part did not open');
        }
    });
});
