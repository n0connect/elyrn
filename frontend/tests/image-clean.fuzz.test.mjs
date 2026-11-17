// Fuzz: frontend/js/image-clean.js reads the first bytes of whatever a user chooses or a peer
// sends: recognition and header reading are total (never throw, never loop) on any bytes, and a
// size read is always whole and non-negative. Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load } from './fuzz-helpers.mjs';

const SEED = 0x5eed0011;
const ITERATIONS = 5000;
const MAX_LENGTH = 96;
const KINDS = ['png', 'jpeg', 'webp'];
const PREFIXES = [
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [0xff, 0xd8, 0xff], [0x52, 0x49, 0x46, 0x46, 1, 2, 3, 4, 0x57, 0x45, 0x42, 0x50]
];

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js', '../js/image-clean.js']);
const I = get('ImageClean');

test('image recognition and header reading are total on any bytes', async () => {
    await fuzz(SEED, ITERATIONS, (r) => {
        const tail = r.bytes(r.int(0, MAX_LENGTH));
        const bytes = r.bool(0.7) ? Uint8Array.from([...r.pick(PREFIXES), ...tail]) : tail;
        const kind = I.kindOf(bytes);
        assert.ok(kind === null || KINDS.includes(kind));
        for (const asked of KINDS) {
            const size = I.declaredSize(bytes, asked);
            if (size !== null) {
                assert.ok(Number.isSafeInteger(size.width) && size.width >= 0, JSON.stringify(size));
                assert.ok(Number.isSafeInteger(size.height) && size.height >= 0, JSON.stringify(size));
            }
        }
    });
});
