// frontend/js/file-transfer.js against a real node:http server that keeps parts as the elyrn
// server does (negative-helpers.mjs), then misbehaves: lost answers, 429, 507, 503, 409 of every
// kind, 404, wrong sizes and shapes. The real modules are loaded as the browser loads them; the
// request function is utils.js apiCall itself. Run: node --test frontend/tests/*.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { load } from './fuzz-helpers.mjs';
import { startHostileServer, useServer, MARKUP } from './negative-helpers.mjs';

const { context, get } = load(
    { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, AbortSignal, DOMException, Response, setTimeout },
    ['../js/log.js', '../js/errors.js', '../js/utils.js', '../js/crypto.js', '../js/room-crypto.js', '../js/file-crypto.js',
        '../validation.js', '../js/file-transfer.js']);
const C = get('ElyrnCrypto');
const F = get('ElyrnFileCrypto');
const T = get('FileTransfer');
const Errors = get('Errors');
const CODES = Errors.CODES;
const apiCall = get('apiCall');
const CONV = '3b241101-e2bb-4255-8caf-4136c566a962';
const PART = F.FILE_PART_BYTES;
const never = () => false;

let server;
before(async () => {
    server = await startHostileServer();
    useServer(context, server.origin);
});
after(() => server.close());

const FILES = `/api/v2/conversations/${CONV}/files`;

// The server's part rules (docs/api/rest-api.md "Files"), kept in memory: 201 stored; 409
// "Conflict" for the same bytes again; 409 "Id taken" for other bytes; 409 "File part out of
// order" before part 0; 404 for a part not stored. `misbehave(seen, n)` may answer instead.
function behave(misbehave = () => null) {
    const parts = new Map();
    let n = 0;
    server.answer((seen) => {
        n++;
        const instead = misbehave(seen, n, parts);
        if (instead) return instead;
        if (seen.method === 'POST' && seen.path === FILES) {
            const { id, part, data } = JSON.parse(seen.body);
            const key = `${id}/${part}`;
            if (part > 0 && !parts.has(`${id}/0`)) return { status: 409, body: { success: false, message: 'File part out of order' } };
            if (parts.has(key)) {
                return parts.get(key) === data ? { status: 409, text: 'Conflict\n', type: 'text/plain' }
                    : { status: 409, body: { success: false, message: 'Id taken' } };
            }
            parts.set(key, data);
            return { status: 201, text: '', type: 'text/plain' };
        }
        const match = seen.path.match(/\/files\/([0-9a-f-]+)\?part=(\d+)$/);
        if (seen.method === 'GET' && match && parts.has(`${match[1]}/${match[2]}`)) {
            return { status: 200, body: { data: parts.get(`${match[1]}/${match[2]}`) } };
        }
        return { status: 404, text: 'Not found\n', type: 'text/plain' };
    });
    return parts;
}

async function newFile(size) {
    const bytes = new Uint8Array(size);
    for (let i = 0; i < size; i++) bytes[i] = (i * 13 + 1) & 0xff;
    const { id, key } = F.newFile();
    return { bytes, file: { id, key, size, hash: await F.hashOf(bytes), name: 'a.bin' } };
}

const upload = (one, over = {}) => T.upload({ api: apiCall, conversationId: CONV, file: one.file, bytes: one.bytes, cancelled: never, ...over });
const download = (file, over = {}) => T.download({ api: apiCall, conversationId: CONV, file, cancelled: never, ...over });

test('a behaving server: parts go up in order, each exactly one sealed part, and come back to the same bytes', async () => {
    const parts = behave();
    const one = await newFile(2 * PART + 7);
    const progress = [];
    const up = await upload(one, { onProgress: (p) => progress.push(`${p.done}/${p.total}`) });
    assert.equal(up.ok, true);
    assert.deepEqual(progress, ['1/3', '2/3', '3/3']);
    const posted = server.requests.filter((r) => r.method === 'POST').slice(-3).map((r) => JSON.parse(r.body));
    assert.deepEqual(posted.map((b) => b.part), [0, 1, 2]);
    for (const body of posted) {
        assert.deepEqual(Object.keys(body).sort(), ['data', 'id', 'part']);
        assert.equal(body.id, one.file.id);
        assert.equal(body.data.length, F.SEALED_PART_CHARS);
    }
    assert.equal(parts.size, 3);
    const down = await download(one.file);
    assert.equal(down.ok, true);
    assert.deepEqual(down.bytes, one.bytes);
});

test('lost answers are tried again; a part stored before its answer was lost counts as stored (409 Conflict)', async () => {
    let dropped = 0;
    behave((seen, n, parts) => {
        // Part 1's first answer is lost after the part was stored
        if (seen.method === 'POST' && JSON.parse(seen.body).part === 1 && dropped === 0) {
            dropped++;
            const body = JSON.parse(seen.body);
            parts.set(`${body.id}/1`, body.data);
            return { drop: true };
        }
        return null;
    });
    const one = await newFile(2 * PART);
    const up = await upload(one);
    assert.equal(up.ok, true);
    assert.equal(dropped, 1);
});

test('a server that never answers stops the upload where it stopped; the same file id continues there', async () => {
    let cut = true;
    behave((seen) => (cut && seen.method === 'POST' && JSON.parse(seen.body).part === 1 ? { drop: true } : null));
    const one = await newFile(3 * PART);
    const stopped = await upload(one);
    assert.deepEqual({ ok: stopped.ok, code: stopped.code, next: stopped.next, restart: stopped.restart },
        { ok: false, code: CODES.W_FILE_UPLOAD_STOPPED, next: 1, restart: false });
    cut = false;
    const before = server.requests.length;
    const resumed = await upload(one, { from: stopped.next });
    assert.equal(resumed.ok, true);
    assert.deepEqual(server.requests.slice(before).map((r) => JSON.parse(r.body).part), [1, 2]);
    assert.equal((await download(one.file)).ok, true);
});

test('every refusal has its code: budget, rate, quota, store, busy, gone, id taken, out of order, refused', async () => {
    const cases = [
        [{ status: 429, body: { success: false, message: 'File budget spent' } }, CODES.W_FILE_BUDGET_SPENT, false],
        [{ status: 429, text: 'Too many requests\n', type: 'text/plain' }, CODES.W_FILE_RATE_LIMITED, false],
        [{ status: 507, body: { success: false, message: 'File quota reached' } }, CODES.E_FILE_QUOTA_REACHED, false],
        [{ status: 507, body: { success: false, message: 'File store full' } }, CODES.E_FILE_STORE_FULL, false],
        [{ status: 507, body: { success: false, message: MARKUP[0] } }, CODES.E_FILE_STORE_FULL, false],
        [{ status: 503, text: 'Service unavailable\n', type: 'text/plain' }, CODES.W_FILE_SERVER_BUSY, false],
        [{ status: 404, text: 'Not found\n', type: 'text/plain' }, CODES.W_FILE_CONVERSATION_GONE, false],
        [{ status: 409, body: { success: false, message: 'Id taken' } }, CODES.E_FILE_UPLOAD_RESTART, true],
        [{ status: 409, body: { success: false, message: 'File part out of order' } }, CODES.E_FILE_UPLOAD_RESTART, true],
        [{ status: 400, text: 'Invalid request\n', type: 'text/plain' }, CODES.E_FILE_UPLOAD_REFUSED, false],
        [{ status: 413, body: { code: 'E_BODY_TOO_LARGE' } }, CODES.E_FILE_UPLOAD_REFUSED, false]
    ];
    for (const [answer, code, restart] of cases) {
        server.answer(() => answer);
        const one = await newFile(10);
        const out = await upload(one);
        assert.deepEqual({ ok: out.ok, code: out.code, next: out.next, restart: Boolean(out.restart) },
            { ok: false, code, next: 0, restart }, JSON.stringify(answer));
        assert.ok(Object.hasOwn(Errors.REGISTRY, out.code));
    }
    // A 401 ends quietly: chat.js has already ended the session
    server.answer(() => ({ status: 401, text: 'Unauthorized\n', type: 'text/plain' }));
    const quiet = await upload(await newFile(10));
    assert.equal(quiet.ok, false);
    assert.equal(quiet.quiet, true);
});

test('a cancelled upload stops between parts and never sends the rest', async () => {
    behave();
    const one = await newFile(3 * PART);
    let posts = 0;
    const out = await upload(one, { onProgress: () => { posts++; }, cancelled: () => posts >= 1 });
    assert.equal(out.ok, false);
    assert.equal(out.quiet, true);
    assert.equal(out.next, 1);
});

test('downloads: a missing part is gone; a malformed, misplaced or altered part, or a wrong hash, is unreadable', async () => {
    const parts = behave();
    const one = await newFile(2 * PART);
    assert.equal((await upload(one)).ok, true);
    const id = one.file.id;
    const keep = new Map(parts);
    const cases = [
        [() => parts.delete(`${id}/1`), CODES.W_FILE_GONE],
        [() => parts.set(`${id}/1`, keep.get(`${id}/0`)), CODES.E_FILE_UNREADABLE],
        [() => parts.set(`${id}/0`, keep.get(`${id}/0`).slice(1)), CODES.E_FILE_UNREADABLE],
        [() => parts.set(`${id}/0`, 'A'.repeat(F.SEALED_PART_CHARS)), CODES.E_FILE_UNREADABLE]
    ];
    for (const [spoil, code] of cases) {
        parts.clear();
        keep.forEach((v, k) => parts.set(k, v));
        spoil();
        const out = await download(one.file);
        assert.equal(out.ok, false);
        assert.equal(out.code, code);
        assert.equal(out.bytes, undefined);
    }
    parts.clear();
    keep.forEach((v, k) => parts.set(k, v));
    // A message that declares another hash, or another size, never yields the bytes
    const other = await newFile(2 * PART);
    assert.equal((await download({ ...one.file, hash: other.file.hash })).code, CODES.E_FILE_UNREADABLE);
    assert.equal((await download({ ...one.file, size: 2 * PART - 1 })).code, CODES.E_FILE_UNREADABLE);
    assert.equal((await download({ ...one.file, size: 2 * PART + 1 })).ok, false);
});

test('downloads: answers of the wrong shape are unreadable; lost answers are tried again, then stop', async () => {
    const one = await newFile(10);
    for (const body of [{ data: 5 }, { data: 'x' }, { data: null }, [], { data: 'A'.repeat(F.SEALED_PART_CHARS), extra: 1 }, MARKUP[0]]) {
        server.answer(() => ({ status: 200, body }));
        assert.equal((await download(one.file)).code, CODES.E_FILE_UNREADABLE, JSON.stringify(body));
    }
    let tries = 0;
    server.answer(() => { tries++; return { drop: true }; });
    assert.equal((await download(one.file)).code, CODES.E_FILE_DOWNLOAD_STOPPED);
    assert.equal(tries, T.PART_ATTEMPTS);
    server.answer(() => ({ status: 401, text: 'Unauthorized\n', type: 'text/plain' }));
    assert.equal((await download(one.file)).quiet, true);
});
