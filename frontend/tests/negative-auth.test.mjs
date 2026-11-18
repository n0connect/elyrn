// Negative use around login and registration: a hostile proof-of-work challenge and /me answer,
// a registration left mid-way, every action pressed twice. js/auth.js touches no DOM when it
// loads, so it is loaded as the browser loads it (after utils.js and validation.js) and its
// DOM-free parts are called directly; the DOM-bound parts are in the manual negative-use tour
// (docs/development/testing-and-contributing.md). The clipboard is the one browser API given a
// stand-in here: the module under test is auth.js, never the clipboard.
// Run: node --test frontend/tests/*.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { load } from './fuzz-helpers.mjs';
import { ACCOUNT_A, ACCOUNT_B, MARKUP, startHostileServer, useServer } from './negative-helpers.mjs';

// What the system clipboard holds, as navigator.clipboard sees it
const clipboard = {
    text: '',
    writeText: async (text) => { clipboard.text = text; },
    readText: async () => clipboard.text
};
const { context, get } = load(
    { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, AbortSignal, DOMException, Response, setTimeout, clearTimeout,
        window: { isSecureContext: true }, navigator: { clipboard } },
    ['../js/log.js', '../js/errors.js', '../js/utils.js', '../js/crypto.js', '../js/room-crypto.js', '../js/file-crypto.js',
        '../validation.js', '../js/auth.js']);
const Errors = get('Errors');
const CODES = Errors.CODES;
const C = get('ElyrnCrypto');
const set = (name, value) => vm.runInContext(`${name} = ${JSON.stringify(value)}`, context);

const MAX_POW_DIFFICULTY = get('MAX_POW_DIFFICULTY');
const MAX_MESSAGE_TTL_DAYS = get('MAX_MESSAGE_TTL_DAYS');
const MAX_ROOM_TTL_HOURS = get('MAX_ROOM_TTL_HOURS');
const MAX_MESSAGE_PAGE_LIMIT = get('MAX_MESSAGE_PAGE_LIMIT');
const R = get('ElyrnRoomCrypto');
const FILE_PART = get('ElyrnFileCrypto').FILE_PART_BYTES;
const FILE_BOUND = C.MAX_FILE_BYTES_BOUND;
// The server's default MAX_FILE_BYTES (backend/internal/config)
const FILE_MAX = 10485760;

let server;
before(async () => {
    server = await startHostileServer();
    useServer(context, server.origin);
});
after(() => server.close());

const CHALLENGE = Object.freeze({ challenge: 'c', difficulty: 1, salt: 's', timestamp: 1, ttl: 300 });

// ---------- the proof-of-work challenge ----------

test('a challenge that is not an object, on a 2xx error body, or on an error status is no challenge', async () => {
    const getPowChallenge = get('getPowChallenge');
    const cases = [
        [200, { success: true, challenge: 'abc' }, CODES.E_REQUEST_FAILED],
        [200, { success: true, challenge: [CHALLENGE] }, CODES.E_REQUEST_FAILED],
        [200, { success: true, challenge: 24 }, CODES.E_REQUEST_FAILED],
        [200, { success: true, challenge: null }, CODES.E_REQUEST_FAILED],
        [200, { success: false, message: 'Too many requests', challenge: CHALLENGE }, CODES.E_REQUEST_FAILED],
        [200, MARKUP[0], CODES.E_REQUEST_FAILED],
        [500, { success: true, challenge: CHALLENGE }, CODES.E_API_INTERNAL],
        [429, { success: false, message: 'too many requests' }, CODES.E_API_TOO_MANY_REQUESTS]
    ];
    for (const [status, body, want] of cases) {
        server.answer(() => ({ status, body }));
        const issued = await getPowChallenge();
        assert.equal(issued.challenge, null, JSON.stringify(body));
        assert.equal(Errors.fromResult(issued), want, JSON.stringify(body));
    }
    // Extra fields ride along; the worker reads only its three (pow-worker.js validates them)
    server.answer(() => ({ status: 200, body: { success: true, challenge: { ...CHALLENGE, extra: MARKUP[0] } } }));
    assert.equal((await getPowChallenge()).challenge.salt, 's');
});

test('a challenge over the difficulty cap is refused before any worker starts: E_POW_TOO_HARD', async () => {
    const solve = get('solvePowChallenge');
    const powFailureCode = get('powFailureCode');
    const isPowCancelled = get('isPowCancelled');
    // No Worker exists in this context: reaching one would reject with a ReferenceError instead
    for (const difficulty of [MAX_POW_DIFFICULTY + 1, 64, Number.MAX_SAFE_INTEGER]) {
        await assert.rejects(solve({ ...CHALLENGE, difficulty }), (error) =>
            error.name === 'PowStopped' && powFailureCode(error, CODES.E_REQUEST_FAILED) === CODES.E_POW_TOO_HARD &&
            !isPowCancelled(error));
    }
    assert.equal(get('powRuns').size, 0);
});

// ---------- the /me answer ----------

test('a /me answer that does not carry this device\'s key is E_IDENTITY_MISMATCH, whatever else it holds', async () => {
    const judgeMe = get('judgeMe');
    const mine = (await C.deriveIdentity(ACCOUNT_A)).publicKey;
    const theirs = (await C.deriveIdentity(ACCOUNT_B)).publicKey;
    const good = { public_key: mine, message_ttl_days: 30, room_max_members: 8, room_max_ttl_hours: 24, message_page_limit: 50,
        file_max_bytes: FILE_MAX };
    for (const data of [null, undefined, 'x', 7, [], {}, { ...good, public_key: theirs }, { ...good, public_key: MARKUP[0] },
        { ...good, public_key: { toString: () => mine } }, { ...good, public_key: [mine] }, { success: false, message: 'unauthorized' }]) {
        assert.equal(judgeMe(data, mine).code, CODES.E_IDENTITY_MISMATCH, JSON.stringify(data));
    }
});

test('a /me answer with this key and settings of the wrong type or out of range is E_SERVER_LIMITS_INVALID', async () => {
    const judgeMe = get('judgeMe');
    const mine = (await C.deriveIdentity(ACCOUNT_A)).publicKey;
    const good = { public_key: mine, message_ttl_days: 30, room_max_members: 8, room_max_ttl_hours: 24, file_max_bytes: FILE_MAX };
    const changes = [
        // the largest file: from one part to the bound any server may set (backend/internal/config)
        { file_max_bytes: undefined }, { file_max_bytes: '10485760' }, { file_max_bytes: FILE_PART - 1 }, { file_max_bytes: 0 },
        { file_max_bytes: FILE_BOUND + 1 }, { file_max_bytes: 1.5 * FILE_PART }, { file_max_bytes: null }, { file_max_bytes: -FILE_MAX },
        { message_ttl_days: '30' }, { message_ttl_days: 0 }, { message_ttl_days: MAX_MESSAGE_TTL_DAYS + 1 }, { message_ttl_days: 1.5 },
        { message_ttl_days: -1 }, { message_ttl_days: null }, { room_max_members: '8' }, { room_max_members: R.MIN_MEMBERS - 1 },
        { room_max_members: R.MAX_MEMBERS + 1 }, { room_max_ttl_hours: 0 }, { room_max_ttl_hours: MAX_ROOM_TTL_HOURS + 1 },
        { room_max_ttl_hours: Number.MAX_SAFE_INTEGER + 2 }
    ];
    for (const change of changes) {
        assert.equal(judgeMe({ ...good, ...change }, mine).code, CODES.E_SERVER_LIMITS_INVALID, JSON.stringify(change));
    }
});

test('a /me answer with extra fields is taken for its known ones; a page size out of range turns paging off', async () => {
    const judgeMe = get('judgeMe');
    const mine = (await C.deriveIdentity(ACCOUNT_A)).publicKey;
    const good = { public_key: mine, message_ttl_days: 30, room_max_members: 8, room_max_ttl_hours: 24, file_max_bytes: FILE_MAX,
        set_cookie: MARKUP[2], html: MARKUP[0], admin: true };
    for (const [limit, want] of [[50, 50], [undefined, 0], ['50', 0], [0, 0], [MAX_MESSAGE_PAGE_LIMIT + 1, 0], [MAX_MESSAGE_PAGE_LIMIT, MAX_MESSAGE_PAGE_LIMIT]]) {
        const judged = judgeMe({ ...good, message_page_limit: limit }, mine);
        assert.equal(judged.code, null);
        assert.equal(judged.ttlDays, 30);
        assert.deepEqual({ ...judged.limits }, { maxMembers: 8, maxTTLHours: 24, pageLimit: want, fileMaxBytes: FILE_MAX }, String(limit));
    }
    for (const bytes of [FILE_PART, FILE_BOUND]) {
        assert.equal(judgeMe({ ...good, file_max_bytes: bytes }, mine).limits.fileMaxBytes, bytes);
    }
});

// ---------- a registration left mid-way: nothing of it stays ----------

test('leaving registration drops the number and token, ends every proof of work and clears the clipboard it filled', async () => {
    await get('copyToClipboard')(ACCOUNT_A);
    assert.equal(clipboard.text, ACCOUNT_A);
    set('pendingRegistrationAccountNumber', ACCOUNT_A);
    set('pendingRegistrationToken', 'pending-token');
    const run = get('registrationRun');
    const key = get('registrationKey')();
    await get('forgetRegistration')();
    assert.equal(get('pendingRegistrationAccountNumber'), null);
    assert.equal(get('pendingRegistrationToken'), null);
    assert.equal(get('registrationAccountMayExist'), false);
    assert.equal(get('registrationLeaveArmed'), false);
    assert.equal(get('registrationRun'), run + 1, 'every run still in flight now stops at its next step');
    assert.notEqual(get('registrationKey')(), key, 'a run left behind never holds the next registration\'s lock');
    assert.equal(get('powRuns').size, 0);
    assert.equal(clipboard.text, '');
});

test('leaving registration leaves the clipboard alone once something else was copied over the number', async () => {
    await get('copyToClipboard')(ACCOUNT_A);
    set('pendingRegistrationAccountNumber', ACCOUNT_A);
    await get('copyToClipboard')('something the user copied');
    await get('forgetRegistration')();
    assert.equal(clipboard.text, 'something the user copied');
    assert.equal(get('pendingRegistrationAccountNumber'), null);
    // with no number held there is nothing to clear
    await get('forgetRegistration')();
    assert.equal(clipboard.text, 'something the user copied');
});

test('a clipboard write that never settles fails within the time limit, so registration is never stuck on it', async () => {
    const limit = get('CLIPBOARD_WRITE_TIMEOUT_MS');
    assert.ok(limit > 0 && limit <= 10000);
    const write = clipboard.writeText;
    // An unfocused tab's write (headless Chromium): the promise never settles
    clipboard.writeText = () => new Promise(() => {});
    try {
        const started = Date.now();
        // The selection fallback needs a page (no document here), so the copy fails: in time
        await assert.rejects(get('copyToClipboard')(ACCOUNT_B));
        const took = Date.now() - started;
        assert.ok(took >= limit - 50 && took < limit + 2000, `${took} ms`);
        assert.notEqual(clipboard.text, ACCOUNT_B);
    } finally {
        clipboard.writeText = write;
    }
    // ...and what registration shows then: copy by hand, keep it, then continue
    assert.match(Errors.REGISTRY.W_ACCOUNT_NUMBER_NOT_COPIED.text, /by hand.*then press continue/);
});

test('where the account may already exist the way back asks once, then leaves; a definite state leaves at once', async () => {
    const exit = get('registrationExit');
    const EXIT = get('REGISTRATION_EXIT');
    set('registrationAccountMayExist', false);
    set('registrationLeaveArmed', false);
    assert.equal(exit(), EXIT.LEAVE);
    set('registrationAccountMayExist', true);
    assert.equal(exit(), EXIT.ASK);
    set('registrationLeaveArmed', true);
    assert.equal(exit(), EXIT.LEAVE);
    assert.equal(Errors.REGISTRY[CODES.W_REGISTRATION_LEAVE_CONFIRM].severity, 'warning');
    await get('forgetRegistration')();
    assert.equal(exit(), EXIT.LEAVE);
});

test('registration success drops the secrets without ending the session\'s runs', async () => {
    set('pendingRegistrationAccountNumber', ACCOUNT_B);
    set('pendingRegistrationToken', 'pending-token');
    set('registrationAccountMayExist', true);
    const run = get('registrationRun');
    await get('dropRegistrationSecrets')();
    assert.equal(get('pendingRegistrationAccountNumber'), null);
    assert.equal(get('pendingRegistrationToken'), null);
    assert.equal(get('registrationAccountMayExist'), false);
    assert.equal(get('registrationRun'), run);
});

// ---------- pressed twice, pressed during another action ----------

test('every guarded action pressed twice in a row runs once; a different key runs alongside', async () => {
    const once = get('once');
    for (const key of ['login', get('registrationKey')(), 'register-leave', 'account', 'send', 'join', 'invite', 'room']) {
        let runs = 0;
        let release;
        const first = once(key, () => { runs++; return new Promise((resolve) => { release = resolve; }); });
        assert.equal(await once(key, () => { runs++; }), undefined, key);
        assert.equal(await once(key + '-other', () => 'ran'), 'ran');
        release();
        await first;
        assert.equal(runs, 1, key);
    }
});
