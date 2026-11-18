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
import { readFileSync } from 'node:fs';
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
        { file_max_bytes: FILE_BOUND + 1 }, { file_max_bytes: FILE_PART + 0.5 }, { file_max_bytes: null }, { file_max_bytes: -FILE_MAX },
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
    // Any whole number of bytes in the server's range (backend/internal/database/validate.go
    // fileBounds: one part to MaxFileBytesBound), a multiple of a part or not
    for (const bytes of [FILE_PART, 1.5 * FILE_PART, FILE_BOUND]) {
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

// ---------- a clipboard clear that fails is told (fix-spec B1) ----------

test('a clear the clipboard refuses, or that never settles, comes back as a failure within the time limit', async () => {
    const clear = get('clearClipboardIfHolds');
    const limit = get('CLIPBOARD_WRITE_TIMEOUT_MS');
    const write = clipboard.writeText;
    try {
        for (const [what, refuse] of [
            ['refused', () => Promise.reject(new Error('Document is not focused'))],
            // an unfocused tab's write (headless Chromium): it never settles
            ['never settles', () => new Promise(() => {})]
        ]) {
            clipboard.writeText = write;
            await get('copyToClipboard')(ACCOUNT_A);
            clipboard.writeText = refuse;
            const started = Date.now();
            const failure = await clear(ACCOUNT_A);
            assert.ok(failure, `${what}: a failed clear must say so`);
            assert.ok(Date.now() - started < limit + 2000, `${what}: ${Date.now() - started} ms`);
            assert.equal(clipboard.text, ACCOUNT_A, `${what}: the number is still in the clipboard`);
        }
        // A page with no Clipboard API to clear with cannot clear either
        clipboard.writeText = write;
        await get('copyToClipboard')(ACCOUNT_B);
        const navigator = get('navigator');
        const api = navigator.clipboard;
        navigator.clipboard = undefined;
        try {
            assert.ok(await clear(ACCOUNT_B));
        } finally {
            navigator.clipboard = api;
        }
    } finally {
        clipboard.writeText = write;
    }
    // A clear that works, or one with nothing left to clear (something else was copied since), is no failure
    await get('copyToClipboard')(ACCOUNT_A);
    assert.equal(await clear(ACCOUNT_A), null);
    assert.equal(clipboard.text, '');
    assert.equal(await clear(ACCOUNT_A), null);
    // The failure is shown with what to do: the account number, invite and room codes alike
    assert.equal(Errors.REGISTRY.W_CLIPBOARD_NOT_CLEARED.severity, 'warning');
    const utils = readFileSync(new URL('../js/utils.js', import.meta.url), 'utf8');
    assert.match(utils, /function clearClipboardLater\(value\) \{\n    setTimeout\(\(\) => clearClipboardOrWarn\(value\)/);
    const auth = readFileSync(new URL('../js/auth.js', import.meta.url), 'utf8');
    assert.match(auth, /clearClipboardOrWarn\(accountNumber\)/);
    assert.doesNotMatch(auth + utils, /clearClipboardIfHolds\(accountNumber\)|=> clearClipboardIfHolds\(/);
});

// ---------- only a 401 or another key ends a session (fix-spec C1) ----------

test('a /me answer ends the stored session only on a 401 or another public key; every other answer keeps it', async () => {
    const meVerdict = get('meVerdict');
    const ENTRY = get('ENTRY');
    const mine = (await C.deriveIdentity(ACCOUNT_A)).publicKey;
    const theirs = (await C.deriveIdentity(ACCOUNT_B)).publicKey;
    const good = { public_key: mine, message_ttl_days: 30, room_max_members: 8, room_max_ttl_hours: 24, file_max_bytes: FILE_MAX };
    const kept = [
        [{ ok: false, status: 429, data: { code: 'E_EDGE_RATE_LIMITED' } }, CODES.E_API_TOO_MANY_REQUESTS],
        [{ ok: false, status: 429, data: { success: false, message: 'Too many requests' } }, CODES.E_API_TOO_MANY_REQUESTS],
        [{ ok: false, status: 404, data: { code: 'E_EDGE_NOT_FOUND' } }, CODES.E_API_ROUTE_UNKNOWN],
        [{ ok: false, status: 404, data: null }, CODES.E_API_INVALID_REQUEST],
        [{ ok: false, status: 405, data: null }, CODES.E_API_METHOD_NOT_ALLOWED],
        [{ ok: false, status: 403, data: null }, CODES.E_API_FORBIDDEN],
        [{ ok: false, status: 400, data: null }, CODES.E_API_INVALID_REQUEST],
        [{ ok: false, status: 500, data: null }, CODES.E_API_INTERNAL],
        [{ ok: false, status: 503, data: null }, CODES.E_API_UNAVAILABLE],
        [{ ok: false, status: 0, data: null, timedOut: true }, CODES.E_REQUEST_TIMEOUT],
        [{ ok: false, status: 0, data: null }, CODES.E_SERVER_UNREACHABLE],
        // this key, settings this app refuses: refused, the identity kept
        [{ ok: true, status: 200, data: { ...good, message_ttl_days: 0 } }, CODES.E_SERVER_LIMITS_INVALID]
    ];
    for (const [check, code] of kept) {
        const verdict = meVerdict(check, mine);
        assert.equal(verdict.entry, ENTRY.UNREACHABLE, JSON.stringify(check));
        assert.equal(verdict.code, code, JSON.stringify(check));
    }
    assert.equal(meVerdict({ ok: false, status: 401, data: null }, mine).entry, ENTRY.REFUSED);
    const swapped = meVerdict({ ok: true, status: 200, data: { ...good, public_key: theirs } }, mine);
    assert.equal(swapped.entry, ENTRY.REFUSED);
    assert.equal(swapped.code, CODES.E_IDENTITY_MISMATCH);
    const entered = meVerdict({ ok: true, status: 200, data: good }, mine);
    assert.equal(entered.entry, ENTRY.ENTERED);
    assert.equal(entered.judged.ttlDays, 30);
    // enterApp wipes only on REFUSED: the one Keystore.wipeIdentity in it is behind that branch
    const auth = readFileSync(new URL('../js/auth.js', import.meta.url), 'utf8');
    const enter = auth.slice(auth.indexOf('async function enterApp'), auth.indexOf('// Raised whenever the login screen is left'));
    assert.equal((enter.match(/wipeIdentity\(/g) || []).length, 1);
    assert.match(enter, /if \(verdict\.entry === ENTRY\.REFUSED\) \{\n\s+\/\/[^\n]*\n\s+await Keystore\.wipeIdentity\(\);/);
});

test('the same /me key comparison is made on a stream reconnect and on a return from the back-forward cache', () => {
    const live = readFileSync(new URL('../js/live-updates.js', import.meta.url), 'utf8');
    for (const name of ['async function reconnect', 'async function onRestored']) {
        const body = live.slice(live.indexOf(name), live.indexOf('\n        }\n', live.indexOf(name)));
        assert.match(body, /const check = await hooks\.api\('GET', '\/me'\);\n\s+if \(!meConfirms\(check\)\) return;/, name);
    }
    assert.match(live, /if \(!hooks\.sameIdentity\(check\.data\)\) \{\n\s+hooks\.identityLost\(\);/);
    const chat = readFileSync(new URL('../js/chat.js', import.meta.url), 'utf8');
    assert.match(chat, /sameIdentity: data => me !== null && sameIdentity\(data, me\.publicKey\), identityLost/);
    // One comparison, in one place: judgeMe asks it too
    const sameIdentity = get('sameIdentity');
    assert.equal(sameIdentity({ public_key: 'k' }, 'k'), true);
    for (const data of [null, 'k', { public_key: ['k'] }, { public_key: 'K' }, {}]) assert.equal(sameIdentity(data, 'k'), false);
});

// ---------- login never shows the number, never completes after a leave (fix-spec B2, B3) ----------
// The page's own drill shows the rendered frames (docs/development/testing-and-contributing.md);
// here every writer of the login field is read from the source.

test('login: no writer puts the field into clear text or writes the number while a login runs', () => {
    const auth = readFileSync(new URL('../js/auth.js', import.meta.url), 'utf8');
    const eye = readFileSync(new URL('../eye-hover-animation.js', import.meta.url), 'utf8');
    // auth.js never makes any field clear text, and its old unmasking animation is gone
    assert.doesNotMatch(auth, /\.type\s*=\s*'text'/);
    assert.doesNotMatch(auth, /animateInputToMask/);
    // The only clear-text writer is the hover effect's own frame, and it draws nothing while held
    assert.equal((eye.match(/\.type = 'text'/g) || []).length, 1);
    assert.match(eye, /handleMouseMove\(e\) \{\n\s+if \(!this\.eyeIcon \|\| !this\.accountNumberInput \|\| this\.held\) return;/);
    assert.match(eye, /startAnimation\(\) \{\n\s+if \(this\.animationFrame \|\| this\.held\) return;/);
    // resetToMasked: back to password before the value is written (no frame shows it in clear)
    const reset = eye.slice(eye.indexOf('    resetToMasked() {'), eye.indexOf('    }\n', eye.indexOf('    resetToMasked() {')));
    assert.ok(reset.indexOf("type = 'password'") >= 0 && reset.indexOf("type = 'password'") < reset.indexOf('.value ='), reset);
    // holdMasked holds first, stops the frame, then masks
    const hold = eye.slice(eye.indexOf('    holdMasked() {'), eye.indexOf('    release() {'));
    assert.ok(hold.indexOf('this.held = true') < hold.indexOf('this.stopAnimation()') &&
        hold.indexOf('this.stopAnimation()') < hold.indexOf('this.resetToMasked()'), hold);
});

test('login: the run is taken before the first wait and every wait is followed by the leave check', () => {
    const auth = readFileSync(new URL('../js/auth.js', import.meta.url), 'utf8');
    const start = auth.indexOf('async function loginNow()');
    const body = auth.slice(start, auth.indexOf('\n}\n', start));
    // Order is read from the code, not from comments that name the first await
    const code = body.split('\n').filter((line) => !line.trim().startsWith('//')).join('\n');
    const runAt = code.indexOf('const run = loginRun;');
    assert.ok(runAt > 0 && runAt < code.indexOf('await'), 'the run is taken after a wait');
    assert.match(body, /const alive = \(\) => run === loginRun && isShown\('loginContainer'\);/);
    // Each wait inside the try is followed at once by the leave check (enterApp asks it itself)
    const waits = body.split('\n').map((line, i, lines) => [line, lines[i + 1]]).filter(([line]) => /await /.test(line));
    assert.ok(waits.length >= 4);
    for (const [line, next] of waits) {
        assert.ok(/alive\(\)/.test(next) || /enterApp\(identity, true, alive\)/.test(line), `no leave check after: ${line.trim()}`);
    }
    // enterApp asks alive() after /me and after saving, before opening anything
    const enter = auth.slice(auth.indexOf('async function enterApp'), auth.indexOf('// Raised whenever the login screen is left'));
    assert.match(enter, /const check = await apiCall\('GET', '\/me'\);\n\s+if \(!alive\(\)\) return/);
    assert.match(enter, /await Keystore\.save\(identity\);\n\s+if \(!alive\(\)\) return/);
});
