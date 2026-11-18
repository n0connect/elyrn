// frontend/js/errors.js loaded exactly as the browser loads it (after js/log.js).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({});
for (const file of ['../js/log.js', '../js/errors.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const Errors = vm.runInContext('Errors', context);
// The module throws the TypeError of its own realm (the vm context), not this file's.
const ContextTypeError = vm.runInContext('TypeError', context);
const throwsTypeError = (fn, message) =>
    assert.throws(fn, error => error instanceof ContextTypeError && error.message === message);
const CODE_SHAPE = /^[EW]_[A-Z0-9_]+$/;

test('every registered failure has a code of the right shape, a matching severity and a sentence', () => {
    const codes = Object.keys(Errors.REGISTRY);
    assert.ok(codes.length > 0);
    for (const code of codes) {
        const entry = Errors.REGISTRY[code];
        assert.match(code, CODE_SHAPE);
        assert.equal(entry.severity, code.startsWith('E_') ? 'error' : 'warning', code);
        assert.equal(typeof entry.text, 'string', code);
        assert.notEqual(entry.text.trim(), '', code);
        assert.equal(entry.text, entry.text.trimEnd(), `${code} ends in a space`);
        assert.equal(Errors.CODES[code], code);
    }
    assert.deepEqual(Object.keys(Errors.CODES), codes);
});

test('codes are unique across the registry and the log-only codes', () => {
    const internal = Object.keys(Errors.INTERNAL);
    for (const code of internal) {
        assert.match(code, CODE_SHAPE);
        assert.equal(Errors.INTERNAL[code], code);
    }
    const all = Object.keys(Errors.REGISTRY).concat(internal);
    assert.equal(new Set(all).size, all.length);
});

test('the tables cannot be changed at run time', () => {
    for (const table of [Errors, Errors.REGISTRY, Errors.CODES, Errors.INTERNAL, Errors.NOTICE]) {
        assert.ok(Object.isFrozen(table));
    }
    for (const entry of Object.values(Errors.REGISTRY)) {
        assert.ok(Object.isFrozen(entry));
    }
});

test('the formatter fills named parameters and refuses a missing one', () => {
    const code = Errors.CODES.E_MESSAGE_TOO_MANY_CHARS;
    assert.equal(Errors.format(code, { max: 2000 }), 'max 2000 characters');
    for (const params of [undefined, null, {}, { other: 1 }, { max: undefined }, { max: null }]) {
        throwsTypeError(() => Errors.format(code, params), 'missing parameter');
    }
    // The safe path shows the generic sentence instead of throwing
    assert.equal(Errors.message(code, {}), Errors.REGISTRY.E_BAD_PARAMS.text);
});

test('an unknown code yields the generic sentence and never throws', () => {
    const generic = Errors.REGISTRY.E_UNKNOWN_CODE.text;
    for (const code of [undefined, null, '', 'E_NOT_A_CODE', 'constructor', '__proto__', 'toString', 42, {}]) {
        assert.equal(Errors.message(code), generic);
        throwsTypeError(() => Errors.format(code), 'unknown error code');
    }
});

test('server answers map to registered codes, never to their own text', () => {
    assert.equal(Errors.fromApi('Invalid credentials', 401), Errors.CODES.E_API_INVALID_CREDENTIALS);
    assert.equal(Errors.fromApi('  TOO MANY REQUESTS ', 200), Errors.CODES.E_API_TOO_MANY_REQUESTS);
    assert.equal(Errors.fromApi('Pending token required', 400), Errors.CODES.E_API_INVALID_REQUEST);
    assert.equal(Errors.fromApi('<script>leak</script>', 400), Errors.CODES.E_REQUEST_FAILED);
    assert.equal(Errors.fromApi('constructor', 400), Errors.CODES.E_REQUEST_FAILED);
    assert.equal(Errors.fromApi(null, 429), Errors.CODES.E_API_TOO_MANY_REQUESTS);
    assert.equal(Errors.fromApi(undefined, 404), Errors.CODES.E_API_INVALID_REQUEST);
    assert.equal(Errors.fromApi(null, 418), Errors.CODES.E_REQUEST_FAILED);
    for (const status of [400, 401, 403, 404, 429, 500, 0, 418]) {
        assert.ok(Object.hasOwn(Errors.REGISTRY, Errors.fromApi(null, status)));
    }
});

test('a failed request result maps to a registered code: no answer says whether it timed out', () => {
    const C = Errors.CODES;
    assert.equal(Errors.fromResult({ ok: false, status: 0, data: null, timedOut: true }), C.E_REQUEST_TIMEOUT);
    assert.equal(Errors.fromResult({ ok: false, status: 0, data: null, timedOut: false }), C.E_SERVER_UNREACHABLE);
    // getPowChallenge's shape: a status and no data
    assert.equal(Errors.fromResult({ status: 0 }), C.E_SERVER_UNREACHABLE);
    assert.equal(Errors.fromResult({ status: 401, data: { success: false, message: 'Invalid credentials' } }), C.E_API_INVALID_CREDENTIALS);
    assert.equal(Errors.fromResult({ status: 429, data: null }), C.E_API_TOO_MANY_REQUESTS);
    assert.equal(Errors.fromResult({ status: 503, data: { message: '<b>leak</b>' } }), C.E_REQUEST_FAILED);
    for (const status of [0, 400, 401, 403, 404, 429, 500, 503, 418]) {
        assert.ok(Object.hasOwn(Errors.REGISTRY, Errors.fromResult({ status, data: null })), String(status));
    }
});

test('the situation codes exist with the severity they are reported at', () => {
    for (const code of ['E_REQUEST_TIMEOUT', 'E_SERVER_UNREACHABLE', 'E_ACCOUNT_CREATED_NOT_ENTERED',
        'E_POW_TIMEOUT', 'E_POW_TOO_HARD', 'E_UNEXPECTED']) {
        assert.equal(Errors.CODES[code], code);
        assert.equal(Errors.REGISTRY[code].severity, 'error', code);
    }
    for (const code of ['E_SYNC_FAILED', 'W_REQUEST_TIMED_OUT']) {
        assert.equal(Errors.INTERNAL[code], code);
    }
});

test('wave 2 codes exist with the severity they are reported at', () => {
    const C = Errors.CODES;
    for (const code of ['E_SERVER_LIMITS_INVALID', 'E_BROWSER_UNSUPPORTED', 'E_RESPONSE_TOO_LARGE',
        'E_IDENTITY_DELETE_UNKNOWN', 'E_MESSAGE_ID_CONFLICT', 'E_ROOM_LIMITS_REFUSED']) {
        assert.equal(C[code], code);
        assert.equal(Errors.REGISTRY[code].severity, 'error', code);
    }
    for (const code of ['W_STORAGE_UNAVAILABLE', 'W_STORAGE_BLOCKED', 'W_STORAGE_CLOSED']) {
        assert.equal(C[code], code);
        assert.equal(Errors.REGISTRY[code].severity, 'warning', code);
    }
    for (const code of ['W_RESPONSE_TOO_LARGE', 'W_COUNTER_LOCK_UNAVAILABLE', 'W_COUNTER_RECORDS_EVICTED']) {
        assert.equal(Errors.INTERNAL[code], code);
    }
    // The identity kept on this device (keystore.js): both told; one that is stored but cannot be
    // read back says that logging in once restores it, never that anything is gone
    assert.equal(C.W_IDENTITY_NOT_KEPT, 'W_IDENTITY_NOT_KEPT');
    assert.equal(Errors.REGISTRY.W_IDENTITY_NOT_KEPT.severity, 'warning');
    assert.match(Errors.REGISTRY.W_IDENTITY_NOT_KEPT.text, /account number/);
    assert.equal(C.W_IDENTITY_UNREADABLE, 'W_IDENTITY_UNREADABLE');
    assert.equal(Errors.REGISTRY.W_IDENTITY_UNREADABLE.severity, 'warning');
    assert.equal(Errors.REGISTRY.W_IDENTITY_UNREADABLE.text,
        'your key could not be read back in this browser — log in once with your account number; nothing is lost');
    assert.equal(Object.hasOwn(Errors.INTERNAL, 'W_IDENTITY_UNREADABLE'), false);
    assert.equal(Errors.INTERNAL.W_KEY_PROBE_FAILED, 'W_KEY_PROBE_FAILED');
    // An authentic message a newer elyrn wrote is named as such, never as tampered with
    assert.equal(Errors.REGISTRY.W_MESSAGE_FROM_NEWER.severity, 'warning');
    assert.equal(Errors.REGISTRY.W_MESSAGE_FROM_NEWER.text, 'sent by a newer elyrn; reload this page to read it');
    // Member roles: the server's own sentence maps to its code, as the other sentences do
    assert.equal(Errors.fromApi('Role not allowed', 403), C.E_ROLE_NOT_ALLOWED);
    assert.equal(Errors.fromResult({ status: 403, data: { success: false, message: 'Role not allowed' } }), C.E_ROLE_NOT_ALLOWED);
    assert.equal(Errors.REGISTRY.E_ROLE_TOO_LONG.text.includes('{max}'), true);
    assert.equal(Errors.INTERNAL.W_ROLE_UNREADABLE, 'W_ROLE_UNREADABLE');
    // Files: each of the server's own sentences (backend/internal/apperr) maps to its code
    for (const [sentence, status, code] of [['File part out of order', 409, C.E_FILE_UPLOAD_RESTART],
        ['File quota reached', 507, C.E_FILE_QUOTA_REACHED], ['File store full', 507, C.E_FILE_STORE_FULL],
        ['File budget spent', 429, C.W_FILE_BUDGET_SPENT]]) {
        assert.equal(Errors.fromResult({ status, data: { success: false, message: sentence } }), code, sentence);
    }
    const apperr = readFileSync(new URL('../../backend/internal/apperr/apperr.go', import.meta.url), 'utf8');
    for (const sentence of ['File part out of order', 'File quota reached', 'File store full', 'File budget spent']) {
        assert.ok(apperr.includes(`"${sentence}"`), `${sentence} is no longer the server's sentence`);
    }
    assert.match(Errors.REGISTRY.E_FILE_TOO_LARGE.text, /\{max\}/);
    assert.equal(Errors.INTERNAL.W_FILE_TRANSFER_CANCELLED, 'W_FILE_TRANSFER_CANCELLED');
    // A room judged expired by this device's clock names the clock
    assert.match(Errors.REGISTRY.E_ROOM_CODE_EXPIRED.text, /device clock/);
    assert.match(Errors.REGISTRY.W_ROOM_EXPIRED.text, /device clock/);
    // An oversized answer is its own code, whatever its status says
    assert.equal(Errors.fromResult({ status: 0, data: null, timedOut: false, tooLarge: true }), C.E_RESPONSE_TOO_LARGE);
});

// The ids nginx's own /api/ failures carry, read from their one registration (EdgeAnswers)
const EDGE_GO = new URL('../../backend/internal/apperr/edge.go', import.meta.url);
const EDGE_ENTRY = /\{\s*"(E_[A-Z0-9_]+)"\s*,\s*http\.Status[A-Za-z]+\s*,/g;
function edgeIds() {
    const source = readFileSync(EDGE_GO, 'utf8');
    const start = source.indexOf('var EdgeAnswers');
    assert.ok(start >= 0, 'EdgeAnswers not found in edge.go');
    const block = source.slice(start, source.indexOf('\n}', start));
    return Array.from(block.matchAll(EDGE_ENTRY), match => match[1]);
}

// Each edge code and the browser code it must become, with the status nginx answers it under
const EDGE_TABLE = [
    ['E_BACKEND_UNAVAILABLE', 503, 'Service unavailable', 'E_API_UNAVAILABLE'],
    ['E_EDGE_NOT_FOUND', 404, 'Not Found', 'E_API_ROUTE_UNKNOWN'],
    ['E_EDGE_METHOD_NOT_ALLOWED', 405, 'Method not allowed', 'E_API_ROUTE_UNKNOWN'],
    ['E_BODY_TOO_LARGE', 413, 'Request entity too large', 'E_API_BODY_TOO_LARGE'],
    ['E_EDGE_RATE_LIMITED', 429, 'Too many requests', 'E_API_TOO_MANY_REQUESTS']
];

test('every edge code registered in edge.go has a browser mapping, and no mapping is stale', () => {
    const ids = edgeIds();
    assert.ok(ids.length > 0, 'no edge ids extracted from edge.go');
    assert.deepEqual([...ids].sort(), Object.keys(Errors.EDGE_CODES).sort());
    assert.deepEqual([...ids].sort(), EDGE_TABLE.map(row => row[0]).sort());
    assert.ok(Object.isFrozen(Errors.EDGE_CODES));
});

test('an edge code maps to its registered browser code, ahead of message and status', () => {
    for (const [edge, status, message, expected] of EDGE_TABLE) {
        const body = { success: false, message: message, code: edge };
        assert.equal(Errors.fromResult({ ok: false, status, data: body }), expected, edge);
        // The code alone decides: a status or message saying otherwise does not change it
        assert.equal(Errors.fromResult({ ok: false, status: 418, data: { code: edge, message: 'x' } }), expected, edge);
        assert.equal(Errors.fromApi(null, 418, edge), expected, edge);
        assert.equal(Errors.REGISTRY[expected].severity, 'error', edge);
    }
    // Each tells the user what to do
    assert.match(Errors.REGISTRY.E_API_UNAVAILABLE.text, /try again/);
    assert.match(Errors.REGISTRY.E_API_TOO_MANY_REQUESTS.text, /wait/);
    assert.match(Errors.REGISTRY.E_API_BODY_TOO_LARGE.text, /shorter/);
    assert.match(Errors.REGISTRY.E_API_ROUTE_UNKNOWN.text, /reload/);
});

test('an unknown code falls back to the message and status mapping; text/plain maps by status', () => {
    const C = Errors.CODES;
    for (const code of ['E_NOT_AN_EDGE_CODE', 'E_API_UNAVAILABLE', 'e_backend_unavailable', '', null, undefined]) {
        assert.equal(Errors.fromResult({ status: 401, data: { message: 'Invalid credentials', code } }), C.E_API_INVALID_CREDENTIALS);
        assert.equal(Errors.fromResult({ status: 429, data: { code } }), C.E_API_TOO_MANY_REQUESTS);
    }
    // apiCall gives data null for a text/plain body: the status alone maps it, as before
    for (const [status, expected] of [[400, C.E_API_INVALID_REQUEST], [401, C.E_API_UNAUTHORIZED],
        [403, C.E_API_FORBIDDEN], [404, C.E_API_INVALID_REQUEST], [429, C.E_API_TOO_MANY_REQUESTS],
        [500, C.E_API_INTERNAL], [405, C.E_API_METHOD_NOT_ALLOWED], [413, C.E_API_BODY_TOO_LARGE],
        [415, C.E_API_INVALID_REQUEST], [503, C.E_API_UNAVAILABLE], [409, C.E_REQUEST_FAILED], [412, C.E_REQUEST_FAILED]]) {
        assert.equal(Errors.fromResult({ ok: false, status, data: null }), expected, String(status));
    }
});

// The ids the backend answers with 503, read from their one registration (apperr.go)
const APPERR_GO = new URL('../../backend/internal/apperr/apperr.go', import.meta.url);
const UNAVAILABLE_ENTRY = /\{\s*"(E_[A-Z0-9_]+)"\s*,\s*http\.StatusServiceUnavailable\s*,/g;
function unavailableIds() {
    const source = readFileSync(APPERR_GO, 'utf8');
    return Array.from(source.matchAll(UNAVAILABLE_ENTRY), match => match[1]);
}

test('every backend 503 code (apperr.go) reaches the user as E_API_UNAVAILABLE', () => {
    const ids = unavailableIds();
    for (const id of ['E_STORE_UNAVAILABLE', 'E_SHUTTING_DOWN', 'E_REQUEST_CANCELLED']) {
        assert.ok(ids.includes(id), `${id} not found as a 503 in apperr.go`);
    }
    for (const id of ids) {
        // A text/plain body is data null (status alone); a JSON body carries "Service unavailable"
        assert.equal(Errors.fromResult({ ok: false, status: 503, data: null }), Errors.CODES.E_API_UNAVAILABLE, id);
        assert.equal(Errors.fromResult({ ok: false, status: 503, data: { message: 'Service unavailable' } }),
            Errors.CODES.E_API_UNAVAILABLE, id);
    }
});

test('hostile code and message values never throw and never reach the screen', () => {
    const long = 'A'.repeat(1 << 20);
    const hostile = [
        {}, [], ['E_BACKEND_UNAVAILABLE'], { toString: 1 }, { valueOf: 1, toString: 1 }, 42, true, NaN,
        long, '__proto__', 'constructor', 'toString', 'hasOwnProperty', '<img src=x onerror=alert(1)>',
        JSON.parse('{"__proto__":{"code":"E_BACKEND_UNAVAILABLE"}}')
    ];
    const sentences = new Set(Object.values(Errors.REGISTRY).map(entry => entry.text));
    const check = (data, status) => {
        const code = Errors.fromResult({ ok: false, status, data });
        assert.ok(Object.hasOwn(Errors.REGISTRY, code), String(code));
        assert.ok(sentences.has(Errors.message(code)));
        return code;
    };
    for (const value of hostile) {
        for (const status of [400, 404, 413, 429, 503, 418]) {
            const asCode = check({ success: false, message: 'Not Found', code: value }, status);
            assert.equal(asCode, Errors.CODES.E_API_INVALID_REQUEST);
            const asMessage = check({ success: false, message: value }, status);
            assert.ok(asMessage === Errors.CODES.E_REQUEST_FAILED || asMessage === Errors.fromApi(null, status));
            check(value, status);
        }
        assert.doesNotThrow(() => Errors.fromApi(value, 400, value));
    }
    // A body whose own __proto__ carries a code is not an edge answer
    const parsed = JSON.parse('{"__proto__":{"code":"E_EDGE_RATE_LIMITED"},"message":"x"}');
    assert.equal(Errors.fromResult({ status: 400, data: parsed }), Errors.CODES.E_REQUEST_FAILED);
    // A long message is unrecognised text, never shown
    assert.equal(Errors.fromResult({ status: 503, data: { message: long } }), Errors.CODES.E_REQUEST_FAILED);
});

test('notices: every one is a non-empty sentence; notice() fills parameters and never throws', () => {
    for (const [name, text] of Object.entries(Errors.NOTICE)) {
        assert.equal(typeof text, 'string', name);
        assert.notEqual(text.trim(), '', name);
    }
    assert.equal(Errors.notice(Errors.NOTICE.FRIEND_REQUEST_SENT, { name: 'quiet-fox' }), 'friend request sent to quiet-fox');
    assert.equal(Errors.notice(Errors.NOTICE.WELCOME), Errors.NOTICE.WELCOME);
    // Missing parameter, misspelt notice (undefined) or free text: the generic sentence
    assert.equal(Errors.notice(Errors.NOTICE.FRIEND_REQUEST_SENT, {}), Errors.REGISTRY.E_BAD_PARAMS.text);
    for (const text of [undefined, null, 'free text', 42]) {
        assert.equal(Errors.notice(text), Errors.REGISTRY.E_UNKNOWN_CODE.text);
    }
});

// The send's two 409s, read from the server's one registration (apperr.go sayIDTaken)
function serverIDTaken() {
    const match = readFileSync(APPERR_GO, 'utf8').match(/\bsayIDTaken\s*=\s*"([^"]+)"/);
    assert.ok(match, 'sayIDTaken not found in apperr.go');
    return match[1];
}

test('a send\'s 409 "Id taken" (JSON) is told from the 409 "Conflict" (text/plain: no data) by its message', () => {
    const C = Errors.CODES;
    const taken = { ok: false, status: 409, data: { success: false, message: serverIDTaken() } };
    assert.equal(Errors.fromResult(taken), C.E_MESSAGE_ID_TAKEN);
    assert.equal(Errors.idTaken(taken), true);
    assert.equal(Errors.REGISTRY.E_MESSAGE_ID_TAKEN.severity, 'error');
    assert.match(Errors.REGISTRY.E_MESSAGE_ID_TAKEN.text, /nothing was sent/);
    // The stored earlier attempt: a plain-text body is no data
    assert.equal(Errors.idTaken({ ok: false, status: 409, data: null }), false);
    // The message under another status, another message under 409, and no answer are not it
    for (const result of [
        { ok: false, status: 400, data: { message: serverIDTaken() } },
        { ok: false, status: 409, data: { message: 'Conflict' } },
        { ok: false, status: 409, data: { message: 'room full' } },
        { ok: false, status: 409, data: { message: serverIDTaken(), code: 'E_BACKEND_UNAVAILABLE' } },
        { ok: false, status: 0, data: null, timedOut: false },
        { ok: true, status: 201, data: { seq: 1 } }
    ]) {
        assert.equal(Errors.idTaken(result), false, JSON.stringify(result));
    }
});

test('18 Nov: the server\'s new refusals and the trust warnings have codes that say what to do', () => {
    const C = Errors.CODES;
    // A1: a room message or note under a card that is not the sender's stored one (400)
    assert.equal(Errors.fromResult({ status: 400, data: { success: false, message: 'Sender card mismatch' } }), C.E_SENDER_CARD_MISMATCH);
    // E1: a member's own share of the conversation's files (507), told from the whole quota
    assert.equal(Errors.fromResult({ status: 507, data: { success: false, message: 'File share reached' } }), C.E_FILE_SHARE_REACHED);
    assert.equal(Errors.fromResult({ status: 507, data: { success: false, message: 'File quota reached' } }), C.E_FILE_QUOTA_REACHED);
    // Both are the server's own sentences (backend/internal/apperr, from the server half of this release)
    const apperr = readFileSync(new URL('../../backend/internal/apperr/apperr.go', import.meta.url), 'utf8');
    for (const sentence of ['Sender card mismatch', 'File share reached']) {
        assert.ok(apperr.includes(`"${sentence}"`), `${sentence} is not the server's sentence`);
    }
    for (const [code, severity, words] of [
        ['E_SENDER_CARD_MISMATCH', 'error', /reload the page/],
        ['E_FILE_SHARE_REACHED', 'error', /once some of yours have expired/],
        // B1: a clear that failed is shown, with what to do, no longer only logged
        ['W_CLIPBOARD_NOT_CLEARED', 'warning', /copy something else to overwrite it/],
        // A2
        ['W_MEMBER_DISPUTED', 'warning', /two seats claim this identity/],
        ['W_ROOM_SEATS_DISPUTED', 'warning', /safety number/],
        ['W_OWN_SEAT_DISPUTED', 'warning', /claims to be you/],
        // A4
        ['E_FRIEND_REQUEST_RELAYED', 'error', /did not come from the member who sent it/],
        ['W_FRIEND_REQUEST_OUTDATED', 'warning', /ask them to send a new request/],
        // C2: a sender the full counter record did not take, and the room's record full
        ['W_SENDER_NOT_RECORDED', 'warning', /replay protection is not kept for this sender/],
        ['W_COUNTER_RECORD_FULL', 'warning', /record on this device is full/]
    ]) {
        assert.equal(Errors.REGISTRY[code].severity, severity, code);
        assert.match(Errors.REGISTRY[code].text, words, code);
    }
    assert.equal(Object.prototype.hasOwnProperty.call(Errors.INTERNAL, 'W_CLIPBOARD_NOT_CLEARED'), false);
});

test('a standing message stays until closed: W_IDENTITY_UNREADABLE is one, and report and the toast carry it', () => {
    // Every entry declares it, in the one place messages are declared
    for (const [code, entry] of Object.entries(Errors.REGISTRY)) assert.equal(typeof entry.standing, 'boolean', code);
    assert.equal(Errors.REGISTRY.W_IDENTITY_UNREADABLE.standing, true);
    assert.equal(Errors.REGISTRY.W_IDENTITY_NOT_KEPT.standing, false);
    // report hands it to the toast, and the toast gives a standing message no timer
    const errors = readFileSync(new URL('../js/errors.js', import.meta.url), 'utf8');
    assert.match(errors, /showWarning\(resolved\.text, resolved\.standing\);/);
    assert.match(errors, /showError\(resolved\.text, resolved\.standing\);/);
    assert.match(errors, /standing: REGISTRY\[code\]\.standing \}/);
    const toast = readFileSync(new URL('../js/notifications.js', import.meta.url), 'utf8');
    assert.match(toast, /const NOTIFICATION_STAYS = 0;/);
    assert.match(toast, /return standing === true \? NOTIFICATION_STAYS : NOTIFICATION_SHOWN_MS;/);
    assert.match(toast, /function showWarning\(message, standing = false\) \{\n\s*showNotification\(message, 'warning', shownFor\(standing\)\);/);
    assert.match(toast, /if \(duration > 0\) \{\n\s*setTimeout\(\(\) => \{\n\s*closeNotification/);
});
