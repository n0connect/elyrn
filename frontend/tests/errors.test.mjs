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
    for (const code of ['W_RESPONSE_TOO_LARGE', 'W_COUNTER_LOCK_UNAVAILABLE']) {
        assert.equal(Errors.INTERNAL[code], code);
    }
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
        [500, C.E_API_INTERNAL], [405, C.E_REQUEST_FAILED], [413, C.E_REQUEST_FAILED], [503, C.E_REQUEST_FAILED]]) {
        assert.equal(Errors.fromResult({ ok: false, status, data: null }), expected, String(status));
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
