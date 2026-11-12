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
