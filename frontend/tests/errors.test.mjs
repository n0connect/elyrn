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
        assert.throws(() => Errors.format(code, params), TypeError);
    }
    // The safe path shows the generic sentence instead of throwing
    assert.equal(Errors.message(code, {}), Errors.REGISTRY.E_BAD_PARAMS.text);
});

test('an unknown code yields the generic sentence and never throws', () => {
    const generic = Errors.REGISTRY.E_UNKNOWN_CODE.text;
    for (const code of [undefined, null, '', 'E_NOT_A_CODE', 'constructor', '__proto__', 'toString', 42, {}]) {
        assert.equal(Errors.message(code), generic);
        assert.throws(() => Errors.format(code), TypeError);
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
