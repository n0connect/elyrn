// Fuzz: frontend/js/errors.js, loaded as the browser loads it (after js/log.js). Arbitrary
// answers, codes and parameters: the safe paths never throw and always yield a registered code
// and a registry sentence; the server's own text is never what is shown.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load } from './fuzz-helpers.mjs';

const SEED = 0x5eed0004;
const ITERATIONS = 5000;
const STATUSES = [0, 200, 204, 400, 401, 403, 404, 405, 409, 412, 413, 429, 500, 502, 503, 504];

// No console in the context: Log stays silent, as in a worker
const { get } = load({}, ['../js/log.js', '../js/errors.js']);
const Errors = get('Errors');
const ContextTypeError = get('TypeError');
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const registered = (code) => typeof code === 'string' && own(Errors.REGISTRY, code);
const codes = Object.keys(Errors.REGISTRY);
const sentences = new Set(codes.map((code) => Errors.REGISTRY[code].text));
const PLACEHOLDER = /\{(\w+)\}/g;

// A registry sentence with its {name} placeholders filled by params, as the module documents
function filled(code, params) {
    return Errors.REGISTRY[code].text.replace(PLACEHOLDER, (match, name) => String(params[name]));
}

// Parameters: none, random, or exactly the ones the code's sentence names
function params(r, code) {
    if (r.bool(0.3)) return r.value();
    const out = {};
    if (registered(code)) {
        for (const [, name] of Errors.REGISTRY[code].text.matchAll(PLACEHOLDER)) {
            if (r.bool(0.9)) out[name] = r.bool() ? r.int(0, 100) : r.string(r.int(0, 8));
        }
    }
    return out;
}

const someCode = (r) => (r.bool(0.7) ? r.pick(codes) : r.bool() ? r.mutate(r.pick(codes)) : r.value());

test('fromResult / fromApi: any answer maps to a registered code, never to the server\'s text', async () => {
    const edges = Object.keys(Errors.EDGE_CODES);
    await fuzz(SEED, ITERATIONS, (r) => {
        const data = r.bool(0.6)
            ? { success: false, message: r.bool() ? r.string() : r.value(), code: r.bool() ? r.mutate(r.pick(edges)) : r.value() }
            : r.value();
        const result = { ok: r.bool(), status: r.bool(0.8) ? r.pick(STATUSES) : r.value(), data, timedOut: r.value(0), tooLarge: r.value(0) };
        const code = Errors.fromResult(result);
        assert.ok(registered(code), `fromResult gave ${String(code)}`);
        assert.ok(registered(Errors.fromApi(r.value(), r.value(), r.value())));
        assert.ok(registered(Errors.fromApi(result.data && result.data.message, result.status, result.data && result.data.code)));
    });
});

test('message / notice: never throw; always a registry sentence or a notice', async () => {
    const notices = Object.values(Errors.NOTICE);
    await fuzz(SEED + 1, ITERATIONS, (r) => {
        const code = someCode(r);
        const p = params(r, code);
        const text = Errors.message(code, p);
        assert.equal(typeof text, 'string');
        if (!registered(code)) {
            assert.equal(text, Errors.REGISTRY.E_UNKNOWN_CODE.text);
        } else if (text !== Errors.REGISTRY.E_BAD_PARAMS.text) {
            assert.equal(text, filled(code, p), 'not the registered sentence filled with its parameters');
        }
        const pick = r.bool(0.7) ? r.pick(notices) : r.value();
        const shown = Errors.notice(pick, params(r, code));
        assert.equal(typeof shown, 'string');
        assert.ok(notices.includes(pick) || sentences.has(shown), 'an unknown notice shown as given');
    });
});

test('format: a filled sentence, or the module\'s own TypeError for an unknown code or a missing parameter', async () => {
    await fuzz(SEED + 2, ITERATIONS, (r) => {
        const code = someCode(r);
        const p = params(r, code);
        let text;
        try {
            text = Errors.format(code, p);
        } catch (error) {
            assert.ok(error instanceof ContextTypeError, `format threw ${error && error.name}`);
            return;
        }
        assert.ok(registered(code));
        assert.equal(text, filled(code, p));
    });
});
