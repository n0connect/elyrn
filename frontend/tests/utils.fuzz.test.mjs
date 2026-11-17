// Fuzz: frontend/js/utils.js, loaded as the browser loads it (after log.js and errors.js).
// apiCall reads answers of random status, type, size and chunking from a real local node:http
// server, including bodies around MAX_RESPONSE_BYTES, declared or streamed; once and
// singleFlight run under random interleavings of calls and completions; streamNeedsPolling (the
// event stream watchdog's decision) is checked against an independent model.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { fuzz, load, plain } from './fuzz-helpers.mjs';

const SEED = 0x5eed0005;
const BODY_ITERATIONS = 300;
const BOUND_ITERATIONS = 6;
const INTERLEAVING_ITERATIONS = 500;
const MAX_STEPS = 40;
const MAX_SMALL_BODY = 4096;
const MAX_CHUNKS = 8;
const STATUSES = [200, 201, 204, 400, 401, 403, 404, 409, 413, 429, 500, 502, 503];
const TYPES = ['application/json', 'application/json; charset=utf-8', 'text/plain', 'text/html', ''];
const NO_BODY = 204;
const POLL_ITERATIONS = 5000;
// Times and limits the watchdog decision is fuzzed over, in milliseconds either side of zero
const POLL_SPAN = 600000;

const { context, get } = load({ AbortSignal, DOMException, Response, TextDecoder }, ['../js/log.js', '../js/errors.js', '../js/utils.js']);
const MAX = get('MAX_RESPONSE_BYTES');
const API_BASE_URL = get('API_BASE_URL');

// Each request path names a plan: { status, type, chunks, declare }
const plans = new Map();

function startServer() {
    const server = createServer((request, response) => {
        // The client stops reading past the bound: the cut connection is expected
        request.socket.on('error', () => {});
        const plan = plans.get(request.url.slice(API_BASE_URL.length));
        const headers = plan.type ? { 'Content-Type': plan.type } : {};
        const body = plan.status !== NO_BODY;
        if (plan.declare && body) headers['Content-Length'] = String(plan.chunks.reduce((n, c) => n + c.length, 0));
        response.writeHead(plan.status, headers);
        if (body) for (const chunk of plan.chunks) response.write(chunk);
        response.end();
    });
    return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// Splits bytes into up to MAX_CHUNKS random pieces
function chunked(r, bytes) {
    const cuts = Array.from({ length: r.int(0, MAX_CHUNKS - 1) }, () => r.int(0, bytes.length)).sort((a, b) => a - b);
    const out = [];
    let from = 0;
    for (const cut of cuts.concat(bytes.length)) {
        out.push(bytes.subarray(from, cut));
        from = cut;
    }
    return out;
}

// What readBody must make of a body that fits: its JSON for a JSON type, otherwise null
function expected(status, type, bytes) {
    if (status === NO_BODY || !type.includes('application/json')) return null;
    try {
        return JSON.parse(new TextDecoder().decode(bytes));
    } catch (error) {
        return null;
    }
}

async function withServer(body) {
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    context.fetch = (path, options) => fetch(origin + path, options);
    try {
        await body();
    } finally {
        await new Promise((resolve) => server.close(resolve));
    }
}

async function check(r, i, status, type, bytes) {
    const path = `/fuzz-${i}-${r.int(0, 1e9)}`;
    plans.set(path, { status, type, chunks: chunked(r, bytes), declare: r.bool() });
    try {
        // Fetch refuses a GET with a body before sending anything (TypeError), so only a POST
        // carries one, as every caller of apiCall does
        const method = r.pick(['GET', 'POST']);
        const body = method === 'POST' && r.bool() ? { k: r.string(r.int(0, 8)) } : undefined;
        const result = await get('apiCall')(method, path, body);
        if (bytes.length > MAX) {
            assert.deepEqual(plain(result), { ok: false, status: 0, data: null, timedOut: false, tooLarge: true });
            return;
        }
        assert.equal(result.status, status);
        assert.equal(result.ok, status >= 200 && status < 300);
        assert.equal(result.timedOut, false);
        assert.equal(result.tooLarge, false);
        assert.deepEqual(plain({ data: result.data }), plain({ data: expected(status, type, bytes) }));
    } finally {
        plans.delete(path);
    }
}

test('apiCall: any small answer is read whole, its JSON or null, whatever the chunking', async () => {
    await withServer(() => fuzz(SEED, BODY_ITERATIONS, async (r, i) => {
        const status = r.pick(STATUSES);
        const type = r.pick(TYPES);
        let bytes = new Uint8Array(0);
        if (status !== NO_BODY) {
            const text = r.bool(0.6) ? JSON.stringify(r.value(3)) ?? '' : r.string(r.int(0, MAX_SMALL_BODY));
            bytes = r.bool(0.9) ? new TextEncoder().encode(r.bool(0.8) ? text : r.mutate(text)) : r.bytes(r.int(0, MAX_SMALL_BODY));
        }
        await check(r, i, status, type, bytes);
    }));
});

test('apiCall: bodies around MAX_RESPONSE_BYTES are read up to the bound and refused past it', async () => {
    await withServer(() => fuzz(SEED + 1, BOUND_ITERATIONS, async (r, i) => {
        const bytes = new Uint8Array(MAX + r.int(-1, 1)).fill(0x61);
        await check(r, i, 200, 'application/json', bytes);
    }));
});

// A promise and the function that settles it, so the fuzzer decides when an action finishes
function gate() {
    let open;
    const promise = new Promise((resolve) => { open = resolve; });
    return { promise, open };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

test('once: one action per key at a time; a skipped press resolves undefined; keys free again after', async () => {
    await fuzz(SEED + 2, INTERLEAVING_ITERATIONS, async (r) => {
        const once = get('once');
        const keys = [`a${r.int(0, 1e9)}`, `b${r.int(0, 1e9)}`];
        const running = new Map(); // key -> { gate, call, value, fails }
        const inside = new Map();  // key -> actions of that key running now
        for (let step = 0; step < MAX_STEPS; step++) {
            const key = r.pick(keys);
            if (r.bool(0.6)) {
                const value = r.int(0, 1e6);
                const fails = r.bool(0.2);
                const g = gate();
                let entered = false;
                const call = once(key, async () => {
                    entered = true;
                    inside.set(key, (inside.get(key) || 0) + 1);
                    assert.equal(inside.get(key), 1, 'two actions of one key at once');
                    try {
                        await g.promise;
                        if (fails) throw new Error(`fail ${value}`);
                        return value;
                    } finally {
                        inside.set(key, inside.get(key) - 1);
                    }
                });
                if (running.has(key)) {
                    assert.equal(entered, false, 'a press ran while its key was taken');
                    assert.equal(await call, undefined);
                } else {
                    assert.equal(entered, true, 'the action did not start at once');
                    running.set(key, { gate: g, call, value, fails });
                }
            } else if (running.has(key)) {
                const { gate: g, call, value, fails } = running.get(key);
                running.delete(key);
                g.open();
                if (fails) await assert.rejects(call);
                else assert.equal(await call, value);
            }
        }
        for (const { gate: g, call } of running.values()) {
            g.open();
            await call.catch(() => {});
        }
    });
});

test('singleFlight: runs never overlap, and every call awaits a run that started after it', async () => {
    await fuzz(SEED + 3, INTERLEAVING_ITERATIONS, async (r) => {
        let tick = 0;
        let active = 0;
        const starts = [];
        const gates = [];
        const refresh = get('singleFlight')(async () => {
            assert.equal(active, 0, 'two runs at once');
            active++;
            starts.push(++tick);
            const g = gate();
            gates.push(g);
            await g.promise;
            active--;
        });
        const settled = [];
        const unserved = []; // ticks of calls that settled without a run started after them
        let calls = 0;
        const openNext = async () => {
            const g = gates.shift();
            if (g) g.open();
            await flush();
        };
        for (let step = 0; step < MAX_STEPS; step++) {
            if (r.bool(0.6)) {
                const at = ++tick;
                calls++;
                settled.push(refresh().then(() => {
                    if (!starts.some((start) => start > at)) unserved.push(at);
                }));
            } else {
                await openNext();
            }
        }
        while (gates.length > 0 || active > 0) await openNext();
        await Promise.all(settled);
        assert.deepEqual(unserved, [], 'calls settled without a run started after them');
        assert.ok(starts.length <= calls, `${starts.length} runs for ${calls} calls`);
    });
});

test('streamNeedsPolling: matches an independent model on random times, limits and states', async () => {
    const needs = get('streamNeedsPolling');
    const odd = [NaN, Infinity, -Infinity, undefined, null, '5', {}, -0];
    const number = (r) => (r.bool(0.1) ? r.pick(odd) : r.int(-POLL_SPAN, POLL_SPAN));
    const flag = (r) => (r.bool(0.1) ? r.pick([1, 'true', null, undefined]) : r.bool());
    const finite = (v) => typeof v === 'number' && Number.isFinite(v);
    // The model: `at` provably lies less than `limit` before `now`
    const proven = (now, at, limit) => [now, at, limit].every(finite) && limit > 0 && at <= now && now - at < limit;
    const before = (r, now) => (r.bool(0.3) && Number.isFinite(now) ? now - r.int(0, POLL_SPAN) : number(r));
    await fuzz(SEED + 4, POLL_ITERATIONS, async (r) => {
        const look = {
            now: number(r), silenceLimitMs: number(r), visible: flag(r), loggedIn: flag(r), hiddenIntervalMs: number(r)
        };
        look.lastEventAt = before(r, look.now);
        look.lastPollAt = r.bool(0.1) ? -Infinity : before(r, look.now);
        const got = needs(look);
        assert.equal(typeof got, 'boolean');
        // Never for a page logged out, nor while an event provably lies inside the limit; then
        // always for a visible page, and for a hidden one unless a poll provably lies inside the
        // hidden interval
        const silent = look.loggedIn === true && !proven(look.now, look.lastEventAt, look.silenceLimitMs);
        const want = silent && (look.visible === true || !proven(look.now, look.lastPollAt, look.hiddenIntervalMs));
        assert.equal(got, want, JSON.stringify(look, (k, v) => (typeof v === 'number' && !Number.isFinite(v) ? String(v) : v)));
        // A hidden page never polls more than a visible one would
        if (got && look.visible !== true) assert.equal(needs({ ...look, visible: true }), true);
        // Monotone in time: once a page polls, a later look with no new event or poll polls too
        // (a poll stamped after now could come to lie inside the interval: no proof either way)
        const pastPoll = look.visible === true || !finite(look.lastPollAt) || look.lastPollAt <= look.now;
        if (got && pastPoll && [look.now, look.lastEventAt, look.silenceLimitMs].every(finite) &&
            look.silenceLimitMs > 0 && look.lastEventAt <= look.now) {
            assert.equal(needs({ ...look, now: look.now + r.int(0, POLL_SPAN) }), true);
        }
    });
});
