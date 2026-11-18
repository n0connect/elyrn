// frontend/js/utils.js apiCall, loaded as the browser loads it (after js/log.js and js/errors.js),
// against a real local HTTP server. The page's fetch takes a same-origin path; here the one
// difference is that the path is resolved against the test server's origin.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import vm from 'node:vm';

// TextDecoder: apiCall reads every body itself, up to MAX_RESPONSE_BYTES, and decodes it
const context = vm.createContext({ AbortSignal, DOMException, Response, TextDecoder });
for (const file of ['../js/log.js', '../js/errors.js', '../js/utils.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const fn = (name) => vm.runInContext(name, context);
const Errors = fn('Errors');

// Answers every request with what the path asks for
function startServer() {
    const server = createServer((request, response) => {
        if (request.url.endsWith('/login')) {
            response.writeHead(401, { 'Content-Type': 'application/json' });
            response.end(JSON.stringify({ success: false, message: 'Invalid credentials' }));
        } else if (request.url.endsWith('/text')) {
            response.writeHead(500, { 'Content-Type': 'text/html' });
            response.end('<html>bad gateway</html>');
        } else {
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end('{not json');
        }
    });
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

function useOrigin(origin) {
    context.fetch = (path, options) => fetch(origin + path, options);
}

test('every request carries the timeout signal, and the timeout is bounded', () => {
    const timeout = fn('REQUEST_TIMEOUT_MS');
    assert.ok(Number.isSafeInteger(timeout) && timeout > 0);
    assert.ok(/signal:\s*AbortSignal\.timeout\(REQUEST_TIMEOUT_MS\)/.test(fn('apiCall').toString()));
});

test('an answer keeps its status and JSON; a body that is not JSON reads as null', async () => {
    const server = await startServer();
    try {
        useOrigin(`http://127.0.0.1:${server.address().port}`);
        const refused = await fn('apiCall')('POST', '/login', { auth_key: 'x' });
        assert.equal(refused.ok, false);
        assert.equal(refused.status, 401);
        assert.equal(refused.timedOut, false);
        assert.equal(Errors.fromResult(refused), Errors.CODES.E_API_INVALID_CREDENTIALS);

        const page = await fn('apiCall')('GET', '/text');
        assert.equal(page.status, 500);
        assert.equal(page.data, null);

        const broken = await fn('apiCall')('GET', '/broken');
        assert.equal(broken.ok, true);
        assert.equal(broken.data, null);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

test('no server: status 0, not a timeout, reported as unreachable', async () => {
    const server = await startServer();
    const origin = `http://127.0.0.1:${server.address().port}`;
    await new Promise(resolve => server.close(resolve));
    useOrigin(origin);
    const result = await fn('apiCall')('GET', '/me');
    assert.equal(result.ok, false);
    assert.equal(result.status, 0);
    assert.equal(result.timedOut, false);
    assert.equal(Errors.fromResult(result), Errors.CODES.E_SERVER_UNREACHABLE);
});

test('a timeout is no answer and says so', async () => {
    const cut = new DOMException('signal timed out', 'TimeoutError');
    const before = fn('noAnswer')(cut);
    assert.equal(before.status, 0);
    assert.equal(before.timedOut, true);
    assert.equal(Errors.fromResult(before), Errors.CODES.E_REQUEST_TIMEOUT);
    assert.equal(fn('noAnswer')(new TypeError('fetch failed')).timedOut, false);

    // A 204 is never read
    const empty = new Response(null, { status: 204, headers: { 'Content-Type': 'application/json' } });
    assert.equal(await fn('readBody')(empty), null);
});

// One body past the bound, served with its length declared (/huge) and streamed without one
// (/huge-stream), next to a body exactly at the bound that is still read
function startLargeServer(max) {
    const over = Buffer.alloc(max + 1, 0x61);
    const server = createServer((request, response) => {
        // The client stops reading past the bound: the cut connection is expected here
        request.socket.on('error', () => {});
        if (request.url.endsWith('/huge')) {
            response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(over.length) });
            response.end(over);
        } else if (request.url.endsWith('/huge-stream')) {
            response.writeHead(200, { 'Content-Type': 'application/json' });
            const step = 1024 * 1024;
            for (let offset = 0; offset < over.length; offset += step) {
                response.write(over.subarray(offset, offset + step));
            }
            response.end();
        } else {
            const body = JSON.stringify({ fill: 'a'.repeat(max - '{"fill":""}'.length) });
            response.writeHead(200, { 'Content-Type': 'application/json' });
            response.end(body);
        }
    });
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

test('an answer past MAX_RESPONSE_BYTES is refused unread, declared or streamed; one at the bound is read', async () => {
    const max = fn('MAX_RESPONSE_BYTES');
    assert.ok(Number.isSafeInteger(max) && max > 0);
    const server = await startLargeServer(max);
    try {
        useOrigin(`http://127.0.0.1:${server.address().port}`);
        for (const path of ['/huge', '/huge-stream']) {
            const refused = await fn('apiCall')('GET', path);
            assert.equal(refused.ok, false, path);
            assert.equal(refused.status, 0, path);
            assert.equal(refused.tooLarge, true, path);
            assert.equal(refused.timedOut, false, path);
            assert.equal(Errors.fromResult(refused), Errors.CODES.E_RESPONSE_TOO_LARGE, path);
        }
        const fits = await fn('apiCall')('GET', '/fits');
        assert.equal(fits.ok, true);
        assert.equal(fits.tooLarge, false);
        assert.equal(fits.data.fill.length, max - '{"fill":""}'.length);
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});

// A promise and the function that settles it, so a test decides when an action finishes
function gate() {
    let open;
    const promise = new Promise(resolve => { open = resolve; });
    return { promise, open };
}

test('once: a second press while the action runs is skipped; the key is free again after, even after a throw', async () => {
    const once = fn('once');
    let runs = 0;
    const first = gate();
    const running = once('k', async () => { runs++; await first.promise; return 'done'; });
    assert.equal(await once('k', async () => { runs++; }), undefined);
    // Another key is another action
    assert.equal(await once('other', async () => 'other'), 'other');
    first.open();
    assert.equal(await running, 'done');
    assert.equal(runs, 1);
    await assert.rejects(once('k', async () => { runs++; throw new Error('boom'); }));
    assert.equal(await once('k', async () => { runs++; return 'again'; }), 'again');
    assert.equal(runs, 3);
});

test('singleFlight: calls during a run share it and add exactly one run after it', async () => {
    const gates = [];
    let runs = 0;
    const refresh = fn('singleFlight')(async () => {
        runs++;
        const next = gate();
        gates.push(next);
        await next.promise;
    });
    const first = refresh();
    const second = refresh();
    const third = refresh();
    assert.equal(second, first);
    assert.equal(third, first);
    assert.equal(runs, 1);
    gates[0].open();
    // The follow-up starts only once the first run ended
    while (gates.length < 2) await new Promise(resolve => setImmediate(resolve));
    assert.equal(runs, 2);
    gates[1].open();
    await first;
    assert.equal(runs, 2);
    // Nothing in flight: the next call starts a new run
    const later = refresh();
    assert.notEqual(later, first);
    gates[2].open();
    await later;
    assert.equal(runs, 3);
});

// The watchdog's look as live-updates.js asks it: named fields, defaults a visible logged-in page with no
// poll yet; `over` replaces any of them
const HIDDEN_INTERVAL = 30000;
function look(over) {
    return fn('streamNeedsPolling')(Object.assign({
        now: 0, lastEventAt: 0, silenceLimitMs: 60000, visible: true, loggedIn: true,
        lastPollAt: -Infinity, hiddenIntervalMs: HIDDEN_INTERVAL
    }, over));
}

test('streamNeedsPolling: a logged-in visible page polls only once its stream was silent for the whole limit', () => {
    const limit = 60000;
    const at = (now, extra) => look(Object.assign({ now, lastEventAt: 1000, silenceLimitMs: limit }, extra));
    // An event inside the limit: the stream is delivering, nothing is fetched, visible or not
    assert.equal(at(1000), false);
    assert.equal(at(1000 + limit - 1), false);
    assert.equal(at(1000 + limit - 1, { visible: false }), false);
    // Silent for the whole limit, or longer: a visible page fetches at every look
    assert.equal(at(1000 + limit), true);
    assert.equal(at(1000 + 10 * limit), true);
    assert.equal(at(1000 + limit, { lastPollAt: 1000 + limit - 1 }), true);
    // Logged out: never, however long the silence
    assert.equal(at(10 * limit, { loggedIn: false }), false);
    assert.equal(at(10 * limit, { loggedIn: false, visible: false }), false);
    // Only true itself counts as logged in
    assert.equal(at(10 * limit, { loggedIn: 1 }), false);
});

test('streamNeedsPolling: a hidden page behind a silent stream polls once per hidden interval', () => {
    const limit = 60000;
    const now = 10 * limit;
    const hidden = (extra) => look(Object.assign({ now, lastEventAt: 0, silenceLimitMs: limit, visible: false }, extra));
    // No poll yet: due at once
    assert.equal(hidden({}), true);
    // A poll inside the interval: wait; at the interval or past it: due again
    assert.equal(hidden({ lastPollAt: now - 1 }), false);
    assert.equal(hidden({ lastPollAt: now - HIDDEN_INTERVAL + 1 }), false);
    assert.equal(hidden({ lastPollAt: now - HIDDEN_INTERVAL }), true);
    assert.equal(hidden({ lastPollAt: now - 10 * HIDDEN_INTERVAL }), true);
    // Only true itself counts as visible: anything else is held to the hidden interval
    assert.equal(hidden({ visible: 'visible', lastPollAt: now - 1 }), false);
    assert.equal(hidden({ visible: 1, lastPollAt: now - 1 }), false);
    // A stream that proves itself stops a hidden page's polls too
    assert.equal(hidden({ lastEventAt: now - 1 }), false);
});

test('streamNeedsPolling: anything that is no proof of a recent event or poll counts as none', () => {
    const limit = 60000;
    // An event later than now (a clock that went back) proves nothing
    assert.equal(look({ now: 1000, lastEventAt: 2000 }), true);
    for (const bad of [NaN, Infinity, -Infinity, undefined, null, '1000']) {
        assert.equal(look({ now: bad, lastEventAt: 1000 }), true, `now ${String(bad)}`);
        assert.equal(look({ now: 1000, lastEventAt: bad }), true, `last event ${String(bad)}`);
        assert.equal(look({ now: 1000, lastEventAt: 1000, silenceLimitMs: bad }), true, `limit ${String(bad)}`);
        // ...and a hidden page's last poll or interval that proves nothing makes the poll due
        assert.equal(look({ now: limit, visible: false, lastPollAt: bad }), true, `last poll ${String(bad)}`);
        assert.equal(look({ now: limit, visible: false, lastPollAt: limit - 1, hiddenIntervalMs: bad }), true, `interval ${String(bad)}`);
    }
    // A limit that is no positive number never lets the stream count as delivering
    assert.equal(look({ now: 1000, lastEventAt: 1000, silenceLimitMs: 0 }), true);
    assert.equal(look({ now: 1000, lastEventAt: 1000, silenceLimitMs: -1 }), true);
    // A poll later than now proves nothing either
    assert.equal(look({ now: limit, visible: false, lastPollAt: limit + 1 }), true);
});

// The watchdog's limits in live-updates.js against the heartbeat the server really sends, read from both
// sources: a new stream shows one heartbeat at once and must show it within the first-proof
// limit; a proven stream is allowed at least two heartbeats of silence before the page polls
test('the stream limits match the server\'s named heartbeats', () => {
    const live = readFileSync(new URL('../js/live-updates.js', import.meta.url), 'utf8');
    const events = readFileSync(new URL('../../backend/internal/handlers/events.go', import.meta.url), 'utf8');
    const seconds = (source, pattern) => {
        const found = source.match(pattern);
        assert.ok(found, `${pattern} moved or changed form`);
        return Number(found[1]);
    };
    const firstProof = seconds(live, /const STREAM_FIRST_PROOF_MS = (\d+) \* SECOND_MS;/);
    const limit = seconds(live, /const STREAM_SILENCE_LIMIT_MS = (\d+) \* SECOND_MS;/);
    const poll = seconds(live, /const POLL_INTERVAL_MS = (\d+) \* SECOND_MS;/);
    const hiddenPoll = seconds(live, /const HIDDEN_POLL_INTERVAL_MS = (\d+) \* SECOND_MS;/);
    const keepAlive = seconds(events, /sseKeepAlive = (\d+) \* time\.Second/);
    assert.ok(limit >= 2 * keepAlive, 'silence limit shorter than two heartbeats');
    // ...and shorter than three: a held stream is noticed as soon as two heartbeats are missing
    assert.ok(limit < 3 * keepAlive, 'silence limit waits past a third heartbeat before polling');
    assert.ok(firstProof > 0 && firstProof < keepAlive, 'the first proof must not wait for a periodic heartbeat');
    assert.ok(poll > 0 && poll <= firstProof, 'the watchdog looks less often than the first-proof limit');
    // A hidden page polls less often than a visible one, at a whole number of looks
    assert.ok(hiddenPoll > poll && hiddenPoll % poll === 0, 'the hidden interval is not a multiple of the look');
    // The heartbeat is a named event the page listens to, never a comment it cannot see, and the
    // first one follows the preamble at once (the preamble stays first: the agent waits for it)
    assert.match(events, /ssePing = "event: ping\\ndata: \{\}\\n\\n"/);
    assert.match(events, /sseRetryPreamble = "retry: 3000\\n: ready\\n\\n"/);
    assert.match(events, /if !write\(sseRetryPreamble \+ ssePing\) \{/);
    assert.match(live, /const STREAM_EVENTS = Object\.freeze\(\['ping', 'msg', 'conv'\]\);/);
});

test('pollDelayMs: polls answered with a server error back off, doubling, up to the cap', () => {
    const delay = fn('pollDelayMs');
    const BASE = 5000;
    const CAP = 60000;
    assert.equal(delay(0, BASE, CAP), BASE);
    assert.equal(delay(1, BASE, CAP), 2 * BASE);
    assert.equal(delay(2, BASE, CAP), 4 * BASE);
    assert.equal(delay(3, BASE, CAP), 8 * BASE);
    assert.equal(delay(4, BASE, CAP), CAP);
    assert.equal(delay(5000, BASE, CAP), CAP);
    assert.equal(delay(Number.MAX_SAFE_INTEGER, BASE, CAP), CAP);
    // Anything that is no count of answers is none
    for (const n of [-1, 0.5, NaN, Infinity, '3', null, undefined]) assert.equal(delay(n, BASE, CAP), BASE, String(n));
    // live-updates.js counts only 5xx answers while polling, resets on any success or stream event,
    // and arms its watchdog with this delay
    const live = readFileSync(new URL('../js/live-updates.js', import.meta.url), 'utf8');
    assert.match(live, /cause\.status >= HTTP_STATUS\.SERVER_ERROR\) \{\n\s+serverErrors\+\+;/);
    assert.match(live, /pollTimer = setTimeout\(watchStream, pollDelayMs\(serverErrors, POLL_INTERVAL_MS, POLL_BACKOFF_MAX_MS\)\);/);
    for (const reset of ['function endOutage', 'function noteStreamEvent', 'function stop']) {
        const at = live.indexOf(reset);
        assert.match(live.slice(at, live.indexOf('\n        }\n', at)), /serverErrors = 0;/, reset);
    }
});
