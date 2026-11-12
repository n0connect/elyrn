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
