// frontend/js/utils.js apiCall, loaded as the browser loads it (after js/log.js and js/errors.js),
// against a real local HTTP server. The page's fetch takes a same-origin path; here the one
// difference is that the path is resolved against the test server's origin.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import vm from 'node:vm';

const context = vm.createContext({ AbortSignal, DOMException, Response });
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
