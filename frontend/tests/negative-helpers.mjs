// Shared by the negative-use tests (negative-*.test.mjs): a hostile elyrn server played by a
// real node:http server, the public test accounts, and look-alike text builders. Nothing here
// stands in for a module under test; the modules are loaded as the browser loads them.
import { createServer } from 'node:http';

// Public test-account vectors (the same as crypto.test.mjs and room-crypto.test.mjs); never real accounts
export const ACCOUNT_A = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
export const ACCOUNT_B = 'HxwdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
export const ACCOUNT_C = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8';
export const ACCOUNT_D = 'QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8';

// Markup and header text a hostile server or peer puts in any string field
export const MARKUP = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'Set-Cookie: session=stolen; Path=/',
    '"><svg onload=alert(1)>',
    'javascript:alert(1)'
];

// ASCII to its fullwidth look-alike (U+FF01..U+FF5E): NFKC folds it back
const FULLWIDTH_OFFSET = 0xfee0;
export function fullwidth(text) {
    return text.replace(/[\x21-\x7e]/g, (ch) => String.fromCharCode(ch.charCodeAt(0) + FULLWIDTH_OFFSET));
}

// Latin letters to the Cyrillic letters drawn the same: NFKC keeps them apart
const HOMOGLYPHS = { A: 'А', a: 'а', e: 'е', o: 'о', c: 'с', p: 'р', x: 'х' };
export function homoglyph(text) {
    const at = [...text].findIndex((ch) => Object.prototype.hasOwnProperty.call(HOMOGLYPHS, ch));
    if (at < 0) throw new Error('no letter with a homoglyph');
    return text.slice(0, at) + HOMOGLYPHS[text[at]] + text.slice(at + 1);
}

// A hostile server: every request is recorded ({ method, path, body }) and answered by the
// current script, which returns { status, body } (JSON), { status, text, type } (anything else)
// or { drop: true } (the connection is cut: the client gets no answer)
export async function startHostileServer() {
    const requests = [];
    let script = () => ({ status: 404, body: { success: false, message: 'not found' } });
    const server = createServer((request, response) => {
        let raw = '';
        request.setEncoding('utf8');
        request.on('data', (chunk) => { raw += chunk; });
        request.on('end', () => {
            const seen = { method: request.method, path: request.url, body: raw };
            requests.push(seen);
            const answer = script(seen);
            if (answer.drop) {
                request.socket.destroy();
                return;
            }
            const json = answer.text === undefined;
            response.writeHead(answer.status, { 'Content-Type': json ? 'application/json' : answer.type });
            response.end(json ? JSON.stringify(answer.body) : answer.text);
        });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return {
        origin: `http://127.0.0.1:${server.address().port}`,
        requests,
        answer: (next) => { script = next; },
        close: () => new Promise((resolve) => server.close(resolve))
    };
}

// The page's same-origin fetch, resolved against the hostile server (as utils.test.mjs does)
export function useServer(context, origin) {
    context.fetch = (path, options) => fetch(origin + path, options);
}
