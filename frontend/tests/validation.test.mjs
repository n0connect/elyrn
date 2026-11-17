// frontend/validation.js loaded exactly as the browser loads it (after js/crypto.js).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
for (const file of ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const neutralize = (text) => vm.runInContext('neutralizeReceivedText', context)(text);

// The sender's client refuses these characters, but a modified client can still encrypt
// them: the receiver must not let bidi overrides reorder what it displays.
test('received text: bidi overrides and control characters become U+FFFD', () => {
    const cases = {
        'pay ‮txt.exe': 'pay �txt.exe',
        'a⁦b⁩c': 'a�b�c',
        'bell\u0007 nul\u0000': 'bell� nul�',
        'c1\u0085x\u009F': 'c1�x�',
    };
    for (const [input, want] of Object.entries(cases)) {
        assert.equal(neutralize(input), want);
    }
});

test('received text: newlines, tabs, emoji and right-to-left scripts are untouched', () => {
    for (const text of ['line one\nline two', 'col\tcol', 'merhaba 👋 <b>&', 'שלום עולם', 'مرحبا']) {
        assert.equal(neutralize(text), text);
    }
});

test('the join field tells invite codes and room codes apart, and refuses everything else', () => {
    const validate = vm.runInContext('validateJoinCode', context);
    const R = vm.runInContext('ElyrnRoomCrypto', context);
    const room = R.buildRoomCode(R.newRoomCode(4, 500000));
    const parsed = validate('  ' + room + '\n');
    assert.equal(parsed.valid, true);
    assert.equal(parsed.kind, 'room');
    assert.equal(parsed.sanitized.maxMembers, 4);
    const invite = 'noaddx:' + 'A'.repeat(43);
    assert.equal(validate(invite).kind, 'invite');
    for (const bad of ['', '   ', room.slice(0, -1), room + 'A', 'noaddx#hello', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8']) {
        assert.equal(validate(bad).valid, false, `accepted ${JSON.stringify(bad)}`);
    }
});

test('the robot entrance builds its command only from an http(s) origin', () => {
    const build = vm.runInContext('buildAgentCommand', context);
    const cases = {
        'https://elyrn.example': 'elyrn-agent mcp --server https://elyrn.example',
        'http://localhost:8080': 'elyrn-agent mcp --server http://localhost:8080',
        'http://[::1]:3000': 'elyrn-agent mcp --server http://[::1]:3000',
        'http://abcdefghijklmnop.onion': 'elyrn-agent mcp --server http://abcdefghijklmnop.onion',
    };
    for (const [origin, want] of Object.entries(cases)) {
        assert.equal(build(origin), want);
    }
    for (const bad of [undefined, null, 42, '', 'null', 'file://', 'ftp://host', 'javascript:alert(1)',
        'https://host/path', 'https://host?x=1', 'https://host; rm -rf ~', 'https://host\n--evil', 'https://HOST',
        'https://host:', 'https://host:123456', 'https://user@host']) {
        assert.equal(build(bad), '', `accepted ${JSON.stringify(bad)}`);
    }
});

// ---------- member roles: the one rule, before sealing and after opening ----------

const validateRole = (text) => vm.runInContext('validateRoleText', context)(text);
const isRole = (text) => vm.runInContext('isRoleText', context)(text);
const ROLE_CODES = vm.runInContext('Errors.CODES', context);

test('a role is 1 to 16 letters, digits, - or _, kept in NFC and in its own case', () => {
    for (const text of ['lider', 'Komutan', 'Kâşif-7_ü', 'x'.repeat(16), '𝔸'.repeat(16), '日本語', 'ｌｉｄｅｒ', '٣٤', 'о-wner', 'оwner']) {
        const checked = validateRole(text);
        assert.equal(checked.valid, true, text);
        assert.equal(checked.value, text.normalize('NFC'));
        assert.equal(isRole(text), true, text);
    }
    // Typed decomposed, sealed composed; only the composed form passes when it is opened
    const decomposed = 'u\u0308ber';
    assert.equal(validateRole(decomposed).value, 'über');
    assert.equal(isRole(decomposed), false);
    assert.equal(isRole('über'), true);
});

test('a role is refused with the reason: empty, too long, a character outside the rule, a reserved word', () => {
    const cases = [
        ['', ROLE_CODES.E_ROLE_EMPTY], ['x'.repeat(17), ROLE_CODES.E_ROLE_TOO_LONG], ['🙂'.repeat(17), ROLE_CODES.E_ROLE_TOO_LONG],
        ['#lider', ROLE_CODES.E_ROLE_CHARS], ['li der', ROLE_CODES.E_ROLE_CHARS], [' lider', ROLE_CODES.E_ROLE_CHARS],
        ['<b>x</b>', ROLE_CODES.E_ROLE_CHARS], ['a.b', ROLE_CODES.E_ROLE_CHARS], ['lider\u202e', ROLE_CODES.E_ROLE_CHARS],
        ['li\u200bder', ROLE_CODES.E_ROLE_CHARS], ['🙂', ROLE_CODES.E_ROLE_CHARS], ['a\u0000', ROLE_CODES.E_ROLE_CHARS],
        // reserved: compared after NFKC and lowercasing (fullwidth, mixed case)
        ['owner', ROLE_CODES.E_ROLE_RESERVED], ['you', ROLE_CODES.E_ROLE_RESERVED], ['OwNeR', ROLE_CODES.E_ROLE_RESERVED],
        ['YOU', ROLE_CODES.E_ROLE_RESERVED], ['ｏｗｎｅｒ', ROLE_CODES.E_ROLE_RESERVED], ['ＹＯＵ', ROLE_CODES.E_ROLE_RESERVED],
        [5, ROLE_CODES.E_ROLE_INVALID], [null, ROLE_CODES.E_ROLE_INVALID], [undefined, ROLE_CODES.E_ROLE_INVALID], [['x'], ROLE_CODES.E_ROLE_INVALID]
    ];
    for (const [text, code] of cases) {
        const checked = validateRole(text);
        assert.equal(checked.valid, false, JSON.stringify(text));
        assert.equal(checked.error, code, JSON.stringify(text));
        assert.equal(checked.value, '');
        assert.equal(isRole(text), false, JSON.stringify(text));
    }
    assert.deepEqual({ ...validateRole('x'.repeat(17)).params }, { max: 16 });
});

test('the role rule agrees with the Go side\'s own cases (vectors from backend/internal/e2e)', () => {
    // vectors-go.json role_text_rule, 17 Nov 2026: Go folds with full Unicode case folding, the
    // browser lowercases; for the reserved words the two agree
    for (const text of ['ｏｗｎｅｒ', 'ＹＯＵ', 'OwNeR', 'owner']) {
        assert.equal(validateRole(text).error, ROLE_CODES.E_ROLE_RESERVED, text);
    }
    for (const text of ['ｌｉｄｅｒ', 'über', 'оwner']) {
        assert.equal(validateRole(text).value, text, text);
    }
});
