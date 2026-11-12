// frontend/validation.js loaded exactly as the browser loads it (after js/crypto.js).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
for (const file of ['../js/crypto.js', '../js/room-crypto.js', '../validation.js']) {
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
