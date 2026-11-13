// Negative use at the input fields: what a careless, confused or hostile user types or pastes
// into the account number, invite / room code, message and door answer fields. The real
// modules (validation.js, crypto.js, room-crypto.js, robot-door.js) are loaded as the browser
// loads them; every refusal is asserted by its exact registered code.
// The DOM-bound part of each flow (which field shows the code) is in the manual negative-use tour,
// docs/development/testing-and-contributing.md.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { load, goAccountNumberSamples } from './fuzz-helpers.mjs';
import { ACCOUNT_A, ACCOUNT_B, MARKUP, fullwidth, homoglyph } from './negative-helpers.mjs';

const { context, get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js']);
const Errors = get('Errors');
const C = get('ElyrnCrypto');
const R = get('ElyrnRoomCrypto');
const CODES = Errors.CODES;
const parseAccountNumber = get('parseAccountNumber');
const validateInviteCode = get('validateInviteCode');
const validateJoinCode = get('validateJoinCode');
const validateMessageText = get('validateMessageText');
const RobotDoor = vm.runInContext(
    readFileSync(new URL('../js/robot-door.js', import.meta.url), 'utf8') + '\n;RobotDoor', context);

const MAX_MESSAGE_CHARS = get('MAX_MESSAGE_CHARS');
const INVITE_TOKEN_BYTES = 16;
// A room code valid for a day, and one whose hour has passed
const HOUR_MS = R.HOUR_MS;
const SEATS = 4;
const freshRoomCode = () => R.buildRoomCode(R.newRoomCode(SEATS, R.expiryHourFor(24, Date.now())));
const expiredRoomCode = () => R.buildRoomCode(R.newRoomCode(SEATS, Math.floor(Date.now() / HOUR_MS) - 1));

async function inviteFor(publicKey) {
    const token = C.b64urlEncode(crypto.getRandomValues(new Uint8Array(INVITE_TOKEN_BYTES)));
    return C.buildInviteCode(token, publicKey);
}

// Every whitespace a paste can carry around a value
const PADDING = [' ', '\t', '\n', '\r\n', ' ', '　', '﻿'];
const BLANKS = ['', ' ', '   \t\n', '　', ' ﻿\r\n'];

// ---------- the login field (and the delete field, which reads it the same way) ----------

test('login field: empty or whitespace only is E_LOGIN_EMPTY; a non-string is too', () => {
    for (const input of [...BLANKS, undefined, null, 42, {}, []]) {
        const parsed = parseAccountNumber(input);
        assert.equal(parsed.valid, false, JSON.stringify(input));
        assert.equal(parsed.error, CODES.E_LOGIN_EMPTY, JSON.stringify(input));
        assert.equal(parsed.value, '');
    }
});

test('login field: over-length, short, wrong alphabet, padding, inner whitespace and homoglyphs are E_LOGIN_FORMAT', () => {
    const cases = [
        ACCOUNT_A + 'A', ACCOUNT_A.slice(0, -1), 'x'.repeat(100000),
        ACCOUNT_A.slice(0, 10) + '+' + ACCOUNT_A.slice(11),   // standard base64, not base64url
        ACCOUNT_A.slice(0, 10) + '/' + ACCOUNT_A.slice(11),
        ACCOUNT_A + '=',                                       // padding
        ACCOUNT_A.slice(0, 20) + '\n' + ACCOUNT_A.slice(20),   // pasted across two lines
        ACCOUNT_A + '\n' + ACCOUNT_B,                          // two numbers pasted at once
        ACCOUNT_A.slice(0, 20) + '​' + ACCOUNT_A.slice(21),  // zero-width space inside
        homoglyph(ACCOUNT_A),                                  // Cyrillic А for Latin A
        ...MARKUP
    ];
    for (const input of cases) {
        const parsed = parseAccountNumber(input);
        assert.equal(parsed.error, CODES.E_LOGIN_FORMAT, JSON.stringify(input).slice(0, 80));
        assert.equal(parsed.value, '', 'a refused number is never handed back');
    }
});

test('login field: surrounding whitespace and fullwidth look-alikes read as the same number', () => {
    for (const pad of PADDING) {
        assert.deepEqual({ ...parseAccountNumber(pad + ACCOUNT_A + pad) }, { valid: true, value: ACCOUNT_A, error: '' });
    }
    // NFKC folds fullwidth digits, letters, '-' and '_' back to ASCII: the same account
    assert.equal(parseAccountNumber(fullwidth(ACCOUNT_A)).value, ACCOUNT_A);
    assert.equal(parseAccountNumber(' ' + fullwidth(ACCOUNT_B) + '\n').value, ACCOUNT_B);
});

test('login field: an invite or a room code pasted there is E_LOGIN_INVITE_PASTED, under every prefix and look-alike', async () => {
    const invite = await inviteFor((await C.deriveIdentity(ACCOUNT_B)).publicKey);
    const body = invite.slice(C.INVITE_PREFIX.length);
    const room = freshRoomCode();
    const roomBody = room.slice(R.CODE_PREFIX.length);
    const cases = [
        ...C.INVITE_PREFIXES.map(prefix => prefix + body),
        ...R.CODE_PREFIXES.map(prefix => prefix + roomBody),
        ' ' + invite + '\n', fullwidth(invite), fullwidth(room), expiredRoomCode()
    ];
    for (const input of cases) {
        assert.equal(parseAccountNumber(input).error, CODES.E_LOGIN_INVITE_PASTED, input);
    }
});

// ---------- the join field (invite or room code) ----------

test('join field: empty or whitespace only is E_JOIN_CODE_EMPTY (E_INVITE_EMPTY where only an invite is read)', () => {
    for (const input of [...BLANKS, undefined, null, 7]) {
        assert.equal(validateJoinCode(input).error, CODES.E_JOIN_CODE_EMPTY, JSON.stringify(input));
        assert.equal(validateInviteCode(input).error, CODES.E_INVITE_EMPTY, JSON.stringify(input));
    }
});

test('join field: an account number is E_INVITE_IS_ACCOUNT_NUMBER, padded or as a fullwidth look-alike, and never handed back', () => {
    for (const input of [ACCOUNT_A, ' ' + ACCOUNT_A + '\n', '　' + ACCOUNT_B, fullwidth(ACCOUNT_A), fullwidth(' ' + ACCOUNT_B)]) {
        for (const result of [validateJoinCode(input), validateInviteCode(input)]) {
            assert.equal(result.valid, false);
            assert.equal(result.error, CODES.E_INVITE_IS_ACCOUNT_NUMBER, JSON.stringify(input));
            assert.equal(result.sanitized, null, 'the number is not carried on toward a request');
        }
    }
});

test('join field: a room code where only an invite is read is E_INVITE_INVALID; each kind is told apart where both are read', async () => {
    const room = freshRoomCode();
    const invite = await inviteFor((await C.deriveIdentity(ACCOUNT_B)).publicKey);
    assert.equal(validateInviteCode(room).error, CODES.E_INVITE_INVALID);
    const asRoom = validateJoinCode(room);
    assert.equal(asRoom.valid, true);
    assert.equal(asRoom.kind, 'room');
    const asInvite = validateJoinCode(invite);
    assert.equal(asInvite.valid, true);
    assert.equal(asInvite.kind, 'invite');
});

test('join field: over-length, truncated, wrong alphabet, multi-line, look-alike and markup codes are refused by kind', async () => {
    const invite = await inviteFor((await C.deriveIdentity(ACCOUNT_B)).publicKey);
    const room = freshRoomCode();
    const flipChar = (text, at, ch) => text.slice(0, at) + ch + text.slice(at + 1);
    const inviteCases = [
        invite + 'A', invite.slice(0, -1), flipChar(invite, invite.length - 5, '+'),
        invite + '\n' + invite, invite.slice(0, 20) + '\n' + invite.slice(20),
        fullwidth(invite),                       // fullwidth prefix: not read as an invite at all
        homoglyph(invite),                       // Cyrillic е in the prefix
        C.INVITE_PREFIX, C.INVITE_PREFIX + ' ',  // the prefix alone
        ...MARKUP, C.INVITE_PREFIX + MARKUP[0]
    ];
    for (const input of inviteCases) {
        const result = validateJoinCode(input);
        assert.equal(result.error, CODES.E_INVITE_INVALID, JSON.stringify(input).slice(0, 80));
        assert.equal(result.sanitized, null);
    }
    const roomCases = [room + 'A', room.slice(0, -1), flipChar(room, room.length - 3, '/'), room + '\n' + room,
        R.CODE_PREFIX, R.CODE_PREFIX + MARKUP[1]];
    for (const input of roomCases) {
        const result = validateJoinCode(input);
        assert.equal(result.kind, 'room');
        assert.equal(result.error, CODES.E_ROOM_CODE_INVALID, JSON.stringify(input).slice(0, 80));
    }
});

test('join field: surrounding whitespace is dropped and the same token or room is read', async () => {
    const invite = await inviteFor((await C.deriveIdentity(ACCOUNT_B)).publicKey);
    const room = freshRoomCode();
    const token = validateJoinCode(invite).sanitized.token;
    const secret = [...validateJoinCode(room).sanitized.secret];
    for (const pad of PADDING) {
        assert.equal(validateJoinCode(pad + invite + pad).sanitized.token, token);
        assert.deepEqual([...validateJoinCode(pad + room + pad).sanitized.secret], secret);
    }
});

test('join field: the user\'s own invite is recognised by its fingerprint (chat.js then reports W_OWN_INVITE)', async () => {
    const mine = (await C.deriveIdentity(ACCOUNT_A)).publicKey;
    const theirs = (await C.deriveIdentity(ACCOUNT_B)).publicKey;
    const own = validateInviteCode(await inviteFor(mine)).sanitized;
    assert.equal(await C.fingerprintMatches(own, mine), true);
    assert.equal(await C.fingerprintMatches(own, theirs), false);
    assert.ok(Errors.REGISTRY[CODES.W_OWN_INVITE]);
});

test('join field: an expired room code still parses; its hour is past, which chat.js reports as E_ROOM_CODE_EXPIRED', () => {
    const parsed = validateJoinCode(expiredRoomCode());
    assert.equal(parsed.valid, true);
    assert.ok(parsed.sanitized.expiresHour * HOUR_MS <= Date.now());
    assert.ok(Errors.REGISTRY[CODES.E_ROOM_CODE_EXPIRED]);
});

// ---------- the composer ----------

test('composer: empty or whitespace only is E_MESSAGE_EMPTY', () => {
    for (const input of [...BLANKS, '\r\n\r\n', '  ']) {
        assert.equal(validateMessageText(input).error, CODES.E_MESSAGE_EMPTY, JSON.stringify(input));
    }
    assert.equal(validateMessageText(undefined).error, CODES.E_MESSAGE_INVALID);
    assert.equal(validateMessageText({ toString: () => 'hi' }).error, CODES.E_MESSAGE_INVALID);
});

test('composer: one character over the limit is E_MESSAGE_TOO_MANY_CHARS with its limit, counted in characters', () => {
    for (const input of ['a'.repeat(MAX_MESSAGE_CHARS + 1), '😀'.repeat(MAX_MESSAGE_CHARS + 1), 'x'.repeat(1000000)]) {
        const result = validateMessageText(input);
        assert.equal(result.error, CODES.E_MESSAGE_TOO_MANY_CHARS);
        assert.equal(Errors.message(result.error, result.params), `max ${MAX_MESSAGE_CHARS} characters`);
    }
    // Within the character limit yet over the encrypted frame (4 bytes each): E_MESSAGE_TOO_LONG
    assert.equal(validateMessageText('😀'.repeat(MAX_MESSAGE_CHARS)).error, CODES.E_MESSAGE_TOO_LONG);
    assert.equal(validateMessageText('a'.repeat(MAX_MESSAGE_CHARS)).valid, true);
});

test('composer: control characters and bidi overrides are E_MESSAGE_CONTROL_CHARS', () => {
    for (const input of ['a\u0000b', 'bell\u0007', 'pay ‮txt.exe', 'x⁦y⁩', 'c1\u0085']) {
        assert.equal(validateMessageText(input).error, CODES.E_MESSAGE_CONTROL_CHARS, JSON.stringify(input));
    }
});

test('composer: an account number anywhere in the message is E_MESSAGE_IS_ACCOUNT_NUMBER, so it is never sent', () => {
    const cases = [
        ACCOUNT_A, '  ' + ACCOUNT_A + '\n', 'my number is ' + ACCOUNT_A + ' keep it safe',
        'line one\n' + ACCOUNT_B + '\nline three', fullwidth(ACCOUNT_A), 'here:\t' + fullwidth(ACCOUNT_B)
    ];
    for (const input of cases) {
        const result = validateMessageText(input);
        assert.equal(result.error, CODES.E_MESSAGE_IS_ACCOUNT_NUMBER, JSON.stringify(input));
        assert.equal(result.sanitized, '', 'the number is not handed on toward encryption');
    }
});

// One table pins both sides: the agent's ValidateMessageText (backend/internal/agent/fuzz_test.go
// accountNumberSamples, read from the Go source) refuses exactly the rows the browser refuses
test('composer: the agent\'s account-number samples are refused or sent here exactly as there', () => {
    const samples = goAccountNumberSamples();
    assert.ok(samples.some(([, refused]) => refused) && samples.some(([, refused]) => !refused));
    for (const [text, refused] of samples) {
        const result = validateMessageText(text);
        if (refused) {
            assert.equal(result.error, CODES.E_MESSAGE_IS_ACCOUNT_NUMBER, JSON.stringify(text));
            assert.equal(result.sanitized, '');
        } else {
            assert.equal(result.valid, true, `${JSON.stringify(text)} refused: ${result.error}`);
        }
    }
});

test('composer: invites, room codes, near-misses and markup are sent as plain text', async () => {
    const invite = await inviteFor((await C.deriveIdentity(ACCOUNT_B)).publicKey);
    const cases = [invite, 'join me: ' + freshRoomCode(), ACCOUNT_A + 'A', ACCOUNT_A.slice(0, -1),
        'a\r\nb', ...MARKUP];
    for (const input of cases) {
        const result = validateMessageText(input);
        assert.equal(result.valid, true, `${JSON.stringify(input)} refused: ${result.error}`);
    }
    // Markup stays text: the composer neither escapes nor strips it (ui.js renders textContent only)
    assert.equal(validateMessageText(MARKUP[0]).sanitized, MARKUP[0]);
    assert.equal(validateMessageText('  a\r\nb  ').sanitized, 'a\nb');
});

// ---------- the robot door's answer field (theatre: checked in the page, nothing is sent) ----------

test('door answer: blank, padded junk, multi-line, over-length, look-alike or an account number never pass; the right answer does', async () => {
    const nonce = RobotDoor.newNonce();
    const right = await RobotDoor.expectedAnswer(nonce);
    for (const input of [...BLANKS, right + '0', right.slice(0, -1), right + '\n' + right, fullwidth(right),
        ACCOUNT_A, MARKUP[0], undefined, null]) {
        assert.equal(await RobotDoor.checkAnswer(nonce, input), false, JSON.stringify(input));
    }
    for (const input of [right, ' ' + right + '\n', right.toUpperCase()]) {
        assert.equal(await RobotDoor.checkAnswer(nonce, input), true, JSON.stringify(input));
    }
});
