// Fuzz: frontend/validation.js, loaded as the browser loads it, with generated strings (ASCII,
// controls, bidi, zero-width, every space, lone surrogates, astral, huge) and mutated valid
// codes. Where the server has the same rule (backend/internal/contract/patterns.go), the
// browser's acceptance is checked against the Go expression itself.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load, goPatterns, goBase64Exact } from './fuzz-helpers.mjs';

const SEED = 0x5eed0001;
const MESSAGE_ITERATIONS = 3000;
const CODE_ITERATIONS = 3000;
const ID_ITERATIONS = 5000;
const ORIGIN_ITERATIONS = 3000;
const MAX_MESSAGE_CHARS = 2000;
// crypto.js INVITE_TOKEN_BYTES and the server's utils.InviteTokenBytes
const INVITE_TOKEN_BYTES = 16;
// What a command copied into a shell may hold: an origin, never a shell metacharacter
const SHELL_SAFE_ORIGIN = /^[a-z0-9:/.[\]-]+$/;

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js']);
const Errors = get('Errors');
const C = get('ElyrnCrypto');
const R = get('ElyrnRoomCrypto');
const FORBIDDEN = get('FORBIDDEN_TEXT_CHARS');
const go = goPatterns();
const GO_UUID = new RegExp(go.exprUUIDv4);

const registered = (code) => typeof code === 'string' && Object.prototype.hasOwnProperty.call(Errors.REGISTRY, code);

// A valid invite or room code, under a random prefix choice, for the mutator to start from
function validCode(r) {
    if (r.bool()) {
        return r.pick(C.INVITE_PREFIXES) + C.b64urlEncode(r.bytes(32));
    }
    const code = { secret: r.bytes(32), maxMembers: r.int(R.MIN_MEMBERS, R.MAX_MEMBERS), expiresHour: r.int(1, 0xffffffff) };
    return r.pick(R.CODE_PREFIXES) + R.buildRoomCode(code).slice(R.CODE_PREFIX.length);
}

test('validateMessageText: never throws; what it accepts is clean, bounded and re-validates to itself', async () => {
    const validate = get('validateMessageText');
    await fuzz(SEED, MESSAGE_ITERATIONS, (r) => {
        const input = r.bool(0.9) ? r.string() : r.value();
        const result = validate(input);
        if (!result.valid) {
            assert.equal(result.sanitized, '');
            assert.ok(registered(result.error), `unregistered code ${result.error}`);
            return;
        }
        const text = result.sanitized;
        const chars = [...text].length;
        assert.ok(chars >= 1 && chars <= MAX_MESSAGE_CHARS, `${chars} characters accepted`);
        assert.equal(FORBIDDEN.test(text), false, 'a forbidden character was accepted');
        assert.equal(text.includes('\r'), false);
        assert.equal(text.trim(), text);
        assert.equal(result.error, '');
        const again = validate(text);
        assert.equal(again.valid, true);
        assert.equal(again.sanitized, text);
    });
});

test('neutralizeReceivedText: never throws, leaves no forbidden character, one for one and idempotent', async () => {
    const neutralize = get('neutralizeReceivedText');
    await fuzz(SEED + 1, MESSAGE_ITERATIONS, (r) => {
        const input = r.bool(0.9) ? r.string() : r.value();
        const shown = neutralize(input);
        assert.equal(typeof shown, 'string');
        assert.equal(FORBIDDEN.test(shown), false);
        assert.equal(shown.length, String(input).length, 'not a one-for-one replacement');
        assert.equal(neutralize(shown), shown);
        if (!FORBIDDEN.test(String(input))) assert.equal(shown, String(input));
    });
});

test('validateInviteCode / validateJoinCode: never throw; accepted codes are canonical and round-trip', async () => {
    const validateInvite = get('validateInviteCode');
    const validateJoin = get('validateJoinCode');
    const looksLikeAccountNumber = get('looksLikeAccountNumber');
    const goToken = goBase64Exact(go, INVITE_TOKEN_BYTES);
    await fuzz(SEED + 2, CODE_ITERATIONS, (r) => {
        const roll = r.next();
        const input = roll < 0.6 ? r.mutate(validCode(r)) : roll < 0.7 ? r.base64url(43) : roll < 0.9 ? r.string() : r.value();
        const invite = validateInvite(input);
        if (invite.valid) {
            const value = String(input).trim();
            const body = C.codeBody(value, C.INVITE_PREFIXES);
            assert.notEqual(body, null);
            // the token sent to the server is what the server's own pattern accepts
            assert.match(invite.sanitized.token, goToken);
            const rebuilt = C.b64urlEncode(C.concat(C.b64urlDecode(invite.sanitized.token), invite.sanitized.fingerprint));
            assert.equal(rebuilt, body, 'an invite that is not canonical was accepted');
            assert.equal(looksLikeAccountNumber(input), false);
        } else {
            assert.equal(invite.sanitized, null);
            assert.ok(registered(invite.error), `unregistered code ${invite.error}`);
            if (looksLikeAccountNumber(input)) assert.equal(invite.error, Errors.CODES.E_INVITE_IS_ACCOUNT_NUMBER);
        }
        const join = validateJoin(input);
        if (!join.valid) {
            assert.ok(registered(join.error), `unregistered code ${join.error}`);
            return;
        }
        if (join.kind === 'invite') {
            assert.equal(invite.valid, true, 'the join field accepted an invite the invite field refuses');
            return;
        }
        assert.equal(join.kind, 'room');
        const canonical = R.buildRoomCode(join.sanitized);
        const reparsed = R.parseRoomCode(canonical);
        assert.deepEqual([...reparsed.secret], [...join.sanitized.secret]);
        assert.equal(reparsed.maxMembers, join.sanitized.maxMembers);
        assert.equal(reparsed.expiresHour, join.sanitized.expiresHour);
        const value = String(input).trim();
        if (value.startsWith(R.CODE_PREFIXES[0])) assert.equal(canonical, value, 'a room code that is not canonical was accepted');
    });
});

test('validateConversationId: never laxer than the server\'s UUIDv4 pattern', async () => {
    const validateId = get('validateConversationId');
    await fuzz(SEED + 3, ID_ITERATIONS, (r) => {
        const roll = r.next();
        const input = roll < 0.7 ? r.mutate(globalThis.crypto.randomUUID()) : roll < 0.9 ? r.string() : r.value();
        if (validateId(input)) {
            assert.match(input, GO_UUID, `the browser accepts ${JSON.stringify(input)}, the server does not`);
        }
    });
});

test('buildAgentCommand: an origin or nothing, never a shell metacharacter', async () => {
    const build = get('buildAgentCommand');
    const command = get('AGENT_COMMAND');
    const origins = ['https://elyrn.example', 'http://localhost:8080', 'http://[::1]:3000', 'https://a.b.c'];
    await fuzz(SEED + 4, ORIGIN_ITERATIONS, (r) => {
        const input = r.bool(0.7) ? r.mutate(r.pick(origins)) : r.bool() ? r.string() : r.value();
        const result = build(input);
        if (result === '') return;
        assert.equal(result, command + ' ' + input);
        assert.match(input, SHELL_SAFE_ORIGIN, `the command carries ${JSON.stringify(input)}`);
    });
});
