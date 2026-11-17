// Fuzz: frontend/js/crypto.js and room-crypto.js, loaded as the browser loads them. Codes and
// encodings round-trip; cards, vaults, messages and notes served flipped, cut, extended, swapped
// or re-addressed never open to anything but their genuine plaintext, and sealed output opens
// for its intended members only.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load, plain, rng } from './fuzz-helpers.mjs';

const SEED = 0x5eed0002;
const CODE_ITERATIONS = 3000;
const DECODE_ITERATIONS = 3000;
const SEALED_ITERATIONS = 300;
const ROOM_SEATS = 4;
const EXPIRES_HOUR = 500000;
const ACCOUNT_BYTES = 32;
const MAX_TEXT_CHARS = 64;
const SENT_AT = 1729700000000;

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/crypto.js', '../js/room-crypto.js']);
const C = get('ElyrnCrypto');
const R = get('ElyrnRoomCrypto');

// The outcome of a call that may throw or reject: { ok, value }
async function attempt(fn) {
    try {
        return { ok: true, value: await fn() };
    } catch (error) {
        return { ok: false };
    }
}

// A mutation of a base64url blob: a text edit, or a flipped, cut or extended byte
function mutateBlob(r, blob) {
    if (r.bool()) return r.mutate(blob);
    const raw = C.b64urlDecode(blob);
    const roll = r.next();
    if (roll < 0.5) {
        raw[r.int(0, raw.length - 1)] ^= 1 << r.int(0, 7);
        return C.b64urlEncode(raw);
    }
    if (roll < 0.75) return C.b64urlEncode(raw.subarray(0, r.int(0, raw.length - 1)));
    return C.b64urlEncode(C.concat(raw, r.bytes(r.int(1, 8))));
}

const opened = (message) => message && plain({ text: message.text, sentAt: message.sentAt, counter: message.counter, sender: message.sender });

async function newRoom(r) {
    const code = R.newRoomCode(ROOM_SEATS, EXPIRES_HOUR);
    const room = await R.deriveRoom(code.secret);
    const members = [];
    for (let i = 0; i < 3; i++) {
        const root = await R.deriveRoomsRoot(C.b64urlEncode(r.bytes(ACCOUNT_BYTES)));
        members.push({ root, member: await R.member(room, root) });
    }
    return { code, room, members };
}

test('room codes: parse accepts only canonical codes, and what it accepts rebuilds to the same code', async () => {
    await fuzz(SEED, CODE_ITERATIONS, (r) => {
        const code = { secret: r.bytes(32), maxMembers: r.int(R.MIN_MEMBERS, R.MAX_MEMBERS), expiresHour: r.int(1, 0xffffffff) };
        const text = R.buildRoomCode(code);
        const input = r.bool(0.8) ? r.mutate(text) : r.string();
        let parsed;
        try {
            parsed = R.parseRoomCode(input);
        } catch (error) {
            return;
        }
        const canonical = R.buildRoomCode(parsed);
        assert.equal(canonical.slice(R.CODE_PREFIX.length), C.codeBody(input.trim(), R.CODE_PREFIXES),
            `${JSON.stringify(input)} parsed but is not canonical`);
        assert.ok(parsed.maxMembers >= R.MIN_MEMBERS && parsed.maxMembers <= R.MAX_MEMBERS);
    });
});

test('b64urlDecode: strict; what it accepts re-encodes to itself', async () => {
    await fuzz(SEED + 1, DECODE_ITERATIONS, (r) => {
        const input = r.bool(0.7) ? r.mutate(C.b64urlEncode(r.bytes(r.int(0, 48)))) : r.string();
        let bytes;
        try {
            bytes = C.b64urlDecode(input);
        } catch (error) {
            return;
        }
        assert.equal(C.b64urlEncode(bytes), input);
        assert.throws(() => C.b64urlDecode(input, bytes.length + 1));
    });
});

test('invites: parse accepts only canonical codes; what it accepts rebuilds to the same body', async () => {
    await fuzz(SEED + 2, CODE_ITERATIONS, (r) => {
        const text = r.pick(C.INVITE_PREFIXES) + C.b64urlEncode(r.bytes(32));
        const input = r.bool(0.8) ? r.mutate(text) : r.string();
        let invite;
        try {
            invite = C.parseInviteCode(input);
        } catch (error) {
            return;
        }
        const body = C.b64urlEncode(C.concat(C.b64urlDecode(invite.token), invite.fingerprint));
        assert.equal(body, C.codeBody(input.trim(), C.INVITE_PREFIXES));
    });
});

test('cards and vaults: a mutated one never opens; a genuine one opens only in its own room and for its own root', async () => {
    const r0 = rng(SEED + 3);
    const { code, room, members } = await newRoom(r0);
    const other = await newRoom(r0);
    const [a, b] = members;
    const vault = await R.sealVault(a.root, room.id, code);
    assert.equal((await attempt(async () => R.openCard(other.room, a.member.card))).ok, false, 'a card opened in another room');
    assert.equal((await attempt(() => R.openVault(b.root, room.id, vault))).ok, false, 'a vault opened for another root');
    assert.equal((await attempt(() => R.openVault(a.root, other.room.id, vault))).ok, false, 'a vault opened for another room');
    const genuineCard = await R.openCard(room, a.member.card);
    await fuzz(SEED + 3, SEALED_ITERATIONS, async (r) => {
        const card = mutateBlob(r, a.member.card);
        const cardOpen = await attempt(async () => R.openCard(room, card));
        if (cardOpen.ok) {
            assert.equal(card, a.member.card, 'a mutated card opened');
            assert.deepEqual([...cardOpen.value], [...genuineCard]);
        }
        const sealed = mutateBlob(r, vault);
        const vaultOpen = await attempt(() => R.openVault(a.root, room.id, sealed));
        if (vaultOpen.ok) {
            assert.equal(sealed, vault, 'a mutated vault opened');
            assert.deepEqual([...vaultOpen.value.secret], [...code.secret]);
        }
    });
});

test('messages and notes: a served blob opens to its genuine plaintext or not at all, and only for its recipients', async () => {
    const r0 = rng(SEED + 4);
    const { room, members } = await newRoom(r0);
    const [a, b, outsider] = members;
    // a and b are the roster; the outsider holds the room key but no seat in this message
    const roster = [a.member.card, b.member.card];
    await fuzz(SEED + 4, SEALED_ITERATIONS, async (r) => {
        const id = globalThis.crypto.randomUUID();
        const text = r.string(r.int(1, MAX_TEXT_CHARS));
        const counter = r.int(1, 1000);
        const { recipients, digest } = await R.recipients(room, a.member, roster);
        const blob = await R.sealMessage({ room, me: a.member, id, recipients, digest, text, sentAt: SENT_AT, counter });
        const genuine = opened(await R.openMessage(room, b.member, id, blob));
        assert.deepEqual(opened(await R.openMessage(room, a.member, id, blob)), genuine, 'the sender reads other plaintext than the recipient');
        assert.equal(genuine.counter, counter);
        assert.equal((await attempt(() => R.openMessage(room, outsider.member, id, blob))).ok, false, 'opened by a non-recipient');
        assert.equal((await attempt(() => R.openMessage(room, b.member, globalThis.crypto.randomUUID(), blob))).ok, false,
            'opened under another message id');
        assert.equal((await attempt(() => R.openNote(room, b.member, id, blob))).ok, false, 'a message opened as a note');

        const served = mutateBlob(r, blob);
        const result = await attempt(() => R.openMessage(room, b.member, id, served));
        if (result.ok) {
            // a byte in another member's wrap changes nothing for b: still the genuine message
            assert.deepEqual(opened(result.value), genuine, 'a mutated message opened to other plaintext');
        }

        const noteId = globalThis.crypto.randomUUID();
        const note = await R.sealNote({ room, me: a.member, id: noteId, toCard: b.member.card, text, sentAt: SENT_AT });
        const genuineNote = opened(await R.openNote(room, b.member, noteId, note));
        assert.equal((await attempt(() => R.openNote(room, outsider.member, noteId, note))).ok, false, 'a note opened by another member');
        assert.equal((await attempt(() => R.openMessage(room, b.member, noteId, note))).ok, false, 'a note opened as a message');
        const servedNote = mutateBlob(r, note);
        const noteResult = await attempt(() => R.openNote(room, b.member, noteId, servedNote));
        if (noteResult.ok) {
            assert.deepEqual(opened(noteResult.value), genuineNote, 'a mutated note opened to other plaintext');
        }
    });
});

test('roles: any text up to the byte bound round-trips; a mutated role, or one moved to another card or room, never opens', async () => {
    const r0 = rng(SEED + 6);
    const { room, members } = await newRoom(r0);
    const other = await newRoom(r0);
    const [a, b] = members;
    const encoder = new TextEncoder();
    await fuzz(SEED + 6, SEALED_ITERATIONS, async (r) => {
        const text = r.string(r.int(0, R.MAX_ROLE_BYTES));
        const fits = encoder.encode(text).length <= R.MAX_ROLE_BYTES && text === new TextDecoder().decode(encoder.encode(text));
        const sealed = await attempt(() => R.sealRole({ room, card: a.member.card, text }));
        // Bytes only: the text rule is validation.js's; a lone surrogate is not text and never seals as itself
        if (!fits) {
            if (sealed.ok) assert.notEqual(await R.openRole({ room, card: a.member.card, role: sealed.value }), text);
            return;
        }
        assert.ok(sealed.ok, 'a role within the bound was refused');
        const blob = sealed.value;
        assert.equal(blob.length, Math.ceil(R.ROLE_BYTES * 4 / 3));
        assert.equal(await R.openRole({ room, card: a.member.card, role: blob }), text);
        assert.equal((await attempt(() => R.openRole({ room, card: b.member.card, role: blob }))).ok, false, 'moved to another card');
        assert.equal((await attempt(() => R.openRole({ room: other.room, card: a.member.card, role: blob }))).ok, false, 'opened in another room');
        const mutated = mutateBlob(r, blob);
        const back = await attempt(() => R.openRole({ room, card: a.member.card, role: mutated }));
        if (back.ok) {
            assert.equal(mutated, blob, 'a mutated role opened');
            assert.equal(back.value, text);
        }
    });
});
