// frontend/js/rooms.js lookalike detection, loaded as the browser loads it (after its crypto globals).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
for (const file of ['../js/crypto.js', '../js/room-crypto.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const Rooms = vm.runInContext(readFileSync(new URL('../js/rooms.js', import.meta.url), 'utf8') + '\n;Rooms', context);
const C = vm.runInContext('ElyrnCrypto', context);

// A name carries 12 bits: about 4,096 tries make a chosen one, far fewer (birthday) make any pair
const MAX_GRIND = 20000;

async function member() {
    const publicKey = C.b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    return { publicKey, aura: await C.aura(publicKey) };
}

// Grinds real keys until two of them carry the same name, as an attacker holding the code would
async function namesake() {
    const byName = new Map();
    for (let i = 0; i < MAX_GRIND; i++) {
        const entry = await member();
        const earlier = byName.get(entry.aura.name);
        if (earlier && earlier.publicKey !== entry.publicKey) return [earlier, entry];
        byName.set(entry.aura.name, entry);
    }
    throw new Error('no name collision within the grind budget');
}

async function distinctMembers(count) {
    const byName = new Map();
    while (byName.size < count) {
        const entry = await member();
        byName.set(entry.aura.name, entry);
    }
    return [...byName.values()];
}

test('distinct names: nothing collides', async () => {
    const roster = await distinctMembers(8);
    assert.equal(Rooms.nameCollisions(roster, []).size, 0);
    assert.equal(Rooms.nameCollisions([], []).size, 0);
});

test('two roster keys under one name are both flagged, and no one else', async () => {
    const [victim, lookalike] = await namesake();
    assert.equal(victim.aura.name, lookalike.aura.name);
    const others = (await distinctMembers(6)).filter(entry => entry.aura.name !== victim.aura.name);
    const colliding = Rooms.nameCollisions([...others, victim, lookalike], []);
    assert.deepEqual([...colliding].sort(), [victim.publicKey, lookalike.publicKey].sort());
});

test('a sender off the roster named like a member is flagged with that member', async () => {
    const [victim, outsider] = await namesake();
    const colliding = Rooms.nameCollisions([victim], [outsider]);
    assert.deepEqual([...colliding].sort(), [victim.publicKey, outsider.publicKey].sort());
});

test('one key listed twice (roster and outsiders, or a repeated card) is not a collision', async () => {
    const [entry] = await distinctMembers(1);
    assert.equal(Rooms.nameCollisions([entry, entry], [entry]).size, 0);
});

test('outsiders are read from any iterable, as the room keeps them in a Map', async () => {
    const [victim, outsider] = await namesake();
    const outsiders = new Map([[outsider.publicKey, outsider]]);
    assert.equal(Rooms.nameCollisions([victim], outsiders.values()).size, 2);
});

// A code with the same secret and other limit bytes opens the same room id (the id derives from
// the secret only): only the limits tell the doctored code apart, so join must carry them
test('a code doctored in its limit bytes opens the same room id and is told apart by its limits', async () => {
    const R = vm.runInContext('ElyrnRoomCrypto', context);
    const code = R.newRoomCode(R.MIN_MEMBERS + 1, R.expiryHourFor(1, Date.now()));
    const honest = R.parseRoomCode(R.buildRoomCode(code));
    const longer = R.parseRoomCode(R.buildRoomCode({ ...code, expiresHour: code.expiresHour + 1 }));
    const larger = R.parseRoomCode(R.buildRoomCode({ ...code, maxMembers: code.maxMembers + 1 }));
    const id = await Rooms.roomIdOf(code);
    for (const doctored of [longer, larger]) {
        assert.equal(await Rooms.roomIdOf(doctored), id);
        assert.equal(Rooms.sameLimits(code, doctored), false);
    }
    assert.equal(Rooms.sameLimits(code, honest), true);
});

// The notes panel after accept, read from the real sources: drawing it needs a browser and is
// driven by hand (docs/development/testing-and-contributing.md); what can be pinned is pinned.
test('accepting a friend request draws the notes panel again on every answer, through its one render path', () => {
    const chat = readFileSync(new URL('../js/chat.js', import.meta.url), 'utf8');
    const ui = readFileSync(new URL('../js/ui.js', import.meta.url), 'utf8');
    // One render path: refreshRoomPanels is the only caller of renderNotes
    assert.equal((chat.match(/renderNotes\(/g) || []).length, 1);
    const panels = chat.slice(chat.indexOf('async function refreshRoomPanels'));
    assert.match(panels.slice(0, panels.indexOf('\n    }\n')), /renderNotes\(notes,/);
    const start = chat.indexOf('async function acceptNoteNow');
    const body = chat.slice(start, chat.indexOf('\n    }\n', start));
    // The accepted request leaves the panel through dismissNote (count, then refreshRoomPanels)
    // before the new conversation opens; a bare server dismissal left the stale request shown
    assert.doesNotMatch(body, /Rooms\.dismissNote\(/);
    assert.match(body, /await dismissNote\(conv, note\);\n\s*showSuccess\(Errors\.NOTICE\.FRIENDS_NOW\);[\s\S]*await open\(id\);/);
    // Every other way out draws the panel again, except a session that ended meanwhile
    const exits = body.split('return;').slice(0, -1);
    assert.ok(exits.length >= 4);
    for (const exit of exits) {
        if (/if \(!me\) $/.test(exit)) continue;
        assert.match(exit, /(refreshRoomPanels\(conv\)|dismissNote\(conv, note\));\s*$/, 'an accept answer leaves the panel stale');
    }
    // A refused request is refused with the code the panel shows for it (ui.js noteRefusal)
    assert.match(body, /const refusal = noteRefusal\(note\);\n\s*if \(refusal\) \{\n\s*Errors\.report\(refusal\);\n\s*await refreshRoomPanels\(conv\);/);
    assert.match(ui, /const refusal = noteRefusal\(note\);[\s\S]*memberTag\(Errors\.message\(refusal\)\)/);
    assert.match(ui, /if \(note\.newer\) return Errors\.CODES\.W_MESSAGE_FROM_NEWER;/);
    assert.match(ui, /if \(!note\.binder\) return Errors\.CODES\.W_FRIEND_REQUEST_OUTDATED;/);
});
