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
