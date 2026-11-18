// Trust between room members (fix-spec A2 and A4), through frontend/js/rooms.js as the page uses
// it: the real modules, loaded as the browser loads them, talking to a real node:http server that
// plays a hostile elyrn server or a hostile member's seat. Nothing here stands in for a module.
//   A2: two served cards opening to one key (a code holder sealing another member's key into its
//       own seat's card) make that key disputed: no role, no role control, no friend request,
//       the owner badge kept, and a room safety number that differs from the room without it.
//   A4: a friend request's invite is bound to the member who sent it: a member relaying another
//       account's invite cannot make a binder the addressee accepts.
// What only a page can show (the members panel, the warnings, the burn after a relayed request)
// is in the drill (docs/development/testing-and-contributing.md).
// Run: node --test frontend/tests/*.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { load, plain } from './fuzz-helpers.mjs';
import { ACCOUNT_A, ACCOUNT_B, ACCOUNT_C, ACCOUNT_D, startHostileServer, useServer } from './negative-helpers.mjs';

const { context, get } = load(
    { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, AbortSignal, DOMException, Response, setTimeout, clearTimeout,
        window: { isSecureContext: true }, navigator: {} },
    ['../js/log.js', '../js/errors.js', '../js/utils.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js', '../js/rooms.js']);
const C = get('ElyrnCrypto');
const R = get('ElyrnRoomCrypto');
const Rooms = get('Rooms');
const apiCall = get('apiCall');
const HOUR_SECONDS = 3600;
const MAX_MEMBERS = 6;
// The room safety number of the room the vector keys of vectors-js.json name, with three seats
// for two keys (vectors-js.json safety_number_disputed, made by this module for the Go side)
const VECTOR_KEYS = ['W8eS0mxpk64t2ikVSK_TjuuAtndUpH1_XgsDi0ObJm8', 'Rr1i9oWfcZMTHT3ZWyOfTo8I7bdpM2f2TPQD1r13qks'];
const VECTOR_DISPUTED = ['06715', '65360', '05436', '06981', '25277', '41004'];
const VECTOR_UNDISPUTED = ['85841', '84549', '45068', '72184', '50057', '56593'];

let server;
before(async () => {
    server = await startHostileServer();
    useServer(context, server.origin);
});
after(() => server.close());

// One room, and each account's view of it as Rooms.adopt makes it from a vault the account sealed
async function roomOf(accounts) {
    const code = R.newRoomCode(MAX_MEMBERS, R.expiryHourFor(24, Date.now()));
    const keys = await R.deriveRoom(code.secret);
    const views = {};
    for (const [name, account] of Object.entries(accounts)) {
        const root = await R.deriveRoomsRoot(account);
        const item = {
            id: keys.id, peer_public_key: '',
            room: { vault: await R.sealVault(root, keys.id, code), max_members: code.maxMembers,
                expires_at: code.expiresHour * HOUR_SECONDS, owner: false, members: 0, notes: 0 }
        };
        const room = await Rooms.adopt(root, item);
        views[name] = { id: keys.id, room, identity: await C.deriveIdentity(account) };
    }
    return { keys, views };
}

// The member list a server serves: rows { card, owner, role, of } (of: the seat's account), sorted
// by card as backend chat RoomMembers sorts it, `mine` set for the viewer's own seat
function serveRoster(rows, viewer) {
    const members = [...rows].sort((x, y) => (x.card < y.card ? -1 : x.card > y.card ? 1 : 0))
        .map((row) => ({ card: row.card, mine: row.of === viewer, owner: row.owner, role: row.role }));
    server.answer(() => ({ status: 200, body: { members } }));
}

async function rosterAs(views, rows, viewer) {
    serveRoster(rows, viewer);
    await Rooms.loadRoster(apiCall, views[viewer]);
    return views[viewer].room;
}

const entryOf = (room, publicKey) => room.roster.find((entry) => entry.publicKey === publicKey);

// ---------- A2: two seats, one key ----------

// A (owner), B and C hold their own seats; M took a seat with a card carrying B's key, and set a
// role on it (any member may set its own)
async function shadowedRoom() {
    const { keys, views } = await roomOf({ A: ACCOUNT_A, B: ACCOUNT_B, C: ACCOUNT_C });
    const rows = [
        { card: views.A.room.member.card, owner: true, role: '', of: 'A' },
        { card: views.B.room.member.card, owner: false, role: '', of: 'B' },
        { card: views.C.room.member.card, owner: false, role: '', of: 'C' }
    ];
    const victim = views.B.room.member.publicKey;
    const shadow = await R.sealCard(keys, C.b64urlDecode(victim, C.KEY_BYTES));
    rows.push({ card: shadow, owner: false, role: await R.sealRole({ room: keys, card: shadow, text: 'imposter' }), of: 'M' });
    return { keys, views, rows, victim, shadow };
}

test('A2: a key two served cards open to is disputed: no role, no role control, no friend request', async () => {
    const { views, rows, victim } = await shadowedRoom();
    for (const viewer of ['A', 'C']) {
        const room = await rosterAs(views, rows, viewer);
        const entry = entryOf(room, victim);
        assert.equal(room.roster.length, 3, 'one entry per key');
        assert.equal(entry.seats, 2);
        assert.equal(Rooms.disputed(entry), true);
        assert.equal(entry.role, '', 'the impostor seat\'s role is never shown as the member\'s');
        assert.equal(Rooms.roleShown(entry), '');
        assert.equal(Rooms.mayBefriend(entry), false);
        room.owner = true;  // even the owner may not set a disputed member's role
        assert.equal(Rooms.mayEditRole(room, entry), false);
        assert.deepEqual(plain(Rooms.disputedEntries(room).map((e) => e.publicKey)), [victim]);
        assert.equal(room.skipped, 0, 'a duplicated key is shown as disputed, not as a card that failed');
        // Nothing is sealed for it
        await assert.rejects(Rooms.setRole({ api: apiCall, conv: views[viewer], entry, text: 'x' }));
        await assert.rejects(Rooms.befriend({ api: apiCall, conv: views[viewer], entry, invite: { code: 'x', token: 'x' }, accountKey: null }));
        // Every other member stays as it was
        for (const other of room.roster.filter((e) => e.publicKey !== victim)) assert.equal(Rooms.disputed(other), false);
    }
});

test('A2: the owner badge cannot be taken away by a second seat under the owner\'s key', async () => {
    const { keys, views } = await roomOf({ A: ACCOUNT_A, B: ACCOUNT_B });
    const owner = views.A.room.member.publicKey;
    const shadow = await R.sealCard(keys, C.b64urlDecode(owner, C.KEY_BYTES));
    const rows = [
        { card: views.A.room.member.card, owner: true, role: '', of: 'A' },
        { card: views.B.room.member.card, owner: false, role: '', of: 'B' },
        { card: shadow, owner: false, role: '', of: 'M' }
    ];
    const room = await rosterAs(views, rows, 'B');
    assert.equal(entryOf(room, owner).owner, true);
    assert.equal(Rooms.disputed(entryOf(room, owner)), true);
});

test('A2: the member whose own key is disputed sees itself disputed and keeps its stored card', async () => {
    const { views, rows, victim } = await shadowedRoom();
    const room = await rosterAs(views, rows, 'B');
    const own = entryOf(room, victim);
    assert.equal(own.mine, true);
    assert.equal(Rooms.disputed(own), true);
    assert.equal(own.card, views.B.room.member.card);
    assert.equal(room.member.card, views.B.room.member.card, 'messages go out under the card the server stores for B');
});

test('A2: the room safety number covers the seats: a duplicated seat changes it, one seat per key does not', async () => {
    const { views, rows } = await shadowedRoom();
    const honest = rows.filter((row) => row.of !== 'M');
    const viewer = views.A;
    await rosterAs(views, honest, 'A');
    const without = plain(await Rooms.safetyNumber(viewer));
    // As every build before seats were counted computed it: the distinct keys alone
    assert.deepEqual(without, plain(await R.safetyNumber(viewer.room.roster.map((e) => e.publicKey))));
    await rosterAs(views, rows, 'A');
    const withShadow = plain(await Rooms.safetyNumber(viewer));
    assert.notDeepEqual(withShadow, without);
    // The same view from another member: equal digits for equal lists
    await rosterAs(views, rows, 'C');
    assert.deepEqual(plain(await Rooms.safetyNumber(views.C)), withShadow);
});

test('A2: the seat count is appended exactly as the Go side reads it (vectors-js.json safety_number_disputed)', async () => {
    assert.deepEqual(plain(await R.safetyNumber(VECTOR_KEYS, 3)), VECTOR_DISPUTED);
    assert.deepEqual(plain(await R.safetyNumber(VECTOR_KEYS, 2)), VECTOR_UNDISPUTED);
    assert.deepEqual(plain(await R.safetyNumber(VECTOR_KEYS)), VECTOR_UNDISPUTED);
    // The bytes behind the digits: prefix, sorted keys, label, big-endian uint32 seats
    const encoder = new TextEncoder();
    const sorted = VECTOR_KEYS.map((key) => C.b64urlDecode(key, 32)).sort(Buffer.compare);
    const seats = new Uint8Array([0, 0, 0, 3]);
    const input = C.concat(encoder.encode('noaddx/room/safety/v1'), ...sorted, encoder.encode('noaddx/room/seats/v1'), seats);
    assert.deepEqual(plain(C.digitGroups(await C.sha256(input))), VECTOR_DISPUTED);
});

test('A2: a member who left and came back holds one seat: nothing is disputed', async () => {
    const { views } = await roomOf({ A: ACCOUNT_A, B: ACCOUNT_B });
    // B's card after a rejoin is a fresh one (random nonce); the server dropped the old seat
    const rejoined = await R.sealCard(views.B.room.keys, C.b64urlDecode(views.B.room.member.publicKey, C.KEY_BYTES));
    const rows = [
        { card: views.A.room.member.card, owner: true, role: '', of: 'A' },
        { card: rejoined, owner: false, role: '', of: 'B' }
    ];
    const room = await rosterAs(views, rows, 'A');
    assert.equal(Rooms.disputedEntries(room).length, 0);
    assert.equal(entryOf(room, views.B.room.member.publicKey).seats, 1);
});

test('A2: two seats flagged as the viewer\'s own are the server misattributing, not a dispute', async () => {
    const { keys, views } = await roomOf({ A: ACCOUNT_A, B: ACCOUNT_B });
    const second = await R.sealCard(keys, C.b64urlDecode(views.A.room.member.publicKey, C.KEY_BYTES));
    const rows = [
        { card: views.A.room.member.card, owner: true, role: '', of: 'A' },
        { card: second, owner: false, role: '', of: 'A' },
        { card: views.B.room.member.card, owner: false, role: '', of: 'B' }
    ];
    serveRoster(rows, 'A');
    await assert.rejects(Rooms.loadRoster(apiCall, views.A), /misattributes/);
});

// ---------- A4: a friend request is bound to its sender ----------

// W, X and V share a room; every note posted is kept by the server and listed to its addressee
async function befriendRoom() {
    const { views } = await roomOf({ W: ACCOUNT_A, X: ACCOUNT_B, V: ACCOUNT_C });
    const rows = Object.keys(views).map((name, i) => ({ card: views[name].room.member.card, owner: i === 0, role: '', of: name }));
    for (const name of Object.keys(views)) await rosterAs(views, rows, name);
    return { views, rows };
}

// Posts are kept; a listing gives the notes addressed to `to` (a card)
function noteStore() {
    const notes = [];
    server.answer((seen) => {
        if (seen.method === 'POST' && seen.path.endsWith('/notes')) {
            notes.push(JSON.parse(seen.body));
            return { status: 201, body: { success: true } };
        }
        return { status: 404, body: { success: false, message: 'not found' } };
    });
    return notes;
}

function listNotes(notes, toCard) {
    server.answer(() => ({ status: 200, body: { notes: notes.filter((n) => n.to === toCard).map((n) => ({ id: n.id, blob: n.blob })) } }));
}

async function newInvite(identity) {
    const token = C.b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
    return { token, code: await C.buildInviteCode(token, identity.publicKey) };
}

test('A4: a request the inviting member sent itself carries a binder its addressee accepts', async () => {
    const { views } = await befriendRoom();
    const notes = noteStore();
    const invite = await newInvite(views.W.identity);
    const toX = entryOf(views.W.room, views.X.room.member.publicKey);
    const sent = await Rooms.befriend({ api: apiCall, conv: views.W, entry: toX, invite, accountKey: views.W.identity.privateKey });
    assert.equal(sent.status, 201);
    listNotes(notes, views.X.room.member.card);
    const [note] = await Rooms.notes(apiCall, views.X);
    assert.equal(note.invite, invite.code);
    assert.equal(note.sender, views.W.room.member.publicKey);
    assert.equal(note.newer, false);
    assert.equal(note.binder.length, C.BINDER_BYTES);
    // The redeem answer names W's account key, which the invite's fingerprint confirms
    assert.equal(await C.fingerprintMatches(C.parseInviteCode(invite.code), views.W.identity.publicKey), true);
    assert.equal(await Rooms.binderMatches({ conv: views.X, note, token: invite.token, creatorKey: views.W.identity.publicKey }), true);
});

test('A4: a member relaying another account\'s invite cannot make a binder the addressee accepts', async () => {
    const { views } = await befriendRoom();
    const notes = noteStore();
    const invite = await newInvite(views.W.identity);
    const toX = entryOf(views.W.room, views.X.room.member.publicKey);
    await Rooms.befriend({ api: apiCall, conv: views.W, entry: toX, invite, accountKey: views.W.identity.privateKey });
    listNotes(notes, views.X.room.member.card);
    const [atX] = await Rooms.notes(apiCall, views.X);
    // X (a modified client) relays W's invite to V: once with a binder of its own account key,
    // once with the binder W made for X copied in
    const relayed = noteStore();
    const toV = entryOf(views.X.room, views.V.room.member.publicKey);
    await Rooms.befriend({ api: apiCall, conv: views.X, entry: toV, invite: { code: atX.invite, token: invite.token }, accountKey: views.X.identity.privateKey });
    const copiedId = C.newMessageId();
    relayed.push({ id: copiedId, to: toV.card, blob: await R.sealNote({
        room: views.X.room.keys, me: views.X.room.member, id: copiedId, toCard: toV.card, text: atX.invite, sentAt: Date.now(), binder: atX.binder
    }) });
    listNotes(relayed, views.V.room.member.card);
    const atV = await Rooms.notes(apiCall, views.V);
    assert.equal(atV.length, 2);
    for (const note of atV) {
        assert.equal(note.sender, views.X.room.member.publicKey);
        // The invite itself is W's genuine one: the fingerprint passes, the binder does not
        assert.equal(await C.fingerprintMatches(C.parseInviteCode(note.invite), views.W.identity.publicKey), true);
        assert.equal(await Rooms.binderMatches({ conv: views.V, note, token: invite.token, creatorKey: views.W.identity.publicKey }), false);
    }
});

test('A4: a request from a browser before binders opens without one and is never accepted', async () => {
    const { views } = await befriendRoom();
    const invite = await newInvite(views.W.identity);
    const toX = entryOf(views.W.room, views.X.room.member.publicKey);
    const id = C.newMessageId();
    const blob = await R.sealNote({ room: views.W.room.keys, me: views.W.room.member, id, toCard: toX.card, text: invite.code, sentAt: Date.now() });
    listNotes([{ id, to: toX.card, blob }], toX.card);
    const [note] = await Rooms.notes(apiCall, views.X);
    assert.equal(note.binder, null);
    assert.equal(note.invite, invite.code);
    assert.equal(await Rooms.binderMatches({ conv: views.X, note, token: invite.token, creatorKey: views.W.identity.publicKey }), false);
});

test('A4: the binder is the documented HKDF over X25519, the same from both ends', async () => {
    const { views } = await befriendRoom();
    const W = views.W;
    const V = views.V;
    const token = C.b64urlEncode(new Uint8Array(16).fill(7));
    const fromW = await R.befriendBinder({ room: W.room.keys, privateKey: W.identity.privateKey, peerPublic: V.room.member.publicKey,
        token, requester: W.room.member.publicKey, addressee: V.room.member.publicKey });
    const atV = await R.befriendBinder({ room: V.room.keys, privateKey: V.room.member.privateKey, peerPublic: W.identity.publicKey,
        token, requester: W.room.member.publicKey, addressee: V.room.member.publicKey });
    assert.equal(R.sameBinder(fromW, atV), true);
    // Each input moves it: another token, requester, addressee, or creator key
    const other = C.b64urlEncode(new Uint8Array(16).fill(8));
    for (const changed of [
        { token: other }, { requester: views.X.room.member.publicKey }, { addressee: views.X.room.member.publicKey },
        { peerPublic: views.X.identity.publicKey }
    ]) {
        const moved = await R.befriendBinder({ room: V.room.keys, privateKey: V.room.member.privateKey, peerPublic: W.identity.publicKey,
            token, requester: W.room.member.publicKey, addressee: V.room.member.publicKey, ...changed });
        assert.equal(R.sameBinder(moved, atV), false, JSON.stringify(Object.keys(changed)));
    }
    assert.equal(R.sameBinder(fromW, fromW.slice(0, 31)), false);
    assert.equal(R.sameBinder(null, fromW), false);
});

test('A4: a note payload carries the binder only for a note\'s reader; a message with one is from a newer elyrn', async () => {
    const binder = new Uint8Array(C.BINDER_BYTES).fill(9);
    const framed = C.encodePayload({ text: 'elyrn:x', sentAt: 1729700000000, counter: 1, binder });
    assert.deepEqual([...C.decodePayload(framed, { binder: true }).binder], [...binder]);
    assert.throws(() => C.decodePayload(framed), (error) => C.isNewerPayload(error));
    assert.equal(C.decodePayload(C.encodePayload({ text: 'x', sentAt: 1, counter: 1 }), { binder: true }).binder, null);
    assert.throws(() => C.encodePayload({ text: 'x', sentAt: 1, counter: 1, binder: binder.slice(1) }));
});

test('A4: an older build drops a binder note unread: it sees a key it does not know (a newer elyrn)', async () => {
    // A build before binders read notes with decodePayload(plain) and no option: what it does now
    const framed = C.encodePayload({ text: 'elyrn:x', sentAt: 1729700000000, counter: 1, binder: new Uint8Array(32) });
    assert.throws(() => C.decodePayload(framed), (error) => C.isNewerPayload(error));
});

test('A4 and A2 together: a disputed addressee is never sent a friend request', async () => {
    const { views, rows, victim } = await shadowedRoom();
    const room = await rosterAs(views, rows, 'A');
    const requests = server.requests.length;
    await assert.rejects(Rooms.befriend({ api: apiCall, conv: views.A, entry: entryOf(room, victim),
        invite: await newInvite(views.A.identity), accountKey: views.A.identity.privateKey }));
    assert.equal(server.requests.length, requests, 'nothing was posted');
});

test('a roster that does not list the viewer\'s own seat is refused', async () => {
    const { views } = await roomOf({ A: ACCOUNT_A, D: ACCOUNT_D });
    serveRoster([{ card: views.A.room.member.card, owner: true, role: '', of: 'A' }], 'D');
    await assert.rejects(Rooms.loadRoster(apiCall, views.D), /does not match/);
});
