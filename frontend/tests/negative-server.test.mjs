// Negative use by a hostile server: what the browser client does with wrong types, extra fields,
// lies and markup in every list it reads. A real node:http server plays the elyrn server; the
// real modules (utils.js apiCall, errors.js, crypto.js, room-crypto.js, rooms.js) are loaded as
// the browser loads them and called as chat.js calls them. Every refusal is asserted exactly.
// Run: node --test frontend/tests/*.test.mjs
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { load } from './fuzz-helpers.mjs';
import { ACCOUNT_A, ACCOUNT_B, ACCOUNT_C, ACCOUNT_D, MARKUP, startHostileServer, useServer } from './negative-helpers.mjs';

const { context, get } = load(
    { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, AbortSignal, DOMException, Response },
    ['../js/log.js', '../js/errors.js', '../js/utils.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js', '../js/rooms.js']);
const Errors = get('Errors');
const CODES = Errors.CODES;
const C = get('ElyrnCrypto');
const R = get('ElyrnRoomCrypto');
const Rooms = get('Rooms');
const apiCall = get('apiCall');
const validateInviteCode = get('validateInviteCode');

const HOUR_SECONDS = 3600;
const SEATS = 4;
const OK = 200;

let server;
before(async () => {
    server = await startHostileServer();
    useServer(context, server.origin);
});
after(() => server.close());

const serve = (status, body) => server.answer(() => ({ status, body }));

// A real room A owns, as the server would list it, and the cards of three other accounts
async function roomFixture(seats = SEATS) {
    const code = R.newRoomCode(seats, R.expiryHourFor(24, Date.now()));
    const keys = await R.deriveRoom(code.secret);
    const rootA = await R.deriveRoomsRoot(ACCOUNT_A);
    const item = {
        id: keys.id, peer_public_key: '', last_seq: 0, read_seq: 0,
        room: { vault: await R.sealVault(rootA, keys.id, code), max_members: seats, expires_at: code.expiresHour * HOUR_SECONDS,
            owner: true, members: 1, notes: 0 }
    };
    const others = [];
    for (const account of [ACCOUNT_B, ACCOUNT_C, ACCOUNT_D]) {
        others.push(await R.member(keys, await R.deriveRoomsRoot(account)));
    }
    const room = await Rooms.adopt(rootA, item);
    return { code, keys, rootA, item, room, conv: { id: keys.id, room }, me: room.member, others };
}

const withView = (item, change) => ({ ...item, room: { ...item.room, ...change } });

// ---------- error and success bodies on the wrong status; markup in every text field ----------

test('a server\'s own text never reaches the user: markup, headers and odd types map to a registered code', async () => {
    for (const message of MARKUP) {
        serve(400, { success: false, message, code: message });
        const result = await apiCall('GET', '/me');
        assert.equal(Errors.fromResult(result), CODES.E_REQUEST_FAILED, message);
    }
    for (const [body, want] of [
        [{ message: { toString: '<b>x</b>' } }, CODES.E_REQUEST_FAILED],
        [{ message: ['invalid credentials'] }, CODES.E_REQUEST_FAILED],
        [{ message: ' INVALID CREDENTIALS ' }, CODES.E_API_INVALID_CREDENTIALS],
        [{ code: '__proto__' }, CODES.E_API_INVALID_REQUEST],
        [{ code: 'constructor', message: 'constructor' }, CODES.E_REQUEST_FAILED],
        ['<html>bad</html>', CODES.E_API_INVALID_REQUEST]
    ]) {
        serve(400, body);
        assert.equal(Errors.fromResult(await apiCall('GET', '/me')), want, JSON.stringify(body));
    }
    // Every sentence the user can be shown is the registry's own: none carries markup
    for (const code of Object.keys(Errors.REGISTRY)) {
        assert.equal(/[<>]/.test(Errors.REGISTRY[code].text), false, code);
    }
});

test('an HTML body is no data, whatever its status; an error status with a success body is still a failure', async () => {
    server.answer(() => ({ status: OK, text: MARKUP[0], type: 'text/html' }));
    const page = await apiCall('GET', '/conversations');
    assert.equal(page.ok, true);
    assert.equal(page.data, null);
    serve(500, { success: true, conversations: [] });
    const failed = await apiCall('GET', '/conversations');
    assert.equal(failed.ok, false);
    assert.equal(Errors.fromResult(failed), CODES.E_API_INTERNAL);
});

test('nothing in the page builds markup: no file under frontend/js writes HTML into the DOM', () => {
    const SINKS = /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|createContextualFragment|DOMParser|srcdoc/;
    const dir = new URL('../js/', import.meta.url);
    for (const file of readdirSync(dir).filter(name => name.endsWith('.js'))) {
        assert.equal(SINKS.test(readFileSync(new URL(file, dir), 'utf8')), false, file);
    }
    // and the edge enforces it: Trusted Types for every script sink
    const site = readFileSync(new URL('../../nginx-site.conf', import.meta.url), 'utf8');
    assert.match(site, /require-trusted-types-for 'script'; trusted-types noaddx-worker;/);
});

// ---------- the conversation list: a room's listing ----------

test('a listed room with wrong types or a non-empty peer key is refused as malformed (chat.js: E_ROOM_UNVERIFIED)', async () => {
    const { rootA, item } = await roomFixture();
    const bad = [
        { ...item, room: null }, { ...item, room: 'room' }, { ...item, peer_public_key: 'x' },
        withView(item, { vault: 7 }), withView(item, { max_members: String(SEATS) }), withView(item, { expires_at: '1' }),
        withView(item, { expires_at: 1.5 }), withView(item, { owner: 'true' }), withView(item, { members: -1 }),
        withView(item, { members: 1.5 }), withView(item, { notes: R.MAX_MEMBERS + 1 }), withView(item, { notes: null })
    ];
    for (const listed of bad) {
        await assert.rejects(Rooms.adopt(rootA, listed), { message: 'malformed room' }, JSON.stringify(listed.room));
    }
});

test('a listed room whose limits disagree with its code, or whose vault is another\'s, is refused', async () => {
    const { rootA, item, code, keys } = await roomFixture();
    for (const change of [{ max_members: SEATS + 1 }, { expires_at: (code.expiresHour + 1) * HOUR_SECONDS },
        { expires_at: 0 }, { expires_at: Number.MAX_SAFE_INTEGER }]) {
        await assert.rejects(Rooms.adopt(rootA, withView(item, change)), { message: 'the server reports other limits than the code' });
    }
    const rootB = await R.deriveRoomsRoot(ACCOUNT_B);
    await assert.rejects(Rooms.adopt(rootA, withView(item, { vault: await R.sealVault(rootB, keys.id, code) })));
    await assert.rejects(Rooms.adopt(rootB, item));
    for (const vault of MARKUP) {
        await assert.rejects(Rooms.adopt(rootA, withView(item, { vault })));
    }
});

test('extra fields in a listed room are ignored; the limits come from the code', async () => {
    const { rootA, item, code } = await roomFixture();
    const room = await Rooms.adopt(rootA, { ...withView(item, { extra: MARKUP[0], admin: true }), set_cookie: MARKUP[2] });
    assert.equal(room.maxMembers, SEATS);
    assert.equal(room.expiresAt, code.expiresHour * R.HOUR_MS);
});

test('a room whose limits change between two listings is refused on the second (chat.js: E_ROOM_DATA_CHANGED)', async () => {
    const { room, item, code } = await roomFixture();
    assert.equal(Rooms.refreshView(room, withView(item, { members: 3, notes: 1, owner: false })), true);
    assert.equal(room.members, 3);
    for (const change of [{ max_members: SEATS + 1 }, { max_members: SEATS - 1 }, { expires_at: (code.expiresHour + 1) * HOUR_SECONDS },
        { vault: 'other' }, { owner: 1 }, { members: R.MAX_MEMBERS + 1 }]) {
        assert.equal(Rooms.refreshView(room, withView(item, change)), false, JSON.stringify(change));
    }
});

// ---------- the member list ----------

const card = (member, mine = false, owner = false, role = '') => ({ card: member.card, mine, owner, role });

test('a member list of the wrong shape is refused as malformed (chat.js: E_ROSTER_UNVERIFIED)', async () => {
    const { conv, me, others } = await roomFixture();
    const bodies = [
        { success: true, members: 'x' }, { success: true, members: {} }, { success: true }, { success: true, members: [] },
        { success: true, members: Array(R.MAX_MEMBERS + 1).fill(card(me, true)) },
        { success: true, members: [card(me, true), null] },
        { success: true, members: [card(me, true), { ...card(others[0]), mine: 'false' }] },
        { success: true, members: [card(me, true), { ...card(others[0]), owner: 0 }] },
        { success: true, members: [card(me, true), { card: 5, mine: false, owner: false, role: '' }] },
        // the role: missing or not a string is a malformed entry, as any other field
        { success: true, members: [card(me, true), { card: others[0].card, mine: false, owner: false }] },
        { success: true, members: [card(me, true), { ...card(others[0]), role: null }] },
        { success: true, members: [card(me, true), { ...card(others[0]), role: 7 }] },
        { success: true, members: [{ ...card(me, true), role: ['x'] }] },
        // 2xx with an error body
        { success: false, message: 'unauthorized' }
    ];
    for (const body of bodies) {
        serve(OK, body);
        await assert.rejects(Rooms.loadRoster(apiCall, conv), (e) => e.message === 'malformed roster' && !e.result, JSON.stringify(body).slice(0, 80));
    }
});

test('a member list served with an error status is a failed request, reported by its own code', async () => {
    const { conv, me } = await roomFixture();
    serve(500, { success: true, members: [card(me, true)] });
    await assert.rejects(Rooms.loadRoster(apiCall, conv), (e) => e.result && Errors.fromResult(e.result) === CODES.E_API_INTERNAL);
    serve(429, { success: false, message: 'too many requests' });
    await assert.rejects(Rooms.loadRoster(apiCall, conv), (e) => e.result && Errors.fromResult(e.result) === CODES.E_API_TOO_MANY_REQUESTS);
});

test('`mine` flags that lie: another\'s card marked mine is refused; my own card not marked mine leaves me off', async () => {
    const { conv, me, others } = await roomFixture();
    serve(OK, { success: true, members: [card(me, true), card(others[0], true)] });
    await assert.rejects(Rooms.loadRoster(apiCall, conv), { message: 'the server misattributes a card' });
    serve(OK, { success: true, members: [card(me, false), card(others[0])] });
    await assert.rejects(Rooms.loadRoster(apiCall, conv), { message: 'roster does not match this room' });
});

test('cards that are invites, room codes, account numbers, markup or duplicates are skipped and counted', async () => {
    const { conv, me, others, code } = await roomFixture(R.MAX_MEMBERS);
    const junk = [C.INVITE_PREFIX + ACCOUNT_B, R.buildRoomCode(code), ACCOUNT_C, ...MARKUP.slice(0, 2)];
    serve(OK, { success: true, members: [card(me, true), card(others[0]), card(others[0]),
        ...junk.map(text => ({ card: text, mine: false, owner: false, role: '' })), { ...card(others[1]), extra: MARKUP[0] }] });
    const roster = await Rooms.loadRoster(apiCall, conv);
    assert.deepEqual([...roster].map(entry => entry.publicKey).sort(), [me.publicKey, others[0].publicKey, others[1].publicKey].sort());
    assert.equal(conv.room.skipped, 1 + junk.length);
    // Every card served counts toward the seats the code allows
    assert.equal(conv.room.members, 4 + junk.length);
});

test('a list longer than the code\'s seats is refused', async () => {
    const { conv, me, others } = await roomFixture(SEATS);
    serve(OK, { success: true, members: [card(me, true), ...others.map(o => card(o)), { card: 'x', mine: false, owner: false, role: '' }] });
    await assert.rejects(Rooms.loadRoster(apiCall, conv), { message: 'roster does not match this room' });
});

test('a member list that drops then adds members between reads is taken as served each time', async () => {
    const { conv, me, others } = await roomFixture(SEATS);
    // The roster is made in the vm context: copied into this realm's array before comparing
    const keys = () => [...conv.room.roster].map(entry => entry.publicKey).sort();
    serve(OK, { success: true, members: [card(me, true), card(others[0]), card(others[1])] });
    await Rooms.loadRoster(apiCall, conv);
    assert.deepEqual(keys(), [me.publicKey, others[0].publicKey, others[1].publicKey].sort());
    serve(OK, { success: true, members: [card(me, true), card(others[1])] });
    await Rooms.loadRoster(apiCall, conv);
    assert.deepEqual(keys(), [me.publicKey, others[1].publicKey].sort());
    assert.equal(Rooms.senderOf(conv.room, others[0].publicKey), undefined, 'a dropped member is no longer a sender');
    serve(OK, { success: true, members: [card(me, true), ...others.map(o => card(o))] });
    await Rooms.loadRoster(apiCall, conv);
    assert.equal(conv.room.roster.length, 4);
});

test('roles: each opens for its own card only; one that does not open or breaks the rule is no role', async () => {
    const { conv, keys, me, others } = await roomFixture(R.MAX_MEMBERS);
    const seal = (member, text) => R.sealRole({ room: keys, card: member.card, text });
    // Sealed by a code holder with text the rule refuses: shown as no role, never as the text
    const refused = [];
    for (const text of ['owner', 'ＹＯＵ', 'a b', 'u\u0308ber', '<b>x</b>']) refused.push(await seal(others[2], text));
    serve(OK, { success: true, members: [
        card(me, true, true, await seal(me, 'komutan')),
        card(others[0], false, false, await seal(others[0], 'Kâşif-7_ü')),
        // another member's role moved onto this card: does not open here
        card(others[1], false, false, await seal(others[0], 'lider')),
        card(others[2], false, false, refused[0])
    ] });
    const roster = await Rooms.loadRoster(apiCall, conv);
    const roleOf = (member) => roster.find(entry => entry.card === member.card).role;
    assert.equal(roleOf(me), 'komutan');
    assert.equal(roleOf(others[0]), 'Kâşif-7_ü');
    assert.equal(roleOf(others[1]), '');
    for (const blob of refused) {
        serve(OK, { success: true, members: [card(me, true), card(others[2], false, false, blob)] });
        assert.equal((await Rooms.loadRoster(apiCall, conv)).find(entry => entry.card === others[2].card).role, '');
    }
    // The cleared role and the never-set role both read as none; markup, junk and a role from
    // another room are none too, and none of them makes the list malformed
    const otherRoom = await R.deriveRoom(R.newRoomCode(SEATS, R.expiryHourFor(24, Date.now())).secret);
    for (const role of ['', await seal(others[0], ''), ...MARKUP, 'x'.repeat(124),
        await R.sealRole({ room: otherRoom, card: others[0].card, text: 'lider' })]) {
        serve(OK, { success: true, members: [card(me, true), card(others[0], false, false, role)] });
        assert.equal((await Rooms.loadRoster(apiCall, conv)).find(entry => entry.card === others[0].card).role, '', role.slice(0, 40));
    }
});

test('roles: a set role is sealed for the target card and posted as the contract asks; refusals keep their status', async () => {
    const { conv, keys, me, others } = await roomFixture();
    serve(OK, { success: true, members: [card(me, true, true), card(others[0])] });
    await Rooms.loadRoster(apiCall, conv);
    const target = conv.room.roster.find(entry => entry.card === others[0].card);
    let seen = null;
    server.answer((request) => {
        seen = request;
        return { status: 204 };
    });
    const stored = await Rooms.setRole({ api: apiCall, conv, entry: target, text: 'lider' });
    assert.equal(stored.status, 204);
    assert.equal(seen.method, 'POST');
    assert.ok(seen.path.endsWith(`/conversations/${conv.id}/members`));
    const body = JSON.parse(seen.body);
    assert.deepEqual(Object.keys(body).sort(), ['card', 'role']);
    assert.equal(body.card, others[0].card);
    assert.equal(body.role.length, 124);
    assert.equal(await R.openRole({ room: keys, card: others[0].card, role: body.role }), 'lider');
    // Who may edit: the owner anyone, a member itself only
    assert.equal(Rooms.mayEditRole({ owner: true }, { mine: false }), true);
    assert.equal(Rooms.mayEditRole({ owner: false }, { mine: true }), true);
    assert.equal(Rooms.mayEditRole({ owner: false }, { mine: false }), false);
    assert.equal(Rooms.mayEditRole({ owner: 'true' }, { mine: 1 }), false);
    // The server's refusal reaches the caller with its status and maps to the registered code
    serve(403, { success: false, message: 'Role not allowed' });
    const refused = await Rooms.setRole({ api: apiCall, conv, entry: target, text: 'lider' });
    assert.equal(refused.status, 403);
    assert.equal(Errors.fromResult(refused), CODES.E_ROLE_NOT_ALLOWED);
});

// ---------- friend requests (notes) ----------

async function noteFor(fixture, from, to, text) {
    const id = C.newMessageId();
    const blob = await R.sealNote({ room: fixture.keys, me: from, id, toCard: to.card, text, sentAt: Date.now() });
    return { id, blob };
}

test('notes of the wrong shape are dropped; a note listed twice is shown once', async () => {
    const fixture = await roomFixture();
    const { conv, me, others } = fixture;
    serve(OK, { success: true, members: [card(me, true), card(others[0])] });
    await Rooms.loadRoster(apiCall, conv);
    const invite = C.INVITE_PREFIX + ACCOUNT_B;
    const good = await noteFor(fixture, others[0], conv.room.member, invite);
    for (const body of [{ success: true, notes: 'x' }, { success: true }, { success: true, notes: { 0: good } }]) {
        serve(OK, body);
        assert.equal((await Rooms.notes(apiCall, conv)).length, 0, JSON.stringify(body));
    }
    serve(500, { success: true, notes: [good] });
    assert.equal((await Rooms.notes(apiCall, conv)).length, 0);
    serve(OK, { success: true, notes: [good, good, { id: 'nope', blob: good.blob }, { id: good.id, blob: 5 }, null,
        { id: C.newMessageId(), blob: MARKUP[0] }, await noteFor(fixture, others[0], others[1], invite)] });
    const opened = await Rooms.notes(apiCall, conv);
    assert.equal(opened.length, 1);
    assert.equal(opened[0].id, good.id);
    assert.equal(opened[0].invite, invite);
});

test('a note that holds a room code, an account number or markup is refused when accepted (chat.js: E_FRIEND_REQUEST_MALFORMED)', async () => {
    const fixture = await roomFixture();
    const { conv, me, others, code } = fixture;
    serve(OK, { success: true, members: [card(me, true), card(others[0])] });
    await Rooms.loadRoster(apiCall, conv);
    const texts = [[R.buildRoomCode(code), CODES.E_INVITE_INVALID], [ACCOUNT_C, CODES.E_INVITE_IS_ACCOUNT_NUMBER],
        [MARKUP[1], CODES.E_INVITE_INVALID], ['', CODES.E_INVITE_EMPTY]];
    for (const [text, want] of texts) {
        serve(OK, { success: true, notes: [await noteFor(fixture, others[0], conv.room.member, text)] });
        const [note] = await Rooms.notes(apiCall, conv);
        // The text arrives as a string, never parsed: ui.js shows it with textContent
        assert.equal(note.invite, text);
        assert.equal(validateInviteCode(note.invite).error, want, text);
    }
});

// ---------- joining and creating rooms ----------

test('join: a 2xx that names another room, a 2xx error body and a success body on an error status take no seat', async () => {
    const { code } = await roomFixture();
    const root = await R.deriveRoomsRoot(ACCOUNT_B);
    const other = (await roomFixture()).keys.id;
    const cases = [
        [OK, { success: true, conversation: { id: other } }, { id: null, status: 0 }],
        [OK, { success: false, message: 'forbidden' }, { id: null, status: 0 }],
        [201, { success: true, conversation: { id: MARKUP[0] } }, { id: null, status: 0 }],
        [404, { success: true, conversation: { id: (await R.deriveRoom(code.secret)).id } }, { id: null, status: 404 }],
        [409, { success: false, message: 'room full' }, { id: null, status: 409 }]
    ];
    for (const [status, body, want] of cases) {
        serve(status, body);
        assert.deepEqual({ ...(await Rooms.join(apiCall, root, code)) }, want, JSON.stringify(body));
    }
});

test('join: the request carries the room id, lookup, card, vault and limits only, never the code or the account number', async () => {
    const { code, keys } = await roomFixture();
    const root = await R.deriveRoomsRoot(ACCOUNT_B);
    serve(201, { success: true, conversation: { id: keys.id } });
    const from = server.requests.length;
    assert.deepEqual({ ...(await Rooms.join(apiCall, root, code)) }, { id: keys.id, status: 201 });
    const sent = server.requests[from];
    assert.deepEqual(Object.keys(JSON.parse(sent.body)).sort(), ['card', 'expires_at', 'id', 'lookup', 'max_members', 'vault']);
    const body = R.buildRoomCode(code).slice(R.CODE_PREFIX.length);
    assert.equal(sent.body.includes(body), false);
    assert.equal(sent.body.includes(C.b64urlEncode(code.secret)), false);
    assert.equal(sent.body.includes(ACCOUNT_B), false);
});

test('create: no proof of work, a 2xx naming another room, or three collisions create nothing', async () => {
    const root = await R.deriveRoomsRoot(ACCOUNT_A);
    assert.deepEqual({ ...(await Rooms.create(apiCall, root, SEATS, 1, async () => null)) }, { status: 0 });
    serve(201, { success: true, conversation: { id: MARKUP[0] } });
    assert.deepEqual({ ...(await Rooms.create(apiCall, root, SEATS, 1, async () => ({}))) }, { status: 201 });
    serve(409, { success: false });
    assert.deepEqual({ ...(await Rooms.create(apiCall, root, SEATS, 1, async () => ({}))) }, { status: 409 });
});

// ---------- messages: `mine` that lies, a sender's clock ----------

test('a pair message whose `mine` flag lies does not open: the sender is bound into the AAD', async () => {
    const a = await C.deriveIdentity(ACCOUNT_A);
    const b = await C.deriveIdentity(ACCOUNT_B);
    const conversationId = C.newMessageId();
    const messageId = C.newMessageId();
    const keyA = await C.conversationKey(a.privateKey, b.publicKey, conversationId);
    const sealed = await C.encryptMessage({ key: keyA, conversationId, messageId, senderPublicKey: b.publicKey,
        text: MARKUP[0], sentAt: Date.now(), counter: 1 });
    await assert.rejects(C.decryptMessage(keyA, conversationId, messageId, a.publicKey, sealed));
    const opened = await C.decryptMessage(keyA, conversationId, messageId, b.publicKey, sealed);
    assert.equal(opened.text, MARKUP[0], 'markup arrives as text');
});

test('a room message names its real sender, whatever `mine` the server sets (chat.js compares the two)', async () => {
    const fixture = await roomFixture();
    const { conv, me, others } = fixture;
    serve(OK, { success: true, members: [card(me, true), card(others[0])] });
    await Rooms.loadRoster(apiCall, conv);
    const { recipients, digest } = await R.recipients(fixture.keys, others[0], conv.room.rosterCards);
    const id = C.newMessageId();
    const ciphertext = await R.sealMessage({ room: fixture.keys, me: others[0], id, recipients, digest,
        text: 'hi', sentAt: Date.now(), counter: 1 });
    const plain = await Rooms.open(conv, { id, ciphertext, mine: true });
    assert.equal(plain.sender, others[0].publicKey);
    assert.notEqual(plain.sender, conv.room.member.publicKey);
});

// ---------- a friend request's id taken ----------

const ID_TAKEN = { success: false, message: 'Id taken' };

test('befriend: a 409 "Id taken" seals and sends again once under a fresh id; a plain 409 is returned as is', async () => {
    const fixture = await roomFixture();
    const { conv, me, others } = fixture;
    serve(OK, { success: true, members: [card(me, true), card(others[0])] });
    await Rooms.loadRoster(apiCall, conv);
    const entry = conv.room.roster.find(e => !e.mine);
    const invite = C.INVITE_PREFIX + ACCOUNT_B;
    const posted = (from) => server.requests.slice(from).map(r => JSON.parse(r.body));

    // Taken once: a second note under another id, then the server's answer to it
    let calls = 0;
    server.answer(() => (++calls === 1 ? { status: 409, body: ID_TAKEN } : { status: 201, body: { success: true } }));
    let from = server.requests.length;
    assert.equal((await Rooms.befriend(apiCall, conv, entry, invite)).status, 201);
    let bodies = posted(from);
    assert.equal(bodies.length, 2);
    assert.notEqual(bodies[0].id, bodies[1].id);
    assert.notEqual(bodies[0].blob, bodies[1].blob);

    // Taken twice: no third attempt, and the answer is the refusal
    serve(409, ID_TAKEN);
    from = server.requests.length;
    const twice = await Rooms.befriend(apiCall, conv, entry, invite);
    assert.equal(twice.status, 409);
    assert.equal(Errors.idTaken(twice), true);
    assert.equal(posted(from).length, 2);

    // The plain-text 409 (a note already waits for them) is not an id taken: one attempt only
    server.answer(() => ({ status: 409, text: 'Conflict\n', type: 'text/plain; charset=utf-8' }));
    from = server.requests.length;
    const waiting = await Rooms.befriend(apiCall, conv, entry, invite);
    assert.equal(waiting.status, 409);
    assert.equal(Errors.idTaken(waiting), false);
    assert.equal(posted(from).length, 1);
});
