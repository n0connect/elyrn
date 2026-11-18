// ========================================
// ROOMS (code-based group conversations)
// ========================================
// docs/architecture/rooms.md. The server stays an untrusted relay: the room id, member limit
// and expiry it reports are checked against the code in this account's vault, every card is
// opened with the code-derived key, and every message is authenticated per sender.

const Rooms = (() => {
    'use strict';

    const R = ElyrnRoomCrypto;
    // A code's expiry is a whole hour; the server reports it in seconds
    const HOUR_SECONDS = 3600;
    const TTL_CHOICES = [1, 24, 168];
    const MAX_CREATE_ATTEMPTS = 3;  // a fresh secret per attempt; a collision is astronomically rare
    const MAX_NOTE_CHARS = 64;      // a note carries one invite code

    function isCount(value, max) {
        return Number.isSafeInteger(value) && value >= 0 && value <= max;
    }

    // ---------- adopting what the server lists ----------

    // Verifies a listed room against the code its vault holds and derives this account's key
    // in it. Throws on any mismatch: the caller hides the room.
    async function adopt(root, item) {
        const view = item.room;
        if (!view || typeof view.vault !== 'string' || !isCount(view.max_members, R.MAX_MEMBERS) ||
            !Number.isSafeInteger(view.expires_at) || typeof view.owner !== 'boolean' ||
            !isCount(view.members, R.MAX_MEMBERS) || !isCount(view.notes, R.MAX_MEMBERS) || item.peer_public_key !== '') {
            throw new Error('malformed room');
        }
        const code = await R.openVault(root, item.id, view.vault);
        if (code.maxMembers !== view.max_members || code.expiresHour * HOUR_SECONDS !== view.expires_at) {
            throw new Error('the server reports other limits than the code');
        }
        const keys = await R.deriveRoom(code.secret);
        return {
            vault: view.vault,
            code: code,
            keys: keys,
            member: await R.member(keys, root),
            maxMembers: code.maxMembers,
            expiresAt: code.expiresHour * R.HOUR_MS,
            owner: view.owner,
            members: view.members,
            notes: view.notes,
            roster: null,       // [{ card, publicKey, aura, mine, owner, role, seats }], one per key (verifyMembers)
            rosterCards: null,  // every card as served (the digest covers them all)
            skipped: 0,         // cards that failed to open: counted, never wrapped for
            requested: new Set(),
            outsiders: new Map(),   // publicKey -> { publicKey, aura }: senders not on the roster (left)
            lookalikes: new Set(),  // public keys whose aura name another key shares
            warned: new Set(),      // lookalike keys already announced this session
            disputeWarned: false    // the room's disputed seats were announced this session
        };
    }

    // The listing's counters change; the code, its limits and the keys never do: a listing that
    // reports other limits than the code (checked once by adopt) is the server changing its story
    function refreshView(room, item) {
        const view = item.room;
        if (!view || view.vault !== room.vault || typeof view.owner !== 'boolean' ||
            view.max_members !== room.maxMembers || view.expires_at !== room.code.expiresHour * HOUR_SECONDS ||
            !isCount(view.members, R.MAX_MEMBERS) || !isCount(view.notes, R.MAX_MEMBERS)) {
            return false;
        }
        room.owner = view.owner;
        room.members = view.members;
        room.notes = view.notes;
        return true;
    }

    function expired(room) {
        return Date.now() >= room.expiresAt;
    }

    // ---------- roster ----------

    // Fetches the room's member list, verifies it, and makes it the room's roster. A failed
    // request throws an error carrying its result (the caller reports it as such); anything the
    // server answered that does not verify throws one without it.
    async function loadRoster(api, conv) {
        const room = conv.room;
        const result = await api('GET', `/conversations/${conv.id}/members`);
        if (!result.ok) {
            throw Object.assign(new Error('roster not served'), { status: result.status, result: result });
        }
        if (!result.data || !Array.isArray(result.data.members) ||
            result.data.members.length === 0 || result.data.members.length > R.MAX_MEMBERS) {
            throw new Error('malformed roster');
        }
        const { cards, roster, skipped, storedCard } = await verifyMembers(room, result.data.members);
        // A card is sealed under a random nonce, so the one derived at login differs in bytes from
        // the one stored when this account joined. Others address notes to the stored one.
        room.member = Object.freeze({ privateKey: room.member.privateKey, publicKey: room.member.publicKey, card: storedCard });
        room.roster = roster;
        room.rosterCards = cards;
        room.skipped = skipped;
        room.members = cards.length;
        return roster;
    }

    // Opens every listed card with the room's key and checks the list against this account and
    // the code's seat limit. Throws when the server misrepresents the room; returns every card
    // as served, the verified roster (one entry per key), how many cards did not open, and this
    // account's stored card.
    //
    // A card proves the room code, not the key it announces, so a code holder can take a seat with
    // a card carrying another member's key. Such a key has more than one seat (`seats`) and is
    // disputed (disputed()): its entry shows no role, and nobody can set its role or send it a
    // friend request (an address chosen between its cards could reach the impostor's seat). Its
    // owner flag is true when any of its cards is the owner's: only the server flags the owner,
    // and an impostor's seat is never the owner's, so the badge cannot be taken away. Its card is
    // this account's stored card when the key is ours (the server flags our seat `mine`), else the
    // first served. A member who left and came back holds one card: the server drops a card when
    // its seat is left.
    async function verifyMembers(room, members) {
        const cards = [];
        const byKey = new Map();    // publicKey -> { rows: [served entries], mine: our seat's entry }
        let skipped = 0;
        for (const entry of members) {
            if (!entry || typeof entry.card !== 'string' || typeof entry.mine !== 'boolean' || typeof entry.owner !== 'boolean' ||
                typeof entry.role !== 'string') {
                throw new Error('malformed roster');
            }
            cards.push(entry.card);
            let publicKey;
            try {
                publicKey = ElyrnCrypto.b64urlEncode(await R.openCard(room.keys, entry.card));
            } catch (e) {
                skipped++;
                continue;
            }
            const mine = publicKey === room.member.publicKey;
            const seat = byKey.get(publicKey) || { rows: [], mine: null };
            if (entry.mine && (!mine || seat.mine)) {
                // A seat flagged ours under another key, or two seats flagged ours
                throw new Error('the server misattributes a card');
            }
            if (entry.mine) seat.mine = entry;
            seat.rows.push(entry);
            byKey.set(publicKey, seat);
        }
        const own = byKey.get(room.member.publicKey);
        // The vault says how many seats exist; a longer list is the server breaking the code's
        // limit. Our own seat must be listed, flagged ours.
        if (!own || !own.mine || cards.length > room.maxMembers) {
            throw new Error('roster does not match this room');
        }
        const roster = [];
        for (const [publicKey, seat] of byKey) {
            const mine = publicKey === room.member.publicKey;
            const shown = mine ? seat.mine : seat.rows[0];
            const seats = seat.rows.length;
            roster.push({
                card: shown.card, publicKey: publicKey, aura: await ElyrnCrypto.aura(publicKey), mine: mine,
                owner: seat.rows.some(row => row.owner), seats: seats,
                // A disputed key's role is never opened: no card of it speaks for the member
                role: seats > 1 ? '' : await roleOf(room, shown)
            });
        }
        return { cards: cards, roster: roster, skipped: skipped, storedCard: own.mine.card };
    }

    // The one judgement of a disputed key: more than one served card opens to it (verifyMembers).
    // Everything that shows or acts on a member asks here: the members panel, the role control,
    // the befriend control and its request, the bubbles, the room's warning and the safety number.
    function disputed(entry) {
        return Boolean(entry) && Number.isSafeInteger(entry.seats) && entry.seats > 1;
    }

    // The role shown for a roster entry, or '' (none, or disputed)
    function roleShown(entry) {
        return entry && !disputed(entry) ? entry.role : '';
    }

    // The roster's disputed entries
    function disputedEntries(room) {
        return room.roster ? room.roster.filter(disputed) : [];
    }

    // The role an entry's sealed role opens to: '' when it never had one or it was cleared, and
    // also when it does not open for this room and card or its text breaks the rule (logged
    // under a code only: the text is other members' data and never reaches the log)
    async function roleOf(room, entry) {
        if (entry.role === '') return '';
        try {
            const text = await R.openRole({ room: room.keys, card: entry.card, role: entry.role });
            if (text === '' || isRoleText(text)) return text;
        } catch (e) {
            // Falls through to the same answer as a text the rule refuses
        }
        Log.warn(Errors.INTERNAL.W_ROLE_UNREADABLE);
        return '';
    }

    // Seals text (validated by the caller; '' clears) for the member whose stored card is
    // entry.card and stores it. Returns the request's result. A disputed entry is refused: which
    // of its cards is the member's own nobody can tell.
    async function setRole({ api, conv, entry, text }) {
        if (disputed(entry)) throw new Error('disputed member');
        const role = await R.sealRole({ room: conv.room.keys, card: entry.card, text });
        return api('POST', `/conversations/${conv.id}/members`, { card: entry.card, role: role });
    }

    // Who may change entry's role: the room's owner anyone's, every member its own (the server
    // enforces the same rule; nobody is shown a control they may not use); nobody a disputed one's
    function mayEditRole(room, entry) {
        return !disputed(entry) && (room.owner === true || entry.mine === true);
    }

    // Whether a friend request may be sent to entry: someone else, not disputed
    function mayBefriend(entry) {
        return entry.mine !== true && !disputed(entry);
    }

    function senderOf(room, publicKey) {
        return room.roster ? room.roster.find(entry => entry.publicKey === publicKey) : undefined;
    }

    // A name carries 12 bits, so whoever holds the code can grind an account offline until its
    // member key is named like someone here. Returns every public key whose name a different
    // key shares: roster entries and outsiders ([{ publicKey, aura }]) alike.
    function nameCollisions(roster, outsiders) {
        const keysByName = new Map();
        for (const entry of [...roster, ...outsiders]) {
            const keys = keysByName.get(entry.aura.name) || new Set();
            keys.add(entry.publicKey);
            keysByName.set(entry.aura.name, keys);
        }
        const colliding = new Set();
        keysByName.forEach(keys => {
            if (keys.size > 1) keys.forEach(key => colliding.add(key));
        });
        return colliding;
    }

    // ---------- messages ----------

    async function seal({ conv, id, text, counter, file }) {
        const room = conv.room;
        const { recipients, digest } = await R.recipients(room.keys, room.member, room.rosterCards);
        if (recipients.length > room.maxMembers) {
            throw new Error('roster exceeds the room limit');
        }
        return R.sealMessage({ room: room.keys, me: room.member, id, recipients, digest, text, sentAt: Date.now(), counter, file });
    }

    function open(conv, raw) {
        return R.openMessage(conv.room.keys, conv.room.member, raw.id, raw.ciphertext);
    }

    // ---------- create & join ----------

    // The limits a code carries, as create and join send them: the server binds a join to them
    function limitsOf(code) {
        return { max_members: code.maxMembers, expires_at: code.expiresHour * HOUR_SECONDS };
    }

    // True when two codes carry the same limits (a code with the same secret and other limits
    // is doctored: the server refuses it)
    function sameLimits(a, b) {
        return a.maxMembers === b.maxMembers && a.expiresHour === b.expiresHour;
    }

    // The room id a code opens, derived locally
    async function roomIdOf(code) {
        return (await R.deriveRoom(code.secret)).id;
    }

    function ttlChoices(maxTTLHours) {
        return TTL_CHOICES.filter(hours => hours <= maxTTLHours);
    }

    // Draws a code, pays a proof of work and stores the room. Returns { id, code } or a
    // { status } the caller explains.
    async function create({ api, root, maxMembers, ttlHours, solvePow }) {
        for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
            const code = R.newRoomCode(maxMembers, R.expiryHourFor(ttlHours, Date.now()));
            const keys = await R.deriveRoom(code.secret);
            const member = await R.member(keys, root);
            const pow = await solvePow();
            if (!pow) return { status: HTTP_STATUS.NO_ANSWER };
            const result = await api('POST', '/rooms', {
                id: keys.id,
                lookup: keys.lookup,
                ...limitsOf(code),
                card: member.card,
                vault: await R.sealVault(root, keys.id, code),
                pow: pow
            });
            if (result.status === HTTP_STATUS.CONFLICT) continue;
            if (!result.ok || !result.data || !result.data.conversation || result.data.conversation.id !== keys.id) {
                return { status: result.status };
            }
            return { id: keys.id, code: R.buildRoomCode(code) };
        }
        return { status: HTTP_STATUS.CONFLICT };
    }

    // Takes a seat. Returns { id, status }.
    async function join(api, root, code) {
        const keys = await R.deriveRoom(code.secret);
        const member = await R.member(keys, root);
        const result = await api('POST', '/rooms/join', {
            id: keys.id,
            lookup: keys.lookup,
            card: member.card,
            vault: await R.sealVault(root, keys.id, code),
            ...limitsOf(code)
        });
        const conv = result.data && result.data.conversation;
        if (result.ok && (!conv || conv.id !== keys.id)) {
            return { id: null, status: HTTP_STATUS.NO_ANSWER };
        }
        return { id: result.ok ? keys.id : null, status: result.status };
    }

    function codeText(conv) {
        return R.buildRoomCode(conv.room.code);
    }

    // ---------- friend requests ----------
    // A friend request is a note holding an invite code and its binder (R.befriendBinder): the
    // addressee accepts only when the binder proves that the account which created the invite
    // also holds the room key that sent the note (binderMatches, after the redeem answer named
    // the creator). docs/architecture/rooms.md, Friend Requests.

    // Sends entry a friend request for invite ({ code, token }), bound with accountKey (this
    // account's identity key, a CryptoKey used for deriveBits only). A 409 "Id taken" (the note's
    // id is held by something else, nothing stored) seals and sends the same request again under a
    // fresh id, MAX_ID_REDRAWS times at most; any other answer is returned. A disputed entry, or
    // this account's own, is refused before anything is sealed.
    async function befriend({ api, conv, entry, invite, accountKey }) {
        if (!mayBefriend(entry)) throw new Error('not a member to befriend');
        const room = conv.room;
        const binder = await R.befriendBinder({
            room: room.keys, privateKey: accountKey, peerPublic: entry.publicKey, token: invite.token,
            requester: room.member.publicKey, addressee: entry.publicKey
        });
        let result = await sendNote(api, conv, entry, invite.code, binder);
        for (let redraw = 0; Errors.idTaken(result) && redraw < MAX_ID_REDRAWS; redraw++) {
            result = await sendNote(api, conv, entry, invite.code, binder);
        }
        return result;
    }

    async function sendNote(api, conv, entry, inviteCode, binder) {
        const id = ElyrnCrypto.newMessageId();
        const blob = await R.sealNote({
            room: conv.room.keys, me: conv.room.member, id, toCard: entry.card, text: inviteCode, sentAt: Date.now(), binder
        });
        return api('POST', `/conversations/${conv.id}/notes`, { id: id, to: entry.card, blob: blob });
    }

    // Whether note (from notes()) was sent by the member whose account created its invite:
    // creatorKey is the account key the redeem answer named (already checked against the invite's
    // fingerprint), token the invite's. False for a note without a binder.
    async function binderMatches({ conv, note, token, creatorKey }) {
        if (!note.binder) return false;
        const room = conv.room;
        const expected = await R.befriendBinder({
            room: room.keys, privateKey: room.member.privateKey, peerPublic: creatorKey, token: token,
            requester: note.sender, addressee: room.member.publicKey
        });
        return R.sameBinder(expected, note.binder);
    }

    // Returns the notes that open, as [{ id, from (roster entry or null), aura, sender (its room
    // key), invite, binder, newer }]: binder null for a request sent before binders (it can only
    // be ignored), newer true (invite null) for one a newer elyrn wrote. The server cannot make a
    // note open, so anything else is dropped. A listing that failed shows no notes until the next
    // refresh; it is logged (a 401 has already ended the session).
    async function notes(api, conv) {
        const result = await api('GET', `/conversations/${conv.id}/notes`);
        if (!result.ok || !result.data || !Array.isArray(result.data.notes)) {
            if (result.status !== HTTP_STATUS.UNAUTHORIZED) Log.warn(Errors.INTERNAL.W_NOTES_NOT_LOADED, result);
            return [];
        }
        const opened = [];
        const seen = new Set();
        let dropped = 0;
        for (const raw of result.data.notes.slice(0, R.MAX_MEMBERS)) {
            // A note listed twice is one request: shown once, answered once
            if (!raw || !ElyrnCrypto.isUuidV4(raw.id) || typeof raw.blob !== 'string' || seen.has(raw.id)) continue;
            seen.add(raw.id);
            try {
                const note = await R.openNote(conv.room.keys, conv.room.member, raw.id, raw.blob);
                if (note.text.length > MAX_NOTE_CHARS) {
                    dropped++;
                    continue;
                }
                opened.push(await listedNote(conv, raw.id, note.sender, { invite: note.text, binder: note.binder, newer: false }));
            } catch (e) {
                if (ElyrnCrypto.isNewerPayload(e) && typeof e.sender === 'string') {
                    // Authentic and addressed to this member, written by a newer elyrn: shown as such
                    opened.push(await listedNote(conv, raw.id, e.sender, { invite: null, binder: null, newer: true }));
                    continue;
                }
                // Not for us, or tampered with: a note sealed for another member never opens here
                // by design, and the server can add notes at will, so each is dropped and counted;
                // one line per listing is logged below rather than letting the server fill the console
                dropped++;
            }
        }
        if (dropped > 0) Log.warn(Errors.INTERNAL.W_NOTES_DROPPED);
        return opened;
    }

    async function listedNote(conv, id, sender, content) {
        return Object.assign({ id: id, from: senderOf(conv.room, sender) || null, aura: await ElyrnCrypto.aura(sender), sender: sender }, content);
    }

    function dismissNote(api, conv, noteId) {
        return api('DELETE', `/conversations/${conv.id}/notes/${noteId}`);
    }

    // Over the distinct member keys and, when it differs from their number, the seats served
    // (R.safetyNumber): a room with a disputed key shows other digits than one without
    function safetyNumber(conv) {
        return R.safetyNumber(conv.room.roster.map(entry => entry.publicKey), conv.room.rosterCards.length);
    }

    return Object.freeze({
        adopt, refreshView, expired, loadRoster, senderOf, nameCollisions, seal, open, setRole, mayEditRole,
        disputed, roleShown, disputedEntries, mayBefriend,
        ttlChoices, create, join, roomIdOf, sameLimits, codeText, befriend, binderMatches, notes, dismissNote, safetyNumber,
        aura: (id) => R.roomAura(id)
    });
})();
