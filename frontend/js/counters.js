// ========================================
// COUNTERS (replay, reorder and gap detection per sender)
// ========================================
// Every message carries its sender's counter inside the authenticated payload, so the server
// can withhold, repeat or reorder messages but never change a counter. This module decides,
// for pairs and rooms alike, what a counter says about the message that carries it. It is pure:
// no storage, no DOM, no network (chat.js persists the record through Keystore).
//
// THE RULE. A sender's device sends one message at a time and numbers them 1, 2, 3…, and the
// server numbers stored messages with an increasing seq, so for one sender the counter grows
// strictly with seq. Two consequences are checked:
//   1. Within one loaded sequence (everything synced since a conversation was opened), a
//      sender's counter must be strictly above the last one seen from them. A counter at or
//      below it is an old message served again, or one served out of order.
//   2. Across reloads, the device remembers the highest seq it processed and each sender's
//      highest counter at that point. A message with a higher seq is new to this device, so
//      its counter must be above that sender's remembered counter; at or below is a replay.
//      A message at or below the remembered seq is history the device has already seen: its
//      old counter is legitimate there, and only rule 1 applies to it. This is what separates
//      the first page of history after a reload (old counters, old seqs) from a replay (old
//      counter, new seq).
// A gap is a counter more than one above the sender's last: messages withheld or deleted.
// The baseline is the last counter seen in this sequence; for a sender not yet seen in it,
// the remembered counter if the message is new, otherwise none (older messages may have
// expired, so the first one visible starts the count).
//
// EARLIER PAGES. Paging back loads messages below everything already loaded. Each such page is
// judged on its own ledger (history()): rule 1 inside the page, rule 2 against the record read
// at open, and, from rule 1 across pages, each sender's counter must stay below the lowest one
// already loaded above it (the page's ceiling). A gap is measured inside the page only: the
// messages between the record and the page may sit on a page not loaded yet. A history ledger
// is never snapshotted, so an earlier page can neither lower nor raise what the device stores.
//
// WHAT IT CANNOT SEE. A device with no record (first open on this device, after a logout or a
// wiped or private browser storage) has only rule 1. A record is per device, so another
// device's view is not checked. A replay given a seq at or below the remembered one is shown
// as history, under its original authenticated time. A server that rolls its seqs back below
// the remembered one makes new messages look like history. Two devices of one account sending
// at once can spend the same counter; the second is then flagged as a replay. Two tabs of one
// browser cannot: chat.js takes each counter under a lock they share, from the record as stored
// at that moment, and stores the raised record before the message is posted.
//
// KEEPING RECORDS (zero trust; the agent's rule, backend/internal/agent/state.go). The server
// may omit a conversation from one listing, or answer 404 for it, and list it again later: a
// record dropped on that word would let its old messages replay undetected. So a record is
// dropped only on facts this device holds itself: the user's own burn or leave the server
// confirmed (204), or, for a room, its own expiry from its verified code lying more than
// EXPIRED_ROOM_GRACE_MS in the past (such a room is then never shown again either). A pair has
// no expiry of its own: its record stays until the user burns it. Past MAX_RECORDS records the
// least recently used go first (retention()): a use is a raise of the record (a message seen
// or sent), stamped with an increasing number, never a time.

const Counters = (() => {
    'use strict';

    const PUBLIC_KEY_SHAPE = /^[A-Za-z0-9_-]{43}$/;
    // Bounds the cost of reading a stored record; a room has at most 32 seats at a time,
    // so even heavy churn stays far below this
    const MAX_SENDERS = 4096;
    // The most counter records one device keeps (the agent keeps as many, maxStateRooms)
    const MAX_RECORDS = 1024;
    // How long past its own expiry a room's record is kept (the agent's expiredRoomGrace)
    const EXPIRED_ROOM_GRACE_MS = 24 * 60 * 60 * 1000;

    const EMPTY = Object.freeze({ seq: 0, mine: 0, senders: Object.freeze([]) });
    const REPLAY = Object.freeze({ replay: true, gap: 0 });
    const IN_ORDER = Object.freeze({ replay: false, gap: 0 });

    function isCount(value) {
        return Number.isSafeInteger(value) && value >= 0;
    }

    function isEntry(entry) {
        return Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string' &&
            PUBLIC_KEY_SHAPE.test(entry[0]) && isCount(entry[1]) && entry[1] > 0;
    }

    function freeze(seq, mine, senders) {
        return Object.freeze({
            seq: seq,
            mine: mine,
            senders: Object.freeze([...senders].map(entry => Object.freeze([entry[0], entry[1]])))
        });
    }

    // A stored record, checked: anything malformed counts as no record (today's behaviour)
    function parse(raw) {
        if (!raw || typeof raw !== 'object' || !isCount(raw.seq) || !isCount(raw.mine) ||
            !Array.isArray(raw.senders) || raw.senders.length > MAX_SENDERS || !raw.senders.every(isEntry)) {
            return EMPTY;
        }
        return freeze(raw.seq, raw.mine, new Map(raw.senders));
    }

    // Every field is a high-water mark, so two records combine by taking the higher of each:
    // a sender's counter in either came from a message at or below the higher seq
    function merge(a, b) {
        const senders = new Map(a.senders);
        for (const [key, counter] of b.senders) {
            senders.set(key, Math.max(senders.get(key) || 0, counter));
        }
        return freeze(Math.max(a.seq, b.seq), Math.max(a.mine, b.mine), senders);
    }

    function same(a, b) {
        return a.seq === b.seq && a.mine === b.mine && a.senders.length === b.senders.length &&
            a.senders.every(([key, counter]) => b.senders.some(entry => entry[0] === key && entry[1] === counter));
    }

    // The state of one loaded sequence: the record it started from and what it has seen since
    // (run: each sender's last counter; first: their first, the lowest in ascending seq)
    function ledger(record) {
        return { record: record, seq: record.seq, stored: new Map(record.senders), run: new Map(), first: new Map(), ceiling: null };
    }

    // The state of one earlier page: `above` holds each sender's lowest counter loaded above it
    function history(record, above) {
        return Object.assign(ledger(record), { ceiling: new Map(above) });
    }

    // Each sender's lowest counter across `above` and what `state` admitted: the next page's ceiling
    function lowest(above, state) {
        const merged = new Map(above);
        for (const [key, counter] of state.first) {
            merged.set(key, Math.min(merged.has(key) ? merged.get(key) : counter, counter));
        }
        return merged;
    }

    // The verdict on one authenticated message, without changing the ledger
    function judge(state, sender, counter, seq) {
        const run = state.run.get(sender);
        const isNew = seq > state.seq;
        const stored = state.stored.get(sender) || 0;
        const ceiling = state.ceiling ? state.ceiling.get(sender) : undefined;
        if ((run !== undefined && counter <= run) || (isNew && counter <= stored) ||
            (ceiling !== undefined && counter >= ceiling)) {
            return REPLAY;
        }
        // An earlier page measures gaps from inside itself only (see EARLIER PAGES)
        const last = run !== undefined ? run : (isNew && !state.ceiling ? stored : 0);
        return last > 0 && counter > last + 1 ? Object.freeze({ replay: false, gap: counter - last - 1 }) : IN_ORDER;
    }

    // Records a message judge() did not call a replay, so its counter is above the sender's last
    function admit(state, sender, counter) {
        state.run.set(sender, counter);
        if (!state.first.has(sender)) state.first.set(sender, counter);
    }

    // What to remember: the starting record raised by this sequence, up to `seq` processed
    function snapshot(state, seq, mine) {
        return merge(state.record, freeze(seq, mine, state.run));
    }

    // ---------- keeping records (see KEEPING RECORDS) ----------

    // Whether a room that expires at expiresMs (0: no expiry of its own, a pair) expired more
    // than EXPIRED_ROOM_GRACE_MS before nowMs
    function expiredLongAgo(expiresMs, nowMs) {
        return isCount(expiresMs) && expiresMs > 0 && nowMs > expiresMs + EXPIRED_ROOM_GRACE_MS;
    }

    // What retention() needs of a stored record: its use stamp and its room's expiry (both 0
    // when missing or malformed: a record from before they were kept is the oldest, with none)
    function retentionEntry(id, raw) {
        const used = raw && isCount(raw.used) ? raw.used : 0;
        const expires = raw && isCount(raw.expires) ? raw.expires : 0;
        return { id: id, used: used, expires: expires };
    }

    // The ids of the records to drop: those of rooms expired long ago, then, past MAX_RECORDS,
    // the least recently used (the conversations in `held`, listed now, last). `evicted` says
    // whether the bound evicted any.
    function retention(entries, nowMs, held) {
        const drop = [];
        const kept = [];
        for (const entry of entries) {
            if (expiredLongAgo(entry.expires, nowMs)) drop.push(entry.id);
            else kept.push(entry);
        }
        const excess = kept.length - MAX_RECORDS;
        if (excess <= 0) return { drop: drop, evicted: false };
        const isHeld = entry => (held && held.has(entry.id) ? 1 : 0);
        kept.sort((a, b) => (isHeld(a) - isHeld(b)) || (a.used - b.used));
        return { drop: drop.concat(kept.slice(0, excess).map(entry => entry.id)), evicted: true };
    }

    return Object.freeze({
        EMPTY, MAX_RECORDS, EXPIRED_ROOM_GRACE_MS, parse, merge, same, ledger, history, lowest, judge, admit, snapshot,
        expiredLongAgo, retentionEntry, retention
    });
})();
