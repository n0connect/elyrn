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
// WHAT IT CANNOT SEE. A device with no record (first open on this device, after a logout or a
// wiped or private browser storage) has only rule 1. A record is per device, so another
// device's view is not checked. A replay given a seq at or below the remembered one is shown
// as history, under its original authenticated time. A server that rolls its seqs back below
// the remembered one makes new messages look like history. Two devices of one account sending
// at once can spend the same counter; the second is then flagged as a replay.

const Counters = (() => {
    'use strict';

    const PUBLIC_KEY_SHAPE = /^[A-Za-z0-9_-]{43}$/;
    // Bounds the cost of reading a stored record; a room has at most 32 seats at a time,
    // so even heavy churn stays far below this
    const MAX_SENDERS = 4096;

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
    function ledger(record) {
        return { record: record, seq: record.seq, stored: new Map(record.senders), run: new Map() };
    }

    // The verdict on one authenticated message, without changing the ledger
    function judge(state, sender, counter, seq) {
        const run = state.run.get(sender);
        const isNew = seq > state.seq;
        const stored = state.stored.get(sender) || 0;
        if ((run !== undefined && counter <= run) || (isNew && counter <= stored)) {
            return REPLAY;
        }
        const last = run !== undefined ? run : (isNew ? stored : 0);
        return last > 0 && counter > last + 1 ? Object.freeze({ replay: false, gap: counter - last - 1 }) : IN_ORDER;
    }

    // Records a message judge() did not call a replay, so its counter is above the sender's last
    function admit(state, sender, counter) {
        state.run.set(sender, counter);
    }

    // What to remember: the starting record raised by this sequence, up to `seq` processed
    function snapshot(state, seq, mine) {
        return merge(state.record, freeze(seq, mine, state.run));
    }

    return Object.freeze({ EMPTY, parse, merge, same, ledger, judge, admit, snapshot });
})();
