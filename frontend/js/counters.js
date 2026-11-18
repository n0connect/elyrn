// ========================================
// COUNTERS (replay, reorder and gap detection per sender)
// ========================================
// Every message carries its sender's counter inside the authenticated payload, so the server
// can withhold, repeat or reorder messages but never change a counter. This module decides,
// for pairs and rooms alike, what a counter says about the message that carries it. It is pure:
// no storage, no DOM, no network (counter-records.js persists the record through Keystore).
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
// browser cannot: counter-records.js takes each counter under a lock they share, from the record as stored
// at that moment, and stores the raised record before the message is posted.
//
// THE SENDER BOUND. A record names at most MAX_SENDERS senders. A room member could send under
// keys of its own making (until the server refuses a header card that is not the sender's stored
// card), so the senders a room's record sees are not bounded by its seats. The bound is kept where
// a record is written (bound(), called by counter-records.js before every write), and an entry
// recorded earlier is never given up to a made-up sender:
//   - a new sender that is not on the current roster is recorded only while there is room; at
//     the bound it is not recorded (bound() names it: its messages are shown with a warning that
//     replay protection is not kept for it on this device);
//   - a new sender on the current roster is always recorded: it displaces the off-roster entry
//     recorded longest ago (the order a record lists its senders in is the order they were first
//     recorded, merge() keeps it). This device's own entry and the roster's are never displaced.
// A record above the bound (an older build wrote it) is read keeping this device's own entry, the
// roster's, then the earliest-recorded others up to the bound (trim()): never thrown away whole,
// which would forget this device's own counter and the remembered seq.
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
    // The most senders one record names (THE SENDER BOUND): a room has at most 32 seats at a time,
    // so honest churn stays far below it; made-up senders past it are not recorded
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

    // A stored record, checked: anything malformed counts as no record. One naming more than
    // MAX_SENDERS senders (an older build wrote it) is trimmed (trim(), keeping the keys in `keep`:
    // this device's own and the roster's), never discarded whole. Returns the record;
    // parseBounded also says how many senders were dropped.
    function parse(raw, keep) {
        return parseBounded(raw, keep).record;
    }

    function parseBounded(raw, keep) {
        if (!raw || typeof raw !== 'object' || !isCount(raw.seq) || !isCount(raw.mine) ||
            !Array.isArray(raw.senders) || !raw.senders.every(isEntry)) {
            return { record: EMPTY, evicted: 0 };
        }
        return trim(freeze(raw.seq, raw.mine, new Map(raw.senders)), keep);
    }

    // record with at most MAX_SENDERS senders, for reading one above the bound: { record, evicted }.
    // Every sender in keep (an iterable of public keys) stays; the others stay in the order the
    // record lists them (earliest recorded first) while there is room, and the later ones go. The
    // kept senders alone may pass the bound (keep is this device's own key and a roster of at most
    // 32 members): they all stay. Order, seq and mine are unchanged; a record within the bound is
    // returned as it is.
    function trim(record, keep) {
        if (record.senders.length <= MAX_SENDERS) return { record: record, evicted: 0 };
        const kept = new Set(keep || []);
        let room = MAX_SENDERS - record.senders.filter(([key]) => kept.has(key)).length;
        const senders = record.senders.filter(([key]) => {
            if (kept.has(key)) return true;
            if (room <= 0) return false;
            room--;
            return true;
        });
        return { record: freeze(record.seq, record.mine, senders), evicted: record.senders.length - senders.length };
    }

    // The record to write (THE SENDER BOUND): next (the record raised by what was just seen; it
    // holds every sender of earlier) brought within the bound without giving up what earlier
    // recorded. earlier is the record as recorded before (stored and this tab's last write),
    // trimmed first should it be above the bound. Senders of earlier keep their place and take
    // next's counters; next's new senders follow in next's order: each is recorded while there is
    // room; at the bound one in keep (this device's own key, the roster) displaces the off-roster
    // entry recorded longest ago, and one not in keep is refused. Returns { record, refused (the
    // senders not recorded), displaced (how many entries gave way to a roster member) }.
    function bound(earlier, next, keep) {
        const kept = new Set(keep || []);
        const counters = new Map(next.senders);
        const out = new Map();
        for (const [key, counter] of trim(earlier, kept).record.senders) {
            out.set(key, Math.max(counter, counters.get(key) || 0));
        }
        const refused = [];
        let displaced = 0;
        let oldest = out.keys();  // walks the entries recorded longest ago, for displacement
        for (const [key, counter] of next.senders) {
            if (out.has(key)) continue;
            if (out.size >= MAX_SENDERS) {
                if (!kept.has(key)) {
                    refused.push(key);
                    continue;
                }
                const victim = firstOffRoster(oldest, out, kept);
                if (victim !== null) {
                    out.delete(victim);
                    displaced++;
                } else {
                    oldest = out.keys();
                }
            }
            out.set(key, counter);
        }
        return {
            record: freeze(Math.max(earlier.seq, next.seq), Math.max(earlier.mine, next.mine), out),
            refused: refused, displaced: displaced
        };
    }

    // The first key the iterator still yields that is in out and not kept, or null
    function firstOffRoster(iterator, out, kept) {
        for (let step = iterator.next(); !step.done; step = iterator.next()) {
            if (out.has(step.value) && !kept.has(step.value)) return step.value;
        }
        return null;
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

    // Linear in the senders (a record names each sender once), so a record at MAX_SENDERS is
    // compared on every save without a quadratic cost
    function same(a, b) {
        if (a.seq !== b.seq || a.mine !== b.mine || a.senders.length !== b.senders.length) return false;
        const other = new Map(b.senders);
        return a.senders.every(([key, counter]) => other.get(key) === counter);
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
        EMPTY, MAX_RECORDS, MAX_SENDERS, EXPIRED_ROOM_GRACE_MS, parse, parseBounded, trim, bound, merge, same, ledger, history,
        lowest, judge, admit, snapshot, expiredLongAgo, retentionEntry, retention
    });
})();
