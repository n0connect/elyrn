// ========================================
// COUNTER RECORDS (what this device remembers of each conversation's counters)
// ========================================
// One job: keeps each conversation's counter record on this device (Keystore), under the
// counter lock every tab shares, so a replay is caught across reloads and no counter is spent
// twice. The rules a record follows are counters.js's; the conversation objects are chat.js's.

const CounterRecords = (() => {
    'use strict';

    // id -> the last counter record of a conversation dropped from this session but not burned by
    // the user (a listing omitted it, a 404): it judges again if the server lists it again, also
    // when storage failed (counters.js KEEPING RECORDS)
    const parked = new Map();
    let evictionWarned = false;       // W_COUNTER_RECORDS_EVICTED is logged once per page load

    // The senders a record never loses to the sender bound (counters.js THE SENDER BOUND): in a
    // room, this device's own member key and the current roster's; a pair names two senders at most
    function keptSenders(conv) {
        if (!conv.room) return [];
        return [conv.room.member.publicKey, ...(conv.room.roster || []).map(entry => entry.publicKey)];
    }

    // A record as stored, read within the sender bound; a stored record above it (written by an
    // older build) keeps this device's own entry, the roster's, then the earliest-recorded others
    // up to the bound (Counters.trim)
    async function readMark(conv) {
        const read = Counters.parseBounded(await Keystore.loadCounters(conv.id), keptSenders(conv));
        if (read.evicted > 0) Log.warn(Errors.INTERNAL.W_COUNTER_RECORDS_EVICTED);
        return read.record;
    }

    // What this device remembers of a conversation; the in-memory copy stands in when storage fails
    async function loadMark(conv) {
        return Counters.merge(await readMark(conv), conv.mark);
    }

    // Records only grow (each field is a high-water mark), so a save merges with the record as
    // stored now, read under the counter lock every tab shares: another tab's higher record is
    // never overwritten, and a save made before the first sync of a reload never lowers it
    async function saveMark(conv) {
        const raised = Counters.merge(await conv.markLoad, Counters.snapshot(conv.ledger, conv.maxSeq, conv.myMaxN));
        await Keystore.withCounterLock(conv.id, async () => {
            const stored = await storedMark(conv);
            const earlier = Counters.merge(stored, conv.mark);
            await writeMark(conv, stored, earlier, Counters.merge(earlier, raised));
        });
    }

    // The record as stored right now (Counters.EMPTY when there is none or storage failed)
    function storedMark(conv) {
        return readMark(conv);
    }

    // Keeps next within the sender bound (Counters.bound: what earlier recorded is never given up
    // to a made-up sender; a new off-roster sender at the bound is not recorded, a new roster
    // member displaces the off-roster entry recorded most recently, logged), as this tab's last
    // one (it stands in when storage fails), and stores it unless the stored one already says the
    // same. Every record this device writes therefore reads back whole. The senders not recorded,
    // refused and displaced alike, are kept in conv.unrecorded, which the page shows (chat.js
    // markUnrecorded, asking isUnrecorded); one recorded since (it joined the roster) leaves it.
    async function writeMark(conv, stored, earlier, next) {
        const kept = Counters.bound(earlier, next, keptSenders(conv));
        if (kept.displaced.length > 0) Log.warn(Errors.INTERNAL.W_COUNTER_RECORDS_EVICTED);
        trackUnrecorded(conv, kept);
        conv.mark = kept.record;
        if (!Counters.same(kept.record, stored)) {
            await Keystore.saveCounters(conv.id, kept.record, conv.room ? conv.room.expiresAt : 0);
        }
    }

    // conv.unrecorded after a write (kept: Counters.bound's answer). It holds at most
    // Counters.MAX_UNRECORDED senders, and the bound may only make the answer more conservative:
    // a sender that finds it full sets conv.unrecordedOverflow, under which isUnrecorded calls
    // every sender neither kept nor in the record unrecorded. Senders recorded since leave the
    // set first; the flag clears only when that brings the set below the bound (a sender still
    // unrecorded in the loaded sequence is refused again by this same write, and sets it again).
    function trackUnrecorded(conv, kept) {
        const recorded = new Map(kept.record.senders);
        for (const key of conv.unrecorded) if (recorded.has(key)) conv.unrecorded.delete(key);
        if (conv.unrecorded.size < Counters.MAX_UNRECORDED) conv.unrecordedOverflow = false;
        for (const key of [...kept.refused, ...kept.displaced]) {
            if (conv.unrecorded.has(key)) continue;
            if (conv.unrecorded.size < Counters.MAX_UNRECORDED) conv.unrecorded.add(key);
            else conv.unrecordedOverflow = true;
        }
    }

    // Whether sender's messages in conv are shown as not recorded (counters.js THE SENDER BOUND):
    // the one place the page asks. Named in conv.unrecorded, or, once that overflowed, neither
    // kept (keptSenders) nor in the record this tab holds (conv.mark): never an unknown sender
    // shown as protected.
    function isUnrecorded(conv, sender) {
        if (conv.unrecorded.has(sender)) return true;
        return conv.unrecordedOverflow && !keptSenders(conv).includes(sender) &&
            !conv.mark.senders.some(([key]) => key === sender);
    }

    // Takes this account's next counter in a conversation, under the counter lock every tab
    // shares: the stored record is read fresh inside it and raised to the new counter before the
    // message is posted (write-ahead), so a second tab, hidden or behind on its syncs, never takes
    // the same one. A counter given back by a send the server refused (releaseCounter) is taken
    // again, as long as no tab has gone past it since.
    async function allocateCounter(conv) {
        const opened = await conv.markLoad;
        return Keystore.withCounterLock(conv.id, async () => {
            const stored = await storedMark(conv);
            const known = Counters.merge(Counters.merge(stored, conv.mark), opened);
            const top = Math.max(conv.myMaxN, known.mine);
            const counter = conv.spare > 0 && conv.spare === top ? top : top + 1;
            conv.spare = 0;
            conv.myMaxN = counter;
            await writeMark(conv, stored, known, Counters.merge(known, Counters.parse({ seq: 0, mine: counter, senders: [] })));
            return counter;
        });
    }

    // A send the server settled as not stored gives its counter back for the next one, unless an
    // earlier attempt of it went unanswered (the server may hold that one) or a later one was taken
    function releaseCounter(conv, attempt) {
        if (!attempt.lost && conv.myMaxN === attempt.counter) {
            conv.spare = attempt.counter;
        }
    }

    // The user's own burn or leave, confirmed by the server (204): the only time a conversation's
    // counter record is forgotten before its room expires (counters.js KEEPING RECORDS). Queued
    // behind the conversation's syncs so a save in flight cannot land after the removal.
    function forgetMark(conv) {
        conv.syncChain = conv.syncChain.then(() => forgetRecord(conv.id));
    }

    function forgetRecord(id) {
        parked.delete(id);
        return Keystore.forgetCounters(id);
    }

    // Once per session, on its first listing: drops the records of rooms expired long ago and,
    // past the bound, the least recently used (the conversations listed now last)
    async function pruneMarks(listedIds) {
        if (await Keystore.pruneCounters(Date.now(), listedIds) && !evictionWarned) {
            evictionWarned = true;
            Log.warn(Errors.INTERNAL.W_COUNTER_RECORDS_EVICTED);
        }
    }

    function park(id, mark) {
        parked.set(id, mark);
    }

    function parkedMark(id) {
        return parked.get(id);
    }

    // The session ended: nothing it dropped is remembered in memory any longer
    function clearParked() {
        parked.clear();
    }

    return Object.freeze({
        loadMark, saveMark, allocateCounter, releaseCounter, forgetMark, forgetRecord, pruneMarks,
        park, parkedMark, clearParked, trackUnrecorded, isUnrecorded
    });
})();
