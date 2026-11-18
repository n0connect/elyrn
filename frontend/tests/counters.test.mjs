// frontend/js/counters.js replay, reorder and gap detection, loaded as the browser loads it.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({});
const Counters = vm.runInContext(readFileSync(new URL('../js/counters.js', import.meta.url), 'utf8') + '\n;Counters', context);
// Arrays made inside the context have its own prototypes: compare them through a Map built here

const ALICE = 'A'.repeat(43);
const BOB = 'B'.repeat(43);

// Feeds [sender, counter, seq] in order, as a sync does, and returns each verdict as a word
function play(state, messages) {
    return messages.map(([sender, counter, seq]) => {
        const verdict = Counters.judge(state, sender, counter, seq);
        if (verdict.replay) return 'replay';
        Counters.admit(state, sender, counter);
        return verdict.gap > 0 ? `gap ${verdict.gap}` : 'ok';
    });
}

function fresh() {
    return Counters.ledger(Counters.EMPTY);
}

// A record as a previous session of this device would have left it
function remembered(seq, senders, mine = 0) {
    return Counters.ledger(Counters.parse({ seq, mine, senders }));
}

test('in order: consecutive counters pass, from the first one visible', () => {
    assert.deepEqual(play(fresh(), [[ALICE, 4, 1], [ALICE, 5, 2], [ALICE, 6, 3]]), ['ok', 'ok', 'ok']);
});

test('gap: a skipped counter reports how many are missing, and only once', () => {
    assert.deepEqual(play(fresh(), [[ALICE, 1, 1], [ALICE, 4, 2], [ALICE, 5, 3]]), ['ok', 'gap 2', 'ok']);
});

test('replay within one sequence: a counter already seen is refused', () => {
    assert.deepEqual(play(fresh(), [[ALICE, 1, 1], [ALICE, 2, 2], [ALICE, 2, 3]]), ['ok', 'ok', 'replay']);
});

test('reorder within one sequence: a lower counter after a higher one is refused', () => {
    assert.deepEqual(play(fresh(), [[ALICE, 1, 1], [ALICE, 3, 2], [ALICE, 2, 3]]), ['ok', 'gap 1', 'replay']);
});

test('replay after a reload: an old counter under a new seq is refused, even alone', () => {
    // The device saw up to seq 10, where Alice was at 5; the server serves only her counter 3 again
    assert.deepEqual(play(remembered(10, [[ALICE, 5]]), [[ALICE, 3, 11]]), ['replay']);
    assert.deepEqual(play(remembered(10, [[ALICE, 5]]), [[ALICE, 5, 11]]), ['replay']);
});

test('first load after a reload: history keeps its old counters, new messages follow on', () => {
    const state = remembered(10, [[ALICE, 5], [BOB, 2]]);
    const history = [[ALICE, 3, 6], [ALICE, 4, 8], [BOB, 2, 9], [ALICE, 5, 10]];
    assert.deepEqual(play(state, history), ['ok', 'ok', 'ok', 'ok']);
    assert.deepEqual(play(state, [[ALICE, 6, 11], [BOB, 3, 12]]), ['ok', 'ok']);
});

test('after a reload, a sender absent from the history page is measured from the record', () => {
    assert.deepEqual(play(remembered(10, [[ALICE, 5]]), [[ALICE, 8, 11]]), ['gap 2']);
    // History (seq at or below the record) has no baseline: older messages may have expired
    assert.deepEqual(play(remembered(10, [[ALICE, 5]]), [[ALICE, 2, 4]]), ['ok']);
});

test('first-ever load: no record, so only order within the sequence is checked', () => {
    assert.deepEqual(play(fresh(), [[ALICE, 7, 40], [ALICE, 8, 41], [ALICE, 7, 42]]), ['ok', 'ok', 'replay']);
});

test('per sender: one sender\'s counters never judge another\'s', () => {
    const state = remembered(10, [[ALICE, 9]]);
    assert.deepEqual(play(state, [[BOB, 1, 11], [ALICE, 10, 12], [BOB, 2, 13], [ALICE, 11, 14]]),
        ['ok', 'ok', 'ok', 'ok']);
    assert.deepEqual(play(fresh(), [[ALICE, 5, 1], [BOB, 1, 2], [BOB, 5, 3], [ALICE, 5, 4]]),
        ['ok', 'ok', 'gap 3', 'replay']);
});

test('a replay leaves the ledger as it was', () => {
    const state = fresh();
    play(state, [[ALICE, 3, 1]]);
    assert.deepEqual(play(state, [[ALICE, 1, 2], [ALICE, 4, 3]]), ['replay', 'ok']);
});

test('the snapshot remembers the highest seq and counters, and never lowers a record', () => {
    const state = remembered(10, [[ALICE, 5], [BOB, 7]], 4);
    play(state, [[ALICE, 2, 3], [ALICE, 6, 11]]);
    const record = Counters.snapshot(state, 11, 6);
    assert.equal(record.seq, 11);
    assert.equal(record.mine, 6);
    assert.deepEqual(new Map(record.senders), new Map([[ALICE, 6], [BOB, 7]]));
    // A snapshot taken before anything new was seen keeps the record's own values
    const early = Counters.snapshot(remembered(10, [[ALICE, 5]], 4), 0, 0);
    assert.equal(early.seq, 10);
    assert.equal(early.mine, 4);
    assert.deepEqual(new Map(early.senders), new Map([[ALICE, 5]]));
});

test('merge takes the higher of every field; same compares regardless of order', () => {
    const a = Counters.parse({ seq: 5, mine: 9, senders: [[ALICE, 3], [BOB, 8]] });
    const b = Counters.parse({ seq: 7, mine: 2, senders: [[BOB, 4], [ALICE, 6]] });
    const merged = Counters.merge(a, b);
    assert.equal(merged.seq, 7);
    assert.equal(merged.mine, 9);
    assert.deepEqual(new Map(merged.senders), new Map([[ALICE, 6], [BOB, 8]]));
    assert.ok(Counters.same(merged, Counters.merge(b, a)));
    assert.ok(!Counters.same(a, b));
});

test('a malformed stored record counts as none', () => {
    for (const raw of [undefined, null, 42, 'x', {}, { seq: -1, mine: 0, senders: [] },
        { seq: 1, mine: 1.5, senders: [] }, { seq: 1, mine: 0, senders: {} },
        { seq: 1, mine: 0, senders: [['short', 1]] }, { seq: 1, mine: 0, senders: [[ALICE, 0]] },
        { seq: 1, mine: 0, senders: [[ALICE, 1, 2]] }, { seq: 1, mine: 0, senders: [[ALICE, '1']] }]) {
        assert.equal(Counters.parse(raw), Counters.EMPTY);
    }
});

// Paging back: the latest page is loaded, then an earlier page judged on its own ledger
function earlierPage(record, loaded, page) {
    const latest = Counters.ledger(record);
    play(latest, loaded);
    const before = Counters.snapshot(latest, loaded[loaded.length - 1][2], 0);
    const state = Counters.history(record, Counters.lowest(new Map(), latest));
    const verdicts = play(state, page);
    return { verdicts, latest, state, before };
}

test('earlier page: old counters below the loaded ones pass, with no gap from the record', () => {
    // The device remembers seq 10 (Alice at 5); seqs 11..299 are on pages not loaded yet
    const record = Counters.parse({ seq: 10, mine: 0, senders: [[ALICE, 5]] });
    const run = earlierPage(record, [[ALICE, 200, 300], [ALICE, 201, 301]], [[ALICE, 50, 100], [ALICE, 51, 101]]);
    assert.deepEqual(run.verdicts, ['ok', 'ok']);
});

test('earlier page: a gap inside the page is reported, a counter at or above the loaded ones is a replay', () => {
    const record = Counters.parse({ seq: 10, mine: 0, senders: [[ALICE, 5]] });
    const loaded = [[ALICE, 200, 300]];
    assert.deepEqual(earlierPage(record, loaded, [[ALICE, 50, 100], [ALICE, 53, 101]]).verdicts, ['ok', 'gap 2']);
    assert.deepEqual(earlierPage(record, loaded, [[ALICE, 200, 100]]).verdicts, ['replay']);
    assert.deepEqual(earlierPage(record, loaded, [[ALICE, 250, 100]]).verdicts, ['replay']);
    // Rule 2 still holds: above the remembered seq, a counter at or below the record's is a replay
    assert.deepEqual(earlierPage(record, loaded, [[ALICE, 5, 20]]).verdicts, ['replay']);
});

test('earlier page: the loaded sequence and its snapshot are left as they were', () => {
    const record = Counters.parse({ seq: 10, mine: 0, senders: [[ALICE, 5], [BOB, 9]] });
    const run = earlierPage(record, [[ALICE, 200, 300]], [[ALICE, 50, 100], [BOB, 20, 101]]);
    assert.deepEqual(new Map(run.latest.run), new Map([[ALICE, 200]]));
    const after = Counters.snapshot(run.latest, 300, 0);
    assert.ok(Counters.same(after, run.before));
    // The next page down is bounded by the lowest counters of everything above it
    assert.deepEqual(new Map(Counters.lowest(Counters.lowest(new Map(), run.latest), run.state)), new Map([[ALICE, 50], [BOB, 20]]));
});

// ---------- keeping records (counters.js KEEPING RECORDS) ----------
// The stored record exactly as Keystore.saveCounters writes it: the counters, a use stamp and
// the room's expiry (0 for a pair)
function storedAs(record, used, expires) {
    return { seq: record.seq, mine: record.mine, senders: record.senders.map((e) => [e[0], e[1]]), used, expires };
}

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 10, 13);

// What retention() drops of { id: [used, expires] }, sorted, in this realm
function dropped(records, held) {
    const entries = Object.entries(records).map(([id, [used, expires]]) => Counters.retentionEntry(id, { used, expires }));
    const verdict = Counters.retention(entries, NOW, held);
    return { drop: [...verdict.drop].sort(), evicted: verdict.evicted };
}

test('hide, relist, replay: a pair the server omitted keeps its record, which flags the replay once it is listed again', () => {
    // The device saw up to seq 10, Alice at 5, and stored that
    const state = fresh();
    assert.deepEqual(play(state, [[ALICE, 4, 9], [ALICE, 5, 10]]), ['ok', 'ok']);
    const stored = storedAs(Counters.snapshot(state, 10, 0), 1, 0);
    // A listing omits the conversation: nothing the device knows itself drops the record,
    // however long the server keeps it hidden
    const later = NOW + 3650 * DAY_MS;
    assert.deepEqual([...Counters.retention([Counters.retentionEntry('pair', stored)], later, new Set()).drop], []);
    // Listed again: the stored record still judges, and the old message under a new seq is a replay
    const relisted = Counters.ledger(Counters.parse(stored));
    assert.deepEqual(play(relisted, [[ALICE, 5, 11]]), ['replay']);
    assert.deepEqual(play(Counters.ledger(Counters.parse(stored)), [[ALICE, 3, 12]]), ['replay']);
    assert.deepEqual(play(Counters.ledger(Counters.parse(stored)), [[ALICE, 6, 11]]), ['ok']);
});

test('a stored record keeps its counters whatever use stamp and expiry it carries', () => {
    const record = Counters.parse({ seq: 10, mine: 3, senders: [[ALICE, 5]] });
    assert.ok(Counters.same(Counters.parse(storedAs(record, 7, NOW)), record));
    // A record from before stamps were kept is the least recently used, with no expiry
    const legacy = Counters.retentionEntry('old', { seq: 1, mine: 0, senders: [] });
    assert.equal(legacy.used, 0);
    assert.equal(legacy.expires, 0);
    for (const junk of [null, 'x', { used: -1, expires: 1.5 }, { used: '9', expires: NaN }]) {
        const entry = Counters.retentionEntry('j', junk);
        assert.equal(entry.used, 0);
        assert.equal(entry.expires, 0);
    }
});

test('a room record goes only once the room\'s own expiry lies more than the grace in the past', () => {
    const grace = Counters.EXPIRED_ROOM_GRACE_MS;
    assert.deepEqual(dropped({ edge: [1, NOW - grace], inside: [2, NOW - grace + 1], past: [3, NOW - grace - 1], pair: [4, 0] }),
        { drop: ['past'], evicted: false });
    assert.equal(Counters.expiredLongAgo(NOW - grace, NOW), false);
    assert.equal(Counters.expiredLongAgo(NOW - grace - 1, NOW), true);
    assert.equal(Counters.expiredLongAgo(0, NOW), false);
});

test('bound: past the most records kept, the least recently used go first and the listed ones last', () => {
    const max = Counters.MAX_RECORDS;
    const records = {};
    for (let i = 1; i <= max; i++) records[`c${i}`] = [i, 0];
    assert.deepEqual(dropped(records), { drop: [], evicted: false });
    // Three more: the three oldest stamps go, and the bound reports an eviction
    records.n1 = [max + 1, 0];
    records.n2 = [max + 2, 0];
    records.legacy = [0, 0];
    assert.deepEqual(dropped(records), { drop: ['c1', 'c2', 'legacy'], evicted: true });
    // A conversation listed now is evicted after every unlisted one, whatever its stamp
    assert.deepEqual(dropped(records, new Set(['legacy', 'c1'])), { drop: ['c2', 'c3', 'c4'], evicted: true });
    // A room expired long ago is dropped first and makes room without evicting anything
    records.n2 = [max + 2, NOW - Counters.EXPIRED_ROOM_GRACE_MS - 1];
    records.n3 = [max + 3, NOW - Counters.EXPIRED_ROOM_GRACE_MS - 1];
    delete records.legacy;
    delete records.n1;
    assert.deepEqual(dropped(records), { drop: ['n2', 'n3'], evicted: false });
});

// ---------- the sender bound (fix-spec C2, as revised by the lead on 18 Nov) ----------

// A 43-character key per index, from the base64url alphabet, as a member could mint them (never
// one of ALICE, BOB or OWN: those start with another letter)
function mintedKey(i) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let out = 'm';
    for (let n = i, d = 0; d < 42; d++, n = Math.floor(n / 64)) out += alphabet[n % 64];
    return out;
}

const OWN = 'O'.repeat(43);
const FORMER = 'F'.repeat(43);  // a member who left: off the roster, recorded before the flood

// A ledger raised from record by messages from each of senders (counter 1), as a sync builds it,
// unbounded; returns its snapshot
function raisedBy(record, senders) {
    const state = Counters.ledger(record);
    for (const key of senders) Counters.admit(state, key, 1);
    return Counters.snapshot(state, record.seq + senders.length, record.mine);
}

test('a stored record past the sender bound is read trimmed, never as no record: own counter, roster and earliest kept', () => {
    const flood = Array.from({ length: Counters.MAX_SENDERS + 1 }, (_, i) => [mintedKey(i), 1]);
    // What a build before the bound wrote: the device's own entry and a member last, after the flood
    const raw = { seq: 9000, mine: 50, senders: [[FORMER, 7], ...flood, [ALICE, 3], [OWN, 50]] };
    const read = Counters.parseBounded(raw, [OWN, ALICE]);
    assert.notEqual(read.record, Counters.EMPTY);
    assert.equal(read.record.seq, 9000);
    assert.equal(read.record.mine, 50);
    assert.equal(read.record.senders.length, Counters.MAX_SENDERS);
    const kept = new Map(read.record.senders);
    assert.equal(kept.get(OWN), 50, 'the device\'s own entry is never dropped');
    assert.equal(kept.get(ALICE), 3, 'a roster member is never dropped');
    assert.equal(kept.get(FORMER), 7, 'the earliest-recorded others stay');
    assert.equal(kept.has(mintedKey(0)), true);
    // the latest-recorded others go
    assert.equal(kept.has(mintedKey(Counters.MAX_SENDERS)), false);
    assert.equal(read.evicted, raw.senders.length - Counters.MAX_SENDERS);
    assert.ok(Counters.same(Counters.parse(raw, [OWN, ALICE]), read.record));
});

test('an attacker\'s made-up senders never displace what was recorded before them, however many', () => {
    // An honest former member recorded first, then the device's own and a member's entries
    let earlier = Counters.parse({ seq: 10, mine: 4, senders: [[FORMER, 9], [OWN, 4], [ALICE, 2]] });
    const keep = [OWN, ALICE];
    const refusedAll = new Set();
    // Floods well above the bound, written save after save as a sync writes them
    for (let wave = 0; wave < 3; wave++) {
        const fresh = Array.from({ length: Counters.MAX_SENDERS }, (_, i) => mintedKey(wave * Counters.MAX_SENDERS + i));
        const next = Counters.merge(earlier, raisedBy(earlier, fresh));
        const written = Counters.bound(earlier, next, keep);
        assert.ok(written.record.senders.length <= Counters.MAX_SENDERS);
        assert.equal(written.displaced.length, 0, 'nothing on the roster was new: nothing gave way');
        for (const key of written.refused) refusedAll.add(key);
        const kept = new Map(written.record.senders);
        assert.equal(kept.get(FORMER), 9, 'the former member\'s entry and counter are untouched');
        assert.equal(kept.get(OWN), 4);
        assert.equal(kept.get(ALICE), 2);
        assert.equal(written.record.mine, 4);
        earlier = written.record;
    }
    assert.equal(refusedAll.size, 3 * Counters.MAX_SENDERS - (Counters.MAX_SENDERS - 3), 'every made-up sender past the room is refused');
});

test('a roster member new to a full record is recorded: it displaces the off-roster entry recorded most recently', () => {
    const full = Counters.parse({ seq: 1, mine: 1, senders: [[FORMER, 5], [OWN, 1],
        ...Array.from({ length: Counters.MAX_SENDERS - 2 }, (_, i) => [mintedKey(i), 1])] });
    assert.equal(full.senders.length, Counters.MAX_SENDERS);
    const next = Counters.merge(full, raisedBy(full, [mintedKey(999999), BOB]));
    const written = Counters.bound(full, next, [OWN, BOB]);
    const kept = new Map(written.record.senders);
    const latest = mintedKey(Counters.MAX_SENDERS - 3);
    assert.equal(kept.has(BOB), true, 'a member is always recorded');
    assert.equal(kept.get(FORMER), 5, 'the long-held former member stays');
    assert.equal(kept.has(latest), false, 'the off-roster entry recorded most recently gave way');
    assert.equal(kept.get(OWN), 1);
    assert.deepEqual([...written.refused], [mintedKey(999999)]);
    assert.deepEqual([...written.displaced], [latest], 'the displaced sender is named, to be marked unrecorded');
    assert.equal(written.record.senders.length, Counters.MAX_SENDERS);
});

test('a roster member displaces an off-roster sender recorded earlier in the same write before any older one', () => {
    const almost = Counters.parse({ seq: 1, mine: 1, senders: [[FORMER, 5], [OWN, 1],
        ...Array.from({ length: Counters.MAX_SENDERS - 3 }, (_, i) => [mintedKey(i), 1])] });
    const flood = mintedKey(999998);
    // The made-up sender fills the last place, then a member arrives in the same write
    const next = Counters.merge(almost, raisedBy(almost, [flood, BOB]));
    const written = Counters.bound(almost, next, [OWN, BOB]);
    const kept = new Map(written.record.senders);
    assert.equal(kept.has(BOB), true);
    assert.equal(kept.has(flood), false, 'the sender recorded last gave way');
    assert.equal(kept.has(mintedKey(Counters.MAX_SENDERS - 4)), true, 'what was recorded before the write stays');
    assert.deepEqual([...written.refused], []);
    assert.deepEqual([...written.displaced], [flood]);
    assert.equal(written.record.senders.length, Counters.MAX_SENDERS);
});

test('counter-records.js bounds every record it writes and every record it reads (one home: counters.js)', () => {
    const source = readFileSync(new URL('../js/counter-records.js', import.meta.url), 'utf8');
    const write = source.slice(source.indexOf('async function writeMark'));
    assert.match(write.slice(0, write.indexOf('\n    }\n')), /Counters\.bound\(earlier, next, keptSenders\(conv\)\)[\s\S]*saveCounters\(conv\.id, kept\.record/);
    assert.match(source, /Counters\.parseBounded\(await Keystore\.loadCounters\(conv\.id\), keptSenders\(conv\)\)/);
    // No other read of a stored record bypasses the bound
    assert.equal((source.match(/Keystore\.loadCounters\(/g) || []).length, 1);
    // What was not recorded is shown: the chat tags the senders and warns once
    const chat = readFileSync(new URL('../js/chat.js', import.meta.url), 'utf8');
    assert.match(chat, /markUnrecorded\(sender => CounterRecords\.isUnrecorded\(conv, sender\)\)/);
    assert.doesNotMatch(chat, /conv\.unrecorded\.has\(/, 'the chat asks CounterRecords.isUnrecorded, never the set');
    assert.match(chat, /Errors\.CODES\.W_COUNTER_RECORD_FULL/);
    // writeMark keeps conv.unrecorded through the one bounded path
    assert.match(write.slice(0, write.indexOf('\n    }\n')), /trackUnrecorded\(conv, kept\);/);
    assert.equal((source.match(/conv\.unrecorded\.add\(/g) || []).length, 1);
});

// ---------- conv.unrecorded: bounded, never failing open (counter-records.js) ----------

// counter-records.js in the same context: its bookkeeping is pure, Keystore is reached only by
// the functions not called here
const CounterRecords = vm.runInContext(readFileSync(new URL('../js/counter-records.js', import.meta.url), 'utf8') + '\n;CounterRecords', context);

// A room conversation as chat.js builds it, with the fields the bookkeeping reads
function roomConv(roster) {
    return {
        room: { member: { publicKey: OWN }, roster: roster.map(publicKey => ({ publicKey })) },
        unrecorded: new Set(), unrecordedOverflow: false, mark: Counters.EMPTY
    };
}

// Bounds next against conv's record and keeps conv as writeMark does
function written(conv, next, keep) {
    const kept = Counters.bound(conv.mark, next, keep);
    CounterRecords.trackUnrecorded(conv, kept);
    conv.mark = kept.record;
    return kept;
}

test('conv.unrecorded holds at most MAX_UNRECORDED senders; past it every unknown sender is shown unrecorded, never a kept or recorded one', () => {
    const conv = roomConv([BOB]);
    conv.mark = Counters.parse({ seq: 1, mine: 1, senders: [[FORMER, 5], [OWN, 1],
        ...Array.from({ length: Counters.MAX_SENDERS - 2 }, (_, i) => [mintedKey(i), 1])] });
    const flood = Array.from({ length: Counters.MAX_UNRECORDED + 2 }, (_, i) => mintedKey(1000000 + i));
    const kept = written(conv, Counters.merge(conv.mark, raisedBy(conv.mark, flood)), [OWN, BOB]);
    assert.equal(kept.refused.length, flood.length);
    assert.equal(conv.unrecorded.size, Counters.MAX_UNRECORDED, 'the set never passes its bound');
    assert.equal(conv.unrecordedOverflow, true);
    const overflowed = flood[flood.length - 1];
    assert.equal(conv.unrecorded.has(overflowed), false);
    assert.equal(CounterRecords.isUnrecorded(conv, overflowed), true, 'a sender the full set could not hold is still shown unrecorded');
    assert.equal(CounterRecords.isUnrecorded(conv, mintedKey(9999999)), true, 'an unknown sender counts as unrecorded');
    assert.equal(CounterRecords.isUnrecorded(conv, flood[0]), true);
    assert.equal(CounterRecords.isUnrecorded(conv, OWN), false, 'this device is never shown unrecorded');
    assert.equal(CounterRecords.isUnrecorded(conv, BOB), false, 'a roster member is never shown unrecorded');
    assert.equal(CounterRecords.isUnrecorded(conv, FORMER), false, 'a recorded sender is never shown unrecorded');
    // A write that records none of them leaves the flag set
    written(conv, conv.mark, [OWN, BOB]);
    assert.equal(conv.unrecordedOverflow, true, 'the flag is sticky');
    assert.equal(CounterRecords.isUnrecorded(conv, overflowed), true);
});

test('the overflow clears only when a sender recorded since brings conv.unrecorded below its bound; the sender it displaced is unrecorded', () => {
    const conv = roomConv([BOB]);
    conv.mark = Counters.parse({ seq: 1, mine: 1, senders: [[FORMER, 5], [OWN, 1],
        ...Array.from({ length: Counters.MAX_SENDERS - 2 }, (_, i) => [mintedKey(i), 1])] });
    const flood = Array.from({ length: Counters.MAX_UNRECORDED + 1 }, (_, i) => mintedKey(1000000 + i));
    written(conv, Counters.merge(conv.mark, raisedBy(conv.mark, flood)), [OWN, BOB]);
    assert.equal(conv.unrecordedOverflow, true);
    // One of them joins the roster: recorded, it leaves the set and displaces the latest off-roster entry
    const joined = flood[0];
    conv.room.roster.push({ publicKey: joined });
    const kept = written(conv, Counters.merge(conv.mark, raisedBy(conv.mark, [joined])), [OWN, BOB, joined]);
    const latest = mintedKey(Counters.MAX_SENDERS - 3);
    assert.deepEqual([...kept.displaced], [latest]);
    assert.equal(conv.unrecordedOverflow, false, 'the set went below its bound');
    assert.equal(CounterRecords.isUnrecorded(conv, joined), false);
    assert.equal(CounterRecords.isUnrecorded(conv, latest), true, 'the displaced sender is marked unrecorded');
    assert.equal(conv.unrecorded.size, Counters.MAX_UNRECORDED);
    assert.equal(CounterRecords.isUnrecorded(conv, FORMER), false);
});
