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
