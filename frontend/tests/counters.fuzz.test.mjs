// Fuzz: frontend/js/counters.js, loaded as the browser loads it. Random message sequences, as a
// server that withholds, repeats and reorders would serve them, go through forward sequences,
// reloads (snapshot, store, parse) and earlier pages; the replay judgement's invariants are
// checked against an independent model (the same invariants FuzzRoomPages asserts for the agent).
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load, plain } from './fuzz-helpers.mjs';

const SEED = 0x5eed0003;
const SEQUENCE_ITERATIONS = 2000;
const RECORD_ITERATIONS = 3000;
const MAX_SEQUENCES = 8;
const MAX_MESSAGES = 12;
const MAX_COUNTER = 16;
const SEQ_SPAN = 64;
const SENDERS = ['A', 'B', 'C'].map((letter) => letter.repeat(43));

const { get } = load({}, ['../js/counters.js']);
const Counters = get('Counters');

// A sequence as a sync loads it: ascending seqs, any senders and counters
function sequence(r, from) {
    const seqs = new Set();
    for (let n = r.int(0, MAX_MESSAGES); n > 0; n--) seqs.add(from + r.int(1, SEQ_SPAN));
    return [...seqs].sort((x, y) => x - y).map((seq) => ({ sender: r.pick(SENDERS), counter: r.int(1, MAX_COUNTER), seq }));
}

// A page below `before` (an earlier page): ascending seqs under it
function earlier(r, before) {
    const seqs = new Set();
    for (let n = r.int(0, MAX_MESSAGES); n > 0 && before > 1; n--) seqs.add(r.int(1, before - 1));
    return [...seqs].sort((x, y) => x - y).map((seq) => ({ sender: r.pick(SENDERS), counter: r.int(1, MAX_COUNTER), seq }));
}

// Feeds messages to state; returns the admitted ones. Within one ledger a sender's admitted
// counters rise strictly (rule 1), and every verdict is a replay or a non-negative gap.
function play(state, messages) {
    const admitted = [];
    const last = new Map();
    for (const m of messages) {
        const verdict = Counters.judge(state, m.sender, m.counter, m.seq);
        assert.ok(verdict.replay === true || (verdict.replay === false && Number.isSafeInteger(verdict.gap) && verdict.gap >= 0));
        if (verdict.replay) continue;
        assert.ok(!last.has(m.sender) || m.counter > last.get(m.sender), 'rule 1: a counter admitted at or below the last one');
        last.set(m.sender, m.counter);
        Counters.admit(state, m.sender, m.counter);
        admitted.push(m);
    }
    return admitted;
}

test('forward sequences across reloads: a counter admitted as new is never admitted as new again', async () => {
    await fuzz(SEED, SEQUENCE_ITERATIONS, (r) => {
        let record = Counters.EMPTY;
        const lastNew = new Map(); // per sender, the last counter admitted as new
        const loaded = [];        // every forward ledger, for the earlier pages
        for (let s = r.int(1, MAX_SEQUENCES); s > 0; s--) {
            const state = Counters.ledger(record);
            const remembered = record.seq;
            const messages = sequence(r, r.bool() ? remembered : r.int(0, remembered));
            for (const m of play(state, messages)) {
                if (m.seq <= remembered) continue;
                assert.ok(m.counter > (lastNew.get(m.sender) || 0),
                    `sender ${m.sender[0]} counter ${m.counter} admitted as new at seq ${m.seq} after ${lastNew.get(m.sender)}`);
                lastNew.set(m.sender, m.counter);
            }
            loaded.push(state);
            const lastSeq = messages.length ? messages[messages.length - 1].seq : remembered;
            const next = Counters.snapshot(state, lastSeq, record.mine);
            // stored and read back as Keystore does: the same record
            const stored = Counters.parse(plain(next));
            assert.ok(Counters.same(stored, next), 'a snapshot does not survive storage');
            assert.ok(stored.seq >= record.seq, 'the remembered seq went down');
            for (const [key, counter] of record.senders) {
                assert.ok(new Map(stored.senders).get(key) >= counter, 'a remembered counter went down');
            }
            record = stored;
        }
        // Earlier pages below the lowest loaded seq, each under the ceiling of everything above it
        let above = new Map();
        for (const state of loaded) above = Counters.lowest(above, state);
        let before = SEQ_SPAN;
        for (let p = r.int(0, 3); p > 0; p--) {
            const page = Counters.history(record, above);
            const ceiling = new Map(above);
            for (const m of play(page, earlier(r, before))) {
                assert.ok(!ceiling.has(m.sender) || m.counter < ceiling.get(m.sender),
                    `an earlier page admitted counter ${m.counter} at or above the ceiling ${ceiling.get(m.sender)}`);
            }
            const next = Counters.lowest(above, page);
            for (const [key, counter] of above) assert.ok(next.get(key) <= counter, 'a ceiling rose');
            above = next;
            before = Math.max(1, before - r.int(1, SEQ_SPAN / 4));
        }
    });
});

test('parse / merge / same: never throw on stored values; parse is a fixed point; merge is a join', async () => {
    const goodRecord = (r) => ({
        seq: r.int(0, 1000),
        mine: r.int(0, 1000),
        senders: SENDERS.filter(() => r.bool()).map((key) => [key, r.int(1, 1000)])
    });
    await fuzz(SEED + 1, RECORD_ITERATIONS, (r) => {
        const raw = r.bool(0.5) ? goodRecord(r) : r.bool() ? Object.assign(goodRecord(r), { [r.pick(['seq', 'mine', 'senders'])]: r.value() }) : r.value();
        const a = Counters.parse(raw);
        assert.ok(Object.isFrozen(a) && Object.isFrozen(a.senders));
        assert.ok(Number.isSafeInteger(a.seq) && a.seq >= 0 && Number.isSafeInteger(a.mine) && a.mine >= 0);
        for (const entry of a.senders) {
            assert.ok(/^[A-Za-z0-9_-]{43}$/.test(entry[0]) && Number.isSafeInteger(entry[1]) && entry[1] > 0);
        }
        assert.ok(Counters.same(Counters.parse(plain(a)), a), 'parse is not a fixed point');
        const b = Counters.parse(goodRecord(r));
        const ab = Counters.merge(a, b);
        assert.ok(Counters.same(ab, Counters.merge(b, a)), 'merge is not commutative');
        assert.ok(Counters.same(Counters.merge(a, a), a), 'merge is not idempotent');
        assert.ok(ab.seq >= Math.max(a.seq, b.seq) && ab.mine >= Math.max(a.mine, b.mine));
        const merged = new Map(ab.senders);
        for (const [key, counter] of [...a.senders, ...b.senders]) assert.ok(merged.get(key) >= counter);
    });
});
