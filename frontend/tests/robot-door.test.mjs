// frontend/js/robot-door.js loaded as the browser loads it: the theatre in front of the robot
// entrance (it gates nothing; these tests pin its arithmetic and its copy, not any security).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder });
const RobotDoor = vm.runInContext(
    readFileSync(new URL('../js/robot-door.js', import.meta.url), 'utf8') + '\n;RobotDoor', context);
const D = RobotDoor;
// Values made in the vm context carry its prototypes; compare them as plain data
const plain = (value) => JSON.parse(JSON.stringify(value));

const CLICK_AT = 100000;

// count moves ending `before` ms ahead of the click, `step` ms apart, along `at(i)`
function trail(count, at, { before = 100, step = 10 } = {}) {
    const points = [];
    for (let i = 0; i < count; i++) {
        const [x, y] = at(i);
        points.push({ x, y, t: CLICK_AT - before - (count - 1 - i) * step });
    }
    return points;
}

const line = (i) => [i * 10, 0];
const zigzag = (i) => [i * 10, i % 2 === 0 ? 0 : 10];
const mouse = { pointerType: 'mouse', detail: 1, at: CLICK_AT };

test('classification: finger and pen are people, whatever the trail', () => {
    for (const [pointerType, reason] of [['touch', D.REASON.TOUCH], ['pen', D.REASON.PEN]]) {
        for (const points of [[], trail(D.MIN_TRAIL_POINTS, line)]) {
            const judged = D.classify({ pointerType, detail: 1, at: CLICK_AT }, points);
            assert.equal(judged.human, true);
            assert.equal(judged.reason, reason);
            assert.equal(judged.measurements, null);
        }
    }
});

test('classification: keyboard (or a scripted click) is machine-like, even after a trail', () => {
    for (const pointerType of ['', undefined, 'mouse']) {
        const judged = D.classify({ pointerType, detail: 0, at: CLICK_AT }, trail(D.MIN_TRAIL_POINTS * 2, zigzag));
        assert.equal(judged.human, false);
        assert.equal(judged.reason, D.REASON.NO_POINTER);
    }
});

test('classification: a mouse click with a recent trail is a person, without one a machine', () => {
    const judged = D.classify(mouse, trail(D.MIN_TRAIL_POINTS, zigzag));
    assert.equal(judged.human, true);
    assert.equal(judged.reason, D.REASON.TRAIL);
    assert.equal(judged.measurements.points, D.MIN_TRAIL_POINTS);

    for (const points of [[], trail(D.MIN_TRAIL_POINTS - 1, zigzag)]) {
        const bare = D.classify(mouse, points);
        assert.equal(bare.human, false);
        assert.equal(bare.reason, D.REASON.NO_TRAIL);
        assert.equal(bare.measurements, null);
    }
});

test('classification: a stale trail, or one stamped after the click, does not count', () => {
    const stale = trail(D.MIN_TRAIL_POINTS * 2, zigzag, { before: D.RECENT_WINDOW_MS + 1 });
    assert.equal(D.classify(mouse, stale).reason, D.REASON.NO_TRAIL);
    const future = trail(D.MIN_TRAIL_POINTS * 2, zigzag, { before: -1000 });
    assert.equal(D.classify(mouse, future).reason, D.REASON.NO_TRAIL);
    // Half stale, half recent: only the recent half is measured
    const mixed = stale.concat(trail(D.MIN_TRAIL_POINTS, zigzag));
    const judged = D.classify(mouse, mixed);
    assert.equal(judged.reason, D.REASON.TRAIL);
    assert.equal(judged.measurements.points, D.MIN_TRAIL_POINTS);
});

test('the trail is a ring buffer: bounded, oldest dropped first, cleared to nothing', () => {
    const t = D.createTrail();
    assert.equal(t.capacity, D.TRAIL_CAPACITY);
    const extra = 10;
    for (let i = 0; i < D.TRAIL_CAPACITY + extra; i++) t.push(i, -i, i);
    assert.equal(t.size(), D.TRAIL_CAPACITY);
    const points = t.points();
    assert.equal(points.length, D.TRAIL_CAPACITY);
    assert.deepEqual(plain(points[0]), { x: extra, y: -extra, t: extra });
    assert.deepEqual(plain(points.at(-1)), { x: D.TRAIL_CAPACITY + extra - 1, y: -(D.TRAIL_CAPACITY + extra - 1), t: D.TRAIL_CAPACITY + extra - 1 });
    for (let i = 1; i < points.length; i++) assert.ok(points[i].t > points[i - 1].t);

    for (const bad of [NaN, Infinity, -Infinity, undefined, '5']) {
        t.push(bad, 0, 0);
        t.push(0, bad, 0);
        t.push(0, 0, bad);
    }
    assert.equal(t.points().at(-1).t, D.TRAIL_CAPACITY + extra - 1);

    t.clear();
    assert.equal(t.size(), 0);
    assert.deepEqual(plain(t.points()), []);
    t.push(1, 2, 3);
    assert.deepEqual(plain(t.points()), [{ x: 1, y: 2, t: 3 }]);
});

test('a small trail wraps correctly', () => {
    const t = D.createTrail(3);
    for (let i = 0; i < 7; i++) t.push(i, i, i);
    assert.deepEqual(plain(t.points().map(p => p.t)), [4, 5, 6]);
});

test('measurements on known trails', () => {
    // A 3-4-5 triangle walked as two legs: path 7, straight 5, detour 1.4
    const legs = [{ x: 0, y: 0, t: 0 }, { x: 3, y: 0, t: 10 }, { x: 3, y: 4, t: 20 }];
    const m = D.measure(legs, 432);
    assert.equal(m.points, 3);
    assert.equal(m.pathPx, 7);
    assert.equal(m.straightPx, 5);
    assert.equal(m.detour, 1.4);
    assert.equal(m.hesitationMs, 412);
    assert.deepEqual([...D.measurementLines(m)], ['points: 3', 'detour: 1.4×', 'hesitation: 412 ms']);

    // A straight line: detour exactly 1
    const straight = D.measure(trail(10, line).map(p => ({ ...p, t: p.t - CLICK_AT })), 0);
    assert.equal(straight.pathPx, 90);
    assert.equal(straight.detour, 1);

    // Out and back: no straight distance, no ratio
    const loop = D.measure([{ x: 0, y: 0, t: 0 }, { x: 50, y: 0, t: 1 }, { x: 1, y: 1, t: 2 }], 2.4);
    assert.equal(loop.detour, null);
    assert.equal(loop.hesitationMs, 0);
    assert.equal(D.measurementLines(loop)[1], 'detour: round trip');

    // A click stamped before the last move never reads as negative hesitation
    assert.equal(D.measure(legs, 5).hesitationMs, 0);
    assert.deepEqual([...D.measurementLines(null)], []);
});

test('verdict lines are chosen by the measurements alone', () => {
    const judgedBy = (detour, hesitationMs) =>
        ({ human: true, reason: D.REASON.TRAIL, measurements: { points: 9, detour, hesitationMs } });
    assert.equal(D.verdictLine({ reason: D.REASON.TOUCH }), D.LINES.TOUCH);
    assert.equal(D.verdictLine({ reason: D.REASON.PEN }), D.LINES.PEN);
    assert.equal(D.verdictLine(judgedBy(null, 0)), D.LINES.LOOP);
    assert.equal(D.verdictLine(judgedBy(1, D.LONG_PAUSE_MS * 2)), D.LINES.STRAIGHT);
    assert.equal(D.verdictLine(judgedBy(D.STRAIGHT_DETOUR_MAX, D.LONG_PAUSE_MS)), D.LINES.PAUSE);
    assert.equal(D.verdictLine(judgedBy(2, D.LONG_PAUSE_MS - 1)), D.LINES.WOBBLE);
    assert.equal(D.verdictLine({ reason: D.REASON.NO_TRAIL, measurements: null }), D.LINES.HONEST);
    // Same input, same line
    const once = D.verdictLine(judgedBy(1.7, 300));
    for (let i = 0; i < 20; i++) assert.equal(D.verdictLine(judgedBy(1.7, 300)), once);
    // The copy stays short and lower-case
    for (const text of Object.values(D.LINES)) assert.equal(text, text.toLowerCase());
    for (const mode of Object.values(D.MODE)) assert.equal(D.greeting(mode), D.greeting(mode).toLowerCase());
    assert.notEqual(D.greeting(D.MODE.ROBOT), D.greeting(D.MODE.OPERATOR));
    assert.equal(D.greeting('anything else'), D.greeting(D.MODE.ROBOT));
});

test('the answer check against known SHA-256 vectors', async () => {
    const vectors = [
        ['000102030405060708090a0b0c0d0e0f', 'd65df89f'],
        ['abc', 'ba7816bf'],
        ['', 'e3b0c442']
    ];
    for (const [nonce, answer] of vectors) {
        assert.equal(await D.expectedAnswer(nonce), answer);
        for (const given of [answer, answer.toUpperCase(), `  ${answer}\n`, `\t${answer.toUpperCase()} `]) {
            assert.equal(await D.checkAnswer(nonce, given), true, JSON.stringify(given));
        }
        const wrongLast = answer.slice(0, -1) + (answer.at(-1) === '0' ? '1' : '0');
        for (const given of [answer.slice(0, 7), answer + '0', 'g' + answer.slice(1), wrongLast,
            '', '        ', 'zzzzzzzz', `${answer.slice(0, 4)} ${answer.slice(4, 7)}`, null, undefined]) {
            assert.equal(await D.checkAnswer(nonce, given), false, JSON.stringify(given));
        }
    }
});

test('nonces are 32 lower-case hex characters, fresh each time', () => {
    const shape = new RegExp(`^[0-9a-f]{${D.NONCE_BYTES * 2}}$`);
    const a = D.newNonce();
    const b = D.newNonce();
    assert.match(a, shape);
    assert.match(b, shape);
    assert.notEqual(a, b);
});

test('the module cannot be changed at run time', () => {
    for (const table of [D, D.MODE, D.REASON, D.LINES, D.createTrail()]) {
        assert.ok(Object.isFrozen(table));
    }
});
