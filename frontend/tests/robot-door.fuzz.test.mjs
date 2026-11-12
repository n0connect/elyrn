// Fuzz: frontend/js/robot-door.js, loaded as the browser loads it (theatre, not a control: these
// targets pin that it is total, deterministic and finite, not any security).
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzz, load, plain } from './fuzz-helpers.mjs';

const SEED = 0x5eed0006;
const CLASSIFY_ITERATIONS = 3000;
const ANSWER_ITERATIONS = 1000;
const MAX_MOVES = 400;
const CLICK_AT = 100000;
const NOT_FINITE = /NaN|Infinity|undefined/;

const { get } = load({ crypto: globalThis.crypto, TextEncoder }, ['../js/robot-door.js']);
const D = get('RobotDoor');
const REASONS = Object.values(D.REASON);
const LINES = Object.values(D.LINES);

// A coordinate or time: mostly a pointer's, sometimes anything a number can be
function number(r, typical) {
    const roll = r.next();
    if (roll < 0.8) return typical;
    if (roll < 0.9) return r.pick([NaN, Infinity, -Infinity, 1e308, -1e308, 5e-324, -0, 2 ** 53]);
    return (r.next() - 0.5) * 2 * r.pick([1e3, 1e6, D.MAX_COORDINATE_PX, 1e12, 1e300]);
}

function trailOf(r) {
    const trail = D.createTrail();
    let x = r.int(0, 2000);
    let y = r.int(0, 2000);
    let t = CLICK_AT - r.int(0, 2 * D.RECENT_WINDOW_MS);
    for (let n = r.int(0, MAX_MOVES); n > 0; n--) {
        x += r.int(-50, 50);
        y += r.int(-50, 50);
        t += r.int(0, 100);
        trail.push(number(r, x), number(r, y), number(r, t));
    }
    return trail;
}

function clickOf(r) {
    return {
        pointerType: r.bool(0.7) ? r.pick(['mouse', 'touch', 'pen', '']) : r.value(0),
        detail: r.bool(0.8) ? r.int(0, 3) : r.value(0),
        at: r.bool(0.8) ? CLICK_AT : number(r, CLICK_AT)
    };
}

test('classify / verdictLine / measurementLines: total, deterministic, and finite in every line', async () => {
    await fuzz(SEED, CLASSIFY_ITERATIONS, (r) => {
        const trail = trailOf(r);
        assert.ok(trail.size() <= D.TRAIL_CAPACITY);
        const points = trail.points();
        for (const p of points) {
            assert.ok([p.x, p.y, p.t].every(Number.isFinite), 'a non-finite move was kept');
            assert.ok(Math.abs(p.x) <= D.MAX_COORDINATE_PX && Math.abs(p.y) <= D.MAX_COORDINATE_PX, 'an off-screen move was kept');
        }
        const click = clickOf(r);
        const judged = D.classify(click, points);
        assert.deepEqual(plain(D.classify(click, points)), plain(judged), 'classify is not deterministic');
        assert.ok(REASONS.includes(judged.reason));
        assert.equal(typeof judged.human, 'boolean');
        assert.equal(judged.measurements !== null, judged.reason === D.REASON.TRAIL);
        assert.ok(LINES.includes(D.verdictLine(judged)));
        for (const line of D.measurementLines(judged.measurements)) {
            assert.doesNotMatch(line, NOT_FINITE, `the verdict screen shows ${JSON.stringify(line)}`);
        }
        if (judged.measurements) {
            const m = judged.measurements;
            assert.ok(m.points >= D.MIN_TRAIL_POINTS && Number.isFinite(m.pathPx) && Number.isFinite(m.straightPx));
            assert.ok(m.detour === null || (Number.isFinite(m.detour) && m.detour > 0));
            assert.ok(Number.isSafeInteger(m.hesitationMs) && m.hesitationMs >= 0 && m.hesitationMs <= D.RECENT_WINDOW_MS);
        }
    });
});

test('checkAnswer: true only for the expected 8 hex characters, in any case and padding', async () => {
    await fuzz(SEED + 1, ANSWER_ITERATIONS, async (r) => {
        const nonce = r.bool(0.8) ? D.newNonce() : r.string(r.int(0, 40));
        const expected = await D.expectedAnswer(nonce);
        assert.match(expected, new RegExp(`^[0-9a-f]{${D.ANSWER_HEX_CHARS}}$`));
        const roll = r.next();
        const answer = roll < 0.3 ? r.mutate(expected) : roll < 0.6 ? r.hex(D.ANSWER_HEX_CHARS) : roll < 0.9 ? r.string() : r.value();
        const right = String(answer).trim().toLowerCase() === expected;
        assert.equal(await D.checkAnswer(nonce, answer), right, `answer ${JSON.stringify(String(answer))}`);
    });
});
