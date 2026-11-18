// frontend/js/burn-fire.js, the burned view going up in flames for the person who burned, after
// the server confirmed the burn: the real module's pure parts on seeded runs, and where the two
// burn paths call it. How it looks is checked in a real browser (the live screenshots).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load, plain } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const css = read('../styles.css');
const chat = read('../js/chat.js');
const source = read('../js/burn-fire.js');
const BurnFire = load({}, ['../js/burn-fire.js']).get('BurnFire');

const SEEDS = [1, 7, 0xdecade, 0xf1e, 0x5eed];
// The desktop window's grid (1280 x 800 at 16 px) and a phone's (375 x 812 at 12 px)
const GRIDS = [{ cols: 80, rows: 50 }, { cols: 32, rows: 68 }];
const plans = () => SEEDS.flatMap(seed => GRIDS.map(({ cols, rows }) => {
    const plan = { seed, cols, rows, list: BurnFire.flames(cols, rows, seed) };
    plan.cover = BurnFire.coverFrame(plan);
    return plan;
}));
const isFlame = (paint) => paint >= BurnFire.RED;

// Connected groups (side by side, or corner to corner when diagonal is true) of the cells keep()
function groups(cols, rows, keep, diagonal = false) {
    const seen = new Uint8Array(cols * rows);
    const steps = diagonal ? [[1, 0], [-1, 0], [0, 1], [0, -1], [1, 1], [1, -1], [-1, 1], [-1, -1]] : [[1, 0], [-1, 0], [0, 1], [0, -1]];
    let count = 0;
    for (let i = 0; i < cols * rows; i++) {
        if (seen[i] || !keep(i)) continue;
        count++;
        const stack = [i];
        seen[i] = 1;
        while (stack.length) {
            const at = stack.pop();
            const x = at % cols;
            const y = Math.floor(at / cols);
            for (const [dx, dy] of steps) {
                const nx = x + dx;
                const ny = y + dy;
                const next = ny * cols + nx;
                if (nx < 0 || ny < 0 || nx >= cols || ny >= rows || seen[next] || !keep(next)) continue;
                seen[next] = 1;
                stack.push(next);
            }
        }
    }
    return count;
}
const flameGroups = (plan, frame) => {
    const grid = BurnFire.paintGrid(plan, frame);
    return groups(plan.cols, plan.rows, i => isFlame(grid[i]), true);
};

test('the flames: pure, 12 to 16, big, taller and redder behind, big ones starting first', () => {
    for (const plan of plans()) {
        assert.deepEqual(plain(BurnFire.flames(plan.cols, plan.rows, plan.seed)), plain(plan.list));
        const rear = plan.list.filter(f => f.rear);
        const stream = plan.list.filter(f => !f.rear);
        assert.ok(stream.length >= 12 && stream.length <= 16);
        // the rear flames (red, behind all others) are only what makes the cover frame whole
        assert.deepEqual(plain(plan.list.slice(0, rear.length)), plain(rear));
        assert.ok(rear.every(f => f.body === BurnFire.RED && f.height <= 1.1 * plan.rows));
        for (const f of stream) {
            assert.ok(f.height >= 0.45 * plan.rows && f.height <= 1.1 * plan.rows);
            assert.ok(f.width >= 0.14 * plan.cols && f.width <= 0.3 * plan.cols);
            assert.ok(f.start >= 0 && f.start <= 3);
            assert.ok(f.body === BurnFire.RED || f.body === BurnFire.ORANGE);
        }
        for (let k = 1; k < stream.length; k++) assert.ok(stream[k].share <= stream[k - 1].share, 'drawn back to front');
        assert.equal(stream[0].body, BurnFire.RED);
        assert.equal(stream[stream.length - 1].body, BurnFire.ORANGE);
        assert.ok(stream[0].start === 0 && stream[stream.length - 1].start >= 2, 'big ones first');
    }
});

test('the motion law: travel(k, n) = k(k+1) / (n(n+1)), from 0 to 1, every step larger than the last', () => {
    assert.deepEqual([0, 1, 2, 3, 4].map(k => Math.round(BurnFire.travel(k, 4) * 1000) / 1000), [0, 0.1, 0.3, 0.6, 1]);
    for (let n = 2; n <= 12; n++) {
        assert.equal(BurnFire.travel(0, n), 0);
        assert.equal(BurnFire.travel(n, n), 1);
        for (let k = 2; k <= n; k++) {
            const step = BurnFire.travel(k, n) - BurnFire.travel(k - 1, n);
            assert.ok(step > BurnFire.travel(k - 1, n) - BurnFire.travel(k - 2, n), `n ${n} k ${k}`);
        }
    }
    assert.match(source, /function travel\(k, n\) \{\n\s*return \(k \* \(k \+ 1\)\) \/ \(n \* \(n \+ 1\)\);/);
    // one home: the law is written once, and the flames and the planner both go through it
    assert.equal((source.match(/k \* \(k \+ 1\)/g) || []).length, 1);
    assert.equal((source.match(/function travel\(/g) || []).length, 1);
});

test('nothing stands still: every flame rises on every frame it is there, each step larger than the last', () => {
    for (const plan of plans()) {
        for (const f of plan.list) {
            assert.ok(f.frames >= 4 && f.frames <= 6);
            const bases = [];
            for (let frame = 0; frame < BurnFire.TOTAL_FRAMES; frame++) {
                const at = BurnFire.pose(f, frame, plan.rows);
                if (at) bases.push(at.base);
            }
            assert.ok(bases.length >= 3, 'it crosses the window');
            for (let k = 1; k < bases.length; k++) {
                assert.ok(bases[k] < bases[k - 1], `seed ${plan.seed}: ${bases[k]} after ${bases[k - 1]}`);
                if (k >= 2) assert.ok(bases[k - 1] - bases[k] > bases[k - 2] - bases[k - 1], 'it accelerates');
            }
            assert.equal(BurnFire.pose(f, BurnFire.LAST_FRAME, plan.rows), null);
        }
    }
});

test('a pass: the flame rises to one peak, the cover, near the middle, and falls; nothing after the last flame', () => {
    for (const plan of plans()) {
        const shares = Array.from({ length: BurnFire.TOTAL_FRAMES }, (_, f) => BurnFire.flameShare(plan, f));
        const peak = shares.indexOf(Math.max(...shares));
        assert.equal(plan.cover, peak);
        assert.ok(peak >= 4 && peak <= 6, `seed ${plan.seed}: peak at ${peak}`);
        // one instant covers everything: the cover frame, and only it, is all flame
        assert.equal(shares[peak], 1, `seed ${plan.seed}: ${shares[peak]} at the peak`);
        assert.equal(shares.filter(share => share === 1).length, 1);
        assert.ok(shares[peak - 1] < 1 && shares[peak + 1] < 1);
        // up to the peak it only grows, after it it only falls: never a frame alike
        for (let f = 1; f <= peak; f++) assert.ok(shares[f] > shares[f - 1], `seed ${plan.seed} rise ${f}`);
        for (let f = peak + 1; f < shares.length; f++) {
            if (shares[f - 1] === 0) break;
            assert.ok(shares[f] < shares[f - 1], `seed ${plan.seed} fall ${f}: ${shares[f]} after ${shares[f - 1]}`);
        }
        assert.equal(shares[BurnFire.LAST_FRAME], 0);
    }
});

test('the black: half, then solid until a frame past the cover, then half, a quarter and none', () => {
    assert.equal(BurnFire.TOTAL_FRAMES, 10);
    assert.equal(BurnFire.hardStopMs(120), 1320);
    const cover = 5;
    assert.deepEqual(Array.from({ length: 10 }, (_, f) => BurnFire.blackLevel(f, cover)), [2, 4, 4, 4, 4, 4, 4, 2, 1, 0]);
    let black = 0;
    for (let row = 0; row < 4; row++) for (let col = 0; col < 4; col++) if (BurnFire.blackAt(0, cover, col, row)) black++;
    assert.equal(black, 8);
});

test('one body: every flame on screen sways by the same cell on the same frame', () => {
    for (const plan of plans()) {
        for (let frame = 0; frame < BurnFire.TOTAL_FRAMES; frame++) {
            const shifts = new Set(plan.list.map(f => BurnFire.pose(f, frame, plan.rows)).map((at, k) => (at ? Math.round(at.x - plan.list[k].x) : null)).filter(v => v !== null));
            assert.ok(shifts.size <= 1, `frame ${frame}: ${[...shifts]}`);
        }
    }
});

test('dies as pieces: the last three painted frames hold at most three separate flames each', () => {
    for (const plan of plans()) {
        const painted = Array.from({ length: BurnFire.TOTAL_FRAMES }, (_, f) => f).filter(f => BurnFire.flameShare(plan, f) > 0);
        for (const frame of painted.slice(-3)) {
            const count = flameGroups(plan, frame);
            assert.ok(count >= 1 && count <= 3, `seed ${plan.seed} ${plan.cols}x${plan.rows} frame ${frame}: ${count}`);
        }
        assert.ok([...BurnFire.paintGrid(plan, BurnFire.LAST_FRAME)].every(p => p === BurnFire.NOT_PAINTED));
    }
});

test('a flame is a teardrop: one connected shape whose topmost row is a single cell, a point', () => {
    for (const plan of plans()) {
        for (const f of plan.list) {
            const tallFlame = Object.assign({}, f, { start: 0, frames: 4, x: f.x + plan.cols });
            const cells = BurnFire.flameCells(tallFlame, 2, plan.cols * 3, 400).filter(c => !c.core);
            const tall = { cols: plan.cols * 3, rows: 400 };
            const set = new Set(cells.map(c => c.row * tall.cols + c.col));
            assert.equal(groups(tall.cols, tall.rows, i => set.has(i), true), 1);
            const top = Math.min(...cells.map(c => c.row));
            assert.equal(cells.filter(c => c.row === top).length, 1, `a point, seed ${plan.seed}`);
            // a belly: the widest row stands in the lower half
            const widths = new Map();
            for (const c of cells) widths.set(c.row, (widths.get(c.row) || 0) + 1);
            const bottom = Math.max(...cells.map(c => c.row));
            const widest = [...widths.entries()].sort((a, b) => b[1] - a[1])[0][0];
            assert.ok(widest > (top + bottom) / 2, 'the belly is low');
        }
    }
});

test('the paint: black, red, the fire orange and the yellow core, from the stylesheet', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-fringe', '--fire-flame', '--fire-orange', '--fire-glow']);
    assert.match(css, /--fire-fringe: #000000;\n\s*--fire-flame: var\(--danger\);\n\s*--fire-orange: #e65100;\n\s*--fire-glow: var\(--warning\);/);
    assert.equal((css.match(/--fire-orange/g) || []).length, 1, 'used by the fire only');
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(/);
});

test('the grid: 16 px cells on a desktop, 12 px under 480 px, capped', () => {
    assert.deepEqual(plain(BurnFire.gridSize(1280, 800)), { cell: 16, cols: 80, rows: 50 });
    assert.deepEqual(plain(BurnFire.gridSize(375, 812)), { cell: 12, cols: 32, rows: 68 });
    const big = BurnFire.gridSize(7680, 4320);
    assert.ok(big.cols <= 240 && big.rows <= 135);
});

test('one frame clock: the fire steps at the stylesheet\'s --frame-ms, the hover frames and the caption too', () => {
    assert.equal(BurnFire.FRAME_PROPERTY, '--frame-ms');
    assert.match(css, /--frame-ms: 120ms;/);
    assert.match(css, /--icon-steps-ms: calc\(var\(--frame-ms\) \* 3\);/);
    assert.match(css, /--caption-steps-ms: calc\(var\(--frame-ms\) \* 3\);/);
    assert.match(source, /frameMs: parseFloat\(style\.getPropertyValue\(FRAME_PROPERTY\)\)/);
    assert.match(source, /timer = setTimeout\(tick, look\.frameMs\);/);
    assert.doesNotMatch(source, /FRAME_MS|\b83\b|\b120\b/);
    assert.equal(BurnFire.shouldPlay(false, false, NaN), false);
    assert.equal(BurnFire.shouldPlay(false, false, 0), false);
});

test('the cover callback runs exactly once: at the frame with the most flame, or at once without the fire, or on any early end', async () => {
    assert.equal(BurnFire.coversAt(6, 6), true);
    assert.equal(Array.from({ length: BurnFire.TOTAL_FRAMES }, (_, f) => BurnFire.coversAt(f, 6)).filter(Boolean).length, 1);
    // without the fire (reduced motion, a hidden page) it runs at once, once
    for (const [reduced, visibility] of [[true, 'visible'], [false, 'hidden']]) {
        const page = { window: { matchMedia: () => ({ matches: reduced }) }, document: { visibilityState: visibility } };
        const fire = load(page, ['../js/burn-fire.js']).get('BurnFire');
        let covered = 0;
        await fire.play(() => covered++);
        assert.equal(covered, 1);
    }
    // in the module: guarded once, called at the cover frame and by every end
    const body = source.match(/function play\(onCovered\) \{[\s\S]*?\n {4}\}/)[0];
    assert.match(body, /const cover = \(\) => \{\n\s*if \(covered\) return;\n\s*covered = true;/);
    assert.match(body, /if \(coversAt\(frame, plan\.cover\)\) cover\(\);/);
    assert.match(body, /plan\.cover = coverFrame\(plan\);/);
    assert.match(body, /if \(canvas\) canvas\.remove\(\);\n\s*cover\(\);\n\s*resolve\(\);/);
    assert.match(body, /if \(frame >= TOTAL_FRAMES\) return end\(\);/);
    assert.match(body, /addEventListener\('keydown', end, true\)/);
    assert.match(body, /addEventListener\('pointerdown', end, true\)/);
    assert.match(body, /hardStop = setTimeout\(end, hardStopMs\(look\.frameMs\)\);/);
    assert.equal((body.match(/Log\.error\(Errors\.INTERNAL\.E_FIRE_FAILED, err\);\n\s*end\(\);/g) || []).length, 2);
    assert.match(body, /if \(!shouldPlay\(reducedMotion, hidden\)\) \{\n\s*cover\(\);\n\s*return Promise\.resolve\(\);/);
});

test('the module makes one canvas by element and attribute: no markup string, no inline style', () => {
    assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|\.style\b|setAttribute\('style'/);
    assert.match(source, /createElement\('canvas'\)/);
    assert.match(source, /setAttribute\('aria-hidden', 'true'\)/);
    assert.match(source, /canvas\.remove\(\)/);
    assert.match(css, /\.burn-fire \{[^}]*image-rendering: pixelated/);
});

test('both burns play it only on the confirmed branch and navigate exactly once, under the cover or when it settles', () => {
    const body = chat.match(/async function burnNow\(\) \{[\s\S]*?\n {4}\}/)[0];
    assert.equal(body.match(/BurnFire\.play/g).length, 1);
    const success = body.indexOf('HTTP_STATUS.NO_CONTENT || result.status === HTTP_STATUS.NOT_FOUND');
    const failure = body.indexOf('} else if (result.status !== HTTP_STATUS.UNAUTHORIZED)');
    const call = body.indexOf('BurnFire.play');
    assert.ok(success > 0 && success < call && call < failure);
    assert.ok(body.indexOf("await api('DELETE'") < call);
    // done is guarded once and is both the cover callback and part of every settling
    assert.match(body, /let navigated = false;\n\s*const done = \(\) => \{\n\s*if \(navigated\) return;\n\s*navigated = true;\n\s*backToList\(\);/);
    assert.match(body, /if \(playsFire\(leaving, result\.status\)\) \{\n\s*const finish = \(\) => \{\n\s*done\(\);\n\s*focusHome\(\);\n\s*\};\n\s*Promise\.resolve\(\)\.then\(\(\) => BurnFire\.play\(done\)\)\.then\(finish, finish\);\n\s*\} else \{\n\s*done\(\);\n\s*\}/);
    assert.equal((body.match(/backToList\(\)/g) || []).length, 1);
    assert.match(chat, /function playsFire\(leaving, status\) \{\n\s*return !leaving && status === HTTP_STATUS\.NO_CONTENT;\n\s*\}/);
    assert.equal(chat.match(/BurnFire\./g).length, 1);
});

test('the script loads after the modules it reads and before the chat that calls it', () => {
    const order = [...html.matchAll(/<script src="([^"]+)"/g)].map(match => match[1]);
    const at = (name) => order.indexOf(name);
    assert.ok(at('js/burn-fire.js') > 0);
    assert.ok(at('js/log.js') < at('js/burn-fire.js'));
    assert.ok(at('js/errors.js') < at('js/burn-fire.js'));
    assert.ok(at('js/burn-fire.js') < at('js/chat.js'));
});
