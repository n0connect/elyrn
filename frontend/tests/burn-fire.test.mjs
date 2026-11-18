// frontend/js/burn-fire.js, the burned view going up in flames for the person who burned, after
// the server confirmed the burn: the real module's pure parts on seeded runs, and where the two
// burn paths call it. How it looks is checked in a real browser (the live screenshots).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { load, plain } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const css = read('../styles.css');
const chat = read('../js/chat.js');
const source = read('../js/burn-fire.js');
const BurnFire = load({}, ['../js/burn-fire.js']).get('BurnFire');

const SEEDS = [1, 7, 0xdecade, 0xf1e, 0x5eed];
// The desktop window's grid (1280 x 800 at 8 px) and a phone's (375 x 812 at 6 px)
const GRIDS = [{ cols: 160, rows: 100 }, { cols: 63, rows: 136 }];
const plans = () => SEEDS.flatMap(seed => GRIDS.map(({ cols, rows }) => Object.assign(BurnFire.plan(cols, rows, seed), { seed })));
const frames = (fire) => Array.from({ length: fire.length }, (_, f) => f);
const isFlame = (paint) => paint >= BurnFire.RED;
const bodyRuns = (fire, flame, frame) => BurnFire.flameRuns(flame, frame, fire.cols, fire.rows).filter(r => !r.core);
const painted = (fire, flame, frame) => bodyRuns(fire, flame, frame).length > 0;
// A resting teardrop's area over its height x width: a quarter ellipse below the belly (a third)
// and the taper above it, (1/3)(pi/4) + (2/3)/1.8
const TEARDROP_AREA = Math.PI / 12 + 2 / 3 / 1.8;

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
const flameGroups = (fire, frame) => {
    const grid = BurnFire.paintGrid(fire, frame);
    return groups(fire.cols, fire.rows, i => isFlame(grid[i]), true);
};

test('the flames: pure, 12 to 16, big, taller and redder behind, big ones starting first', () => {
    for (const fire of plans()) {
        assert.deepEqual(plain(BurnFire.plan(fire.cols, fire.rows, fire.seed)), plain(Object.assign({}, fire, { seed: undefined })));
        const rear = fire.list.filter(f => f.rear);
        const stream = fire.list.filter(f => !f.rear);
        assert.ok(stream.length >= 12 && stream.length <= 16);
        // the rear flames (red, behind all others) are only what makes the cover frame whole
        assert.deepEqual(plain(fire.list.slice(0, rear.length)), plain(rear));
        assert.ok(rear.every(f => f.body === BurnFire.RED && f.height <= 1.1 * fire.rows));
        for (const f of stream) {
            assert.ok(f.height >= 0.45 * fire.rows && f.height <= 1.1 * fire.rows);
            assert.ok(f.width >= 0.14 * fire.cols && f.width <= 0.3 * fire.cols);
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
    // one silhouette for the body and the core
    assert.equal((source.match(/function silhouette\(/g) || []).length, 1);
    assert.equal((source.match(/silhouette\(at, (BODY|CORE)_SCALE, /g) || []).length, 2);
});

test('nothing stands still: every flame rises on every frame it is there, each step larger than the last', () => {
    for (const fire of plans()) {
        for (const f of fire.list) {
            assert.ok(f.frames >= 6 && f.frames <= 8);
            const bases = [];
            for (const frame of frames(fire)) {
                const at = BurnFire.pose(f, frame, fire.rows);
                if (at) bases.push(at.base);
            }
            assert.ok(bases.length >= 3, 'it crosses the window');
            for (let k = 1; k < bases.length; k++) {
                assert.ok(bases[k] < bases[k - 1], `seed ${fire.seed}: ${bases[k]} after ${bases[k - 1]}`);
                if (k >= 2) assert.ok(bases[k - 1] - bases[k] > bases[k - 2] - bases[k - 1], 'it accelerates');
            }
        }
    }
});

test('nothing vanishes inside the window: a flame is painted until its lowest cell is out through the top', () => {
    for (const fire of plans()) {
        for (const f of fire.list) {
            const shown = frames(fire).filter(frame => painted(fire, f, frame));
            const last = shown[shown.length - 1];
            // painted on every frame from its first to its last, none skipped
            assert.deepEqual(shown, Array.from({ length: shown.length }, (_, k) => shown[0] + k));
            // on the frame after its last its base (its lowest point) is at the top edge or above:
            // it left through the top, it was not removed
            assert.equal(BurnFire.pose(f, last + 1, fire.rows), null);
            assert.equal(last + 1, f.start + f.frames);
            // on its last frame it reaches the top edge (it is seen leaving), and on every frame
            // its step to the next is no longer than itself (a stream, never a jump)
            const leaving = BurnFire.pose(f, last, fire.rows);
            assert.ok(leaving.base - leaving.length <= 0, `seed ${fire.seed}: leaves through the top`);
            for (const frame of shown) {
                const at = BurnFire.pose(f, frame, fire.rows);
                assert.ok(BurnFire.step(f, frame, fire.rows) <= at.length, `seed ${fire.seed} frame ${frame}: a jump`);
            }
            for (let frame = last + 1; frame < fire.length + 2; frame++) assert.equal(painted(fire, f, frame), false);
        }
    }
});

test('the length is derived: the frame after the last flame leaves, two lift frames and the clean frame', () => {
    for (const fire of plans()) {
        const shares = frames(fire).map(f => BurnFire.flameShare(fire, f));
        const exit = shares.findLastIndex(share => share > 0) + 1;
        assert.equal(fire.exit, exit);
        assert.equal(fire.length, exit + 2 + 1);
        assert.equal(BurnFire.sequenceLength(exit), exit + 3);
        assert.ok(fire.length * 120 <= 2000, `under two seconds: ${fire.length} frames`);
        // the black: half, solid from the second frame until the last flame has left, then half,
        // a quarter, and the clean last frame
        const levels = frames(fire).map(f => BurnFire.blackLevel(f, fire.exit));
        assert.deepEqual(levels, [2, ...Array(exit - 1).fill(4), 2, 1, 0]);
        for (let f = fire.cover; f < exit; f++) assert.equal(levels[f], 4, 'solid from the cover until the last flame left');
        assert.ok([...BurnFire.paintGrid(fire, fire.length - 1)].every(p => p === BurnFire.NOT_PAINTED));
        assert.equal(BurnFire.hardStopMs(fire.length, 120), (fire.length + 1) * 120);
    }
    let black = 0;
    for (let row = 0; row < 4; row++) for (let col = 0; col < 4; col++) if (BurnFire.blackAt(0, 8, col, row)) black++;
    assert.equal(black, 8);
});

test('a pass: the flame rises to one peak, the cover, near the middle, and falls; nothing after the last flame', () => {
    for (const fire of plans()) {
        const shares = frames(fire).map(f => BurnFire.flameShare(fire, f));
        const peak = shares.indexOf(Math.max(...shares));
        assert.equal(fire.cover, peak);
        assert.ok(peak >= 4 && peak <= 6, `seed ${fire.seed}: peak at ${peak}`);
        // one instant covers everything: the cover frame, and only it, is all flame
        assert.equal(shares[peak], 1, `seed ${fire.seed}: ${shares[peak]} at the peak`);
        assert.equal(shares.filter(share => share === 1).length, 1);
        assert.ok(shares[peak - 1] < 1 && shares[peak + 1] < 1);
        for (let f = 1; f <= peak; f++) if (shares[f - 1] > 0) assert.ok(shares[f] > shares[f - 1], `seed ${fire.seed} rise ${f}`);
        for (let f = peak + 1; f < shares.length; f++) {
            if (shares[f - 1] === 0) break;
            assert.ok(shares[f] < shares[f - 1], `seed ${fire.seed} fall ${f}: ${shares[f]} after ${shares[f - 1]}`);
        }
    }
});

test('one body: every flame on screen sways by the same cells on the same frame', () => {
    for (const fire of plans()) {
        for (const frame of frames(fire)) {
            const shifts = new Set(fire.list.map(f => BurnFire.pose(f, frame, fire.rows)).map((at, k) => (at ? Math.round(at.x - fire.list[k].x) : null)).filter(v => v !== null));
            assert.ok(shifts.size <= 1, `frame ${frame}: ${[...shifts]}`);
        }
    }
});

test('liquid: a flame is longer the faster it moves, its area holds, and its centre line bends anew on every frame', () => {
    for (const fire of plans()) {
        for (const f of fire.list) {
            const on = frames(fire).filter(frame => BurnFire.pose(f, frame, fire.rows));
            for (let k = 1; k < on.length; k++) {
                const before = BurnFire.pose(f, on[k - 1], fire.rows);
                const now = BurnFire.pose(f, on[k], fire.rows);
                assert.ok(BurnFire.step(f, on[k], fire.rows) > BurnFire.step(f, on[k - 1], fire.rows));
                assert.ok(now.length > before.length && now.width < before.width, 'longer and narrower as it speeds up');
            }
            // painted area while the whole flame is inside the window, against its resting area
            const rest = TEARDROP_AREA * f.height * f.width;
            for (const frame of on) {
                const at = BurnFire.pose(f, frame, fire.rows);
                if (at.base > fire.rows || at.base - at.length < 0 || at.x - f.width < 0 || at.x + f.width > fire.cols) continue;
                const area = bodyRuns(fire, f, frame).reduce((sum, r) => sum + r.to - r.from + 1, 0);
                assert.ok(area >= 0.7 * rest && area <= 1.4 * rest, `seed ${fire.seed} frame ${frame}: ${area} of ${rest}`);
            }
        }
        // the centre line, measured on a tall grid where the whole flame shows: never the same
        // shape merely moved from one frame to the next
        const tall = { cols: fire.cols * 3, rows: fire.rows };
        for (const f of fire.list) {
            const wide = Object.assign({}, f, { x: f.x + fire.cols });
            const centres = [];
            for (let frame = f.start + 1; frame < f.start + f.frames; frame++) {
                const at = BurnFire.pose(wide, frame, tall.rows);
                const runs = BurnFire.flameRuns(wide, frame, tall.cols, tall.rows).filter(r => !r.core);
                // the centre at each tenth of its length, relative to its sway, where it is painted
                const line = Array.from({ length: 9 }, (_, i) => {
                    const row = Math.floor(at.base - (i + 1) / 10 * at.length);
                    const run = runs.find(r => r.row === row);
                    return run ? (run.from + run.to) / 2 - at.x : null;
                });
                if (line.filter(v => v !== null).length >= 3) centres.push(line);
            }
            assert.ok(centres.length >= 2, 'the flame is measured');
            for (let k = 1; k < centres.length; k++) {
                const moved = centres[k].some((v, i) => v !== null && centres[k - 1][i] !== null && Math.abs(v - centres[k - 1][i]) >= 1);
                assert.ok(moved, `seed ${fire.seed}: the same bend twice`);
            }
        }
    }
});

test('the cores are drawn over every body, so neighbouring cores fuse', () => {
    for (const fire of plans()) {
        const grid = BurnFire.paintGrid(fire, fire.cover - 1);
        for (const f of fire.list) {
            for (const r of BurnFire.flameRuns(f, fire.cover - 1, fire.cols, fire.rows).filter(run => run.core)) {
                for (let col = r.from; col <= r.to; col++) assert.equal(grid[r.row * fire.cols + col], BurnFire.CORE);
            }
        }
    }
});

test('dies as pieces: the last three painted frames hold at most three separate flames each', () => {
    for (const fire of plans()) {
        const shown = frames(fire).filter(f => BurnFire.flameShare(fire, f) > 0);
        for (const frame of shown.slice(-2)) {
            const count = flameGroups(fire, frame);
            assert.ok(count >= 1 && count <= 4, `seed ${fire.seed} ${fire.cols}x${fire.rows} frame ${frame}: ${count}`);
        }
    }
});

test('a flame is a teardrop: one connected shape whose topmost row is a single cell, a point', () => {
    for (const fire of plans()) {
        for (const f of fire.list) {
            const tallFlame = Object.assign({}, f, { start: 0, frames: 4, x: f.x + fire.cols });
            const tall = { cols: fire.cols * 3, rows: 400 };
            const cells = BurnFire.flameCells(tallFlame, 2, tall.cols, tall.rows).filter(c => !c.core);
            const set = new Set(cells.map(c => c.row * tall.cols + c.col));
            assert.equal(groups(tall.cols, tall.rows, i => set.has(i), true), 1);
            const top = Math.min(...cells.map(c => c.row));
            assert.equal(cells.filter(c => c.row === top).length, 1, `a point, seed ${fire.seed}`);
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
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(|globalAlpha|Gradient|filter|shadowBlur/);
});

test('the grid: 8 px cells on a desktop, 6 px under 480 px, capped', () => {
    assert.equal(BurnFire.CELL_PX, 8);
    assert.deepEqual(plain(BurnFire.gridSize(1280, 800)), { cell: 8, cols: 160, rows: 100 });
    assert.deepEqual(plain(BurnFire.gridSize(375, 812)), { cell: 6, cols: 63, rows: 136 });
    const big = BurnFire.gridSize(7680, 4320);
    assert.ok(big.cols <= 480 && big.rows <= 270);
});

test('bounded work: a 1280 x 800 fire at 8 px cells is planned and every frame painted in time', () => {
    const size = BurnFire.gridSize(1280, 800);
    const started = performance.now();
    const fire = BurnFire.plan(size.cols, size.rows, 0x5eed);
    const planned = performance.now() - started;
    let slowest = 0;
    for (const frame of frames(fire)) {
        const at = performance.now();
        BurnFire.paintGrid(fire, frame);
        slowest = Math.max(slowest, performance.now() - at);
    }
    // measured 50 to 200 ms to plan (a redrawn draft included) and about 3 ms a frame; pinned generously
    assert.ok(planned < 1500, `planned in ${planned} ms`);
    assert.ok(slowest < 60, `a frame painted in ${slowest} ms`);
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
    assert.equal(Array.from({ length: 12 }, (_, f) => BurnFire.coversAt(f, 6)).filter(Boolean).length, 1);
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
    assert.match(body, /if \(coversAt\(frame, fire\.cover\)\) cover\(\);/);
    assert.match(body, /const fire = plan\(size\.cols, size\.rows, /);
    assert.match(body, /if \(canvas\) canvas\.remove\(\);\n\s*cover\(\);\n\s*resolve\(\);/);
    assert.match(body, /if \(frame >= fire\.length\) return end\(\);/);
    assert.match(body, /addEventListener\('keydown', end, true\)/);
    assert.match(body, /addEventListener\('pointerdown', end, true\)/);
    assert.match(body, /hardStop = setTimeout\(end, hardStopMs\(fire\.length, look\.frameMs\)\);/);
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
