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
// The desktop window's grid (1280 x 800 at 8 px) and phones' (375 x 812 and 375 x 667 at 6 px)
const GRIDS = [{ cols: 160, rows: 100 }, { cols: 63, rows: 136 }, { cols: 63, rows: 112 }];
const PLANS = SEEDS.flatMap(seed => GRIDS.map(({ cols, rows }) => Object.assign(BurnFire.plan(cols, rows, seed), { seed })));
const frames = (fire) => Array.from({ length: fire.length }, (_, f) => f);
const runs = (fire, flame, frame) => BurnFire.flameRuns(flame, frame, fire.cols, fire.rows);
const painted = (fire, flame, frame) => runs(fire, flame, frame).length > 0;
const stream = (fire) => fire.list.filter(f => !f.rear);
const area = (list) => list.reduce((sum, r) => sum + r.to - r.from + 1, 0);
const COUNTS = { giant: 2, large: 4, medium: 4, small: 3 };

// Connected groups (corner to corner too) of the cells keep()
function groups(cols, rows, keep) {
    const seen = new Uint8Array(cols * rows);
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
            for (let dx = -1; dx <= 1; dx++) {
                for (let dy = -1; dy <= 1; dy++) {
                    const nx = x + dx;
                    const ny = y + dy;
                    const next = ny * cols + nx;
                    if (nx < 0 || ny < 0 || nx >= cols || ny >= rows || seen[next] || !keep(next)) continue;
                    seen[next] = 1;
                    stack.push(next);
                }
            }
        }
    }
    return count;
}
const runGroups = (cols, rows, list) => {
    const set = new Set();
    for (const r of list) for (let c = r.from; c <= r.to; c++) set.add(r.row * cols + c);
    return groups(cols, rows, i => set.has(i));
};

// A flame of preset alone on a big grid, mid-crossing, as a mask normalised to a SIZE x SIZE box
const SIZE = 24;
const BIG = { cols: 240, rows: 240 };
function alone(preset, extra = {}) {
    return Object.assign({ x: 120, cls: 'large', preset, mirror: false, share: 0.5, height: 120, width: 90, phase: 0, tone: 2, accent: { tone: 3, side: 1, share: 0.3 }, start: 0, frames: 8, snake: false }, extra);
}
function unitMask(flame, frame = 4) {
    const list = BurnFire.flameRuns(flame, frame, BIG.cols, BIG.rows);
    const top = Math.min(...list.map(r => r.row));
    const bottom = Math.max(...list.map(r => r.row));
    const left = Math.min(...list.map(r => r.from));
    const right = Math.max(...list.map(r => r.to));
    const mask = new Uint8Array(SIZE * SIZE);
    for (const r of list) {
        const y = Math.min(SIZE - 1, Math.floor((r.row - top) / (bottom - top + 1) * SIZE));
        for (let c = r.from; c <= r.to; c++) mask[y * SIZE + Math.min(SIZE - 1, Math.floor((c - left) / (right - left + 1) * SIZE))] = 1;
    }
    return { mask, list };
}

test('the stream: thirteen flames in four planned size classes, no two alike, neighbours of different sizes, big ones first', () => {
    for (const fire of PLANS) {
        assert.deepEqual(plain(BurnFire.plan(fire.cols, fire.rows, fire.seed)), plain(Object.assign({}, fire, { seed: undefined })));
        const flames = stream(fire);
        assert.equal(flames.length, 13);
        const rear = fire.list.filter(f => f.rear);
        // the rear flames (plain red, behind all others) are only what makes the cover frame whole
        assert.deepEqual(plain(fire.list.slice(0, rear.length)), plain(rear));
        for (const cls of BurnFire.CLASSES) {
            const members = flames.filter(f => f.cls === cls.name);
            assert.equal(members.length, COUNTS[cls.name], cls.name);
            for (const f of members) {
                assert.ok(f.width >= cls.width[0] * fire.cols - 1e-9 && f.width <= cls.width[1] * fire.cols + 1e-9, `${cls.name} width`);
                assert.ok(f.height >= cls.height[0] * fire.rows - 1e-9 && f.height <= cls.height[1] * fire.rows + 1e-9, `${cls.name} height`);
            }
        }
        assert.ok(flames.filter(f => f.cls === 'giant').every(f => f.height > fire.rows), 'giants are taller than the window');
        assert.equal(new Set(flames.map(f => `${f.preset}/${f.cls}`)).size, 13, 'no two share preset and class');
        assert.equal(new Set(flames.map(f => f.preset)).size, 8, 'all eight silhouettes');
        const byX = flames.slice().sort((a, b) => a.x - b.x);
        for (let i = 1; i < byX.length; i++) assert.notEqual(byX[i].cls, byX[i - 1].cls, `seed ${fire.seed}: neighbours ${i}`);
        const latest = (name) => Math.max(...flames.filter(f => f.cls === name && !f.snake).map(f => f.start));
        const earliest = (name) => Math.min(...flames.filter(f => f.cls === name).map(f => f.start));
        assert.ok(latest('giant') <= earliest('large') + 1 && latest('large') <= earliest('small'), 'big ones first');
        assert.ok(Math.max(...flames.map(f => f.start)) <= 0.4 * fire.length, 'all have entered in the first 40 %');
    }
});

test('eight silhouettes: pairwise different outlines in a unit box, each one connected shape, mirrorable', () => {
    const masks = BurnFire.STREAM_PRESETS.map(preset => [preset, unitMask(alone(preset))]);
    assert.equal(masks.length, 8);
    for (const [preset, { list }] of masks) assert.equal(runGroups(BIG.cols, BIG.rows, list), 1, `${preset} is one shape`);
    for (let i = 0; i < masks.length; i++) {
        for (let j = i + 1; j < masks.length; j++) {
            const a = masks[i][1].mask;
            const b = masks[j][1].mask;
            let differ = 0;
            let union = 0;
            for (let k = 0; k < a.length; k++) {
                differ += a[k] !== b[k] ? 1 : 0;
                union += a[k] || b[k] ? 1 : 0;
            }
            assert.ok(differ / union >= 0.15, `${masks[i][0]} and ${masks[j][0]}: ${(differ / union).toFixed(3)}`);
        }
    }
    // a mirrored flame is the same outline flipped
    const flat = alone('crown', { phase: 0.25 });
    const left = unitMask(Object.assign({}, flat, { mirror: false })).mask;
    const right = unitMask(Object.assign({}, flat, { mirror: true })).mask;
    assert.notDeepEqual(left, right);
    // the multi-tip ones have several tongues: more than one run on some row
    for (const preset of ['twin', 'tongues', 'crown', 'mass']) {
        const { list } = unitMask(alone(preset));
        const perRow = new Map();
        for (const r of list) perRow.set(r.row, (perRow.get(r.row) || 0) + 1);
        assert.ok(Math.max(...perRow.values()) >= 2, `${preset} has tongues`);
    }
});

test('every planned flame is one connected shape on every frame it shows whole', () => {
    for (const fire of PLANS.slice(0, 3)) {
        const wide = { cols: fire.cols * 3, rows: fire.rows * 3 };
        for (const f of stream(fire)) {
            const moved = Object.assign({}, f, { x: f.x + fire.cols });
            for (let frame = f.start; frame < f.start + f.frames; frame++) {
                const list = BurnFire.flameRuns(moved, frame, wide.cols, wide.rows);
                const at = BurnFire.pose(moved, frame, wide.rows);
                if (at.base <= wide.rows) assert.equal(runGroups(wide.cols, wide.rows, list), 1, `seed ${fire.seed} ${f.preset} frame ${frame}`);
            }
        }
    }
});

test('each flame its own colour: one dominant tone and a flat accent on one flank, apart from its neighbours', () => {
    const TONES = [BurnFire.YELLOW, BurnFire.ORANGE, BurnFire.RED];
    for (const fire of PLANS) {
        const flames = stream(fire);
        for (let i = 0; i < flames.length; i++) {
            const f = flames[i];
            assert.ok(TONES.includes(f.tone) && TONES.includes(f.accent.tone) && f.accent.tone !== f.tone);
            assert.ok(Math.abs(TONES.indexOf(f.tone) - TONES.indexOf(f.accent.tone)) === 1, 'the accent is the neighbouring tone');
            // drawn alone on a wide, tall grid mid-crossing: at most two tones, the dominant on 60 %
            const moved = Object.assign({}, f, { x: f.x + fire.cols });
            const tall = { cols: fire.cols * 3, rows: fire.rows * 3, list: [moved], exit: 99, length: 99 };
            const frame = f.start + f.frames - 3;
            const grid = BurnFire.paintGrid(tall, frame);
            const cells = [...grid.keys()].filter(k => grid[k] > BurnFire.BLACK);
            const counts = new Map();
            for (const k of cells) counts.set(grid[k], (counts.get(grid[k]) || 0) + 1);
            assert.ok(counts.size <= 2, `seed ${fire.seed} ${f.preset}: ${counts.size} tones`);
            assert.ok(counts.get(f.tone) >= 0.6 * cells.length, `seed ${fire.seed} ${f.preset}: dominant ${counts.get(f.tone)} of ${cells.length}`);
            // the accent on one flank: in most rows all its cells lie on one side of the middle of
            // the row across the flame
            const list = BurnFire.flameRuns(moved, frame, tall.cols, tall.rows);
            let rows = 0;
            let flank = 0;
            for (const r of list) {
                const accent = [];
                for (let c = r.from; c <= r.to; c++) if (grid[r.row * tall.cols + c] === f.accent.tone) accent.push(c + 0.5 - (r.span[0] + r.span[1] + 1) / 2);
                if (!accent.length) continue;
                rows++;
                if (accent.every(d => Math.sign(d) === f.accent.side)) flank++;
            }
            assert.ok(rows > 0 && flank >= 0.8 * rows, `seed ${fire.seed} ${f.preset}: ${flank} of ${rows} rows on its flank`);
            // apart from the flame drawn just before it and from its nearest neighbour by x
            if (i > 0) assert.notEqual(f.tone, flames[i - 1].tone, `seed ${fire.seed}: same tone as the flame behind`);
            const nearest = flames.filter(g => g !== f).sort((a, b) => Math.abs(a.x - f.x) - Math.abs(b.x - f.x))[0];
            assert.notEqual(f.tone, nearest.tone, `seed ${fire.seed}: same tone as its neighbour`);
        }
        for (const tone of TONES) {
            const share = flames.filter(f => f.tone === tone).length / flames.length;
            assert.ok(share >= 0.15 && share <= 0.5, `seed ${fire.seed}: tone ${tone} on ${share}`);
        }
        assert.ok(flames.every(f => f.tone !== BurnFire.DEEP && f.accent.tone !== BurnFire.DEEP), 'the deep red is the rear flames\' only');
        assert.ok(fire.list.filter(f => f.rear).every(f => f.tone === BurnFire.DEEP && f.accent === null));
    }
    // no height banding, no rims
    assert.doesNotMatch(source, /\bRIM\b|\brim\b|\bbands?\b/);
});

test('the last one alone: the small leaf leaves last, snaking sideways, alone over the black for its last frames', () => {
    for (const fire of PLANS) {
        const last = fire.list[fire.list.length - 1];
        assert.equal(last.preset, 'leaf');
        assert.equal(last.cls, 'small');
        assert.equal(last.snake, true);
        assert.equal(last.start + last.frames, fire.exit);
        assert.ok(fire.list.slice(0, -1).every(f => f.start + f.frames < fire.exit));
        const xs = new Set();
        // its own sideways place, the shared sway taken out
        const still = Object.assign({}, last, { snake: false });
        for (let frame = last.start; frame < last.start + last.frames; frame++) xs.add(Math.round(BurnFire.pose(last, frame, fire.rows).x - BurnFire.pose(still, frame, fire.rows).x));
        assert.ok(xs.size >= 3, `its centre takes ${xs.size} places`);
        const shown = frames(fire).filter(frame => painted(fire, last, frame));
        const alone = shown.filter(frame => fire.list.slice(0, -1).every(f => !painted(fire, f, frame)));
        assert.ok(alone.length >= 1 && alone.length <= 2, `alone on ${alone.length} frames`);
        assert.equal(alone[alone.length - 1], shown[shown.length - 1]);
        for (const frame of alone) {
            assert.equal(BurnFire.blackLevel(frame, fire.exit), 4, 'over the solid black');
            // seen whole across: its snaking never takes it out at a side
            assert.ok(runs(fire, last, frame).every(r => r.from > 0 && r.to < fire.cols - 1), `seed ${fire.seed}: inside the window`);
        }
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
    // one silhouette for every flame, the rear ones included
    assert.equal((source.match(/function silhouette\(/g) || []).length, 1);
    assert.equal((source.match(/silhouette\(at, PRESETS/g) || []).length, 1);
});

test('nothing stands still: every flame rises on every frame it is there, each step larger than the last', () => {
    for (const fire of PLANS) {
        for (const f of fire.list) {
            assert.ok(f.frames >= 6 && f.frames <= 8);
            const bases = frames(fire).map(frame => BurnFire.pose(f, frame, fire.rows)).filter(Boolean).map(at => at.base);
            assert.ok(bases.length >= 3, 'it crosses the window');
            for (let k = 1; k < bases.length; k++) {
                assert.ok(bases[k] < bases[k - 1], `seed ${fire.seed}: ${bases[k]} after ${bases[k - 1]}`);
                if (k >= 2) assert.ok(bases[k - 1] - bases[k] > bases[k - 2] - bases[k - 1], 'it accelerates');
            }
        }
    }
});

test('nothing vanishes inside the window: a flame is painted until its lowest cell is out through the top', () => {
    for (const fire of PLANS) {
        for (const f of fire.list) {
            const shown = frames(fire).filter(frame => painted(fire, f, frame));
            const last = shown[shown.length - 1];
            assert.deepEqual(shown, Array.from({ length: shown.length }, (_, k) => shown[0] + k));
            // on the frame after its last its base (its lowest point) is at the top edge: it left
            // through the top, it was not removed
            assert.equal(BurnFire.pose(f, last + 1, fire.rows), null);
            assert.equal(last + 1, f.start + f.frames);
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
    for (const fire of PLANS) {
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

test('a pass: the flame rises to one peak, the cover, and falls; exactly one frame is all flame', () => {
    for (const fire of PLANS) {
        const shares = frames(fire).map(f => BurnFire.flameShare(fire, f));
        const peak = shares.indexOf(Math.max(...shares));
        assert.equal(fire.cover, peak);
        assert.ok(peak >= 3 && peak <= 7, `seed ${fire.seed}: peak at ${peak}`);
        assert.equal(shares[peak], 1, `seed ${fire.seed}: ${shares[peak]} at the peak`);
        assert.equal(shares.filter(share => share === 1).length, 1);
        for (let f = 1; f <= peak; f++) if (shares[f - 1] > 0) assert.ok(shares[f] > shares[f - 1], `seed ${fire.seed} rise ${f}`);
        for (let f = peak + 1; f < shares.length; f++) {
            if (shares[f - 1] === 0) break;
            assert.ok(shares[f] < shares[f - 1], `seed ${fire.seed} fall ${f}: ${shares[f]} after ${shares[f - 1]}`);
        }
    }
});

test('one body: every flame on screen but the snaking leaf sways by the same cells on the same frame', () => {
    for (const fire of PLANS) {
        for (const frame of frames(fire)) {
            const shifts = new Set(fire.list.filter(f => !f.snake).map(f => [f, BurnFire.pose(f, frame, fire.rows)]).filter(([, at]) => at).map(([f, at]) => Math.round(at.x - f.x)));
            assert.ok(shifts.size <= 1, `frame ${frame}: ${[...shifts]}`);
        }
    }
});

test('liquid: a flame is longer the faster it moves, its area holds, and its centre line bends anew on every frame', () => {
    for (const fire of PLANS) {
        for (const f of fire.list) {
            const on = frames(fire).filter(frame => BurnFire.pose(f, frame, fire.rows));
            for (let k = 1; k < on.length; k++) {
                const before = BurnFire.pose(f, on[k - 1], fire.rows);
                const now = BurnFire.pose(f, on[k], fire.rows);
                assert.ok(BurnFire.step(f, on[k], fire.rows) > BurnFire.step(f, on[k - 1], fire.rows));
                assert.ok(now.length > before.length && now.width < before.width, 'longer and narrower as it speeds up');
            }
        }
        // painted area of a whole flame (on a wide, tall grid) across its crossing: within a band
        // around its middle value
        const wide = { cols: fire.cols * 3, rows: fire.rows * 3 };
        for (const f of stream(fire)) {
            const moved = Object.assign({}, f, { x: f.x + fire.cols, height: f.height, start: 0 });
            const areas = [];
            for (let frame = 1; frame < moved.frames; frame++) {
                const at = BurnFire.pose(moved, frame, wide.rows);
                if (at.base > wide.rows || at.base - at.length < 0) continue;
                areas.push(area(BurnFire.flameRuns(moved, frame, wide.cols, wide.rows)));
            }
            const middle = areas.slice().sort((a, b) => a - b)[Math.floor(areas.length / 2)];
            for (const a of areas) assert.ok(a >= 0.7 * middle && a <= 1.4 * middle, `seed ${fire.seed} ${f.preset}: ${a} of ${middle}`);
            // the centre line at each tenth of the length: never the same shape merely moved
            let previous = null;
            for (let frame = 1; frame < moved.frames; frame++) {
                const at = BurnFire.pose(moved, frame, wide.rows);
                const list = BurnFire.flameRuns(moved, frame, wide.cols, wide.rows);
                const line = Array.from({ length: 9 }, (_, i) => {
                    const run = list.find(r => r.row === Math.floor(at.base - (i + 1) / 10 * at.length));
                    return run ? run.centre - at.x : null;
                });
                if (previous) assert.ok(line.some((v, i) => v !== null && previous[i] !== null && Math.abs(v - previous[i]) >= 0.5), `seed ${fire.seed}: the same bend twice`);
                previous = line;
            }
        }
    }
});

test('the paint: black, red, the fire orange, the yellow and the deep red, from the stylesheet; no alpha, no gradient', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-fringe', '--fire-flame', '--fire-orange', '--fire-glow', '--fire-deep']);
    assert.match(css, /--fire-fringe: #000000;\n\s*--fire-flame: var\(--danger\);\n\s*--fire-orange: #e65100;\n\s*--fire-glow: var\(--warning\);\n\s*--fire-deep: #7a0000;/);
    assert.equal((css.match(/--fire-deep/g) || []).length, 1, 'used by the fire only');
    assert.equal((css.match(/--fire-orange/g) || []).length, 1, 'used by the fire only');
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(|globalAlpha|Gradient|shadowBlur|\bcore\b/);
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
    // measured up to 170 ms to plan (a redrawn draft included) and up to 9 ms a frame; pinned generously
    assert.ok(planned < 1500, `planned in ${planned} ms`);
    assert.ok(slowest < 80, `a frame painted in ${slowest} ms`);
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
