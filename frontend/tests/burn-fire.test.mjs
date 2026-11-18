// frontend/js/burn-fire.js, the pixel fire the person who burns sees after the server confirmed
// the burn: the real module's pure parts with a seeded random source, and where the two burn
// paths call it. How it looks is checked in a real browser (the live screenshots).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load, plain, rng } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const css = read('../styles.css');
const chat = read('../js/chat.js');
const source = read('../js/burn-fire.js');
const BurnFire = load({}, ['../js/burn-fire.js']).get('BurnFire');

const SEEDS = [1, 7, 0xdecade, 0xf1e];
const COLS = 40;
const ROWS = 30;

const none = () => new Uint16Array(COLS);
// A window's grid for the frames that matter
const PEAK_COLS = 160;
const PEAK_ROWS = 100;

function run(grid, bottom, steps, random, cooling = 0) {
    for (let i = 0; i < steps; i++) grid = BurnFire.step(grid, bottom, random, cooling);
    return grid;
}

// Plays the seeded fire as play() does, up to frame `until` (exclusive)
function playTo(seed, until, cols = PEAK_COLS, rows = PEAK_ROWS) {
    const random = rng(seed).next;
    const heat = BurnFire.sourceHeat(rows);
    let grid = BurnFire.createGrid(cols, rows);
    let sources = BurnFire.placeSources(cols, random);
    for (let frame = 0; frame < until; frame++) {
        for (const { share, cooling } of BurnFire.frameSteps(frame, rows, heat)) {
            assert.ok(share >= 0 && share <= 1 && cooling >= 0);
            grid = BurnFire.step(grid, BurnFire.sourceRow(cols, sources, heat, share), random, cooling);
        }
        sources = BurnFire.swaySources(sources, random);
    }
    return { grid, heat };
}
const PEAK = BurnFire.RISE_FRAMES + BurnFire.HOLD_FRAMES - 1;

test('the sources: one per 12 to 20 cells, unevenly spaced, strengths that differ and change slowly, places that sway a cell', () => {
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        const sources = BurnFire.placeSources(PEAK_COLS, random);
        const gaps = sources.slice(1).map((s, i) => s.x - sources[i].x);
        assert.ok(gaps.every(gap => gap >= 12 && gap <= 20), `seed ${seed}: ${gaps}`);
        assert.ok(new Set(gaps).size > 1);
        assert.ok(sources.every(s => s.strength >= 0.45 && s.strength <= 1 && s.half >= 5 && s.half <= 9));
        const later = BurnFire.swaySources(sources, random);
        later.forEach((s, i) => {
            assert.ok(Math.abs(s.x - sources[i].x) <= 1);
            assert.ok(Math.abs(s.strength - sources[i].strength) <= 0.06 + 1e-9);
        });
        // each source makes one tongue: heat falls off with the distance from it
        const heat = BurnFire.sourceHeat(PEAK_ROWS);
        const row = BurnFire.sourceRow(PEAK_COLS, [{ x: 50, half: 8, strength: 1 }], heat, 1);
        for (let dx = 0; dx < 8; dx++) assert.ok(row[50 + dx] > row[51 + dx] && row[50 - dx] > row[49 - dx]);
        assert.equal(row[59], 0);
        assert.equal(row[41], 0);
    }
});

test('a step keeps the grid size, never rises above its bottom row and never goes below zero', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        let grid = BurnFire.createGrid(COLS, ROWS);
        for (let i = 0; i < ROWS * 3; i++) {
            const bottom = BurnFire.sourceRow(COLS, BurnFire.placeSources(COLS, random), heat, 1);
            grid = BurnFire.step(grid, bottom, random, i % 7 === 0 ? 2 : 0);
            assert.equal(grid.cols, COLS);
            assert.equal(grid.rows, ROWS);
            assert.equal(grid.heat.length, COLS * ROWS);
            for (const value of grid.heat) assert.ok(value >= 0 && value <= heat, `seed ${seed} step ${i}: ${value}`);
        }
    }
});

test('with the sources off, every column dies out within the grid height', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        const lit = run(BurnFire.createGrid(COLS, ROWS), new Uint16Array(COLS).fill(heat), ROWS * 2, random);
        assert.ok(lit.heat.some(value => value > 0));
        assert.ok(run(lit, none(), ROWS, random).heat.every(value => value === 0), `seed ${seed}`);
    }
});

test('the whole play leaves nothing after the last frame', () => {
    for (const seed of SEEDS) {
        const { grid } = playTo(seed, BurnFire.TOTAL_FRAMES);
        assert.ok(grid.heat.every(value => value === 0), `seed ${seed}: embers left`);
    }
});

test('tongues, not one body: at the peak at least three gaps of page reach from the top past a third of the height', () => {
    for (const seed of SEEDS) {
        const { grid } = playTo(seed, PEAK + 1);
        const third = Math.ceil(PEAK_ROWS / 3);
        const clear = Array.from({ length: PEAK_COLS }, (_, x) => {
            for (let y = 0; y <= third; y++) if (grid.heat[y * PEAK_COLS + x] > 0) return false;
            return true;
        });
        const gaps = clear.filter((c, x) => c && !clear[x - 1]).length;
        assert.ok(gaps >= 3, `seed ${seed}: ${gaps} gaps`);
        // and flames: the tallest pass the top, most of the bottom row burns
        assert.ok(clear.some(c => !c));
        assert.ok(Array.from({ length: PEAK_COLS }, (_, x) => grid.heat[(PEAK_ROWS - 1) * PEAK_COLS + x] > 0).filter(Boolean).length > PEAK_COLS / 2);
        assert.ok(Array.from({ length: PEAK_COLS }, (_, x) => grid.heat[x] > 0).some(Boolean), `seed ${seed}: no tongue reaches the top`);
    }
});

// Shapes, not static: fewer than ISOLATED_MAX of the painted cells have no painted neighbour of
// their own colour among their four neighbours
const ISOLATED_MAX = 0.1;

test('the peak is shapes, not static: few painted cells stand alone in their colour', () => {
    for (const seed of SEEDS) {
        const { grid, heat } = playTo(seed, PEAK + 1);
        const colour = (x, y) => (x < 0 || y < 0 || x >= PEAK_COLS || y >= PEAK_ROWS ? -2 : BurnFire.paletteStep(grid.heat[y * PEAK_COLS + x], heat));
        let painted = 0;
        let alone = 0;
        for (let y = 0; y < PEAK_ROWS; y++) {
            for (let x = 0; x < PEAK_COLS; x++) {
                const own = colour(x, y);
                if (own === BurnFire.NO_PAINT) continue;
                painted++;
                if (![[1, 0], [-1, 0], [0, 1], [0, -1]].some(([dx, dy]) => colour(x + dx, y + dy) === own)) alone++;
            }
        }
        assert.ok(alone / painted < ISOLATED_MAX, `seed ${seed}: ${alone} of ${painted} alone`);
    }
});

test('the palette: zero heat paints nothing, then the black fringe, the red body, the yellow core; no white', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-fringe', '--fire-flame', '--fire-glow']);
    const max = BurnFire.sourceHeat(ROWS);
    assert.equal(BurnFire.NO_PAINT, -1);
    assert.equal(BurnFire.paletteStep(0, max), BurnFire.NO_PAINT);
    const seen = new Set();
    let last = 0;
    for (let value = 1; value <= max; value++) {
        const index = BurnFire.paletteStep(value, max);
        assert.ok(Number.isInteger(index) && index >= 0 && index < 3, `${value}: ${index}`);
        assert.ok(index >= last, `${value} steps down`);
        last = index;
        seen.add(index);
    }
    assert.equal(seen.size, 3);
    for (const name of BurnFire.PALETTE) assert.match(css, new RegExp(`^\\s*${name}:`, 'm'));
    assert.match(css, /--fire-fringe: #000000;\n\s*--fire-flame: var\(--danger\);\n\s*--fire-glow: var\(--warning\);/);
    assert.doesNotMatch(css, /--fire-smoke|--fire-core/);
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(/);
    // the draw paints only the palette's steps: a cell with no heat is skipped
    assert.match(source, /if \(paletteStep\(heat\[i\], maxHeat\) !== index\) continue;/);
});

test('one frame clock: the fire steps at the stylesheet\'s --frame-ms, the hover frames and the caption too', () => {
    assert.equal(BurnFire.FRAME_PROPERTY, '--frame-ms');
    assert.match(css, /--frame-ms: 120ms;/);
    // the hover frames are three of them, the caption's three steps too
    assert.match(css, /--icon-steps-ms: calc\(var\(--frame-ms\) \* 3\);/);
    assert.match(css, /--caption-steps-ms: calc\(var\(--frame-ms\) \* 3\);/);
    assert.match(css, /steps\(3, end\)/);
    // the module holds no frame duration of its own: it reads the property and steps at it
    assert.match(source, /frameMs: parseFloat\(style\.getPropertyValue\(FRAME_PROPERTY\)\)/);
    assert.match(source, /timer = setTimeout\(tick, look\.frameMs\);/);
    assert.doesNotMatch(source, /FRAME_MS|\b83\b|\b120\b/);
    // without a readable clock the fire does not play
    assert.equal(BurnFire.shouldPlay(false, false, NaN), false);
    assert.equal(BurnFire.shouldPlay(false, false, 0), false);
});

test('the fire plays only on a visible page without reduced motion; play resolves at once otherwise', async () => {
    assert.equal(BurnFire.shouldPlay(false, false), true);
    assert.equal(BurnFire.shouldPlay(true, false), false);
    assert.equal(BurnFire.shouldPlay(false, true), false);
    assert.equal(BurnFire.shouldPlay(true, true), false);
    // the real module in a page that asks for reduced motion, and in a hidden page
    for (const [reduced, visibility] of [[true, 'visible'], [false, 'hidden']]) {
        const page = {
            window: { matchMedia: () => ({ matches: reduced }) },
            document: { visibilityState: visibility }
        };
        const fire = load(page, ['../js/burn-fire.js']).get('BurnFire');
        let covered = 0;
        await fire.play(() => covered++);
        assert.equal(covered, 1);
    }
});

test('the grid is the window divided by the cell, the cell growing past the cap; about 1.6 s on the clock', () => {
    assert.deepEqual(plain(BurnFire.gridSize(1280, 800)), { cell: 8, cols: 160, rows: 100 });
    const big = BurnFire.gridSize(3840, 2160);
    assert.ok(big.cell > 8 && big.cols <= 240 && big.rows <= 135);
    assert.equal(BurnFire.TOTAL_FRAMES, 13);
    assert.equal(BurnFire.hardStopMs(120), 1680);
    assert.ok(BurnFire.hardStopMs(120) > BurnFire.TOTAL_FRAMES * 120);
});

test('the module makes one canvas by element and attribute: no markup string, no inline style', () => {
    assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|\.style\b|setAttribute\('style'/);
    assert.match(source, /createElement\('canvas'\)/);
    assert.match(source, /setAttribute\('aria-hidden', 'true'\)/);
    assert.match(source, /canvas\.remove\(\)/);
    assert.match(css, /\.burn-fire \{[^}]*image-rendering: pixelated/);
});

test('both burns (a pair and a room) play it only on the confirmed branch, never leaving', () => {
    const body = chat.match(/async function burnNow\(\) \{[\s\S]*?\n {4}\}/)[0];
    assert.equal(body.match(/BurnFire\.play/g).length, 1);
    const success = body.indexOf('HTTP_STATUS.NO_CONTENT || result.status === HTTP_STATUS.NOT_FOUND');
    const failure = body.indexOf('} else if (result.status !== HTTP_STATUS.UNAUTHORIZED)');
    const call = body.indexOf('BurnFire.play');
    assert.ok(success > 0 && success < call && call < failure);
    assert.match(body, /if \(!leaving && result\.status === HTTP_STATUS\.NO_CONTENT\) \{\s*BurnFire\.play\(done\)/);
    // the request goes first: nothing of the fire before the DELETE answers
    assert.ok(body.indexOf("await api('DELETE'") < call);
    // nowhere else
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
