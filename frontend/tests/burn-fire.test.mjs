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

// A bottom row of the hottest sources, and one of none
const full = (heat) => new Uint16Array(COLS).fill(heat);
const none = () => new Uint16Array(COLS);

function run(grid, sources, steps, random, cooling = 0) {
    for (let i = 0; i < steps; i++) grid = BurnFire.step(grid, sources, random, cooling);
    return grid;
}

test('the sources: hot clusters with cooler gaps, never above the source heat, drawn again differently', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        const row = BurnFire.sourceRow(COLS, heat, random);
        assert.equal(row.length, COLS);
        const values = new Set(row);
        assert.ok(values.has(heat) && values.size === 2, `seed ${seed}: ${[...values]}`);
        assert.ok([...row].every(value => value > 0 && value <= heat));
        assert.notDeepEqual(plain([...BurnFire.sourceRow(COLS, heat, random)]), plain([...row]));
    }
});

test('a step keeps the grid size, never rises above its sources and never goes below zero', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        let grid = BurnFire.createGrid(COLS, ROWS);
        let sources = BurnFire.sourceRow(COLS, heat, random);
        for (let i = 0; i < ROWS * 3; i++) {
            if (i % 5 === 0) sources = BurnFire.sourceRow(COLS, heat, random);
            grid = BurnFire.step(grid, sources, random, i % 7 === 0 ? 2 : 0);
            assert.equal(grid.cols, COLS);
            assert.equal(grid.rows, ROWS);
            assert.equal(grid.heat.length, COLS * ROWS);
            for (const value of grid.heat) {
                assert.ok(value >= 0 && value <= heat, `seed ${seed} step ${i}: ${value}`);
            }
        }
    }
});

test('tongues, not bands: under clustered sources the flame tips stand at different heights', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    const random = rng(SEEDS[0]).next;
    // a short source so the tips stand inside the grid: the top lit row of every column
    let grid = BurnFire.createGrid(COLS, ROWS);
    const sources = BurnFire.scaled(BurnFire.sourceRow(COLS, heat, random), 0.4);
    grid = run(grid, sources, ROWS * 2, random);
    const tips = Array.from({ length: COLS }, (_, x) => {
        for (let y = 0; y < ROWS; y++) if (grid.heat[y * COLS + x] > 0) return y;
        return ROWS;
    });
    assert.ok(Math.max(...tips) - Math.min(...tips) >= 4, `tips ${tips}`);
});

test('with the sources off, every column dies out within the grid height plus the source heat (a heat moves up a row or loses one every step)', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        const lit = run(BurnFire.createGrid(COLS, ROWS), full(heat), ROWS * 2, random);
        assert.ok(lit.heat.some(value => value > 0));
        const out = run(lit, none(), ROWS + heat, random);
        assert.ok(out.heat.every(value => value === 0), `seed ${seed}`);
    }
});

test('the whole play: shares and cooling in range, the window covered when the rise ends, nothing left at the end', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        let grid = BurnFire.createGrid(COLS, ROWS);
        let sources = null;
        for (let frame = 0; frame < BurnFire.TOTAL_FRAMES; frame++) {
            if (frame % BurnFire.SOURCE_FRAMES === 0) sources = BurnFire.sourceRow(COLS, heat, random);
            const steps = BurnFire.frameSteps(frame, ROWS, heat);
            assert.ok(steps.length > 0);
            for (const { share, cooling } of steps) {
                assert.ok(share >= 0 && share <= 1 && cooling >= 0);
                grid = BurnFire.step(grid, BurnFire.scaled(sources, share), random, cooling);
            }
            if (frame === BurnFire.RISE_FRAMES - 1) {
                const lit = grid.heat.filter(value => value > 0).length;
                assert.ok(lit > COLS * ROWS * 0.8, `seed ${seed}: ${lit} lit at cover`);
            }
        }
        assert.ok(grid.heat.every(value => value === 0), `seed ${seed}: embers left`);
    }
});

test('the palette: zero heat is no paint, every other heat maps to one of exactly three steps, cooler never above hotter', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-flame', '--fire-glow', '--fire-core']);
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
    // the steps are custom properties of the stylesheet, not colours of the module; no black
    for (const name of BurnFire.PALETTE) assert.match(css, new RegExp(`^\\s*${name}:`, 'm'));
    assert.doesNotMatch(css, /--fire-smoke/);
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(/);
    // the draw paints only the palette's steps: a cell with no heat is skipped
    assert.match(source, /if \(paletteStep\(heat\[i\], maxHeat\) !== index\) continue;/);
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

test('the grid is the window divided by the cell, the cell growing past the cap; the length is bounded', () => {
    assert.deepEqual(plain(BurnFire.gridSize(1280, 800)), { cell: 8, cols: 160, rows: 100 });
    const big = BurnFire.gridSize(3840, 2160);
    assert.ok(big.cell > 8 && big.cols <= 240 && big.rows <= 135);
    assert.ok(BurnFire.TOTAL_FRAMES * BurnFire.FRAME_MS <= BurnFire.HARD_STOP_MS);
    assert.ok(BurnFire.HARD_STOP_MS <= 1400);
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
