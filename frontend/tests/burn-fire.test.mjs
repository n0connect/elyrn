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

function run(grid, source, steps, random) {
    for (let i = 0; i < steps; i++) grid = BurnFire.step(grid, source, random);
    return grid;
}

test('a step keeps the grid size, never rises above its source and never goes below zero', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        let grid = BurnFire.createGrid(COLS, ROWS);
        for (let i = 0; i < ROWS * 3; i++) {
            grid = BurnFire.step(grid, heat, random);
            assert.equal(grid.cols, COLS);
            assert.equal(grid.rows, ROWS);
            assert.equal(grid.heat.length, COLS * ROWS);
            for (const value of grid.heat) {
                assert.ok(value >= 0 && value <= heat, `seed ${seed} step ${i}: ${value}`);
            }
        }
        // the flames reach the top row: the window is covered
        const top = Array.from(grid.heat.slice(0, COLS));
        assert.ok(top.filter(value => value > 0).length > COLS * 0.9, `seed ${seed}: top ${top}`);
    }
});

test('with the source off, every column dies out within the grid height', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        const lit = run(BurnFire.createGrid(COLS, ROWS), heat, ROWS * 2, random);
        assert.ok(lit.heat.some(value => value > 0));
        const out = run(lit, 0, ROWS, random);
        assert.ok(out.heat.every(value => value === 0), `seed ${seed}`);
    }
});

test('the whole play: sources never above the source heat, the window covered when the rise ends, nothing left at the end', () => {
    const heat = BurnFire.sourceHeat(ROWS);
    for (const seed of SEEDS) {
        const random = rng(seed).next;
        let grid = BurnFire.createGrid(COLS, ROWS);
        for (let frame = 0; frame < BurnFire.TOTAL_FRAMES; frame++) {
            const sources = BurnFire.frameSources(frame, ROWS, heat);
            assert.ok(sources.length > 0 && sources.every(value => value >= 0 && value <= heat));
            for (const value of sources) grid = BurnFire.step(grid, value, random);
            if (frame === BurnFire.RISE_FRAMES - 1) {
                const lit = grid.heat.filter(value => value > 0).length;
                assert.ok(lit > COLS * ROWS * 0.9, `seed ${seed}: ${lit} lit at cover`);
            }
        }
        assert.ok(grid.heat.every(value => value === 0), `seed ${seed}: embers left`);
    }
});

test('the palette: a cold cell is not drawn, every other heat maps to one of exactly four steps, cooler never above hotter', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-smoke', '--fire-flame', '--fire-glow', '--fire-core']);
    const max = BurnFire.sourceHeat(ROWS);
    assert.equal(BurnFire.paletteStep(0, max), -1);
    const seen = new Set();
    let last = 0;
    for (let value = 1; value <= max; value++) {
        const index = BurnFire.paletteStep(value, max);
        assert.ok(Number.isInteger(index) && index >= 0 && index < 4, `${value}: ${index}`);
        assert.ok(index >= last, `${value} steps down`);
        last = index;
        seen.add(index);
    }
    assert.equal(seen.size, 4);
    // the four steps are custom properties of the stylesheet, not colours of the module
    for (const name of BurnFire.PALETTE) assert.match(css, new RegExp(`^\\s*${name}:`, 'm'));
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(/);
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
