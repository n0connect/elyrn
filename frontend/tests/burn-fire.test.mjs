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
const plans = () => SEEDS.flatMap(seed => GRIDS.map(({ cols, rows }) => ({ seed, cols, rows, layers: BurnFire.tongues(cols, seed) })));
const cells = (plan, frame) => {
    const out = [];
    for (let row = 0; row < plan.rows; row++) for (let col = 0; col < plan.cols; col++) out.push(BurnFire.layerAt(plan, frame, col, row));
    return out;
};
const painted = (plan, frame) => cells(plan, frame).filter(layer => layer !== BurnFire.NONE).length;
const flame = (plan, frame) => cells(plan, frame).filter(layer => layer >= BurnFire.RED).length;

test('the tongues: pure, three layers of 5 to 7 big tongues, the red about a third of the window wide at its base', () => {
    for (const plan of plans()) {
        assert.deepEqual(plain(BurnFire.tongues(plan.cols, plan.seed)), plain(plan.layers));
        assert.equal(plan.layers.length, 3);
        for (const layer of plan.layers) assert.ok(layer.length >= 5 && layer.length <= 7);
        for (const t of plan.layers[0]) assert.ok(t.half * 2 >= plan.cols / 3, `${t.half} of ${plan.cols}`);
        // the front layers are narrower and shorter: flames inside flames
        assert.ok(plan.layers[2][0].half < plan.layers[1][0].half && plan.layers[1][0].half < plan.layers[0][0].half);
        for (const t of plan.layers[2]) assert.ok(t.half * 2 >= plan.cols / 8, 'still big');
    }
});

test('the frame plan: fade 3, rise 5, cover 2, leave 4, about 1.8 s on the shared clock', () => {
    assert.equal(BurnFire.RISE_START, 3);
    assert.equal(BurnFire.COVER_START, 8);
    assert.equal(BurnFire.EXIT_START, 10);
    assert.equal(BurnFire.TOTAL_FRAMES, 14);
    assert.deepEqual([0, 1, 2, 3, 7, 8].map(BurnFire.fadeLevel), [1, 2, 3, 3, 3, 0]);
    assert.equal(BurnFire.hardStopMs(120), 1800);
});

test('the fade is an ordered dither: a quarter, a half, then all black, nothing else painted', () => {
    for (const plan of plans()) {
        const total = plan.cols * plan.rows;
        [0.25, 0.5, 1].forEach((share, frame) => {
            const layers = cells(plan, frame);
            assert.ok(layers.every(layer => layer === BurnFire.NONE || layer === BurnFire.BLACK));
            assert.ok(Math.abs(layers.filter(layer => layer === BurnFire.BLACK).length / total - share) < 0.03, `frame ${frame}`);
        });
    }
});

test('covered: every cell is flame at the cover frames, nothing at the last; the cover never grows back', () => {
    for (const plan of plans()) {
        const total = plan.cols * plan.rows;
        for (let frame = BurnFire.COVER_START; frame < BurnFire.EXIT_START; frame++) assert.equal(flame(plan, frame), total, `seed ${plan.seed} frame ${frame}`);
        assert.equal(painted(plan, BurnFire.TOTAL_FRAMES - 1), 0);
        // the flames only grow while rising, only shrink while leaving
        for (let frame = BurnFire.RISE_START + 1; frame <= BurnFire.COVER_START; frame++) assert.ok(flame(plan, frame) >= flame(plan, frame - 1), `rise ${frame}`);
        for (let frame = BurnFire.EXIT_START; frame < BurnFire.TOTAL_FRAMES; frame++) assert.ok(painted(plan, frame) <= painted(plan, frame - 1), `exit ${frame}`);
        // the leaving uncovers from below: the top row burns longer than the bottom row
        const exit = BurnFire.EXIT_START + 1;
        const row = (r) => Array.from({ length: plan.cols }, (_, col) => BurnFire.layerAt(plan, exit, col, r) !== BurnFire.NONE).filter(Boolean).length;
        assert.ok(row(0) > row(plan.rows - 1));
    }
});

test('mid-rise: big tongues over black, red tallest, orange in the middle, yellow the short core', () => {
    const mid = BurnFire.RISE_START + 2;
    for (const plan of plans()) {
        let ordered = 0;
        for (let col = 0; col < plan.cols; col++) {
            const top = (layer) => {
                for (let row = 0; row < plan.rows; row++) {
                    const at = BurnFire.layerAt(plan, mid, col, row);
                    if (at >= layer) return row;
                }
                return plan.rows;
            };
            if (top(BurnFire.RED) <= top(BurnFire.ORANGE) && top(BurnFire.ORANGE) <= top(BurnFire.YELLOW)) ordered++;
        }
        assert.ok(ordered > plan.cols * 0.8, `seed ${plan.seed}: ${ordered} of ${plan.cols}`);
        // black still shows: the flames have not covered the window yet
        assert.ok(cells(plan, mid).includes(BurnFire.BLACK));
    }
});

// Shapes, not speckle: outside the checker-dithered orange, fewer than SPECKLE_MAX of the painted
// cells differ from all four neighbours
const SPECKLE_MAX = 0.03;

test('shapes, not speckle: few painted cells stand alone in their layer', () => {
    for (const plan of plans()) {
        for (let frame = BurnFire.RISE_START; frame < BurnFire.TOTAL_FRAMES; frame++) {
            const layers = cells(plan, frame);
            const at = (col, row) => (col < 0 || row < 0 || col >= plan.cols || row >= plan.rows ? -1 : layers[row * plan.cols + col]);
            let count = 0;
            let alone = 0;
            for (let row = 0; row < plan.rows; row++) {
                for (let col = 0; col < plan.cols; col++) {
                    const own = at(col, row);
                    if (own === BurnFire.NONE || own === BurnFire.ORANGE) continue;
                    count++;
                    if (![[1, 0], [-1, 0], [0, 1], [0, -1]].some(([dx, dy]) => at(col + dx, row + dy) === own)) alone++;
                }
            }
            assert.ok(count === 0 || alone / count < SPECKLE_MAX, `seed ${plan.seed} frame ${frame}: ${alone} of ${count}`);
        }
    }
});

test('the paint: black, red, yellow and the orange checker of the two; nothing for no layer', () => {
    assert.deepEqual(plain(BurnFire.PALETTE), ['--fire-fringe', '--fire-flame', '--fire-glow']);
    assert.equal(BurnFire.paint(BurnFire.NONE, 0, 0), BurnFire.NOT_PAINTED);
    assert.equal(BurnFire.paint(BurnFire.BLACK, 0, 0), 0);
    assert.equal(BurnFire.paint(BurnFire.RED, 0, 0), 1);
    assert.equal(BurnFire.paint(BurnFire.YELLOW, 0, 0), 2);
    assert.deepEqual([[0, 0], [1, 0], [0, 1], [1, 1]].map(([c, r]) => BurnFire.paint(BurnFire.ORANGE, c, r)), [1, 2, 2, 1]);
    assert.doesNotMatch(source, /#[0-9a-fA-F]{3,6}\b|rgba?\(/);
    for (const name of BurnFire.PALETTE) assert.match(css, new RegExp(`^\\s*${name}:`, 'm'));
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

test('the cover callback runs exactly once: at the cover frame, or at once without the fire, or on any early end', async () => {
    assert.equal(BurnFire.coversAt(BurnFire.COVER_START), true);
    assert.equal(Array.from({ length: BurnFire.TOTAL_FRAMES }, (_, f) => BurnFire.coversAt(f)).filter(Boolean).length, 1);
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
    assert.match(body, /if \(coversAt\(frame\)\) cover\(\);/);
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
