// frontend/js/pixels.js, the one pixel renderer, and the icon controls that use it, read from the
// real files. How a hover looks and moves is checked in a real browser (the icon sheet and the
// live screenshots, docs/development/testing-and-contributing.md); what the sources fix is here.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { load } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const css = read('../styles.css');
const ui = read('../js/ui.js');
const source = read('../js/pixels.js');
const Pixels = load({}, ['../js/pixels.js']).get('Pixels');
const UI_TEXT = vm.runInNewContext('(' + ui.match(/const UI_TEXT = (Object\.freeze\(\{[\s\S]*?\n\}\));/)[1] + ')');

const SET = ['bell-on', 'bell-off', 'logout', 'members', 'code', 'burn', 'back', 'send', 'attach', 'copy', 'close', 'chevron', 'verify'];

test('the table: every icon of the set, three frames, each 10x10 of only the two symbols', () => {
    assert.deepEqual(Object.keys(Pixels.ICONS).sort(), [...SET].sort());
    assert.equal(Pixels.ICON_GRID, 10);
    assert.equal(Pixels.FRAMES, 3);
    for (const [name, frames] of Object.entries(Pixels.ICONS)) {
        assert.equal(frames.length, Pixels.FRAMES, name);
        for (const rows of frames) {
            assert.equal(rows.length, Pixels.ICON_GRID, name);
            for (const row of rows) assert.match(row, /^[#.]{10}$/, name);
        }
        assert.ok(frames[0].some(row => row.includes(Pixels.ON)), `${name} draws something`);
    }
    // the table's own lines hold exactly the frames, nothing else
    const lines = source.match(/^ {12}'[^']*',?$/gm);
    assert.equal(lines.length, SET.length * Pixels.ICON_GRID);
    for (const line of lines) assert.match(line, /^ {12}'[#.]{10}  [#.]{10}  [#.]{10}',?$/);
});

test('bell on and off differ in shape, not only in colour', () => {
    const on = Pixels.ICONS['bell-on'][0].join('\n');
    const off = Pixels.ICONS['bell-off'][0].join('\n');
    assert.notEqual(on, off);
    // off is struck: the full staircase diagonal is drawn
    Pixels.ICONS['bell-off'][0].forEach((row, y) => assert.equal(row[y], Pixels.ON, `diagonal at ${y}`));
    // on is solid: its body has no hole
    assert.match(Pixels.ICONS['bell-on'][0][4], /######/);
    assert.doesNotMatch(Pixels.ICONS['bell-off'][0][4], /######/);
});

test('one renderer: svg rects in currentColor, no markup string, the aura drawn by it too', () => {
    assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.style\b|getContext|<svg/);
    assert.match(source, /document\.createElementNS\(SVG_NS, tag\)/);
    assert.match(source, /svg\.setAttribute\('shape-rendering', 'crispEdges'\);/);
    assert.match(css, /\.icon,\n\.aura-glyph \{\n\s*fill: currentColor;/);
    // no canvas left anywhere in the page for pixels
    assert.doesNotMatch(html, /<canvas/);
    assert.doesNotMatch(ui, /getContext|createElement\('canvas'\)/);
    assert.match(ui, /function drawGlyph\(svg, grid\) \{\n\s*Pixels\.drawGlyph\(svg, grid\);/);
    assert.match(ui, /return Pixels\.glyph\(grid, AURA_GLYPH_CLASS\);/);
    // loaded before every module that draws
    const order = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
    assert.ok(order.indexOf('js/pixels.js') < order.indexOf('js/notifications.js'));
    assert.ok(order.indexOf('js/pixels.js') < order.indexOf('js/ui.js'));
});

test('every icon button has an accessible name and a title from UI_TEXT', () => {
    const table = ui.match(/const ICON_BUTTONS = Object\.freeze\(\[([\s\S]*?)\]\);/)[1];
    const named = new Map([...table.matchAll(/\['(\w+)', UI_TEXT\.(\w+), UI_TEXT\.(\w+), (?:UI_TEXT\.(\w+)|null)\]/g)]
        .map((m) => [m[1], m.slice(2)]));
    // every button in the page that holds an icon is named there (the bell is alerts.js's)
    const buttons = [...html.matchAll(/<button\b[^>]*\bid="(\w+)"[^>]*>(?:(?!<\/button>)[\s\S])*?data-icon="[^"]+"/g)].map((m) => m[1]);
    assert.ok(buttons.length >= 14);
    for (const id of buttons) {
        if (id === 'alertsBtn') continue;
        assert.ok(named.has(id), `${id} is named in ICON_BUTTONS`);
        for (const key of named.get(id).filter(Boolean)) assert.equal(typeof UI_TEXT[key], 'string', `${id} ${key}`);
    }
    assert.match(ui, /button\.setAttribute\('aria-label', name\);\n\s*button\.title = title;/);
    assert.match(ui, /ICON_BUTTONS\.forEach\(\(\[id, name, title, word\]\) => nameIconButton\(document\.getElementById\(id\), name, title, word\)\);/);
    // the bell's name and title come from alerts.js render (alerts.test.mjs); the toast's close
    // control is named where it is made
    assert.match(read('../js/notifications.js'), /closeBtn\.setAttribute\('aria-label', NOTIFICATION_CLOSE_ARIA_LABEL\);\n\s*closeBtn\.title = NOTIFICATION_CLOSE_ARIA_LABEL;/);
    // the bell, back, send, attach, copy and close never carry a visible word
    for (const id of ['alertsBtn', 'backToListBtn', 'sendBtn', 'attachBtn', 'fileRemoveBtn', 'copyBtn', 'copyInviteBtn', 'copyRoomBtn', 'copyRoomCodeBtn', 'copyRobotBtn']) {
        const button = html.match(new RegExp(`<button\\b[^>]*\\bid="${id}"[^>]*>([\\s\\S]*?)</button>`))[1];
        assert.doesNotMatch(button, /icon-word/, id);
        assert.equal(button.replace(/<[^>]*>/g, '').trim(), '', id);
    }
});

test('the word hides on a phone, the motion goes with reduced motion, and the tile is the aura box', () => {
    const phone = [...css.matchAll(/@media \(max-width: 480px\) \{([\s\S]*?)\n\}/g)].map((m) => m[1]).join('\n');
    assert.match(phone, /\.icon-word \{\n\s*display: none;\n\s*\}/);
    const reduced = [...css.matchAll(/@media \(prefers-reduced-motion: reduce\) \{([\s\S]*?)\n\}/g)].map((m) => m[1]).join('\n');
    assert.match(reduced, /\.pixel-frame \{\n\s*animation: none !important;/);
    assert.match(css, /\.icon-tile,\n\.aura-glyph \{[^}]*width: var\(--glyph-size\);[^}]*height: var\(--glyph-size\);[^}]*padding: var\(--tile-pad\);[^}]*border: 1px solid var\(--border\);/);
    // the frames are stepped, never eased
    assert.match(css, /animation-timing-function: step-end;/);
    assert.match(css, /--icon-steps-ms: \d+ms;/);
});

test('no control uses a shadow, and none lifts or moves on hover', () => {
    const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)];
    for (const [, selector, body] of rules) {
        const sel = selector.trim();
        if (/(button|btn|composer|menu-opt|copy)/.test(sel)) {
            assert.doesNotMatch(body, /box-shadow:\s*(?!\s|none)/, sel);
        }
        if (/:hover/.test(sel)) assert.doesNotMatch(body, /transform:\s*(?!\s|none)|translate:/, sel);
    }
});
