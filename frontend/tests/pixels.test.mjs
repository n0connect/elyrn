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

const SET = ['bell-on', 'bell-off', 'logout', 'members', 'code', 'burn', 'back', 'send', 'attach', 'copy', 'close', 'chevron', 'verify', 'role', 'clear', 'erase'];

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
    const named = new Map([...table.matchAll(/\['(\w+)', UI_TEXT\.(\w+), (?:UI_TEXT\.(\w+)|null)\]/g)]
        .map((m) => [m[1], m.slice(2)]));
    // every button in the page that holds an icon is named there (the bell is alerts.js's)
    const buttons = [...html.matchAll(/<button\b[^>]*\bid="(\w+)"[^>]*>(?:(?!<\/button>)[\s\S])*?data-icon="[^"]+"/g)].map((m) => m[1]);
    assert.ok(buttons.length >= 14);
    for (const id of buttons) {
        if (id === 'alertsBtn') continue;
        assert.ok(named.has(id), `${id} is named in ICON_BUTTONS`);
        for (const key of named.get(id).filter(Boolean)) assert.equal(typeof UI_TEXT[key], 'string', `${id} ${key}`);
    }
    assert.match(ui, /button\.setAttribute\('aria-label', name\);/);
    assert.match(ui, /ICON_BUTTONS\.forEach\(\(\[id, name, caption\]\) => nameIconButton\(document\.getElementById\(id\), name, caption\)\);/);
    // the bell's name and title come from alerts.js render (alerts.test.mjs); the toast's close
    // control is named where it is made
    assert.match(read('../js/notifications.js'), /closeBtn\.setAttribute\('aria-label', NOTIFICATION_CLOSE_ARIA_LABEL\);\n\s*closeBtn\.title = NOTIFICATION_CLOSE_ARIA_LABEL;/);
    // the bell, back, send, attach, copy and close never carry a visible word
    for (const id of ['alertsBtn', 'backToListBtn', 'sendBtn', 'attachBtn', 'fileRemoveBtn', 'copyBtn', 'copyInviteBtn', 'copyRoomBtn', 'copyRoomCodeBtn', 'copyRobotBtn']) {
        const button = html.match(new RegExp(`<button\\b[^>]*\\bid="${id}"[^>]*>([\\s\\S]*?)</button>`))[1];
        assert.equal(button.replace(/<[^>]*>/g, '').trim(), '', id);
    }
});

test('a tile shows its caption by one rule from one attribute, and never has a title too', () => {
    // no tile carries a visible word, at any width
    assert.doesNotMatch(html, /icon-word/);
    assert.doesNotMatch(css, /icon-word/);
    // one rule writes every caption, from data-caption; it shows on hover (never on touch) and focus
    assert.match(ui, /const CAPTION_ATTRIBUTE = 'data-caption';/);
    assert.equal((css.match(/content: attr\(data-caption\);/g) || []).length, 1);
    assert.match(css, /@media \(hover: hover\) \{\n\s*\[data-caption\]:hover::after \{\n\s*visibility: visible;/);
    assert.match(css, /\[data-caption\]:focus-visible::after \{\n\s*visibility: visible;/);
    assert.match(css, /\[data-caption\]:last-child::after \{\n\s*left: auto;\n\s*right: 0;/);
    assert.match(css, /animation: caption-in var\(--caption-steps-ms\) steps\(3, end\) both;/);
    // a caption replaces the title: nameIconButton removes it, and markup never has both
    const fn = ui.slice(ui.indexOf('function nameIconButton'), ui.indexOf('\n}\n', ui.indexOf('function nameIconButton')));
    assert.match(fn, /if \(caption\) \{\n\s*button\.setAttribute\(CAPTION_ATTRIBUTE, caption\);\n\s*button\.removeAttribute\('title'\);\n\s*\} else \{\n\s*button\.title = name;/);
    for (const tag of html.match(/<button\b[^>]*>/g)) {
        assert.ok(!(/data-caption=/.test(tag) && /\stitle=/.test(tag)), tag);
    }
    // the motion goes with reduced motion; the tile is the aura's box
    const reduced = [...css.matchAll(/@media \(prefers-reduced-motion: reduce\) \{([\s\S]*?)\n\}/g)].map((m) => m[1]).join('\n');
    assert.match(reduced, /\.pixel-frame,\n\s*\[data-caption\]::after \{\n\s*animation: none !important;/);
    assert.match(css, /\.icon-tile,\n\.aura-glyph \{[^}]*width: var\(--glyph-size\);[^}]*height: var\(--glyph-size\);[^}]*padding: var\(--tile-pad\);[^}]*border: 1px solid var\(--border\);/);
    assert.match(css, /animation-timing-function: step-end;/);
});

test('a conversation fits the window: dvh with its vh fallback, the list takes the rest', () => {
    const block = css.slice(css.indexOf('body.in-conversation {'));
    assert.match(block, /^body\.in-conversation \{\n\s*height: 100vh;\n\s*height: 100dvh;\n\s*min-height: var\(--conversation-min-height\);/);
    assert.match(block, /body\.in-conversation #chatView > \.message-list \{\n\s*flex: 1 1 0;\n\s*height: auto;\n\s*min-height: var\(--list-min-height\);/);
    assert.match(css, /--conversation-min-height: \d+px;/);
    assert.match(ui, /const CONVERSATION_CLASS = 'in-conversation';/);
    assert.match(ui, /setConversationShown\(activeId === 'appContainer' && isShown\('chatView'\)\);/);
    // no height guessed from the window any more
    assert.doesNotMatch(css, /calc\(100vh - \d+px\)/);
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

test('one frame for value boxes, input rows and the composer: a copy control is a cell of its box', () => {
    assert.match(css, /\.account-number-box,\n\.join-input-group,\n\.composer \{\n\s*display: flex;\n\s*align-items: stretch;\n\s*gap: 0;\n\s*border: 1px solid var\(--border\);/);
    const copies = [...html.matchAll(/<button\b[^>]*\bclass="([^"]*\bcopy-btn\b[^"]*)"[^>]*>/g)];
    assert.equal(copies.length, 5);
    for (const [tag, cls] of copies) assert.equal(cls, 'box-cell copy-btn', tag);
    // each sits last in its value box, so its divider is on its left and its caption anchors right
    assert.equal((html.match(/<div class="account-number-box[^"]*"[^>]*>\s*<code id="\w+"><\/code>\s*<button type="button" id="copy\w*Btn" class="box-cell copy-btn">/g) || []).length, 5);
    // no rounded corners, heavier border or shadow on a value
    for (const file of ['../styles.css', '../account-number-animation.css']) {
        const source = read(file);
        const code = [...source.matchAll(/\.account-number-box code[^{]*\{([^}]*)\}/g)].map((m) => m[1]).join('\n');
        assert.doesNotMatch(code, /border-radius|border: 2px|box-shadow/, file);
    }
});

test('an aura glyph is data: no frame or inversion rule can reach it', () => {
    // the glyph's drawing has no frame class; every frame rule needs .icon > .pixel-frame
    assert.match(source, /return draw\(svg, \[rowsOf\(grid\)\], null\);/);
    assert.match(source, /if \(frameClass\) group\.setAttribute\('class', frameClass\);/);
    const bare = css.replace(/\/\*[\s\S]*?\*\//g, '');
    for (const [, selector] of bare.matchAll(/([^{}]*\.pixel-frame[^{}]*)\{/g)) {
        for (const part of selector.split(',').filter(p => p.includes('pixel-frame'))) assert.match(part.trim(), /\.icon > \.pixel-frame/, part);
    }
    // no inversion rule names a glyph
    for (const [, selector, body] of bare.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
        if (/background: var\(--fg\)/.test(body)) assert.doesNotMatch(selector, /aura-glyph/, selector.trim());
    }
});

test('a caption never covers a header rule: both header rows keep the caption\'s reach between their tiles and the rule', () => {
    assert.match(css, /--caption-reach: calc\(var\(--caption-gap\) \+ var\(--caption-size\) \* var\(--caption-line\) \+ 1px\);/);
    assert.match(css, /--header-pad: max\(var\(--row-gap\), calc\(var\(--caption-reach\) - \(var\(--touch-min\) - var\(--tile-box\)\) \/ 2\)\);/);
    const caption = css.match(/\[data-caption\]::after \{[^}]*\}/)[0];
    assert.match(caption, /top: calc\(100% \+ var\(--caption-gap\)\)/);
    assert.match(caption, /font-size: var\(--caption-size\)/);
    assert.match(caption, /line-height: var\(--caption-line\)/);
    for (const selector of ['header', '.chat-header']) {
        const rule = css.match(new RegExp(`^${selector.replace('.', '\\.')} \\{[^}]*\\}`, 'm'))[0];
        assert.match(rule, /padding-bottom: var\(--header-pad\)/, selector);
        assert.match(rule, /min-height: calc\(var\(--touch-min\) \+ var\(--header-pad\)\)/, selector);
        assert.match(rule, /border-bottom: 1px solid var\(--border\)/, selector);
    }
});

test('erase: the aura\'s 5x5 block solid at rest, its pixels (two icon pixels each) falling away in the two hover frames', () => {
    const [rest, one, two] = Pixels.ICONS.erase;
    rest.forEach(row => assert.equal(row, '#'.repeat(Pixels.ICON_GRID)));
    const count = (rows) => rows.join('').split(Pixels.ON).length - 1;
    assert.ok(count(rest) > count(one) && count(one) > count(two));
    // drawn in aura pixels: every 2x2 block is all on or all off
    for (const rows of [one, two]) {
        for (let y = 0; y < 10; y += 2) for (let x = 0; x < 10; x += 2) {
            const block = rows[y][x] + rows[y][x + 1] + rows[y + 1][x] + rows[y + 1][x + 1];
            assert.ok(block === '####' || block === '....', `${y},${x}`);
        }
    }
});
