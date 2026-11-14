// The page's first paint, read from the real files: before any script decides, the only view
// shown is the start view (the brand line, nothing interactive), so a device resuming a stored
// identity never shows the main menu first; without scripting the stylesheet shows the main menu.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const ui = read('../js/ui.js');
const css = read('../styles.css');

// ui.js's view list, START_VIEW_ID resolved: every screen setView switches between
function viewIds() {
    const startId = ui.match(/const START_VIEW_ID = '([^']+)';/)[1];
    const list = ui.match(/const VIEW_IDS = \[([^\]]*)\]/)[1];
    return list.split(',').map(entry => entry.trim()).map(entry =>
        entry === 'START_VIEW_ID' ? startId : entry.replace(/^'|'$/g, ''));
}

// The opening tag of the element with this id in index.html
function openingTag(id) {
    const tags = html.match(new RegExp(`<[a-z]+\\b[^>]*\\bid="${id}"[^>]*>`, 'g'));
    assert.equal(tags && tags.length, 1, `exactly one element #${id}`);
    return tags[0];
}

test('start view: the one view not hidden by markup, listed first in VIEW_IDS', () => {
    const ids = viewIds();
    assert.equal(ids[0], 'startView');
    assert.ok(ids.includes('mainMenu'));
    const shown = ids.filter(id => !/\sdata-hidden\b/.test(openingTag(id)));
    assert.deepEqual(shown, ['startView']);
});

test('start view: the brand line only, nothing interactive', () => {
    const body = html.match(/<div class="start-view" id="startView">([\s\S]*?)<\/div>/)[1];
    assert.match(body, /<h1 class="brand-title">elyrn\.<\/h1>/);
    assert.doesNotMatch(body, /<(button|input|textarea|select|a)\b/);
    assert.doesNotMatch(body, /\bclickable\b|\btabindex\b/);
});

test('start view: without scripting the stylesheet hides it and shows the main menu', () => {
    const block = css.match(/@media \(scripting: none\) \{([\s\S]*?)\n\}/)[1];
    assert.match(block, /#startView \{\s*display: none;\s*\}/);
    assert.match(block, /#mainMenu \{\s*display: block;\s*\}/);
});
