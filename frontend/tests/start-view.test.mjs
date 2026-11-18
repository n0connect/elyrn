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

// Reading IndexedDB needs a browser (the drill); what decides the path is pinned from the sources
test('a stored identity that cannot be read back opens the main menu with W_IDENTITY_UNREADABLE, never silently', () => {
    const app = read('../js/app.js');
    const keystore = read('../js/keystore.js');
    const resume = app.slice(app.indexOf('async function resumeSession'), app.indexOf('\n}\n', app.indexOf('async function resumeSession')));
    assert.match(resume, /if \(!identity\) \{\n\s*showMainMenu\(\);\n\s*if \(stored\.unreadable\) Errors\.report\(Errors\.CODES\.W_IDENTITY_UNREADABLE\);\n\s*return;/);
    // The record is counted in a transaction of its own, before and apart from the get, so a get
    // that fails (a record the released build wrote, in WebKit) still leaves it present
    const readId = keystore.slice(keystore.indexOf('async function readIdentity'), keystore.indexOf('async function identityFrom'));
    assert.match(readId, /const present = \(await run\(STORE, 'readonly', tx => tx\.objectStore\(STORE\)\.count\(RECORD\)\)\) > 0;/);
    assert.match(readId, /try \{\n\s*record = await run\(STORE, 'readonly', tx => tx\.objectStore\(STORE\)\.get\(RECORD\)\);\n\s*\} catch/);
    assert.match(readId, /return \{ present: true, identity: await identityFrom\(record\) \};/);
    const load = keystore.slice(keystore.indexOf('    async function load()'));
    assert.match(load.slice(0, load.indexOf('\n    }\n')), /return \{ identity: read\.identity, unreadable: read\.present && !read\.identity \};/);
});
