// The page's first paint, read from the real files: before any script decides, the only view
// shown is the start view (the brand line, nothing interactive), so a device resuming a stored
// identity never shows the main menu first; without scripting the stylesheet shows the main menu.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load } from './fuzz-helpers.mjs';

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

// ---------- a stored identity this browser cannot read back (keystore.js load, app.js) ----------
// IndexedDB itself needs a browser (the drill): the decision is the real Keystore.startVerdict,
// loaded as the browser loads it, and what load does with it is pinned from the source.

const keystore = read('../js/keystore.js');
const app = read('../js/app.js');
const Keystore = load({}, ['../js/keystore.js']).get('Keystore');
const READABLE = Object.freeze({ publicKey: 'A'.repeat(43) });
const body = (source, head) => {
    const start = source.indexOf(head);
    return source.slice(start, source.indexOf('\n    }\n', start));
};
const loadBody = body(keystore, '    async function load()');
const forgetBody = body(keystore, '    async function forgetUnreadableIdentity()');

test('identity present but unreadable: warned once, only the identity record removed, the next start silent', () => {
    // First start: a record is counted and gives no identity
    const first = Keystore.startVerdict({ present: true, identity: null });
    assert.deepEqual({ ...first }, { identity: null, unreadable: true });
    // load removes the record exactly then, and app.js says so on the main menu
    assert.match(loadBody, /const verdict = startVerdict\(read\);\n\s*if \(verdict\.unreadable\) await forgetUnreadableIdentity\(\);\n\s*return verdict;/);
    const resume = app.slice(app.indexOf('async function resumeSession'), app.indexOf('\n}\n', app.indexOf('async function resumeSession')));
    assert.match(resume, /if \(!identity\) \{\n\s*showMainMenu\(\);\n\s*if \(stored\.unreadable\) Errors\.report\(Errors\.CODES\.W_IDENTITY_UNREADABLE\);\n\s*return;/);
    // The removal deletes the identity record alone: counter records, verified marks, owner,
    // device key and alerts stay; nothing goes to the server
    assert.match(forgetBody, /await transact\('readwrite', store => store\.delete\(RECORD\)\);/);
    assert.doesNotMatch(forgetBody, /ALERTS|OWNER|COUNTERS_STORE|VERIFIED_STORE|clear\(|wipe|apiCall|deleteDatabase/);
    // A removal that fails is logged under its own code, and nothing else changes
    assert.match(forgetBody, /catch \(e\) \{\n(?:\s*\/\/[^\n]*\n)*\s*Log\.warn\(Errors\.INTERNAL\.W_IDENTITY_NOT_FORGOTTEN, e\);\n\s*\}/);
    // Second start: the record is gone, so no warning
    assert.deepEqual({ ...Keystore.startVerdict({ present: false, identity: null }) }, { identity: null, unreadable: false });
});

test('a store that does not answer removes nothing and keeps its own message', () => {
    // The store's own failures (open, count, a tab that retired it) throw out of readIdentity,
    // and load answers them before any verdict: unavailable, never unreadable
    assert.match(loadBody, /try \{\n\s*read = await readIdentity\(\);\n\s*\} catch \(e\) \{\n\s*unavailable\(Errors\.INTERNAL\.W_KEYSTORE_UNAVAILABLE, e\);\n\s*return \{ identity: null, unreadable: false \};\n\s*\}/);
    const readBody = body(keystore, '    async function readIdentity()');
    assert.match(readBody, /const db = await open\(\);/);
    assert.match(readBody, /const count = await inTransaction\(db, STORE, 'readonly', tx => tx\.objectStore\(STORE\)\.count\(RECORD\)\);/);
    assert.match(readBody, /\} catch \(e\) \{\n\s*if \(retired\) throw e;/);
    assert.ok(loadBody.indexOf('unavailable(') < loadBody.indexOf('forgetUnreadableIdentity'));
    // Nothing stored is never unreadable
    assert.equal(Keystore.startVerdict({ present: false, identity: null }).unreadable, false);
});

test('a readable identity is never removed and never warned about', () => {
    const verdict = Keystore.startVerdict({ present: true, identity: READABLE });
    assert.equal(verdict.identity, READABLE);
    assert.equal(verdict.unreadable, false);
    // A present flag that is not exactly true counts as nothing stored, never as unreadable
    assert.equal(Keystore.startVerdict({ present: 1, identity: null }).unreadable, false);
});
