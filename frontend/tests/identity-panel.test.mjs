// The app header and the identity panel, read from the real files: deleting the identity is not
// in the header; the identity badge opens a panel (the pair-panel pattern) whose last control
// opens the unchanged delete panel. Pressing, Escape and focus need a browser and are driven by
// hand (docs/development/testing-and-contributing.md); what the sources fix is pinned here.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const app = read('../js/app.js');
const ui = read('../js/ui.js');
const css = read('../styles.css');

const header = html.match(/<header>([\s\S]*?)<\/header>/)[1];
const panelOf = (id) => html.match(new RegExp(`<div id="${id}" class="pair-panel"[^>]*>([\\s\\S]*?)\\n {16}</div>`))[1];
const fnBody = (source, head) => {
    const start = source.indexOf(head);
    assert.ok(start >= 0, head);
    return source.slice(start, source.indexOf('\n}\n', start));
};

test('the header holds no delete control: the badge, the bell and logout only', () => {
    assert.doesNotMatch(header, /delete/i);
    assert.doesNotMatch(header, /deleteIdentityBtn|burn-yes|danger/);
    const ids = [...header.matchAll(/<button[^>]*\bid="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(ids, ['meBadge', 'alertsBtn', 'logoutBtn']);
    // one control with that id in the whole page, inside the identity panel
    assert.equal((html.match(/id="deleteIdentityBtn"/g) || []).length, 1);
    assert.match(panelOf('identityPanel'), /<button type="button" id="deleteIdentityBtn" class="text-btn identity-delete">delete identity…<\/button>/);
});

test('the identity badge is a real button that names and controls its panel', () => {
    const badge = header.match(/<button[^>]*id="meBadge"[^>]*>/)[0];
    assert.match(badge, /type="button"/);
    assert.match(badge, /aria-expanded="false"/);
    assert.match(badge, /aria-controls="identityPanel"/);
    assert.match(header, /<svg class="aura-glyph" id="meGlyph" aria-hidden="true" focusable="false"><\/svg>/);
    // its name is set with the identity: on a phone the visible name is hidden
    const render = fnBody(ui, 'function renderMe(aura)');
    assert.match(render, /badge\.title = UI_TEXT\.ME_TITLE\(aura\.name, aura\.code\);\n\s*badge\.setAttribute\('aria-label', badge\.title\);/);
    // the panel shows glyph, name and code the one way every aura is shown
    assert.match(render, /clearChildren\(line\);\n\s*appendAura\(line, aura\);/);
    assert.match(css, /\.me-badge:focus-visible,\n\.box-cell:focus-visible \{\n\s*outline: var\(--focus-ring\);/);
    // the badge's glyph is data: it never inverts or plays frames
    assert.doesNotMatch(css, /aura-glyph[^{,]*,?\s*\{[^}]*background: var\(--fg\)/);
});

test('the identity panel is a pair panel: what it is, then delete set apart by a rule', () => {
    assert.match(html, /<div id="identityPanel" class="pair-panel" data-hidden>/);
    const panel = panelOf('identityPanel');
    assert.match(panel, /<p class="account-number-label">your identity<\/p>\n\s*<p id="identityAura" class="identity-aura"><\/p>\n\s*<p class="pair-hint">your aura — derived from your public key<\/p>\n\s*<div class="identity-end">/);
    assert.match(css, /\.identity-end \{[^}]*border-top: 1px solid var\(--border\);/);
    // one list of pair panels, so opening one closes the others, the identity panel included
    assert.match(ui, /const PAIR_PANELS = \['identityPanel', 'invitePanel', 'roomPanel', 'joinPanel', 'deletePanel'\];/);
});

test('one place opens and closes a pair panel, and keeps aria-expanded true to it', () => {
    const set = fnBody(ui, 'function setPairPanel(id, shown)');
    assert.match(set, /document\.getElementById\(id\)\.style\.display = shown \? 'block' : 'none';/);
    assert.match(set, /querySelectorAll\(`\[aria-controls="\$\{id\}"\]`\)/);
    assert.match(set, /setAttribute\('aria-expanded', shown \? 'true' : 'false'\)/);
    assert.match(fnBody(ui, 'function togglePairPanel(panelId)'), /PAIR_PANELS\.forEach\(id => setPairPanel\(id, opening && id === panelId\)\);/);
    assert.match(fnBody(ui, 'function showPairPanel(panelId)'), /PAIR_PANELS\.forEach\(id => setPairPanel\(id, id === panelId\)\);/);
    // nothing else writes a pair panel's display in ui.js's panel helpers
    assert.equal((ui.match(/aria-expanded/g) || []).length, 1);
});

test('wiring: badge toggles (home first from a conversation), Escape closes and returns focus, delete opens the unchanged panel', () => {
    const toggle = fnBody(app, 'function toggleIdentityPanel()');
    assert.match(toggle, /if \(isChatShown\(\)\) \{\n\s*Chat\.backToList\(\);\n\s*showPairPanel\(IDENTITY_PANEL\);\n\s*return;\n\s*\}\n\s*togglePairPanel\(IDENTITY_PANEL\);/);
    const close = fnBody(app, 'function closeIdentityPanel()');
    assert.match(close, /togglePairPanel\(null\);\n\s*document\.getElementById\(IDENTITY_BADGE\)\.focus\(\);/);
    assert.match(app, /const IDENTITY_PANEL = 'identityPanel';\nconst IDENTITY_BADGE = 'meBadge';/);
    const account = fnBody(app, 'function setupAccountListeners()');
    assert.match(account, /getElementById\(IDENTITY_BADGE\)\.addEventListener\('click', toggleIdentityPanel\);/);
    assert.match(account, /getElementById\('deleteIdentityBtn'\)\.addEventListener\('click', \(\) => \{\n\s*showPairPanel\('deletePanel'\);\n\s*document\.getElementById\('deleteAccountInput'\)\.focus\(\);/);
    assert.match(account, /getElementById\('deleteConfirmBtn'\)\.addEventListener\('click', deleteIdentity\);/);
    // Escape: a conversation is left first; on the home view the identity panel closes
    assert.match(app, /\} else if \(isChatShown\(\)\) \{\n\s*Chat\.backToList\(\);\n\s*\} else if \(isShown\(IDENTITY_PANEL\)\) \{\n\s*closeIdentityPanel\(\);\n\s*\}/);
    // the delete panel and its confirmation are as they were
    assert.match(panelOf('deletePanel'), /<input type="password" id="deleteAccountInput"[^>]*>\n\s*<button id="deleteConfirmBtn" class="menu-opt burn-yes">delete<\/button>/);
});
