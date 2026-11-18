// The unread mark, read from the real files: a dot on an unread row (and on the back tile while
// another conversation is unread), from the state the list already has; the tab title, the
// favicon and the notifications never carry unread information.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const ui = read('../js/ui.js');
const chat = read('../js/chat.js');
const css = read('../styles.css');
const html = read('../index.html');

test('an unread row gets the dot, named unread from UI_TEXT; a read row gets neither', () => {
    assert.match(ui, /UNREAD: 'unread',/);
    assert.match(ui, /row\.className = 'conversation-item' \+ \(item\.unread \? ' unread' : ''\);/);
    // the dot is appended only on the unread branch, just before the chevron's marker
    assert.match(ui, /if \(item\.unread\) row\.appendChild\(unreadDot\(\)\);\n\s*row\.appendChild\(marker\);/);
    assert.equal((ui.match(/unreadDot\(/g) || []).length, 3, 'defined once, used on a row and on the back tile');
    const dot = ui.match(/function unreadDot\(inControl = false\) \{[\s\S]*?\n\}/)[0];
    assert.match(dot, /dot\.setAttribute\('aria-label', UI_TEXT\.UNREAD\);/);
    assert.match(dot, /dot\.setAttribute\('role', 'img'\);/);
    // the word is nowhere else: a read row says nothing about it
    assert.equal((ui.match(/UI_TEXT\.UNREAD\b/g) || []).length, 1);
    assert.doesNotMatch(ui, /UNREAD_MARK/);
});

test('the dot is two aura pixels square from the icon pixel property, no frame, no animation', () => {
    const rule = css.match(/\.unread-dot \{[^}]*\}/)[0];
    assert.match(rule, /width: calc\(var\(--icon-px\) \* 4\);/);
    assert.match(rule, /height: calc\(var\(--icon-px\) \* 4\);/);
    assert.match(rule, /background: var\(--fg\);/);
    assert.doesNotMatch(rule, /border|radius|animation|transition/);
    assert.match(css, /--icon-px: 2px;/);
});

test('the back tile carries the dot while another conversation is unread, and says so', () => {
    assert.match(chat, /setBackUnread\(items\.some\(item => item\.unread && item\.id !== activeId\)\);/);
    const back = ui.match(/function setBackUnread\(unread\) \{[\s\S]*?\n\}/)[0];
    assert.match(back, /back\.setAttribute\('aria-label', unread \? UI_TEXT\.BACK_UNREAD : UI_TEXT\.BACK\);/);
    assert.match(css, /\.icon-btn > \.unread-dot \{[^}]*position: absolute;/);
});

test('nothing writes unread information into the title, the favicon or a notification', () => {
    const dir = new URL('../js/', import.meta.url);
    for (const file of readdirSync(dir).filter(name => name.endsWith('.js'))) {
        const source = readFileSync(new URL(file, dir), 'utf8');
        assert.doesNotMatch(source, /document\.title\s*=/, file);
        assert.doesNotMatch(source, /rel=["']?icon|favicon/i, file);
        if (/new (window\.)?Notification\(/.test(source)) assert.doesNotMatch(source, /unread/i, file);
    }
    // the one notification is fixed text: its title and body are constants, never a count
    const alerts = read('../js/alerts.js');
    assert.match(alerts, /new window\.Notification\(TITLE, \{ body: BODY, tag: TAG \}\)/);
    assert.match(alerts, /const BODY = 'new message';/);
    // the title is the page's own, once
    assert.match(html, /<title>elyrn\.<\/title>/);
    assert.doesNotMatch(chat, /updateTitle|APP_TITLE/);
});
