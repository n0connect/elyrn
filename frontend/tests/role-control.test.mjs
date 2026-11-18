// frontend/js/role-control.js and its styles, read from the real files: a member's role is other
// members' data, inserted as text only, and drawn unlike the built-in `you` and `owner` badges.
// Drawing and typing in the members panel needs a browser (docs/development/testing-and-contributing.md).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const control = read('../js/role-control.js');
const ui = read('../js/ui.js');
const css = read('../styles.css');

// The declarations of one rule of styles.css, by its exact selector
function rule(selector) {
    const found = css.match(new RegExp(`(?:^|\\n)${selector.replace(/[.[\]]/g, '\\$&')} \\{([^}]*)\\}`));
    assert.ok(found, `${selector} missing from styles.css`);
    return found[1];
}

test('a role is inserted as text after its mark, never as markup', () => {
    assert.match(control, /span\.textContent = UI_TEXT\.MARK\(ROLE_MARK \+ role\);/);
    assert.match(control, /const ROLE_MARK = '#';/);
    assert.doesNotMatch(control, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    // The role is placed by the same helper in the members panel and on bubbles
    assert.equal((ui.match(/RoleControl\.tag\(/g) || []).length, 2);
});

test('a mark is information, never framed; a role never reads as a built-in mark', () => {
    // you, owner, a role and the warnings are plain text after the middle dot: no frame
    for (const selector of ['.member-tag,\n.member-role', '.verified-mark']) {
        const found = css.match(new RegExp(selector.replace(/[.[\]]/g, '\\$&') + ' \\{([^}]*)\\}'));
        assert.ok(found, selector);
        assert.doesNotMatch(found[1], /border: (?!none)/, selector);
    }
    assert.doesNotMatch(rule('.member-tag.lookalike-tag'), /border/);
    assert.match(ui, /tag\.textContent = UI_TEXT\.MARK\(text\);/);
    assert.match(control, /span\.textContent = UI_TEXT\.MARK\(ROLE_MARK \+ role\);/);
    // the role is italic after its '#', the built-in marks are not
    assert.match(css, /\(validation\.js\) \*\/\n\.member-role \{\n\s*font-style: italic;/);
    assert.doesNotMatch(css.match(/\n\.member-tag,\n\.member-role \{([^}]*)\}/)[1], /italic/);
    // The badges keep their own words, set by ui.js, never by a role
    assert.match(ui, /memberTag\(UI_TEXT\.YOU_TAG\)/);
    assert.match(ui, /memberTag\(UI_TEXT\.OWNER_TAG\)/);
    assert.match(ui, /    YOU_TAG: 'you',\n/);
    assert.match(ui, /    OWNER_TAG: 'owner',\n/);
});

test('every framed thing in the members list is a button: the role tile, its joined editor, befriend', () => {
    // the role control is a tile named from UI_TEXT; the editor is one joined box of cells
    assert.match(control, /const open = iconTile\(OPEN_ICON, UI_TEXT\.ROLE_TITLE, UI_TEXT\.ROLE\);/);
    assert.match(control, /box\.className = 'join-input-group role-box';/);
    assert.match(control, /box\.append\(mark, input, set\);/);
    assert.match(control, /const set = cell\(SET_ICON, UI_TEXT\.ROLE_SET_TITLE, UI_TEXT\.ROLE_SET,/);
    assert.match(control, /cell\(CANCEL_ICON, UI_TEXT\.ROLE_CANCEL_TITLE, UI_TEXT\.ROLE_CANCEL,/);
    assert.match(control, /const SET_ICON = 'verify';/);
    assert.match(control, /const CANCEL_ICON = 'close';/);
    assert.match(control, /mark\.className = 'box-mark';/);
    assert.doesNotMatch(control, /menu-opt|textContent = (SET|CLEAR|CANCEL|OPEN)_LABEL/);
    for (const key of ['ROLE', 'ROLE_TITLE', 'ROLE_SET', 'ROLE_CANCEL', 'ROLE_CLEAR', 'ROLE_INPUT']) assert.match(ui, new RegExp('    ' + key + ': '), key);
    // the row's other framed control is a button (befriend); marks are spans of member-tag
    const members = ui.slice(ui.indexOf('function renderMembers'), ui.indexOf('function renderRoomSafety'));
    assert.match(members, /const button = document\.createElement\('button'\);\n\s*button\.className = 'menu-opt member-action';/);
    assert.match(ui, /function memberTag\(text\) \{\n\s*const tag = document\.createElement\('span'\);/);
    assert.match(css, /\.box-cell:disabled,\n\.box-cell:disabled:hover \{/);
});

test('the control is offered only where it can be used, and every refusal has its code', () => {
    assert.match(control, /if \(!Rooms\.mayEditRole\(room, entry\)\) return null;/);
    for (const code of ['E_ROLE_NOT_ALLOWED', 'W_ROLE_MEMBER_GONE', 'W_ROLE_RATE_LIMITED', 'E_ROLE_NOT_SET']) {
        assert.match(control, new RegExp(`Errors\\.CODES\\.${code}\\b`), code);
    }
});
