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
    assert.match(control, /span\.textContent = ROLE_MARK \+ role;/);
    assert.match(control, /const ROLE_MARK = '#';/);
    assert.doesNotMatch(control, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
    // The role is placed by the same helper in the members panel and on bubbles
    assert.equal((ui.match(/RoleControl\.tag\(/g) || []).length, 2);
});

test('a role never looks like a built-in badge: unframed italic text against a framed tag', () => {
    const badge = rule('.member-tag');
    const role = rule('.member-role');
    assert.match(badge, /border: 1px solid/);
    assert.match(role, /border: none;/);
    assert.match(role, /font-style: italic;/);
    assert.doesNotMatch(badge, /italic/);
    // The badges keep their own words, set by ui.js, never by a role
    assert.match(ui, /memberTag\('you'\)/);
    assert.match(ui, /memberTag\('owner'\)/);
});

test('the control is offered only where it can be used, and every refusal has its code', () => {
    assert.match(control, /if \(!Rooms\.mayEditRole\(room, entry\)\) return null;/);
    for (const code of ['E_ROLE_NOT_ALLOWED', 'W_ROLE_MEMBER_GONE', 'W_ROLE_RATE_LIMITED', 'E_ROLE_NOT_SET']) {
        assert.match(control, new RegExp(`Errors\\.CODES\\.${code}\\b`), code);
    }
});
