// frontend/js/alerts.js, loaded as the browser loads it (after log.js, errors.js and utils.js).
// What only a real browser can show (the permission prompt, the notification itself, focus on
// click) is driven by hand: docs/development/testing-and-contributing.md.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { load } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
// UI_TEXT is ui.js's own object, evaluated from its source (ui.js itself needs a page to load)
const uiSource = read('../js/ui.js');
const UI_TEXT = vm.runInNewContext('(' + uiSource.match(/const UI_TEXT = (Object\.freeze\(\{[\s\S]*?\n\}\));/)[1] + ')');
const { get } = load({ AbortSignal, DOMException, Response, TextDecoder, UI_TEXT },
    ['../js/log.js', '../js/errors.js', '../js/utils.js', '../js/alerts.js']);
const Alerts = get('Alerts');
const Errors = get('Errors');

test('a notification carries only the fixed words, under one fixed tag', () => {
    assert.equal(Alerts.TITLE, 'elyrn.');
    assert.equal(Alerts.BODY, 'new message');
    assert.equal(typeof Alerts.TAG, 'string');
    assert.ok(Alerts.TAG.length > 0);
    assert.ok(Object.isFrozen(Alerts));
    // The one place a notification is made passes these constants and nothing else
    const source = read('../js/alerts.js');
    const made = source.match(/new window\.Notification\(([^)]*)\)/g);
    assert.deepEqual(made, ['new window.Notification(TITLE, { body: BODY, tag: TAG })']);
});

test('one alert per hidden stretch: raised only when on, allowed, hidden and not yet raised', () => {
    const base = { session: true, on: true, raised: false, visible: false, permission: 'granted' };
    assert.equal(Alerts.due(base), true);
    for (const [field, values] of Object.entries({
        session: [false, 1, undefined], on: [false, 'true', undefined], raised: [true],
        visible: [true], permission: ['denied', 'default', undefined, 'GRANTED']
    })) {
        for (const value of values) {
            assert.equal(Alerts.due({ ...base, [field]: value }), false, `${field}=${String(value)}`);
        }
    }
});

test('alerts make no request and need no worker, push service or CSP change', () => {
    const source = read('../js/alerts.js');
    for (const forbidden of [/\bfetch\s*\(/, /XMLHttpRequest/, /EventSource/, /serviceWorker/, /PushManager/,
        /\bicon\b\s*:/, /\bimage\b\s*:/, /\bbadge\b\s*:/, /apiCall/, /sendBeacon/, /WebSocket/]) {
        assert.doesNotMatch(source, forbidden);
    }
    // The control starts hidden in markup and is loaded before the code that raises alerts
    const html = read('../index.html');
    assert.match(html, /<button type="button" id="alertsBtn" class="header-btn bell-btn" aria-pressed="false" aria-label="alerts off" title="alerts off" data-hidden>/);
    const order = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
    assert.ok(order.indexOf('js/keystore.js') < order.indexOf('js/alerts.js'));
    assert.ok(order.indexOf('js/alerts.js') < order.indexOf('js/chat.js'));
    assert.ok(order.indexOf('js/utils.js') < order.indexOf('js/alerts.js'));
});

test('every alerts failure has its registered code', () => {
    for (const code of ['W_ALERTS_DENIED', 'W_ALERTS_NOT_ALLOWED', 'W_ALERTS_REVOKED']) {
        assert.equal(Errors.REGISTRY[code].severity, 'warning', code);
    }
    assert.equal(Errors.REGISTRY.E_ALERTS_UNAVAILABLE.severity, 'error');
    for (const code of ['W_ALERTS_UNSUPPORTED', 'W_ALERT_NOT_SHOWN']) {
        assert.equal(Errors.INTERNAL[code], code);
    }
    // The preference goes with the identity: both wipes and another account's save drop it
    const keystore = read('../js/keystore.js');
    assert.match(keystore, /async function wipeIdentity\(\) \{[\s\S]*?store\.delete\(ALERTS\);[\s\S]*?store\.delete\(RECORD\)/);
    assert.match(keystore, /holder !== publicKey\) \{[\s\S]*?keys\.delete\(ALERTS\);/);
});

// ---------- the bell (index.html, styles.css, alerts.js render) ----------

test('the bell: named, titled and pressed by its state, from UI_TEXT', () => {
    const on = Alerts.controlState({ session: true, supported: true, on: true });
    assert.deepEqual({ ...on }, { shown: true, pressed: 'true', name: 'alerts on', title: UI_TEXT.ALERTS_TITLE('alerts on') });
    const off = Alerts.controlState({ session: true, supported: true, on: false });
    assert.deepEqual({ ...off }, { shown: true, pressed: 'false', name: 'alerts off', title: UI_TEXT.ALERTS_TITLE('alerts off') });
    assert.ok(on.title.startsWith('alerts on'));
    assert.ok(off.title.startsWith('alerts off'));
    // Anything but a strict true is off
    for (const value of ['true', 1, undefined, null]) {
        assert.equal(Alerts.controlState({ session: true, supported: true, on: value }).pressed, 'false', String(value));
    }
    // render writes exactly that state, and the words live in UI_TEXT, not in alerts.js
    const source = read('../js/alerts.js');
    const render = source.slice(source.indexOf('    function render()'), source.indexOf('\n    }\n', source.indexOf('    function render()')));
    assert.match(render, /button\.setAttribute\('aria-pressed', state\.pressed\);/);
    assert.match(render, /button\.setAttribute\('aria-label', state\.name\);/);
    assert.match(render, /button\.title = state\.title;/);
    assert.doesNotMatch(source, /'alerts on'|'alerts off'|textContent/);
});

test('the bell is hidden without the Notification API and outside a session', () => {
    for (const [session, supported] of [[true, false], [false, true], [false, false], [1, true], [true, 'yes']]) {
        assert.equal(Alerts.controlState({ session, supported, on: true }).shown, false, `${session} ${supported}`);
    }
    const source = read('../js/alerts.js');
    assert.match(source, /button\.style\.display = state\.shown \? CONTROL_DISPLAY : 'none';/);
    assert.match(source, /const state = controlState\(\{ session, supported: supported\(\), on \}\);/);
});

test('the bell has two shapes in one place: solid when pressed, struck through and dimmer when not', () => {
    const html = read('../index.html');
    const css = read('../styles.css');
    const button = html.match(/<button type="button" id="alertsBtn"[^>]*>([\s\S]*?)<\/button>/)[1];
    assert.match(button, /<svg class="bell-glyph"[^>]*aria-hidden="true"[^>]*shape-rendering="crispEdges">/);
    for (const part of ['bell-body', 'bell-gap', 'bell-strike']) {
        assert.equal((button.match(new RegExp(`<g class="${part}">`, 'g')) || []).length, 1, part);
    }
    assert.doesNotMatch(button, /style=|<image|<text/);
    assert.equal((html.match(/class="bell-glyph"/g) || []).length, 1);
    // pressed hides the strike and its gap and takes full colour; unpressed is the muted colour
    assert.match(css, /\.bell-btn\[aria-pressed="true"\] \.bell-gap,\n\.bell-btn\[aria-pressed="true"\] \.bell-strike \{\n\s*display: none;/);
    assert.match(css, /\.bell-btn\[aria-pressed="true"\] \{\n\s*color: var\(--fg\);/);
    assert.match(css, /\.header-btn \{[^}]*color: var\(--muted\);[^}]*min-height: var\(--touch-min\);|\.header-btn \{[^}]*min-height: var\(--touch-min\);[^}]*color: var\(--muted\);/);
    assert.match(css, /\.bell-btn \{\n\s*min-width: var\(--touch-min\);/);
    assert.match(css, /\.header-btn:focus-visible \{\n\s*outline: var\(--focus-ring\);/);
    // at the far right, just before logout
    const header = html.match(/<header>([\s\S]*?)<\/header>/)[1];
    const ids = [...header.matchAll(/<button[^>]*\bid="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(ids, ['meBadge', 'alertsBtn', 'logoutBtn']);
});
