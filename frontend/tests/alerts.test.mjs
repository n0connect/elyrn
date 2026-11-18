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
    assert.match(html, /<button type="button" id="alertsBtn" class="icon-btn bell-btn" aria-pressed="false" aria-label="alerts off" data-caption="alerts off" data-hidden>/);
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

test('the bell: named, captioned and pressed by its state, from UI_TEXT', () => {
    const on = Alerts.controlState({ session: true, supported: true, on: true });
    assert.deepEqual({ ...on }, { shown: true, pressed: 'true', name: UI_TEXT.ALERTS_ON });
    const off = Alerts.controlState({ session: true, supported: true, on: false });
    assert.deepEqual({ ...off }, { shown: true, pressed: 'false', name: UI_TEXT.ALERTS_OFF });
    assert.equal(on.name, 'alerts on');
    assert.equal(off.name, 'alerts off');
    // Anything but a strict true is off
    for (const value of ['true', 1, undefined, null]) {
        assert.equal(Alerts.controlState({ session: true, supported: true, on: value }).pressed, 'false', String(value));
    }
    // render writes exactly that state, and the words live in UI_TEXT, not in alerts.js
    const source = read('../js/alerts.js');
    const render = source.slice(source.indexOf('    function render()'), source.indexOf('\n    }\n', source.indexOf('    function render()')));
    assert.match(render, /button\.setAttribute\('aria-pressed', state\.pressed\);/);
    assert.match(render, /button\.setAttribute\('aria-label', state\.name\);/);
    // the caption says the state; a captioned tile has no title (two tooltips never show together)
    assert.match(render, /button\.setAttribute\(CAPTION_ATTRIBUTE, state\.name\);/);
    assert.doesNotMatch(render, /\.title\b/);
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

test('the bell has two shapes in one place: solid when pressed, hollow and struck through when not', () => {
    const html = read('../index.html');
    const css = read('../styles.css');
    const button = html.match(/<button type="button" id="alertsBtn"[^>]*>([\s\S]*?)<\/button>/)[1];
    // both shapes come from the one icon table (pixels.js) into one tile; aria-pressed picks one
    assert.match(button, /<span class="icon-tile" data-icon="bell-on bell-off"><\/span>/);
    assert.doesNotMatch(button, /<svg|style=/);
    assert.match(css, /\.bell-btn\[aria-pressed="true"\] \.icon-bell-off,\n\.bell-btn\[aria-pressed="false"\] \.icon-bell-on \{\n\s*display: none;/);
    // the tile is the box; its 40 px hit area reaches round it
    assert.match(css, /\.icon-btn::before,\n\.me-badge::before \{\n\s*content: '';\n\s*position: absolute;\n\s*inset: calc\(\(var\(--tile-box\) - var\(--touch-min\)\) \/ 2\);/);
    assert.match(css, /\.icon-btn:focus-visible,\n\.me-badge:focus-visible,\n\.box-cell:focus-visible \{\n\s*outline: var\(--focus-ring\);/);
    // at the far right, just before logout
    const header = html.match(/<header>([\s\S]*?)<\/header>/)[1];
    const ids = [...header.matchAll(/<button[^>]*\bid="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(ids, ['meBadge', 'alertsBtn', 'logoutBtn']);
});
