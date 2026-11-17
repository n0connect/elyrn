// frontend/js/alerts.js, loaded as the browser loads it (after log.js, errors.js and utils.js).
// What only a real browser can show (the permission prompt, the notification itself, focus on
// click) is driven by hand: docs/development/testing-and-contributing.md.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { load } from './fuzz-helpers.mjs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const { get } = load({ AbortSignal, DOMException, Response, TextDecoder },
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
    assert.match(html, /<button id="alertsBtn" class="text-btn" aria-pressed="false" data-hidden>alerts off<\/button>/);
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
