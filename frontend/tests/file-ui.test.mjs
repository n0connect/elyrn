// The file controls, read from the real files: file-composer.js (the composer) and file-card.js
// (the bubble). Choosing, pasting, dropping, viewing and saving need a browser and are driven
// by hand (docs/development/testing-and-contributing.md); what can be pinned from the sources is.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const html = read('../index.html');
const card = read('../js/file-card.js');
const composer = read('../js/file-composer.js');
const chat = read('../js/chat.js');
const ui = read('../js/ui.js');

test('the file modules load in order: crypto before transfer, cleaning and cards before the composer and chat', () => {
    const order = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
    const at = (file) => {
        const i = order.indexOf(file);
        assert.ok(i >= 0, `${file} not loaded`);
        return i;
    };
    assert.ok(at('js/room-crypto.js') < at('js/file-crypto.js'));
    assert.ok(at('js/file-crypto.js') < at('js/auth.js'));
    assert.ok(at('js/ui.js') < at('js/file-transfer.js'));
    assert.ok(at('js/file-transfer.js') < at('js/file-card.js'));
    assert.ok(at('js/image-clean.js') < at('js/file-card.js'));
    assert.ok(at('js/file-card.js') < at('js/file-composer.js'));
    assert.ok(at('js/file-composer.js') < at('js/chat.js'));
});

test('the composer\'s controls exist, start hidden, and the file input takes one file', () => {
    for (const id of ['fileChip', 'attachBtn', 'fileInput']) {
        assert.match(html, new RegExp(`id="${id}"[^>]*data-hidden`), id);
    }
    for (const id of ['fileChipName', 'fileChipSize', 'fileChipStatus', 'fileRemoveBtn']) assert.match(html, new RegExp(`id="${id}"`));
    assert.doesNotMatch(html, /<input id="fileInput"[^>]*multiple/);
});

test('received names and sizes are text; nothing is rendered but PNG, JPEG and WebP, and only on a canvas', () => {
    for (const source of [card, composer]) {
        assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|<img|createElement\('img'\)|createElement\('iframe'\)/);
    }
    assert.match(card, /name\.textContent = neutralizeReceivedText\(message\.file\.name\);/);
    assert.match(card, /const kind = ImageClean\.kindOf\(bytes\);\s+if \(!kind\) \{/);
    assert.match(card, /createElement\('canvas'\)/);
    // A download URL is revoked, a decoded image closed
    assert.match(card, /URL\.revokeObjectURL\(url\)/);
    assert.match(card, /bitmap\.close\(\)/);
    // Nothing is fetched until view or save is pressed
    assert.doesNotMatch(card.slice(card.indexOf('function create(')), /fetchFile\(/);
});

test('chat.js reaches the files through thin hooks only', () => {
    assert.match(chat, /FileComposer\.start\(/);
    assert.match(chat, /FileComposer\.stop\(\)/);
    assert.match(chat, /FileComposer\.upload\(/);
    assert.match(chat, /FileComposer\.sent\(file\)/);
    assert.match(chat, /FileTransfer\.download\(/);
    assert.match(ui, /FileCard\.create\(message\)/);
    // The announcing message goes through the one send path (deliver), parts first
    assert.match(chat, /await deliver\(conv, typed, validation\.sanitized, file\);/);
});
