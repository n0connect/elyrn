// The file controls, read from the real files: file-composer.js (the composer) and file-card.js
// (the bubble). Choosing, pasting, dropping and saving need a browser and are driven
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

test('the file modules load in order: crypto before transfer, cards before the composer and chat', () => {
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
    assert.ok(at('js/file-card.js') < at('js/file-composer.js'));
    assert.ok(at('js/file-composer.js') < at('js/chat.js'));
});

test('the composer\'s controls exist, start hidden, and the file input takes one file', () => {
    for (const id of ['fileChip', 'attachBtn', 'fileInput']) {
        assert.match(html, new RegExp(`id="${id}"[^>]*data-hidden`), id);
    }
    for (const id of ['fileChipName', 'fileChipSize', 'fileChipStatus', 'fileChipNotice', 'fileRemoveBtn']) assert.match(html, new RegExp(`id="${id}"`));
    assert.doesNotMatch(html, /<input id="fileInput"[^>]*multiple/);
});

test('a file is delivered as it is: nothing in the page reads, decodes or draws its content', () => {
    const index = read('../index.html');
    assert.doesNotMatch(index, /image-clean/);
    for (const source of [card, composer, read('../js/file-transfer.js'), read('../js/file-crypto.js')]) {
        assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|<img|createElement\('(img|iframe|canvas|video|audio|object|embed)'\)/);
        assert.doesNotMatch(source, /createImageBitmap|getContext\(|toBlob\(|image\/|kindOf|ImageClean|DOMParser|FileReader|\.text\(\)/);
    }
    // The composer sends the bytes it read, under the name outgoingFileName gives
    assert.match(composer, /outgoingFileName\(source\.name, /);
    assert.match(composer, /Object\.assign\(mine, \{ bytes, name, size: bytes\.length, ready: true \}\);/);
});

test('the notice stands at every chosen file; the received card has one control, save, and its fixed line', () => {
    // Set whenever a file is shown in the chip, never once per session, never dismissed
    assert.match(composer, /el\('fileChipNotice'\)\.textContent = Errors\.NOTICE\.FILE_SENT_AS_IS;/);
    assert.doesNotMatch(composer, /once per session|Told|told = /);
    assert.match(card, /text\('file-notice', Errors\.NOTICE\.FILE_FROM_MEMBER\)/);
    assert.match(card, /text\('file-name', neutralizeReceivedText\(message\.file\.name\)\)/);
    assert.equal((card.match(/createElement\('button'\)/g) || []).length, 1);
    assert.doesNotMatch(card, /'view'|VIEW_LABEL/);
    // A download URL is revoked; nothing is fetched until save is pressed
    assert.match(card, /URL\.revokeObjectURL\(url\)/);
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

test('a final upload refusal lets the file go and keeps the typed text; a transient one keeps the file', () => {
    const start = composer.indexOf('async function upload(');
    const upload = composer.slice(start, composer.indexOf('\n    }\n', start));
    // The refusal is said first, then the file leaves the composer only when FileTransfer says final
    assert.match(upload, /Errors\.report\(outcome\.code\);\n\s*\}\n(?:\s*\/\/[^\n]*\n)*\s*if \(outcome\.final && chosen === mine\) clear\(\);\n\s*return null;/);
    assert.equal((upload.match(/clear\(\)/g) || []).length, 1, 'the file leaves on a final refusal only');
    // The one home of final: file-transfer.js, from the same transient() the retries use
    const transfer = read('../js/file-transfer.js');
    assert.match(transfer, /function final\(result\) \{\n\s*return !transient\(result\) && /);
    assert.match(transfer, /final: final\(result\)/);
    // chat.js stops before deliver when no file came back: the typed text stays in the box unsent
    const send = chat.slice(chat.indexOf('FileComposer.upload('));
    assert.match(send, /^[^\n]*\n[^\n]*\n\s*if \(attached && !file\) return;\n\s*await deliver\(/);
});
