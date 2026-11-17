// frontend/js/image-clean.js, loaded as the browser loads it: recognising images by their first
// bytes and reading the size their header declares. Decoding and re-encoding through a canvas
// needs a browser and is shown by the live drill (docs/development/testing-and-contributing.md).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { load } from './fuzz-helpers.mjs';

const { get } = load({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa },
    ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js', '../js/image-clean.js']);
const I = get('ImageClean');

const bytes = (...parts) => Uint8Array.from(parts.flat());
const u32be = (n) => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
const u16be = (n) => [(n >> 8) & 0xff, n & 0xff];
const ascii = (text) => Array.from(text, (ch) => ch.charCodeAt(0));

function png(width, height) {
    return bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], u32be(13), ascii('IHDR'), u32be(width), u32be(height), [8, 6, 0, 0, 0]);
}

// SOI, an APP1 (EXIF) segment to skip, then a baseline start-of-frame
function jpeg(width, height) {
    const exif = ascii('Exif\0\0GPS-and-device');
    return bytes([0xff, 0xd8], [0xff, 0xe1], u16be(exif.length + 2), exif, [0xff, 0xc0], u16be(17), [8], u16be(height), u16be(width), [3]);
}

function webpVp8x(width, height) {
    const w = width - 1;
    const h = height - 1;
    return bytes(ascii('RIFF'), u32be(0), ascii('WEBP'), ascii('VP8X'), u32be(10), [0, 0, 0, 0],
        [w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff], [h & 0xff, (h >> 8) & 0xff, (h >> 16) & 0xff]);
}

test('images are recognised by their first bytes only', () => {
    assert.equal(I.kindOf(png(1, 1)), 'png');
    assert.equal(I.kindOf(jpeg(1, 1)), 'jpeg');
    assert.equal(I.kindOf(webpVp8x(1, 1)), 'webp');
    for (const other of [bytes(ascii('GIF89a')), bytes(ascii('<svg xmlns=')), bytes(ascii('<html>')), bytes(ascii('%PDF-1.7')),
        bytes([0x89, 0x50, 0x4e]), bytes([]), bytes(ascii('RIFF'), u32be(0), ascii('WAVE'))]) {
        assert.equal(I.kindOf(other), null);
    }
});

test('the size a header declares is read for PNG, JPEG (past other segments) and WebP', () => {
    assert.deepEqual({ ...I.declaredSize(png(640, 480), 'png') }, { width: 640, height: 480 });
    assert.deepEqual({ ...I.declaredSize(jpeg(4032, 3024), 'jpeg') }, { width: 4032, height: 3024 });
    assert.deepEqual({ ...I.declaredSize(webpVp8x(5000, 20), 'webp') }, { width: 5000, height: 20 });
    // A header that ends early, or a JPEG with no frame before its scan, gives no size
    assert.equal(I.declaredSize(png(1, 1).subarray(0, 20), 'png'), null);
    assert.equal(I.declaredSize(bytes([0xff, 0xd8, 0xff, 0xda, 0, 2]), 'jpeg'), null);
    assert.equal(I.declaredSize(bytes([0xff, 0xd8, 0x00, 0x00]), 'jpeg'), null);
});

test('the pixel limit is named and drawn by every engine; JPEG quality is named', () => {
    assert.equal(I.MAX_IMAGE_PIXELS, 4096 * 4096);
    assert.ok(I.JPEG_QUALITY > 0 && I.JPEG_QUALITY <= 1);
});

test('a file that is no image is sent as it is, under a name the rule accepts', async () => {
    const pdf = bytes(ascii('%PDF-1.7 author=someone'));
    const out = await I.prepare({ bytes: pdf, name: '.secret/report.pdf', maxBytes: 1000 });
    assert.equal(out.ok, true);
    assert.equal(out.cleaned, false);
    assert.equal(out.bytes, pdf);
    assert.equal(out.name, 'secret_report.pdf');
    assert.equal(get('isFileName')(out.name), true);
});
