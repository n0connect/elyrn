// The favicon, read from the real files: the 8x8 "e." mark, white pixels on a black square, as an
// svg of whole-pixel rects and as an ico of three PNG images (16, 32 and 48 px).
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const BITMAP = [
    '........',
    '..##....',
    '.#..#...',
    '.#..#...',
    '.####...',
    '.#......',
    '..###.#.',
    '........'
];
const cells = (rows) => rows.flatMap((row, y) => [...row].map((c, x) => (c === '#' ? `${x},${y}` : null))).filter(Boolean).sort();

test('the svg is the bitmap: an 8x8 black square and exactly its white cells, nothing else', () => {
    const svg = readFileSync(new URL('../favicon.svg', import.meta.url), 'utf8');
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 8 8" shape-rendering="crispEdges"><rect width="8" height="8" fill="#000"\/>/);
    const tags = svg.match(/<[a-z][^>]*>/g);
    assert.deepEqual([...new Set(tags.map(tag => tag.match(/^<([a-z]+)/)[1]))], ['svg', 'rect']);
    const white = [];
    for (const [, x, y, w, h] of svg.matchAll(/<rect x="(\d)" y="(\d)" width="(\d)" height="(\d)" fill="#fff"\/>/g)) {
        for (let dy = 0; dy < Number(h); dy++) for (let dx = 0; dx < Number(w); dx++) white.push(`${Number(x) + dx},${Number(y) + dy}`);
    }
    assert.equal((svg.match(/<rect /g) || []).length, 1 + (svg.match(/fill="#fff"/g) || []).length);
    assert.deepEqual(white.sort(), cells(BITMAP));
});

test('the ico names three PNG images, 16, 32 and 48 px', () => {
    const ico = readFileSync(new URL('../favicon.ico', import.meta.url));
    assert.equal(ico.readUInt16LE(0), 0);
    assert.equal(ico.readUInt16LE(2), 1);
    assert.equal(ico.readUInt16LE(4), 3);
    [16, 32, 48].forEach((size, i) => {
        const entry = 6 + 16 * i;
        assert.equal(ico[entry], size);
        assert.equal(ico[entry + 1], size);
        const length = ico.readUInt32LE(entry + 8);
        const offset = ico.readUInt32LE(entry + 12);
        assert.ok(offset + length <= ico.length);
        assert.deepEqual([...ico.subarray(offset, offset + 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
        assert.equal(ico.readUInt32BE(offset + 16), size);
    });
});
