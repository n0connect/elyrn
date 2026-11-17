// File names the rule accepts and refuses (validation.js isFileName, the same rule as
// backend/internal/e2e/file.go fileNameValid). Shared with the Go side through vectors-js.json
// file_names; validation.test.mjs pins the browser to it.
export const FILE_NAMES_ACCEPTED = Object.freeze([
    'a', 'résumé ✓ 2026.pdf', 'x'.repeat(128), '日本語の書類.txt', 'é'.repeat(128), 'a.b.c', 'name.', '-dash',
    'zero\u200bwidth.txt', 'no\u00a0break', '🙂'.repeat(128), 'C:drive.txt', 'a<b>.txt', 'Å.txt'
]);

export const FILE_NAMES_REFUSED = Object.freeze([
    '', '.env', '..', '.', 'a/b', 'a\\b', 'x'.repeat(129), '🙂'.repeat(129), '🙂'.repeat(127) + 'ab',
    'a\u0000b', 'a\nb', 'a\tb', 'del\u007f', 'c1\u0085', 'pay\u202etxt.exe', 'a\u2066b', 'lrm\u200e', 'alm\u061c',
    'e\u0301.txt', 'A\u030a.txt', '\u212b.txt'
]);
