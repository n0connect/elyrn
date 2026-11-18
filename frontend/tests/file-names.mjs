// File names the rule accepts and refuses (validation.js isFileName, the same rule as
// backend/internal/e2e/file.go fileNameValid), and the names chosen files are sent under
// (validation.js outgoingFileName). Shared with the Go side through vectors-js.json file_names;
// validation.test.mjs pins the browser to it. Invisible format characters (Unicode Cf) and runs
// of two or more space characters (Unicode Zs) are refused; one space character between words is not.
export const FILE_NAMES_ACCEPTED = Object.freeze([
    'a', 'résumé ✓ 2026.pdf', 'x'.repeat(128), '日本語の書類.txt', 'é'.repeat(128), 'a.b.c', 'name.', '-dash',
    'no\u00a0break', '🙂'.repeat(128), 'C:drive.txt', 'a<b>.txt', 'Å.txt', 'a b c.txt', ' lead and trail ',
    'ideographic\u3000space', 'thin\u2009space'
]);

export const FILE_NAMES_REFUSED = Object.freeze([
    '', '.env', '..', '.', 'a/b', 'a\\b', 'x'.repeat(129), '🙂'.repeat(129), '🙂'.repeat(127) + 'ab',
    'a\u0000b', 'a\nb', 'a\tb', 'del\u007f', 'c1\u0085', 'pay\u202etxt.exe', 'a\u2066b', 'lrm\u200e', 'alm\u061c',
    'e\u0301.txt', 'A\u030a.txt', '\u212b.txt',
    // invisible format characters (Cf)
    'zero\u200bwidth.txt', 'join\u200dme', 'non\u200cjoin', 'word\u2060joiner', 'bom\ufeff.txt', 'soft\u00adhyphen',
    'mongolian\u180evowel', 'tag\u{e0041}.txt', 'arabic\u0600number',
    // runs of space characters (Zs)
    'two  spaces.txt', 'gap\u00a0\u00a0wide', 'mixed \u00a0run', 'wide\u3000\u3000gap', '  lead', 'trail  '
]);

// The random bytes the outgoing cases are built with, and each chosen name with the name it is
// sent under: file-<8 hex> plus the extension when it is 1 to 8 of [a-z0-9] once lowercased
export const OUTGOING_RANDOM = Object.freeze([0xde, 0xad, 0xbe, 0xef]);
export const OUTGOING_NAMES = Object.freeze([
    ['holiday photo.JPG', 'file-deadbeef.jpg'],
    ['r\u00e9sum\u00e9.PdF', 'file-deadbeef.pdf'],
    ['archive.tar.gz', 'file-deadbeef.gz'],
    ['a.12345678', 'file-deadbeef.12345678'],
    ['a.123456789', 'file-deadbeef'],
    ['report.verylongext', 'file-deadbeef'],
    ['README', 'file-deadbeef'],
    ['.bashrc', 'file-deadbeef'],
    ['name.', 'file-deadbeef'],
    ['x.pdf ', 'file-deadbeef'],
    ['x.jp_g', 'file-deadbeef'],
    ['x.\u00e4bc', 'file-deadbeef'],
    ['pay\u202etxt.exe', 'file-deadbeef.exe'],
    ['../../etc/passwd', 'file-deadbeef'],
    ['', 'file-deadbeef']
]);
