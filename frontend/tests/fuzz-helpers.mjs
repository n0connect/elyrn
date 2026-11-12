// Deterministic fuzzing for the browser modules: one seeded PRNG, fixed seeds, named iteration
// counts, and a failure message that names the seed and iteration so it reproduces exactly.
// FUZZ_SEED (decimal or 0x hex) replaces every target's seed and FUZZ_SCALE multiplies every
// iteration count, for a longer local run; CI runs the defaults.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const UINT32 = 0x100000000;
const DEFAULT_SCALE = 1;
const SEED_OVERRIDE = process.env.FUZZ_SEED === undefined ? null : Number(process.env.FUZZ_SEED);
const SCALE = Number(process.env.FUZZ_SCALE) > 0 ? Number(process.env.FUZZ_SCALE) : DEFAULT_SCALE;

// Lengths a generated string takes: mostly short, sometimes long, rarely huge
export const SHORT_MAX = 16;
export const LONG_MAX = 512;
export const HUGE_MAX = 70000;

// Alphabets: each is a function of the generator that returns one code point as a string
const BIDI = [0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c];
const INVISIBLE = [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x180e];
const SPACES = [0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c, 0xa0, 0x1680, 0x2000, 0x2028, 0x2029, 0x3000, 0x85];
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const HEX = '0123456789abcdef';

// mulberry32: small, fast and good enough to spread inputs; never used for anything secret
export function rng(seed) {
    let state = seed >>> 0;
    const next = () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / UINT32;
    };
    const r = {
        next,
        // an integer in [min, max]
        int: (min, max) => min + Math.floor(next() * (max - min + 1)),
        bool: (p = 0.5) => next() < p,
        pick: (items) => items[Math.floor(next() * items.length)],
        bytes: (n) => Uint8Array.from({ length: n }, () => Math.floor(next() * 256)),
        // a length: mostly short, sometimes long, rarely huge
        length: () => {
            const roll = next();
            if (roll < 0.8) return r.int(0, SHORT_MAX);
            if (roll < 0.98) return r.int(0, LONG_MAX);
            return r.int(0, HUGE_MAX);
        },
        char: () => r.pick(CHARSETS)(r),
        string: (length = r.length()) => {
            let out = '';
            for (let i = 0; i < length; i++) out += r.char();
            return out;
        },
        // a string over one alphabet
        from: (alphabet, length = r.length()) => {
            let out = '';
            for (let i = 0; i < length; i++) out += alphabet[Math.floor(next() * alphabet.length)];
            return out;
        },
        base64url: (length) => r.from(BASE64URL, length),
        hex: (length) => r.from(HEX, length),
        // a value of any JSON-ish or JavaScript shape, nested at most depth deep
        value: (depth = 2) => {
            const kinds = depth > 0 ? VALUE_KINDS : SCALAR_KINDS;
            return r.pick(kinds)(r, depth - 1);
        },
        // text with one random edit: flip, cut, extend, duplicate a slice, case change, padding
        mutate: (text) => r.pick(MUTATIONS)(r, String(text))
    };
    return r;
}

const CHARSETS = [
    (r) => String.fromCharCode(r.int(0x20, 0x7e)),               // printable ASCII
    (r) => String.fromCharCode(r.int(0x00, 0x1f)),               // C0 controls
    (r) => String.fromCharCode(r.int(0x7f, 0x9f)),               // DEL and C1
    (r) => String.fromCodePoint(r.pick(BIDI)),                    // bidi controls
    (r) => String.fromCodePoint(r.pick(INVISIBLE)),               // zero-width and BOM
    (r) => String.fromCodePoint(r.pick(SPACES)),                  // every kind of space
    (r) => String.fromCharCode(r.int(0xd800, 0xdfff)),            // a lone surrogate
    (r) => String.fromCodePoint(r.int(0xa0, 0xd7ff)),             // BMP text
    (r) => String.fromCodePoint(r.int(0x10000, 0x10ffff)),        // astral (emoji, CJK ext.)
    (r) => r.pick(BASE64URL),                                      // token alphabet
    (r) => r.pick(['elyrn:', 'elyrn#', 'noaddx:', 'noaddx#', '=', '+', '/', '.', '-'])
];

const SCALAR_KINDS = [
    () => undefined,
    () => null,
    (r) => r.bool(),
    (r) => r.pick([0, -0, 1, -1, 0.5, 2 ** 53, 2 ** 53 + 2, -(2 ** 53), NaN, Infinity, -Infinity, 1e308, 5e-324]),
    (r) => r.int(-1000, 1000),
    (r) => r.string(),
    (r) => r.pick(['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'E_UNKNOWN_CODE', ''])
];

const VALUE_KINDS = SCALAR_KINDS.concat([
    (r, depth) => Array.from({ length: r.int(0, 4) }, () => r.value(depth)),
    (r, depth) => {
        const out = {};
        for (let i = r.int(0, 4); i > 0; i--) {
            const key = r.bool(0.3) ? r.pick(['message', 'code', 'status', 'data', 'tooLarge', 'timedOut', 'max', '__proto__']) : r.string(r.int(0, 8));
            // an own property even for '__proto__': assignment would replace the prototype
            Object.defineProperty(out, key, { value: r.value(depth), enumerable: true, writable: true, configurable: true });
        }
        return out;
    }
]);

const MUTATIONS = [
    (r, t) => t,
    (r, t) => {                                   // replace one character
        if (t.length === 0) return r.char();
        const at = r.int(0, t.length - 1);
        return t.slice(0, at) + r.char() + t.slice(at + 1);
    },
    (r, t) => t.slice(0, r.int(0, t.length)),     // truncate
    (r, t) => t + r.string(r.int(1, 8)),          // extend
    (r, t) => r.string(r.int(1, 4)) + t,          // prefix
    (r, t) => {                                   // duplicate a slice
        const at = r.int(0, t.length);
        return t.slice(0, at) + t.slice(r.int(0, at));
    },
    (r, t) => (r.bool() ? t.toUpperCase() : t.toLowerCase()),
    (r, t) => String.fromCodePoint(r.pick(SPACES)) + t + String.fromCodePoint(r.pick(SPACES))
];

// fuzz runs body(r, i) for scale x iterations inputs from seed, awaiting it when async. A failure
// is rethrown with the seed and iteration that reproduce it.
export async function fuzz(seed, iterations, body) {
    const start = SEED_OVERRIDE === null ? seed : SEED_OVERRIDE;
    const r = rng(start);
    const total = Math.max(1, Math.round(iterations * SCALE));
    for (let i = 0; i < total; i++) {
        try {
            await body(r, i);
        } catch (error) {
            const where = `[fuzz seed=0x${(start >>> 0).toString(16)} iteration=${i}]`;
            if (error && typeof error === 'object') {
                error.message = `${where} ${error.message}`;
                throw error;
            }
            throw new Error(`${where} ${String(error)}`);
        }
    }
}

// Loads frontend files into one vm context exactly as the browser's script tags do
export function load(globals, files) {
    const context = vm.createContext(globals);
    for (const file of files) {
        vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
    }
    return { context, get: (name) => vm.runInContext(name, context) };
}

// Values made in the vm context carry its prototypes; compare them as plain data
export const plain = (value) => JSON.parse(JSON.stringify(value));

// The anchored expressions of backend/internal/contract/patterns.go, by constant name: the
// browser's rules are compared with the server's own text, never with a copy
export function goPatterns() {
    const source = readFileSync(new URL('../../backend/internal/contract/patterns.go', import.meta.url), 'utf8');
    const out = {};
    for (const match of source.matchAll(/^\s*(\w+)\s*=\s*`([^`]*)`/gm)) {
        out[match[1]] = match[2];
    }
    return out;
}

// patterns.go base64URLExact: the canonical base64url text of exactly size bytes
export function goBase64Exact(patterns, size) {
    const length = Math.ceil(size * 4 / 3);
    const base = patterns.classBase64URL;
    switch (size % 3) {
        case 2: return new RegExp(`^${base}{${length - 1}}${patterns.classTailTwoZeroes}$`);
        case 1: return new RegExp(`^${base}{${length - 1}}${patterns.classTailFourZeroes}$`);
        default: return new RegExp(`^${base}{${length}}$`);
    }
}

// patterns.go hexExact: lowercase hex of exactly size bytes
export function goHexExact(patterns, size) {
    return new RegExp(`^${patterns.classHexLower}{${size * 2}}$`);
}

// Go's single-character string escapes, as messages.go spells its trim set
const GO_ESCAPES = { t: '\t', n: '\n', v: '\v', f: '\f', r: '\r' };

// backend/internal/agent/messages.go messageTrimChars, decoded from the Go source: the agent's
// trim set, compared with the browser's MESSAGE_TRIM_CHARS rather than with a copy
export function goMessageTrimChars() {
    const source = readFileSync(new URL('../../backend/internal/agent/messages.go', import.meta.url), 'utf8');
    const declaration = source.match(/const messageTrimChars = ((?:"[^"]*"(?:\s*\+\s*)?)+)/);
    if (declaration === null) throw new Error('messages.go declares no messageTrimChars');
    return [...declaration[1].matchAll(/"([^"]*)"/g)].map((part) => part[1].replace(/\\(?:u([0-9a-fA-F]{4})|([tnvfr]))/g,
        (_, hex, letter) => (hex ? String.fromCharCode(parseInt(hex, 16)) : GO_ESCAPES[letter]))).join('');
}
