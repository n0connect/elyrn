// Cross-implementation tests: frontend/js/crypto.js must match backend/internal/identity.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, CryptoKey: globalThis.CryptoKey, TextEncoder, TextDecoder, atob, btoa });
// As the page's script tags load them: the file name rule (validation.js) is read by decodePayload
for (const file of ['../js/log.js', '../js/errors.js', '../js/crypto.js', '../js/room-crypto.js', '../validation.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const C = vm.runInContext('ElyrnCrypto', context);

// Same vector as backend/tests/identity/identity_test.go
const ACCOUNT = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const GO_AUTH_KEY = 'Thcc1tNIpP2ejPv8dErwLdXtO1dA_hkaGGbEO4LJanA'; // gitleaks:allow (public test-account vector)
const GO_PUBLIC_KEY = '5RnU1Lh-_CuOr8VzbLd0OGx4uFmd9YeLM2YysXB2Bx4';
const CONV = '3b241101-e2bb-4255-8caf-4136c566a962';
const B_ACCOUNT = 'HxwdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
// Produced by backend/internal/e2e (Go, A → B); the browser implementation must open it.
const GO_VECTOR = {
    message: 'a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f607',
    ciphertext: 'RJahYupu3_vKSK6E3fDpsrnGDz-sqWvkBTSYcK7E5FYLBs6iNTerLyd9PxE60FSvW0_X9RCp0venX-t-g5Y8chK6NEYezAMXiF0WErcqVab5fYcuARkWgA9Uz348nEp7f-JmBpaPKQI_9GXk_hZaflCiXOOt5FjU6HYIDvBJKglf336vjcZ4KumSuc62G4v46Dxvq29HXaooXNtanRi5w_eTJRZK-5uZZPbkAQ1OlNgmgh4RAUK8DeAyhApLcu5_eNZrrep1kvjtmh2-g_dvU-vDcZ6Uqr0UfjE5UgLpvMLe4Y-Bho13lN_qzDonJ__cqKdVZUSjVkvaw4M3O8tKkjmHdbZ8kthEh0sitEly7kHUchrWUcO1TnjVniY',
    text: 'noaddx. interop ✓ <b>&',
    sentAt: 1729700000000,
    counter: 3
};

test('auth key matches Go derivation', async () => {
    assert.equal(await C.deriveAuthKey(ACCOUNT), GO_AUTH_KEY);
});

test('identity public key matches Go derivation; private key is not extractable', async () => {
    const id = await C.deriveIdentity(ACCOUNT);
    assert.equal(id.publicKey, GO_PUBLIC_KEY);
    assert.equal(id.privateKey.extractable, false);
});

test('strict base64url rejects malformed account numbers', async () => {
    for (const bad of ['', ACCOUNT.slice(1), ACCOUNT + 'A', ACCOUNT.slice(0, -1) + '+', ACCOUNT.slice(0, -1) + '9']) {
        await assert.rejects(C.deriveAuthKey(bad));
    }
});

// The shared secret privateKey makes with peerPublicKey, read out through the real WebCrypto
async function sharedWith(privateKey, peerPublicKey) {
    const peer = await crypto.subtle.importKey('raw', C.b64urlDecode(peerPublicKey, 32), { name: 'X25519' }, false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256));
}

test('only a kept session derives the sealed form; it opens to the same non-extractable key', async () => {
    assert.equal((await C.deriveIdentity(ACCOUNT)).sealed, undefined);
    const id = await C.deriveIdentity(ACCOUNT, true);
    const b = await C.deriveIdentity(B_ACCOUNT);
    assert.equal(id.publicKey, GO_PUBLIC_KEY);
    assert.equal(id.sealed.deviceKey.extractable, false);
    assert.deepEqual([...id.sealed.deviceKey.usages].sort(), ['unwrapKey', 'wrapKey']);
    const opened = await C.unsealIdentity(id.sealed, id.publicKey);
    assert.equal(opened.extractable, false);
    assert.equal(opened.algorithm.name, 'X25519');
    assert.deepEqual([...opened.usages], ['deriveBits']);
    assert.deepEqual(await sharedWith(opened, b.publicKey), await sharedWith(id.privateKey, b.publicKey));
});

// Keystore.keepsKeys stores what throwawayKey makes and judges what came back with isThrowawayKey
// (the IndexedDB round trip itself needs a browser: docs/development/testing-and-contributing.md)
test('the throwaway key is a fresh non-extractable X25519 private key, and only that is recognised', async () => {
    const one = await C.throwawayKey();
    const two = await C.throwawayKey();
    for (const key of [one, two]) {
        assert.equal(key.type, 'private');
        assert.equal(key.extractable, false);
        assert.equal(key.algorithm.name, 'X25519');
        assert.equal(C.isThrowawayKey(key), true);
    }
    assert.notEqual(one, two);
    const extractable = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])).privateKey;
    const publicOnly = (await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])).publicKey;
    const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    // What an engine that cannot keep the key gives back (WebKit: null), and anything else
    for (const back of [null, undefined, {}, 'key', 0, extractable, publicOnly, aes, { type: 'private', extractable: false, algorithm: { name: 'X25519' } }]) {
        assert.equal(C.isThrowawayKey(back), false);
    }
});

test('each seal has its own device key and nonce', async () => {
    const one = (await C.deriveIdentity(ACCOUNT, true)).sealed;
    const two = (await C.deriveIdentity(ACCOUNT, true)).sealed;
    assert.notDeepEqual([...one.iv], [...two.iv]);
    assert.notDeepEqual([...one.wrapped], [...two.wrapped]);
    await assert.rejects(C.unsealIdentity({ deviceKey: two.deviceKey, iv: one.iv, wrapped: one.wrapped }, GO_PUBLIC_KEY));
});

test('a sealed identity opens for its own public key only, and never once altered', async () => {
    const id = await C.deriveIdentity(ACCOUNT, true);
    const other = (await C.deriveIdentity(B_ACCOUNT)).publicKey;
    const { deviceKey, iv, wrapped } = id.sealed;
    // The AAD binds the blob to one identity: moved under another public key it does not open
    await assert.rejects(C.unsealIdentity(id.sealed, other));
    for (let i = 0; i < wrapped.length; i += 7) {
        const flipped = wrapped.slice();
        flipped[i] ^= 1;
        await assert.rejects(C.unsealIdentity({ deviceKey, iv, wrapped: flipped }, id.publicKey), `byte ${i}`);
    }
    const nonce = iv.slice();
    nonce[0] ^= 1;
    await assert.rejects(C.unsealIdentity({ deviceKey, iv: nonce, wrapped }, id.publicKey));
});

test('anything but the exact sealed shape is refused before any key is touched', async () => {
    const id = await C.deriveIdentity(ACCOUNT, true);
    const { deviceKey, iv, wrapped } = id.sealed;
    const extractable = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']);
    const encryptOnly = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const hostile = [
        null, undefined, 0, 'sealed', [], {},
        { deviceKey: null, iv, wrapped },
        { deviceKey: extractable, iv, wrapped },
        { deviceKey: encryptOnly, iv, wrapped },
        { deviceKey: id.privateKey, iv, wrapped },
        { deviceKey, iv: iv.slice(1), wrapped },
        { deviceKey, iv: [...iv], wrapped },
        { deviceKey, iv, wrapped: wrapped.slice(1) },
        { deviceKey, iv, wrapped: C.concat(wrapped, [0]) },
        { deviceKey, iv, wrapped: C.b64urlEncode(wrapped) }
    ];
    for (const sealed of hostile) {
        await assert.rejects(C.unsealIdentity(sealed, id.publicKey));
    }
    for (const publicKey of [undefined, '', 'x', id.publicKey + 'A', 42]) {
        await assert.rejects(C.unsealIdentity(id.sealed, publicKey));
    }
});

async function peers() {
    const a = await C.deriveIdentity(ACCOUNT);
    const b = await C.deriveIdentity(B_ACCOUNT);
    const ab = await C.conversationKey(a.privateKey, b.publicKey, CONV);
    const ba = await C.conversationKey(b.privateKey, a.publicKey, CONV);
    return { a, b, ab, ba };
}

test('both peers derive the same conversation key and round-trip a message', async () => {
    const { a, ab, ba } = await peers();
    const msg = C.newMessageId();
    const ct = await C.encryptMessage({ key: ab, conversationId: CONV, messageId: msg, senderPublicKey: a.publicKey, text: 'merhaba 👋 <b>', sentAt: 1729700000000, counter: 7 });
    const out = await C.decryptMessage({ key: ba, conversationId: CONV, messageId: msg, senderPublicKey: a.publicKey, ciphertext: ct });
    assert.deepEqual({ ...out }, { text: 'merhaba 👋 <b>', sentAt: 1729700000000, counter: 7 });
    // Length hiding: ciphertext size is a padded bucket, not the text length
    assert.equal(C.b64urlDecode(ct).length, 12 + 256 + 16);
});

// Payload = {"t":"<text>","ts":1,"n":1}: 21 bytes + text; the frame adds a 2-byte length.
test('ciphertext length is one of five power-of-two buckets', async () => {
    const { a, ab } = await peers();
    const frameFor = async (chars) => C.b64urlDecode(
        await C.encryptMessage({ key: ab, conversationId: CONV, messageId: C.newMessageId(), senderPublicKey: a.publicKey, text: 'x'.repeat(chars), sentAt: 1, counter: 1 })).length - 12 - 16;
    assert.equal(await frameFor(1), 256);
    assert.equal(await frameFor(700), 1024);  // 723 framed bytes
    assert.equal(await frameFor(3000), 4096); // 3023 framed bytes
    await assert.rejects(C.encryptMessage({ key: ab, conversationId: CONV, messageId: C.newMessageId(), senderPublicKey: a.publicKey, text: 'x'.repeat(4074), sentAt: 1, counter: 1 }));
});

test('opens a message encrypted by the Go implementation (interop)', async () => {
    const { a, ba } = await peers();
    const out = await C.decryptMessage({ key: ba, conversationId: CONV, messageId: GO_VECTOR.message, senderPublicKey: a.publicKey, ciphertext: GO_VECTOR.ciphertext });
    assert.deepEqual({ ...out }, { text: GO_VECTOR.text, sentAt: GO_VECTOR.sentAt, counter: GO_VECTOR.counter });
});

test('AAD binding: wrong message id, sender, conversation, or tampered bytes fail', async () => {
    const { a, b, ab, ba } = await peers();
    const msg = C.newMessageId();
    const ct = await C.encryptMessage({ key: ab, conversationId: CONV, messageId: msg, senderPublicKey: a.publicKey, text: 'secret', sentAt: 1, counter: 1 });
    await assert.rejects(C.decryptMessage({ key: ba, conversationId: CONV, messageId: C.newMessageId(), senderPublicKey: a.publicKey, ciphertext: ct }));
    await assert.rejects(C.decryptMessage({ key: ba, conversationId: CONV, messageId: msg, senderPublicKey: b.publicKey, ciphertext: ct })); // reflected as if sent by b
    const otherConv = await C.conversationKey(b.privateKey, a.publicKey, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
    await assert.rejects(C.decryptMessage({ key: otherConv, conversationId: CONV, messageId: msg, senderPublicKey: a.publicKey, ciphertext: ct }));
    const raw = C.b64urlDecode(ct);
    raw[20] ^= 1;
    const tampered = Buffer.from(raw).toString('base64url');
    await assert.rejects(C.decryptMessage({ key: ba, conversationId: CONV, messageId: msg, senderPublicKey: a.publicKey, ciphertext: tampered }));
});

test('invite code carries a fingerprint the redeemer can verify', async () => {
    const { a, b } = await peers();
    const token = 'AAAAAAAAAAAAAAAAAAAAAA';
    const code = await C.buildInviteCode(token, a.publicKey);
    assert.ok(code.startsWith('elyrn:'));
    const parsed = C.parseInviteCode(code);
    assert.equal(parsed.token, token);
    assert.equal(await C.fingerprintMatches(parsed, a.publicKey), true);
    assert.equal(await C.fingerprintMatches(parsed, b.publicKey), false);
    assert.throws(() => C.parseInviteCode(ACCOUNT)); // an account number is never an invite
    // Two invites from the same creator share no suffix (not linkable)
    const other = await C.buildInviteCode('AQEBAQEBAQEBAQEBAQEBAQ', a.publicKey);
    assert.notEqual(code.slice(-21), other.slice(-21));
});

test('safety number and aura are symmetric and deterministic', async () => {
    const { a, b } = await peers();
    assert.deepEqual([...await C.safetyNumber(a.publicKey, b.publicKey)], [...await C.safetyNumber(b.publicKey, a.publicKey)]);
    const aura1 = await C.aura(a.publicKey);
    const aura2 = await C.aura(a.publicKey);
    assert.equal(aura1.name, aura2.name);
    assert.match(aura1.name, /^[a-z]+-[a-z]+$/);
    assert.match(aura1.code, /^[0-9a-f]{4}$/);
    assert.equal(aura1.grid.length, 5);
});

test('payload limit is enforced before encryption', async () => {
    const { a, ab } = await peers();
    // 4094-byte payloads; payloadFits budgets 48 bytes of JSON for the longest ts and counter
    assert.equal(C.payloadFits({ text: 'x'.repeat(4046) }), true);
    assert.equal(C.payloadFits({ text: 'x'.repeat(4047) }), false);
    // A file's description takes its share: the longest name leaves less room for the caption
    const longName = 'é'.repeat(128);
    assert.equal(C.payloadFits({ text: '', fileName: longName }), true);
    assert.equal(C.payloadFits({ text: 'x'.repeat(4046), fileName: 'a' }), false);
    assert.equal(C.payloadFits({ text: 'x', fileName: '.hidden' }), false);
    await assert.rejects(C.encryptMessage({ key: ab, conversationId: CONV, messageId: C.newMessageId(), senderPublicKey: a.publicKey, text: 'x'.repeat(7000), sentAt: 1, counter: 1 }));
    await assert.rejects(C.encryptMessage({ key: ab, conversationId: CONV, messageId: C.newMessageId(), senderPublicKey: a.publicKey, text: 'hi', sentAt: 1, counter: 0 })); // counter must be >= 1
});

// The frame as crypto.js writes it (big-endian length, JSON, zeros to a power of two from 256),
// built here independently so payloads this build never writes can be offered to it
function frameOf(json) {
    const bytes = new TextEncoder().encode(json);
    let size = 256;
    while (size < bytes.length + 2) size *= 2;
    const out = new Uint8Array(size);
    out[0] = bytes.length >> 8;
    out[1] = bytes.length & 0xff;
    out.set(bytes, 2);
    return out;
}

const VALID = '"t":"hi","ts":1729700000000,"n":3';
// A valid "f" (backend/internal/e2e/file.go): id, key, size, hash, name
const FILE = { i: '6f1e2d3c-4b5a-4968-8776-655443322110', k: 'gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8', s: 19,
    h: 'Qf1qQZSwVj77ObdHVoZ3fA9IjpCzJotXNZoKn9TrcbA', n: 'résumé ✓ 2026.pdf' };
const FILE_JSON = JSON.stringify(FILE);

// What decodePayload threw for one framed payload (null when it threw nothing)
function decodeFailure(framed) {
    try {
        C.decodePayload(framed);
        return null;
    } catch (e) {
        return e;
    }
}

test('a payload with valid t, ts and n plus unknown keys is a newer elyrn\'s, told apart from tampering', () => {
    for (const json of [`{${VALID},"g":{"i":"x"}}`, `{"z":1,${VALID}}`, `{${VALID},"__proto__":{}}`, `{${VALID},"f":null,"g":[]}`,
        `{${VALID},"f":${FILE_JSON},"x":1}`]) {
        const thrown = decodeFailure(frameOf(json));
        assert.ok(thrown, json);
        assert.equal(C.isNewerPayload(thrown), true, json);
    }
    assert.deepEqual({ ...C.decodePayload(frameOf(`{${VALID}}`)) }, { text: 'hi', sentAt: 1729700000000, counter: 3, file: null });
});

test('everything else that fails stays a bad payload, never a newer one', () => {
    const bad = [
        // a field missing, mistyped or out of range, with or without unknown keys beside it
        '{"t":"hi","ts":1729700000000}', '{"t":"hi","ts":1729700000000,"f":1,"g":2}',
        '{"t":1,"ts":1729700000000,"n":3,"f":1}', '{"t":"hi","ts":0,"n":3,"f":1}', '{"t":"hi","ts":1.5,"n":3,"f":1}',
        '{"t":"hi","ts":1729700000000,"n":0,"f":1}', '{"t":"hi","ts":1729700000000,"n":"3","f":1}',
        '{"t":"hi","ts":1729700000000,"n":9007199254740992,"f":1}',
        // not an object
        '[]', '["hi",1729700000000,3,1]', 'null', '"text"', '7', 'true', '{'
    ];
    for (const json of bad) {
        const thrown = decodeFailure(frameOf(json));
        assert.ok(thrown, json);
        assert.equal(C.isNewerPayload(thrown), false, json);
    }
    // A frame that is not well formed is never read as JSON at all
    const tail = frameOf(`{${VALID},"f":1}`);
    tail[tail.length - 1] = 1;
    for (const framed of [tail, new Uint8Array(256), new Uint8Array(255)]) {
        const thrown = decodeFailure(framed);
        assert.ok(thrown);
        assert.equal(C.isNewerPayload(thrown), false);
    }
    for (const value of [null, undefined, 'NewerPayload', { name: 'NewerPayload' }, new Error('x')]) {
        assert.equal(C.isNewerPayload(value), false);
    }
});

test('a one-to-one message a newer elyrn sealed opens as newer, and as unreadable once altered', async () => {
    const { a, ab, ba } = await peers();
    const id = C.newMessageId();
    // messageAAD, as crypto.js builds it: "NADM" || 1 || conversation || message || SHA-256(sender)
    const aad = C.concat(new TextEncoder().encode('NADM'), [1], C.uuidBytes(CONV), C.uuidBytes(id),
        await C.sha256(C.b64urlDecode(a.publicKey, 32)));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad },
        ab, frameOf(`{${VALID},"g":{"n":"later"}}`)));
    const ciphertext = C.b64urlEncode(C.concat(nonce, sealed));
    await assert.rejects(C.decryptMessage({ key: ba, conversationId: CONV, messageId: id, senderPublicKey: a.publicKey, ciphertext }), (e) => C.isNewerPayload(e));
    const altered = C.b64urlDecode(ciphertext);
    altered[20] ^= 1;
    await assert.rejects(C.decryptMessage({ key: ba, conversationId: CONV, messageId: id, senderPublicKey: a.publicKey, ciphertext: C.b64urlEncode(altered) }), (e) => !C.isNewerPayload(e));
});

// ---------- the file field ----------

test('a file message carries exactly {t, ts, n, f} with f exactly {i, k, s, h, n}; the caption may be empty', () => {
    const opened = C.decodePayload(frameOf(`{"t":"","ts":1729700000000,"n":7,"f":${FILE_JSON}}`));
    assert.equal(opened.text, '');
    assert.deepEqual({ ...opened.file }, { id: FILE.i, key: FILE.k, size: FILE.s, hash: FILE.h, name: FILE.n });
    // Written and read back by this build, in the order Go reads it
    const file = { id: FILE.i, key: FILE.k, size: FILE.s, hash: FILE.h, name: FILE.n };
    const framed = C.encodePayload({ text: 'caption', sentAt: 1729700000000, counter: 7, file });
    const json = new TextDecoder().decode(framed.subarray(2, 2 + ((framed[0] << 8) | framed[1])));
    assert.equal(json, `{"t":"caption","ts":1729700000000,"n":7,"f":${FILE_JSON}}`);
    assert.deepEqual({ ...C.decodePayload(framed).file }, file);
    for (const size of [1, 104857600]) {
        assert.equal(C.decodePayload(frameOf(`{${VALID},"f":${JSON.stringify({ ...FILE, s: size })}}`)).file.size, size);
    }
});

test('every field of f is checked, and an invalid f makes the whole payload bad (never newer)', () => {
    const bad = [
        null, [], 'x', 7, {}, { ...FILE, extra: 1 },
        Object.fromEntries(Object.entries(FILE).filter(([k]) => k !== 'n')),
        { i: FILE.i, k: FILE.k, s: FILE.s, h: FILE.h, x: FILE.n },
        { ...FILE, i: FILE.i.toUpperCase() }, { ...FILE, i: '6f1e2d3c-4b5a-1968-8776-655443322110' }, { ...FILE, i: 7 },
        { ...FILE, k: FILE.k + 'A' }, { ...FILE, k: FILE.k.slice(1) }, { ...FILE, k: FILE.k.replace(/.$/, '9') }, { ...FILE, k: 5 },
        { ...FILE, h: FILE.h.slice(2) }, { ...FILE, h: null },
        { ...FILE, s: 0 }, { ...FILE, s: -1 }, { ...FILE, s: 104857601 }, { ...FILE, s: 1.5 }, { ...FILE, s: '19' },
        { ...FILE, n: '' }, { ...FILE, n: '.env' }, { ...FILE, n: 'a/b' }, { ...FILE, n: 'a\\b' }, { ...FILE, n: 'pay\u202etxt.exe' },
        { ...FILE, n: 'a\u0000b' }, { ...FILE, n: 'x'.repeat(129) }, { ...FILE, n: 'e\u0301' }, { ...FILE, n: 7 }
    ];
    for (const f of bad) {
        const thrown = decodeFailure(frameOf(`{${VALID},"f":${JSON.stringify(f)}}`));
        assert.ok(thrown, JSON.stringify(f));
        assert.equal(C.isNewerPayload(thrown), false, JSON.stringify(f));
    }
    // ...and this build never writes one
    for (const f of bad.filter((v) => v && typeof v === 'object' && !Array.isArray(v) && 'i' in v && !('extra' in v))) {
        assert.throws(() => C.encodePayload({ text: '', sentAt: 1, counter: 1, file: { id: f.i, key: f.k, size: f.s, hash: f.h, name: f.n } }));
    }
});
