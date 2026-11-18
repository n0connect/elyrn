// ========================================
// IMAGE CLEAN (hidden data out of an image before it leaves)
// ========================================
// One job: an image is redrawn before it is sent, so what a camera or an editor hid in it (EXIF,
// GPS, device, time, comments, thumbnails) stays behind (docs/architecture/files.md). PNG, JPEG
// and WebP are recognised by their first bytes, never by name or type; each is decoded with its
// orientation applied and encoded again from the pixels alone through a canvas: PNG stays PNG,
// JPEG stays JPEG (at JPEG_QUALITY), WebP becomes PNG. The name becomes image-<4 random hex>.<ext>.
// An image that cannot be decoded or encoded here is refused, never sent as it was. Anything
// else is sent as it is (the caller says once that its hidden data goes along).
//
// The same recognition and decoding serve viewing a received image (file-card.js): only these
// three kinds, and only within MAX_IMAGE_PIXELS, are ever drawn.

const ImageClean = (() => {
    'use strict';

    // The largest image drawn or cleaned: 4096 x 4096, the largest canvas every engine draws
    // (iOS Safari's bound); beyond it an engine may draw nothing without saying so
    const MAX_IMAGE_PIXELS = 16777216;
    const PIXELS_PER_MEGAPIXEL = 1000000;
    const JPEG_QUALITY = 0.92;
    const NAME_PREFIX = 'image-';
    const NAME_RANDOM_BYTES = 2;
    const KIND = Object.freeze({ PNG: 'png', JPEG: 'jpeg', WEBP: 'webp' });
    // What each kind is encoded to: canvas type and the extension of the new name
    const OUTPUT = Object.freeze({
        [KIND.PNG]: { type: 'image/png', ext: 'png', kind: KIND.PNG },
        [KIND.JPEG]: { type: 'image/jpeg', ext: 'jpg', kind: KIND.JPEG },
        [KIND.WEBP]: { type: 'image/png', ext: 'png', kind: KIND.PNG }
    });
    const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    const JPEG_MAGIC = [0xff, 0xd8, 0xff];
    const RIFF = [0x52, 0x49, 0x46, 0x46];
    const WEBP = [0x57, 0x45, 0x42, 0x50];
    const WEBP_TAG_OFFSET = 8;
    const WEBP_CHUNK_OFFSET = 12;
    // PNG: the IHDR chunk's width and height (big-endian u32) follow the signature and chunk head
    const PNG_WIDTH_OFFSET = 16;
    // JPEG: start-of-frame markers carry height and width (big-endian u16) after length and precision
    const JPEG_SOF = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
    const JPEG_SOS = 0xda;
    const JPEG_EOI = 0xd9;
    const JPEG_STANDALONE = new Set([0x01, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]);
    // What an engine's own encoder may write beside the pixels (WebKit writes an Exif segment of
    // its own): JPEG application segments APP1..APP15 and comments, PNG text, time and Exif
    // chunks. They are dropped from the encoded image, so only the pixels leave.
    const JPEG_APP1 = 0xe1;
    const JPEG_APP15 = 0xef;
    const JPEG_COM = 0xfe;
    const PNG_DROPPED = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME']);
    const PNG_CHUNK_OVERHEAD = 12;

    function startsWith(bytes, magic, offset = 0) {
        if (bytes.length < offset + magic.length) return false;
        return magic.every((b, i) => bytes[offset + i] === b);
    }

    // 'png' | 'jpeg' | 'webp' by the bytes themselves, or null
    function kindOf(bytes) {
        if (startsWith(bytes, PNG_MAGIC)) return KIND.PNG;
        if (startsWith(bytes, JPEG_MAGIC)) return KIND.JPEG;
        if (startsWith(bytes, RIFF) && startsWith(bytes, WEBP, WEBP_TAG_OFFSET)) return KIND.WEBP;
        return null;
    }

    const u16be = (b, i) => (b[i] << 8) | b[i + 1];
    const u16le = (b, i) => b[i] | (b[i + 1] << 8);
    const u24le = (b, i) => b[i] | (b[i + 1] << 8) | (b[i + 2] << 16);
    const u32be = (b, i) => ((b[i] << 24) >>> 0) + (b[i + 1] << 16) + (b[i + 2] << 8) + b[i + 3];

    function jpegSize(b) {
        let i = 2;
        while (i + 3 < b.length) {
            if (b[i] !== 0xff) return null;
            const marker = b[i + 1];
            if (marker === 0xff) {
                i++;
                continue;
            }
            if (JPEG_STANDALONE.has(marker)) {
                i += 2;
                continue;
            }
            if (marker === JPEG_SOS || marker === JPEG_EOI) return null;
            if (JPEG_SOF.has(marker)) {
                return i + 8 < b.length ? { height: u16be(b, i + 5), width: u16be(b, i + 7) } : null;
            }
            i += 2 + u16be(b, i + 2);
        }
        return null;
    }

    function webpSize(b) {
        const chunk = String.fromCharCode(b[12], b[13], b[14], b[15]);
        if (chunk === 'VP8 ' && b.length >= 30) {
            return { width: u16le(b, 26) & 0x3fff, height: u16le(b, 28) & 0x3fff };
        }
        if (chunk === 'VP8L' && b.length >= 25) {
            return { width: 1 + (b[21] | ((b[22] & 0x3f) << 8)), height: 1 + ((b[22] >> 6) | (b[23] << 2) | ((b[24] & 0x0f) << 10)) };
        }
        if (chunk === 'VP8X' && b.length >= 30) {
            return { width: 1 + u24le(b, 24), height: 1 + u24le(b, 27) };
        }
        return null;
    }

    // The width and height an image's header declares, or null when it cannot be read
    function declaredSize(bytes, kind) {
        if (kind === KIND.PNG) {
            return bytes.length >= PNG_WIDTH_OFFSET + 8 ? { width: u32be(bytes, PNG_WIDTH_OFFSET), height: u32be(bytes, PNG_WIDTH_OFFSET + 4) } : null;
        }
        if (kind === KIND.JPEG) return jpegSize(bytes);
        if (kind === KIND.WEBP) return bytes.length > WEBP_CHUNK_OFFSET + 4 ? webpSize(bytes) : null;
        return null;
    }

    // A JPEG without its APP1..APP15 and COM segments (everything up to the first scan is walked;
    // the scan and what follows it are kept as they are), or null when the segments do not parse
    function stripJpeg(b) {
        const kept = [b.subarray(0, 2)];
        let i = 2;
        while (i + 3 < b.length) {
            if (b[i] !== 0xff) return null;
            const marker = b[i + 1];
            if (marker === JPEG_SOS) {
                kept.push(b.subarray(i));
                return ElyrnCrypto.concat(...kept);
            }
            if (JPEG_STANDALONE.has(marker) || marker === 0xff) return null;
            const end = i + 2 + u16be(b, i + 2);
            if (end > b.length) return null;
            const dropped = (marker >= JPEG_APP1 && marker <= JPEG_APP15) || marker === JPEG_COM;
            if (!dropped) kept.push(b.subarray(i, end));
            i = end;
        }
        return null;
    }

    // A PNG without its text, time and Exif chunks, or null when the chunks do not parse
    function stripPng(b) {
        const kept = [b.subarray(0, PNG_MAGIC.length)];
        let i = PNG_MAGIC.length;
        while (i + PNG_CHUNK_OVERHEAD <= b.length) {
            const end = i + PNG_CHUNK_OVERHEAD + u32be(b, i);
            if (end > b.length) return null;
            const type = String.fromCharCode(b[i + 4], b[i + 5], b[i + 6], b[i + 7]);
            if (!PNG_DROPPED.has(type)) kept.push(b.subarray(i, end));
            i = end;
            if (type === 'IEND') return i === b.length ? ElyrnCrypto.concat(...kept) : null;
        }
        return null;
    }

    // The encoded image with nothing but what draws it, or null when it does not parse
    function stripMetadata(bytes, kind) {
        if (kind === KIND.JPEG) return stripJpeg(bytes);
        if (kind === KIND.PNG) return stripPng(bytes);
        return null;
    }

    function withinLimit(size) {
        return Boolean(size) && size.width > 0 && size.height > 0 && size.width * size.height <= MAX_IMAGE_PIXELS;
    }

    // The decoded image, orientation applied, or throws: its header and its pixels both within
    // MAX_IMAGE_PIXELS (a header can lie). The caller closes it.
    async function decode(bytes, kind) {
        const size = declaredSize(bytes, kind);
        if (!size) throw new Error('unreadable image');
        if (!withinLimit(size)) throw Object.assign(new Error('image too large'), { tooLarge: true });
        const bitmap = await createImageBitmap(new Blob([bytes]), { imageOrientation: 'from-image' });
        if (!withinLimit(bitmap)) {
            bitmap.close();
            throw Object.assign(new Error('image too large'), { tooLarge: true });
        }
        return bitmap;
    }

    function encode(canvas, output) {
        return new Promise(resolve => canvas.toBlob(resolve, output.type, JPEG_QUALITY));
    }

    function newName(ext) {
        const random = globalThis.crypto.getRandomValues(new Uint8Array(NAME_RANDOM_BYTES));
        return NAME_PREFIX + Array.from(random, b => b.toString(16).padStart(2, '0')).join('') + '.' + ext;
    }

    function refused(code, params) {
        return { ok: false, code, params: params || null };
    }

    // What leaves for a chosen file: { ok: true, bytes, name, cleaned } or { ok: false, code, params }.
    // bytes is the chosen file's content; maxBytes the server's file limit. The original bytes
    // are released by the caller once a cleaned copy exists (one copy at a time where it can).
    async function prepare({ bytes, name, maxBytes }) {
        const kind = kindOf(bytes);
        if (!kind) return { ok: true, bytes, name: fileNameForSending(name), cleaned: false };
        const output = OUTPUT[kind];
        let bitmap = null;
        const canvas = document.createElement('canvas');
        try {
            bitmap = await decode(bytes, kind);
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            canvas.getContext('2d').drawImage(bitmap, 0, 0);
            const blob = await encode(canvas, output);
            if (!blob) return refused(Errors.CODES.E_FILE_IMAGE_NOT_CLEANED);
            const encoded = new Uint8Array(await blob.arrayBuffer());
            // The engine wrote what was asked, without what it adds of its own, or nothing is sent
            const cleaned = kindOf(encoded) === output.kind ? stripMetadata(encoded, output.kind) : null;
            if (!cleaned) return refused(Errors.CODES.E_FILE_IMAGE_NOT_CLEANED);
            if (cleaned.length > maxBytes) return refused(Errors.CODES.E_FILE_CLEANED_TOO_LARGE, { max: formatFileSize(maxBytes) });
            return { ok: true, bytes: cleaned, name: newName(output.ext), cleaned: true };
        } catch (error) {
            if (error && error.tooLarge) {
                return refused(Errors.CODES.E_FILE_IMAGE_TOO_BIG, { max: Math.floor(MAX_IMAGE_PIXELS / PIXELS_PER_MEGAPIXEL) });
            }
            Log.warn(Errors.CODES.E_FILE_IMAGE_NOT_CLEANED, error);
            return refused(Errors.CODES.E_FILE_IMAGE_NOT_CLEANED);
        } finally {
            if (bitmap) bitmap.close();
            canvas.width = 0;
            canvas.height = 0;
        }
    }

    return Object.freeze({ MAX_IMAGE_PIXELS, JPEG_QUALITY, kindOf, declaredSize, stripMetadata, decode, prepare });
})();
