// ========================================
// FILE TRANSFER (sealed parts to and from the server)
// ========================================
// One job: move a file's sealed parts (file-crypto.js) through the file routes, one part at a
// time, in order (docs/architecture/files.md, docs/api/rest-api.md "Files"). The server is an
// untrusted store: an answer is judged by its status and registered sentence only, and a part
// it serves must open (file-crypto.js) or the file is unreadable.
//
// A request that got no answer, or a server error, is tried again PART_ATTEMPTS times with a
// growing pause; then the transfer stops and says where (`next`), so a later upload of the same
// file id continues there (parts already stored answer 409 "Conflict", which means stored). The
// caller's cancelled() is asked before every part and after every pause: a conversation left or
// a session ended stops a transfer between parts, never half-way through one.
//
// Memory: an upload holds the file's bytes (one copy, the caller's) and one sealed part; a
// download holds the one buffer the file is assembled in and one served part.

const FileTransfer = (() => {
    'use strict';

    const F = ElyrnFileCrypto;
    // Tries per part before the transfer stops, and the first pause between them (doubled each time)
    const PART_ATTEMPTS = 3;
    const RETRY_BASE_MS = 1000;
    const CREATED = 201;
    const CONFLICT = 409;
    const NOT_FOUND = 404;
    const UNAUTHORIZED = 401;
    const TOO_MANY = 429;
    const INSUFFICIENT_STORAGE = 507;
    const SERVER_ERROR = 500;
    // How an ended transfer is told: { ok: true, ... } or { ok: false, code, next, restart, quiet }
    const CANCELLED = Object.freeze({ ok: false, code: Errors.INTERNAL.W_FILE_TRANSFER_CANCELLED, quiet: true });

    function filesPath(conversationId) {
        return `/conversations/${conversationId}/files`;
    }

    function pause(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // No answer, or a server error: worth another try
    function transient(result) {
        return result.status === 0 || result.status >= SERVER_ERROR;
    }

    // One request with its retries: the last result, or null when cancelled meanwhile
    async function withRetries(request, cancelled) {
        let result = null;
        for (let attempt = 0; attempt < PART_ATTEMPTS; attempt++) {
            if (attempt > 0) {
                Log.warn(Errors.INTERNAL.W_FILE_PART_RETRIED, result);
                await pause(RETRY_BASE_MS * 2 ** (attempt - 1));
                if (cancelled()) return null;
            }
            result = await request();
            if (!transient(result)) break;
        }
        return result;
    }

    // What a refused part means: { code, restart (a new upload under a fresh id is needed), quiet }
    function refusal(result) {
        const said = Errors.fromResult(result);
        if (result.status === UNAUTHORIZED) return { code: null, quiet: true };
        if (result.status === NOT_FOUND) return { code: Errors.CODES.W_FILE_CONVERSATION_GONE };
        if (result.status === CONFLICT) return { code: Errors.CODES.E_FILE_UPLOAD_RESTART, restart: true };
        if (result.status === TOO_MANY) {
            return { code: said === Errors.CODES.W_FILE_BUDGET_SPENT ? said : Errors.CODES.W_FILE_RATE_LIMITED };
        }
        if (result.status === INSUFFICIENT_STORAGE) {
            return { code: said === Errors.CODES.E_FILE_QUOTA_REACHED ? said : Errors.CODES.E_FILE_STORE_FULL };
        }
        if (result.status === 0) return { code: Errors.CODES.W_FILE_UPLOAD_STOPPED };
        if (result.status >= SERVER_ERROR) return { code: Errors.CODES.W_FILE_SERVER_BUSY };
        return { code: Errors.CODES.E_FILE_UPLOAD_REFUSED };
    }

    // A 409 that means "stored": the plain "Conflict" (the uploader's own identical part), told
    // from "Id taken" and "File part out of order" by their registered sentences
    function storedBefore(result) {
        if (result.status !== CONFLICT) return false;
        const said = Errors.fromResult(result);
        return said !== Errors.CODES.E_MESSAGE_ID_TAKEN && said !== Errors.CODES.E_FILE_UPLOAD_RESTART;
    }

    // Uploads parts from..count-1 of file (its bytes: `bytes`), in order. Resolves to
    // { ok: true } or { ok: false, code, next (the first part not stored), restart, quiet }.
    async function upload({ api, conversationId, file, bytes, from = 0, onProgress, cancelled }) {
        const parts = F.partCount(file.size);
        for (let index = from; index < parts; index++) {
            if (cancelled()) return { ...CANCELLED, next: index };
            const data = await F.sealPart({ conversationId, file, bytes, index });
            const result = await withRetries(() => api('POST', filesPath(conversationId), { id: file.id, part: index, data }), cancelled);
            if (!result) return { ...CANCELLED, next: index };
            if (result.status !== CREATED && !storedBefore(result)) {
                return { ok: false, next: index, restart: false, quiet: false, ...refusal(result) };
            }
            if (onProgress) onProgress({ done: index + 1, total: parts });
        }
        return { ok: true };
    }

    // The served part of one answer, or null: exactly {"data": <one sealed part>}
    function servedPart(result) {
        const data = result.data;
        if (!result.ok || data === null || typeof data !== 'object' || Object.keys(data).length !== 1 ||
            typeof data.data !== 'string' || data.data.length !== F.SEALED_PART_CHARS) {
            return null;
        }
        return data.data;
    }

    // Fetches and opens every part of file. Resolves to { ok: true, bytes } (exactly the file
    // that hashes to file.hash) or { ok: false, code, quiet }; nothing of a failed file is kept.
    async function download({ api, conversationId, file, onProgress, cancelled }) {
        const parts = F.partCount(file.size);
        const into = new Uint8Array(file.size);
        const fail = (code, quiet = false) => {
            into.fill(0);
            return { ok: false, code, quiet };
        };
        for (let index = 0; index < parts; index++) {
            if (cancelled()) return fail(CANCELLED.code, true);
            const result = await withRetries(() => api('GET', `${filesPath(conversationId)}/${file.id}?part=${index}`), cancelled);
            if (!result) return fail(CANCELLED.code, true);
            if (result.status === UNAUTHORIZED) return fail(null, true);
            if (result.status === NOT_FOUND) return fail(Errors.CODES.W_FILE_GONE);
            if (!result.ok) return fail(Errors.CODES.E_FILE_DOWNLOAD_STOPPED);
            const data = servedPart(result);
            try {
                if (data === null) throw new Error('malformed part');
                await F.openPart({ conversationId, file, index, data, into });
            } catch (error) {
                return fail(Errors.CODES.E_FILE_UNREADABLE);
            }
            if (onProgress) onProgress({ done: index + 1, total: parts });
        }
        if (!(await F.matches(file, into))) return fail(Errors.CODES.E_FILE_UNREADABLE);
        return { ok: true, bytes: into };
    }

    return Object.freeze({ PART_ATTEMPTS, RETRY_BASE_MS, upload, download });
})();
