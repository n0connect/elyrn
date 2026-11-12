// ========================================
// LOG (the only file that writes to the console)
// ========================================
// A log line is a code plus a whitelisted detail. Nothing else gets through: account numbers,
// auth keys, room and invite codes, message text and public keys must never reach the console
// (extensions, shared screens and bug reports read it), so free text is not accepted at all.

const Log = (() => {
    'use strict';

    const CODE_SHAPE = /^[EWI]_[A-Z0-9_]+$/;
    // An error's name is a class name such as TypeError, never a message
    const NAME_SHAPE = /^[A-Za-z]{1,40}$/;
    const MAX_STATUS = 999;
    const BAD_CODE = 'E_LOG_BAD_CODE';

    // Keeps only { name, status } of the right shape; everything else is dropped unseen
    function safeDetail(detail) {
        const safe = {};
        if (!detail || typeof detail !== 'object') return safe;
        if (typeof detail.name === 'string' && NAME_SHAPE.test(detail.name)) {
            safe.name = detail.name;
        }
        if (Number.isSafeInteger(detail.status) && detail.status >= 0 && detail.status <= MAX_STATUS) {
            safe.status = detail.status;
        }
        return safe;
    }

    function write(level, code, detail) {
        // A test or worker context may have no console: logging must never throw
        if (typeof console === 'undefined') return;
        const safeCode = typeof code === 'string' && CODE_SHAPE.test(code) ? code : BAD_CODE;
        const safe = safeDetail(detail);
        if (Object.keys(safe).length > 0) {
            console[level]('[elyrn]', safeCode, safe);
        } else {
            console[level]('[elyrn]', safeCode);
        }
    }

    return Object.freeze({
        info: (code, detail) => write('info', code, detail),
        warn: (code, detail) => write('warn', code, detail),
        error: (code, detail) => write('error', code, detail)
    });
})();
