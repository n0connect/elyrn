// ========================================
// FILE CARD (a received file in its message bubble)
// ========================================
// One job: show a file a message announces and hand it over on request, exactly as it was sent
// (docs/architecture/files.md). elyrn. never reads, interprets or displays a file's content:
// the card shows the name the file was sent under (other people's data: text only), its size,
// a fixed line saying it comes from another member and that opening it is the receiver's own
// decision, and one control, `save`. Nothing is fetched until it is pressed; then the parts are
// fetched and opened, the hash is checked (file-transfer.js), and the bytes are handed to the
// browser as a download under the saved name (validation.js saveName). Its object URL is revoked
// soon after, and the bytes are not kept.

const FileCard = (() => {
    'use strict';

    const SAVE_TYPE = 'application/octet-stream';
    // Long enough for the browser to start the download; the URL is useless after it
    const REVOKE_AFTER_MS = 30000;

    async function save(card, message, status) {
        status.textContent = UI_TEXT.FILE_FETCHING;
        const fetched = await message.fetchFile({
            onProgress: ({ done, total }) => { status.textContent = UI_TEXT.FILE_PROGRESS(UI_TEXT.FILE_FETCHING, done, total); },
            cancelled: () => !card.isConnected
        });
        status.textContent = '';
        if (!fetched.ok) {
            if (!fetched.quiet) Errors.report(fetched.code);
            else if (fetched.code) Log.warn(fetched.code);
            return;
        }
        let url = null;
        try {
            url = URL.createObjectURL(new Blob([fetched.bytes], { type: SAVE_TYPE }));
            const link = document.createElement('a');
            link.href = url;
            link.download = saveName(message.file.name);
            link.click();
        } catch (error) {
            Errors.report(Errors.CODES.E_FILE_NOT_SAVED, null, error);
        } finally {
            if (url) setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
        }
    }

    function text(className, value) {
        const span = document.createElement('span');
        span.className = className;
        span.textContent = value;
        return span;
    }

    // The card for a message carrying a file ({ file, fetchFile })
    function create(message) {
        const card = document.createElement('div');
        card.className = 'file-card';
        const status = text('file-status', '');
        status.setAttribute('role', 'status');
        const button = document.createElement('button');
        button.className = 'menu-opt file-action';
        button.textContent = UI_TEXT.FILE_SAVE;
        // One fetch per card at a time: a double click waits for the first
        const key = 'file-card-' + message.file.id + '-' + message.seq;
        button.addEventListener('click', () => once(key, () => save(card, message, status)));
        card.append(text('file-name', neutralizeReceivedText(message.file.name)), text('file-size', formatFileSize(message.file.size)),
            button, status, text('file-notice', Errors.NOTICE.FILE_FROM_MEMBER));
        return card;
    }

    return Object.freeze({ create });
})();
