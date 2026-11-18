// ========================================
// FILE CARD (a received file in its message bubble)
// ========================================
// One job: show a file a message announces and hand it over on request (docs/architecture/files.md).
// The card shows the name (other people's data: text only) and the size, and fetches nothing
// until `view` or `save` is pressed. `view` draws the opened bytes on a canvas, and only when
// they are PNG, JPEG or WebP by their first bytes and within ImageClean.MAX_IMAGE_PIXELS; SVG,
// HTML and everything else are never rendered, only saved. `save` hands the bytes to the browser
// as a download under the saved name (validation.js saveName); its object URL is revoked soon
// after. One opened file is kept at a time (the last one), so view then save fetches once.

const FileCard = (() => {
    'use strict';

    const VIEW_LABEL = 'view';
    const SAVE_LABEL = 'save';
    const FETCHING = 'fetching';
    const SAVE_TYPE = 'application/octet-stream';
    // Long enough for the browser to start the download; the URL is useless after it
    const REVOKE_AFTER_MS = 30000;

    // The one file kept opened: { card, bytes }; dropped once its card leaves the page
    let held = null;

    function button(text, onClick) {
        const element = document.createElement('button');
        element.className = 'menu-opt file-action';
        element.textContent = text;
        element.addEventListener('click', onClick);
        return element;
    }

    // The opened bytes of the card's file, fetched now if they are not held; null once the
    // reason was shown (or the card left the page)
    async function bytesFor(card, message, status) {
        if (held && !held.card.isConnected) held = null;
        if (held && held.card === card) return held.bytes;
        status.textContent = FETCHING;
        const fetched = await message.fetchFile({
            onProgress: ({ done, total }) => { status.textContent = `${FETCHING} ${done}/${total}`; },
            cancelled: () => !card.isConnected
        });
        status.textContent = '';
        if (!fetched.ok) {
            if (!fetched.quiet) Errors.report(fetched.code);
            else if (fetched.code) Log.warn(fetched.code);
            return null;
        }
        held = { card, bytes: fetched.bytes };
        return fetched.bytes;
    }

    async function view(card, message, status, canvas) {
        const bytes = await bytesFor(card, message, status);
        if (!bytes) return;
        const kind = ImageClean.kindOf(bytes);
        if (!kind) {
            Errors.report(Errors.CODES.W_FILE_NOT_VIEWABLE);
            return;
        }
        let bitmap = null;
        try {
            bitmap = await ImageClean.decode(bytes, kind);
            canvas.width = bitmap.width;
            canvas.height = bitmap.height;
            canvas.getContext('2d').drawImage(bitmap, 0, 0);
            canvas.style.display = 'block';
        } catch (error) {
            Errors.report(error && error.tooLarge ? Errors.CODES.W_FILE_VIEW_TOO_LARGE : Errors.CODES.W_FILE_NOT_VIEWABLE, null, error);
        } finally {
            if (bitmap) bitmap.close();
        }
    }

    async function save(card, message, status) {
        const bytes = await bytesFor(card, message, status);
        if (!bytes) return;
        let url = null;
        try {
            url = URL.createObjectURL(new Blob([bytes], { type: SAVE_TYPE }));
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

    // The card for a message carrying a file ({ file, fetchFile })
    function create(message) {
        const card = document.createElement('div');
        card.className = 'file-card';
        const name = document.createElement('span');
        name.className = 'file-name';
        name.textContent = neutralizeReceivedText(message.file.name);
        const size = document.createElement('span');
        size.className = 'file-size';
        size.textContent = formatFileSize(message.file.size);
        const status = document.createElement('span');
        status.className = 'file-status';
        status.setAttribute('role', 'status');
        const canvas = document.createElement('canvas');
        canvas.className = 'file-view';
        canvas.style.display = 'none';
        // One fetch per card at a time: a double click on view or save waits for the first
        const key = 'file-card-' + message.file.id + '-' + message.seq;
        card.append(name, size,
            button(VIEW_LABEL, () => once(key, () => view(card, message, status, canvas))),
            button(SAVE_LABEL, () => once(key, () => save(card, message, status))),
            status, canvas);
        return card;
    }

    return Object.freeze({ create });
})();
