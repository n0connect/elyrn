// ========================================
// FILE COMPOSER (choosing a file and uploading it before its message)
// ========================================
// One job: hold the one file chosen for the open conversation, from the moment it is chosen
// (the attach control, a pasted file, a file dropped on the conversation) until its message is
// stored (docs/architecture/files.md). A chosen file is checked before it is read (empty, over
// this server's limit) and read once; its bytes are delivered exactly as they are: elyrn. never
// reads, interprets or changes a file's content. The only thing it sets is the name the file is
// sent under (validation.js outgoingFileName): the chosen name never leaves the device. The chip
// in the composer shows the name that will be sent, the size, a way to remove the file, and,
// every time, the notice that the file goes as it is (Errors.NOTICE.FILE_SENT_AS_IS). Pressing
// send uploads its parts (file-transfer.js) and gives chat.js the description its message
// carries. An upload that
// stops keeps its file id and continues where it stopped on the next send, while the page
// lives; one the server lost track of starts afresh under a new id. Leaving the conversation,
// removing the file or ending the session cancels an upload between parts: nothing is sent.

const FileComposer = (() => {
    'use strict';

    const PREPARING = 'preparing';
    const UPLOADING = 'uploading';
    const REMOVE_LABEL = '×';
    const REMOVE_TITLE = 'remove the file';

    let maxBytes = 0;                    // this server's file_max_bytes; 0 outside a session
    let activeConversation = () => null; // chat.js: the open conversation's id
    // The chosen file: { convId, bytes, name, size, ready, upload: { file, next, done } | null }
    let chosen = null;

    const el = (id) => document.getElementById(id);

    // Wires the controls once (app.js)
    function install() {
        el('attachBtn').addEventListener('click', () => {
            if (activeConversation() && !busy()) el('fileInput').click();
        });
        el('fileInput').addEventListener('change', () => {
            // Copied first: emptying the input empties its file list too (WebKit)
            const files = Array.from(el('fileInput').files || []);
            el('fileInput').value = '';
            choose(files);
        });
        el('fileRemoveBtn').addEventListener('click', clear);
        el('messageInput').addEventListener('paste', event => {
            const files = event.clipboardData && event.clipboardData.files;
            if (!files || files.length === 0) return;
            event.preventDefault();
            choose(Array.from(files));
        });
        const target = el('chatView');
        target.addEventListener('dragover', event => {
            if (event.dataTransfer && Array.from(event.dataTransfer.types).includes('Files')) event.preventDefault();
        });
        target.addEventListener('drop', event => {
            if (!event.dataTransfer || event.dataTransfer.files.length === 0) return;
            event.preventDefault();
            choose(Array.from(event.dataTransfer.files));
        });
    }

    function start(limits) {
        maxBytes = limits.maxBytes;
        activeConversation = limits.activeConversation;
        render();
    }

    function stop() {
        clear();
        maxBytes = 0;
        activeConversation = () => null;
    }

    function busy() {
        return Boolean(chosen && (!chosen.ready || chosen.uploading));
    }

    // Checked before reading: one file, not empty, within this server's limit
    async function choose(list) {
        const convId = activeConversation();
        if (!convId || maxBytes === 0 || busy()) return;
        if (!list || list.length !== 1) {
            Errors.report(Errors.CODES.W_FILE_ONE_AT_A_TIME);
            return;
        }
        const source = list[0];
        if (source.size === 0) {
            Errors.report(Errors.CODES.E_FILE_EMPTY);
            return;
        }
        if (source.size > maxBytes) {
            Errors.report(Errors.CODES.E_FILE_TOO_LARGE, { max: formatFileSize(maxBytes) });
            return;
        }
        const mine = { convId, bytes: null, name: '', size: 0, ready: false, uploading: false, upload: null };
        chosen = mine;
        render();
        const bytes = await read(source);
        if (chosen !== mine) return;  // removed, replaced or the conversation left meanwhile
        if (!bytes) {
            chosen = null;
            render();
            Errors.report(Errors.CODES.E_FILE_NOT_READABLE);
            return;
        }
        const name = outgoingFileName(source.name, globalThis.crypto.getRandomValues(new Uint8Array(OUTGOING_NAME_RANDOM_BYTES)));
        Object.assign(mine, { bytes, name, size: bytes.length, ready: true });
        render();
    }

    // The file's bytes, read once and left as they are, or null when it changed or vanished on
    // disk while it was read
    async function read(source) {
        let bytes;
        try {
            bytes = new Uint8Array(await source.arrayBuffer());
        } catch (error) {
            return null;
        }
        return bytes.length === source.size && bytes.length > 0 ? bytes : null;
    }

    // The chosen file of conversation convId: { name, ready } or null
    function attached(convId) {
        return chosen && chosen.convId === convId ? { name: chosen.name, ready: chosen.ready } : null;
    }

    // Uploads the chosen file's parts for conv (continuing a stopped upload). Resolves to the
    // file description its message carries, or null once the reason was shown (or the upload
    // was cancelled: cancelled() is chat.js's, and removing the file cancels too).
    async function upload({ api, conv, cancelled }) {
        const mine = chosen;
        if (!mine || mine.convId !== conv.id || !mine.ready || mine.uploading) return null;
        if (!mine.upload) {
            const { id, key } = ElyrnFileCrypto.newFile();
            mine.upload = {
                file: { id, key, size: mine.size, hash: await ElyrnFileCrypto.hashOf(mine.bytes), name: mine.name },
                next: 0, done: false
            };
        }
        const state = mine.upload;
        if (state.done) return state.file;
        mine.uploading = true;
        render();
        try {
            const outcome = await FileTransfer.upload({
                api, conversationId: conv.id, file: state.file, bytes: mine.bytes, from: state.next,
                onProgress: ({ done, total }) => showStatus(`${UPLOADING} ${done}/${total}`),
                cancelled: () => cancelled() || chosen !== mine
            });
            if (outcome.ok) {
                state.done = true;
                return state.file;
            }
            state.next = outcome.next;
            if (outcome.restart) mine.upload = null;
            if (outcome.quiet) {
                if (outcome.code) Log.warn(outcome.code);
            } else {
                Errors.report(outcome.code);
            }
            return null;
        } finally {
            mine.uploading = false;
            if (chosen === mine) render();
        }
    }

    // The message announcing file was stored: the file leaves the composer
    function sent(file) {
        if (chosen && chosen.upload && chosen.upload.file.id === file.id) clear();
    }

    // Removes the chosen file (and cancels its upload between parts)
    function clear() {
        if (chosen && chosen.bytes) chosen.bytes = null;
        chosen = null;
        render();
    }

    function showStatus(text) {
        el('fileChipStatus').textContent = text;
    }

    function render() {
        const chip = el('fileChip');
        const attach = el('attachBtn');
        attach.style.display = maxBytes > 0 ? 'inline-block' : 'none';
        attach.disabled = busy();
        if (!chosen) {
            el('sendBtn').disabled = false;
            chip.style.display = 'none';
            el('fileChipName').textContent = '';
            el('fileChipSize').textContent = '';
            el('fileChipNotice').textContent = '';
            showStatus('');
            return;
        }
        chip.style.display = 'flex';
        // Every time a file is chosen, for as long as it is: it goes exactly as it is
        el('fileChipNotice').textContent = Errors.NOTICE.FILE_SENT_AS_IS;
        el('fileChipName').textContent = chosen.ready ? chosen.name : '';
        el('fileChipSize').textContent = chosen.ready ? formatFileSize(chosen.size) : '';
        if (!chosen.ready) showStatus(PREPARING);
        else if (!chosen.uploading) showStatus('');
        const remove = el('fileRemoveBtn');
        remove.textContent = REMOVE_LABEL;
        remove.title = REMOVE_TITLE;
        el('sendBtn').disabled = !chosen.ready || chosen.uploading;
    }

    return Object.freeze({ install, start, stop, attached, upload, sent, clear });
})();
