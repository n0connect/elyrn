// ========================================
// UTILITY FUNCTIONS
// ========================================

const API_BASE_URL = '/api/v2';
// The static status page for page navigation (nginx-site.conf); its name is opaque so it cannot
// be guessed at. API failures never lead to a page: nginx answers them JSON with a registered code
// (nginx-api-errors.conf) and the app explains every one in place (apiCall, Errors.fromResult).
const STATUS_PAGES = Object.freeze({
    NOT_FOUND: '/e0ab670f-6801-4475-b337-c08d5adb9e73.html'
});
// The longest any API request may take, answer body included: past it the request is aborted
// and reported as no answer (status 0), so no button, lock or queued sync waits forever. The live
// event stream (EventSource, chat.js) is not an apiCall and is never cut by it.
const REQUEST_TIMEOUT_MS = 30000;
// The largest answer apiCall reads. A full page of messages at this client's own maxima (1000
// messages of at most 11000 characters, auth.js and chat.js) stays well below it; a larger
// answer is a hostile or broken server, refused unread past this point.
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
// A send (a message or a friend request) answered 409 "Id taken" (Errors.idTaken: the id is held
// by something else, nothing stored) goes again under a fresh id this many times at most; the
// agent's maxIDRedraws (backend/internal/agent/limits.go) is the same bound
const MAX_ID_REDRAWS = 1;
// The error name a refused oversized answer carries (readCapped), like TimeoutError for a timeout
const TOO_LARGE = 'ResponseTooLarge';
// Far enough left that the copy fallback's textarea is never on screen
const OFFSCREEN_LEFT = '-999999px';
// A room or invite code is copied for the user to paste elsewhere: after this long it is cleared
// from the clipboard (clearClipboardLater), if the clipboard still holds it
const CLIPBOARD_CLEAR_DELAY_MS = 120000;

// What this page last put in the clipboard, as far as the page can tell: a copy it made, or the
// text the user copied or cut in it (noteUserCopy). Anything copied in another app is unseen.
let lastCopied = null;

// Copies text to the clipboard. Resolves only when the copy happened and rejects otherwise, so
// every caller's catch tells the user to copy by hand instead of announcing a copy that failed.
async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
    } else {
        await copyBySelection(text);
    }
    lastCopied = text;
}

// Copies text and confirms with notice, or asks the user to copy it by hand. clearLater: text is
// a secret worth clearing from the clipboard afterwards (a room or invite code: clearClipboardLater).
async function copyWithNotice(text, notice, clearLater) {
    try {
        await copyToClipboard(text);
    } catch (error) {
        Errors.report(Errors.CODES.W_COPY_MANUALLY, null, error);
        return;
    }
    showSuccess(notice);
    if (clearLater) clearClipboardLater(text);
}

// The document's copy and cut events (app.js): what the user copied replaces what the page did
function noteUserCopy() {
    lastCopied = document.getSelection ? String(document.getSelection()) : null;
}

// Best effort, never throws: empties the clipboard if it still holds value. Where the browser
// lets the page read the clipboard without asking, its content is compared; otherwise value must
// still be the last thing copied in this page. A page without focus may not write the clipboard;
// that is logged, never shown.
async function clearClipboardIfHolds(value) {
    if (!navigator.clipboard || !window.isSecureContext || lastCopied !== value) return;
    try {
        if (await clipboardReadable() && await navigator.clipboard.readText() !== value) return;
        await navigator.clipboard.writeText('');
        lastCopied = null;
    } catch (error) {
        Log.warn(Errors.INTERNAL.W_CLIPBOARD_NOT_CLEARED, error);
    }
}

// The same, CLIPBOARD_CLEAR_DELAY_MS from now
function clearClipboardLater(value) {
    setTimeout(() => clearClipboardIfHolds(value), CLIPBOARD_CLEAR_DELAY_MS);
}

// Whether reading the clipboard is already granted: a read that would ask the user is never made
async function clipboardReadable() {
    if (!navigator.permissions || !navigator.clipboard.readText) return false;
    try {
        return (await navigator.permissions.query({ name: 'clipboard-read' })).state === 'granted';
    } catch (error) {
        // A browser that does not know the permission cannot be asked about it
        return false;
    }
}

// Actions running now, by key (once)
const runningActions = new Set();

// Runs action unless one under the same key is still running (a double click, Enter held down,
// two buttons for one thing). The key is claimed synchronously, before action's first await, so
// a second press always finds it taken. Resolves to action's result, or undefined when skipped.
async function once(key, action) {
    if (runningActions.has(key)) return undefined;
    runningActions.add(key);
    try {
        return await action();
    } finally {
        runningActions.delete(key);
    }
}

// Wraps task so at most one run is in flight. A call arriving meanwhile gets the promise of the
// run in flight, and exactly one more run follows it however many calls arrived, so every caller
// awaits a run that started after its call.
function singleFlight(task) {
    let running = null;
    let again = false;
    return function run() {
        if (running) {
            again = true;
            return running;
        }
        running = (async () => {
            try {
                do {
                    again = false;
                    await task();
                } while (again);
            } finally {
                running = null;
                again = false;
            }
        })();
        return running;
    };
}

// Whether a page must fetch its updates instead of waiting for its live event stream (chat.js
// watchdog): only a logged-in, visible page polls, and only once the stream has delivered no
// event of any kind for silenceLimitMs. Anything that is no proof of a recent event (a time that
// is not finite, an event later than now, a limit that is not a positive number) counts as
// silence: a needless poll costs one request, a missed one hides messages until a tab switch.
function streamNeedsPolling(now, lastEventAt, silenceLimitMs, visible, loggedIn) {
    if (loggedIn !== true || visible !== true) return false;
    const recent = Number.isFinite(now) && Number.isFinite(lastEventAt) && Number.isFinite(silenceLimitMs) &&
        silenceLimitMs > 0 && lastEventAt <= now && now - lastEventAt < silenceLimitMs;
    return !recent;
}

// Fallback for older browsers and insecure contexts: execCommand reports failure by returning
// false or by throwing, depending on the browser; both reject
function copyBySelection(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'absolute';
    textArea.style.left = OFFSCREEN_LEFT;
    document.body.prepend(textArea);
    textArea.select();
    try {
        if (!document.execCommand('copy')) {
            throw new Error('copy refused');
        }
        return Promise.resolve();
    } catch (error) {
        Log.error(Errors.INTERNAL.E_CLIPBOARD_FALLBACK_FAILED, error);
        return Promise.reject(error);
    } finally {
        textArea.remove();
    }
}

// JSON API call for in-app actions: never redirects, never throws.
// Callers decide how to surface errors (Errors.fromResult) and what 401 means.
// SECURITY: the HttpOnly session cookie travels with same-origin requests only.
// Returns { ok, status, data, timedOut, tooLarge } where status 0 means no usable answer: a
// network failure, REQUEST_TIMEOUT_MS passed (timedOut), or an answer over MAX_RESPONSE_BYTES
// (tooLarge). A refused answer counts as none: whether the server acted on the request is open.
async function apiCall(method, path, body) {
    const options = {
        method: method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {},
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    let response;
    try {
        response = await fetch(`${API_BASE_URL}${path}`, options);
    } catch (error) {
        return noAnswer(error);
    }

    try {
        const data = await readBody(response);
        return { ok: response.ok, status: response.status, data: data, timedOut: false, tooLarge: false };
    } catch (error) {
        // Only the timeout and an oversized answer reach here
        return noAnswer(error);
    }
}

// The answer's JSON, or null when there is none or it does not parse. Any other body is drained
// only to free the connection. Throws only when the timeout cuts the body off or the body is
// larger than MAX_RESPONSE_BYTES.
async function readBody(response) {
    const contentType = response.headers.get('content-type') || '';
    const json = response.status !== 204 && contentType.includes('application/json');
    let text;
    try {
        text = await readCapped(response);
    } catch (error) {
        if (isTimeout(error) || isTooLarge(error)) throw error;
        return null;
    }
    if (!json) return null;
    try {
        return JSON.parse(text);
    } catch (error) {
        return null;
    }
}

// The body as text, read up to MAX_RESPONSE_BYTES: a declared length over it is refused before
// reading, and an undeclared one is cut off as soon as it passes it
async function readCapped(response) {
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
        throw tooLarge();
    }
    if (!response.body) return '';
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
            // Stops the download; the request is already reported, so a failed cancel is moot
            reader.cancel().catch(error => Log.warn(Errors.INTERNAL.W_RESPONSE_TOO_LARGE, error));
            throw tooLarge();
        }
        chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return new TextDecoder().decode(bytes);
}

function tooLarge() {
    const error = new Error('response too large');
    error.name = TOO_LARGE;
    return error;
}

// AbortSignal.timeout aborts with a TimeoutError
function isTimeout(error) {
    return Boolean(error) && error.name === 'TimeoutError';
}

function isTooLarge(error) {
    return Boolean(error) && error.name === TOO_LARGE;
}

// The result of a request that got no usable answer; a timeout or an oversized answer is logged
// here, once, whatever the caller then reports
function noAnswer(error) {
    const timedOut = isTimeout(error);
    const refused = isTooLarge(error);
    if (timedOut) {
        Log.warn(Errors.INTERNAL.W_REQUEST_TIMED_OUT);
    } else if (refused) {
        Log.warn(Errors.INTERNAL.W_RESPONSE_TOO_LARGE);
    }
    return { ok: false, status: 0, data: null, timedOut: timedOut, tooLarge: refused };
}
