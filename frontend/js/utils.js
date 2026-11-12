// ========================================
// UTILITY FUNCTIONS
// ========================================

const API_BASE_URL = '/api/v2';
// The static status pages nginx serves (nginx-site.conf, nginx-api-errors.conf); the names are
// opaque so they cannot be guessed at. The app itself only ever leaves for the 404 page: every
// API failure is explained in place (apiCall).
const STATUS_PAGES = Object.freeze({
    NOT_FOUND: '/e0ab670f-6801-4475-b337-c08d5adb9e73.html'
});
// The longest any API request may take, answer body included: past it the request is aborted
// and reported as no answer (status 0), so no button, lock or queued sync waits forever. The live
// event stream (EventSource, chat.js) is not an apiCall and is never cut by it.
const REQUEST_TIMEOUT_MS = 30000;
// Far enough left that the copy fallback's textarea is never on screen
const OFFSCREEN_LEFT = '-999999px';

// Copies text to the clipboard. Resolves only when the copy happened and rejects otherwise, so
// every caller's catch tells the user to copy by hand instead of announcing a copy that failed.
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    }
    return copyBySelection(text);
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
// Returns { ok, status, data, timedOut } where status 0 means no answer: a network failure, or
// REQUEST_TIMEOUT_MS passed (timedOut).
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
        return { ok: response.ok, status: response.status, data: data, timedOut: false };
    } catch (error) {
        // Only the timeout reaches here: the answer stopped arriving
        return noAnswer(error);
    }
}

// The answer's JSON, or null when there is none or it does not parse. Any other body is drained
// only to free the connection. Throws only when the timeout cuts the body off.
async function readBody(response) {
    const contentType = response.headers.get('content-type') || '';
    const json = response.status !== 204 && contentType.includes('application/json');
    try {
        if (json) {
            return await response.json();
        }
        await response.text();
        return null;
    } catch (error) {
        if (isTimeout(error)) throw error;
        return null;
    }
}

// AbortSignal.timeout aborts with a TimeoutError
function isTimeout(error) {
    return Boolean(error) && error.name === 'TimeoutError';
}

// The result of a request that got no answer; a timeout is logged here, once, whatever the
// caller then reports
function noAnswer(error) {
    const timedOut = isTimeout(error);
    if (timedOut) {
        Log.warn(Errors.INTERNAL.W_REQUEST_TIMED_OUT);
    }
    return { ok: false, status: 0, data: null, timedOut: timedOut };
}
