// ========================================
// UTILITY FUNCTIONS
// ========================================

const API_BASE_URL = '/api/v2';
// An account number is 32 random bytes in base64url
const ACCOUNT_NUMBER_LEN = 43;
const ACCOUNT_NUMBER_REGEX = new RegExp('^[A-Za-z0-9_-]{' + ACCOUNT_NUMBER_LEN + '}$');
// The static status pages nginx serves; the names are opaque so they cannot be guessed at
const STATUS_PAGES = Object.freeze({
    BAD_REQUEST: '/76e556a4-0575-4d98-a663-73b1080f26df.html',
    SESSION_EXPIRED: '/90b6b048-4bc9-4083-8585-9063c8e7332e.html',
    FORBIDDEN: '/cb012905-229f-4bf6-bdf4-8778ab34d8d7.html',
    NOT_FOUND: '/e0ab670f-6801-4475-b337-c08d5adb9e73.html',
    RATE_LIMITED: '/8ec9c7e3-a58c-40b1-a918-f8cc67c4fc59.html',
    SERVER_ERROR: '/9a24ed32-d32d-4b4b-a70e-a0bfd39f6710.html'
});
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

// ========================================
// ERROR HANDLING & STATUS PAGE REDIRECTS
// ========================================

// Handle error responses and redirect to appropriate status pages
async function handleErrorResponse(response) {
    const status = response.status;
    
    // Determine redirect URL first (before reading body)
    let redirectUrl = null;
    
    // HTTP status codes are the protocol's own names for these cases
    switch(status) {
        case 204:
            // No Content - usually successful DELETE, no redirect needed
            return; // Notification is sufficient
        
        case 400:
            redirectUrl = STATUS_PAGES.BAD_REQUEST;
            break;
        
        case 401:
            // Session is gone: forget the stored identity key, then redirect
            if (typeof Keystore !== 'undefined') {
                Keystore.wipe();
            }
            redirectUrl = STATUS_PAGES.SESSION_EXPIRED;
            break;
        
        case 403:
            redirectUrl = STATUS_PAGES.FORBIDDEN;
            break;
        
        case 404:
            redirectUrl = STATUS_PAGES.NOT_FOUND;
            break;
        
        case 429:
            redirectUrl = STATUS_PAGES.RATE_LIMITED;
            break;
        
        case 500:
        case 502:
        case 503:
        case 504:
            redirectUrl = STATUS_PAGES.SERVER_ERROR;
            break;
        
        default:
            // Unknown errors - show general error message
            // SECURITY: Never show status code to user (the log keeps it)
            Errors.report(Errors.CODES.E_REQUEST_FAILED, null, { status: status });
            return; // No redirect for unknown errors
    }
    
    // If we have a redirect URL, perform redirect immediately
    // Use replace() instead of href to prevent back button issues
    if (redirectUrl) {
        // Read response body in background (non-blocking) to prevent potential issues
        // But don't wait for it - redirect immediately. A failed read is ignored: the page is
        // being left, and nothing in the body is ever shown.
        if (!response.bodyUsed) {
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                response.json().catch(() => {}); // Consume the body (fire and forget)
            } else {
                response.text().catch(() => {}); // Consume the body (fire and forget)
            }
        }
        
        // Perform redirect immediately using replace() to avoid history issues
        window.location.replace(redirectUrl);
    }
}

// Fetch wrapper with automatic error handling and status page redirects
// SECURITY: the HttpOnly session cookie travels with same-origin requests only
async function fetchWithErrorHandling(url, options = {}) {
    try {
        const fetchOptions = {
            ...options,
            credentials: 'same-origin',
        };

        const response = await fetch(url, fetchOptions);

        if (!response.ok) {
            await handleErrorResponse(response);
            return null; // Return null on error to prevent further processing
        }

        return response;
    } catch (error) {
        // Network error - redirect to 500 error page immediately
        Log.error(Errors.INTERNAL.E_NETWORK_UNREACHABLE, error);
        window.location.replace(STATUS_PAGES.SERVER_ERROR);
        return null;
    }
}

// JSON API call for in-app actions: never redirects, never throws.
// Callers decide how to surface errors (notifications) and what 401 means.
// Returns { ok, status, data } where status 0 means a network failure.
async function apiCall(method, path, body) {
    const options = {
        method: method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {}
    };
    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    let response;
    try {
        response = await fetch(`${API_BASE_URL}${path}`, options);
    } catch (error) {
        return { ok: false, status: 0, data: null };
    }

    let data = null;
    const contentType = response.headers.get('content-type') || '';
    if (response.status !== 204 && contentType.includes('application/json')) {
        try {
            data = await response.json();
        } catch (error) {
            data = null;
        }
    } else {
        // Drained only to free the connection; data stays null either way, so a failed read changes nothing
        await response.text().catch(() => '');
    }
    return { ok: response.ok, status: response.status, data: data };
}
