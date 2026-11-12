// ========================================
// ERRORS (every user-facing failure and warning, by code)
// ========================================
// The one home of what the browser tells the user when something fails. A call site reports
// a code; the sentence, its severity and the log line come from here. Codes are stable: the
// log carries the code, never the sentence or anything the user typed.
// SECURITY: a server's own error text is never shown; fromApi() maps it to a registered code.

const Errors = (() => {
    'use strict';

    const ERROR = 'error';
    const WARNING = 'warning';

    const e = (text) => Object.freeze({ severity: ERROR, text: text });
    const w = (text) => Object.freeze({ severity: WARNING, text: text });

    // Shown when a code or its parameters are wrong: a programming error, logged as such
    const GENERIC = 'something went wrong — reload the page and try again';
    // Registration phase 2 keeps the account number redeemable, so every failure ends alike
    const REGISTRATION_RETRY = ' — your account number is still valid, press continue again';
    // One sentence, two moments: sending to a room that ran out (warning), joining one (error)
    const ROOM_EXPIRED = 'this room has expired';

    const REGISTRY = Object.freeze({
        // programming errors
        E_UNKNOWN_CODE: e(GENERIC),
        E_BAD_PARAMS: e(GENERIC),

        // server answers (mapped by fromApi)
        E_API_INVALID_CREDENTIALS: e('invalid credentials'),
        E_API_UNAUTHORIZED: e('unauthorized'),
        E_API_INVALID_REQUEST: e('invalid request'),
        E_API_FORBIDDEN: e('forbidden'),
        E_API_METHOD_NOT_ALLOWED: e('method not allowed'),
        E_API_TOO_MANY_REQUESTS: e('too many requests — wait a minute'),
        E_API_INTERNAL: e('internal server error — try again in a moment'),
        E_API_UNAVAILABLE: e('service unavailable — try again in a moment'),
        E_REQUEST_FAILED: e('request failed — try again'),
        // no answer at all (apiCall's status 0): the request timed out, or never reached the server
        E_REQUEST_TIMEOUT: e('no answer from the server — check your connection and try again'),
        E_SERVER_UNREACHABLE: e('cannot reach the server — check your connection and try again'),
        E_UNEXPECTED: e('something unexpected went wrong — reload the page if anything stops working'),

        // proof of work (registration, invites, rooms, friend requests)
        E_POW_TIMEOUT: e('the security check took too long — try again'),
        E_POW_TOO_HARD: e('the server asked for too much work — try again later'),

        // login
        E_LOGIN_EMPTY: e('please enter account number'),
        E_LOGIN_INVITE_PASTED: e('that is an invite — log in first, then use join'),
        E_LOGIN_FORMAT: e('invalid format'),
        E_IDENTITY_MISMATCH: e('identity mismatch — the server returned a different public key'),

        // registration
        E_ACCOUNT_NUMBER_FAILED: e('error - try again'),
        W_ACCOUNT_NUMBER_NOT_COPIED: w('Could not copy automatically. Please copy manually.'),
        E_ACCOUNT_NUMBER_MISSING: e('Please generate your account number first'),
        E_REGISTRATION_EXPIRED: e('Session expired. Please try again.'),
        E_REGISTER_CONNECTION_LOST: e('connection lost' + REGISTRATION_RETRY),
        E_REGISTER_RATE_LIMITED: e('too many attempts, wait a minute' + REGISTRATION_RETRY),
        E_REGISTER_SERVER_BUSY: e('server busy' + REGISTRATION_RETRY),
        E_REGISTER_REFUSED: e('request refused' + REGISTRATION_RETRY),
        E_ACCOUNT_NUMBER_EXPIRED: e('that account number expired before the account was created — discard it and copy a new one'),
        E_ACCOUNT_CREATED_NOT_ENTERED: e('account created but not opened — save your account number, then log in with it'),

        // session and identity
        W_SESSION_ENDED: w('session ended — log in again'),
        W_LOGOUT_SERVER_UNREACHABLE: w('logged out here, but the server could not be reached: other sessions stay valid until they expire'),
        E_DELETE_INVALID_NUMBER: e('invalid account number'),
        E_DELETE_WRONG_IDENTITY: e('that is not the account number of this identity'),
        E_IDENTITY_NOT_DELETED: e('identity not deleted'),
        W_TOO_MANY_ATTEMPTS: w('too many attempts — wait a moment'),

        // conversations and messages
        E_CONVERSATIONS_NOT_LOADED: e('could not load conversations'),
        E_ROOM_DATA_CHANGED: e('room data changed unexpectedly — room hidden'),
        E_PEER_KEY_CHANGED: e('peer key changed unexpectedly — conversation hidden'),
        W_ROOM_GONE: w('this room is gone — burned or expired'),
        W_CONVERSATION_BURNED: w('this conversation was burned'),
        E_MESSAGES_NOT_LOADED: e('could not load messages'),
        E_MESSAGE_INVALID: e('invalid input'),
        E_MESSAGE_EMPTY: e('message is empty'),
        E_MESSAGE_TOO_MANY_CHARS: e('max {max} characters'),
        E_MESSAGE_CONTROL_CHARS: e('message contains control characters'),
        E_MESSAGE_TOO_LONG: e('message too long'),
        W_MESSAGE_RATE_LIMITED: w('slow down — too many messages'),
        E_MESSAGE_NOT_SENT: e('message not sent — press send again'),
        W_VERIFICATION_NOT_SAVED: w('could not save verification on this device'),
        E_CONVERSATION_NOT_BURNED: e('could not burn conversation'),
        W_LIVE_UPDATES_PAUSED: w('live updates paused — reload to resume'),
        W_COPY_MANUALLY: w('copy it manually'),
        // The robot door's challenge cannot run here (no random source, or no SHA-256 outside
        // https). The door is theatre and gates nothing, so the visitor is let through.
        W_DOOR_CHECK_UNAVAILABLE: w('this browser cannot run the door check — come in anyway'),
        // Shown in place of a message whose sender counter was already used (counters.js)
        W_MESSAGE_REPLAYED: w('⚠ a message from {who} was replayed or reordered by the server'),

        // invites
        W_POW_RATE_LIMITED: w('too many attempts — wait a minute'),
        E_INVITE_NOT_CREATED: e('could not create invite'),
        W_INVITE_LIMIT: w('invite limit reached — wait for one to be used or expire'),
        E_INVITE_MALFORMED: e('server returned a malformed invite'),
        E_INVITE_EMPTY: e('paste an invite first'),
        E_INVITE_IS_ACCOUNT_NUMBER: e('that looks like an account number — never share it. ask for an invite instead'),
        E_INVITE_INVALID: e('invalid invite'),
        E_JOIN_CODE_EMPTY: e('paste an invite or a room code first'),
        W_OWN_INVITE: w('that is your own invite — send it to someone else'),
        E_INVITE_SPENT: e('invite expired or already used'),
        E_JOIN_FAILED: e('could not join'),
        E_PEER_KEY_SUBSTITUTED: e('verification FAILED: the server substituted the peer key. conversation burned.'),

        // rooms
        E_ROOM_UNVERIFIED: e('a room failed verification against its code — hidden'),
        E_ROSTER_UNVERIFIED: e('the member list failed verification — not sending to it'),
        W_LOOKALIKE_MEMBERS: w('two members share a name — tell them apart by glyph and code'),
        W_ROOM_EXPIRED: w(ROOM_EXPIRED),
        E_ROOM_CODE_EXPIRED: e(ROOM_EXPIRED),
        E_ROOM_CODE_INVALID: e('invalid room code'),
        E_ROOM_NOT_FOUND: e('no such room — the code is wrong, or the room expired or was burned'),
        W_ROOM_FULL: w('this room is full'),
        W_ROOM_JOIN_RATE_LIMITED: w('too many attempts or too many conversations — wait a moment'),
        E_ROOM_JOIN_FAILED: e('could not join the room'),
        W_ROOM_CREATE_RATE_LIMITED: w('too many rooms or attempts — wait a moment'),
        E_ROOM_CLOCK_REFUSED: e('the server refused the room — check your device clock'),
        E_ROOM_NOT_CREATED: e('could not create room'),
        E_ROOM_NOT_LEFT: e('could not leave the room'),
        W_FRIEND_REQUEST_PENDING: w('you already have a request waiting with them'),
        W_FRIEND_GONE: w('they are no longer in this room'),
        E_FRIEND_REQUEST_NOT_SENT: e('friend request not sent'),
        E_FRIEND_REQUEST_MALFORMED: e('that friend request is malformed — ignored')
    });

    // Reported codes are read from here, so a misspelt name is undefined and reports E_UNKNOWN_CODE
    const CODES = Object.freeze(Object.fromEntries(Object.keys(REGISTRY).map(code => [code, code])));

    // Failures nobody is shown, only logged
    const INTERNAL = Object.freeze({
        E_CLIPBOARD_FALLBACK_FAILED: 'E_CLIPBOARD_FALLBACK_FAILED',
        W_CLIPBOARD_NOT_CLEARED: 'W_CLIPBOARD_NOT_CLEARED',
        E_SCRAMBLE_ELEMENTS_MISSING: 'E_SCRAMBLE_ELEMENTS_MISSING',
        W_KEYSTORE_UNAVAILABLE: 'W_KEYSTORE_UNAVAILABLE',
        W_COUNTERS_UNAVAILABLE: 'W_COUNTERS_UNAVAILABLE',
        E_SYNC_FAILED: 'E_SYNC_FAILED',
        W_REQUEST_TIMED_OUT: 'W_REQUEST_TIMED_OUT'
    });

    // Server error texts we recognise (compared lowercased); anything else is E_REQUEST_FAILED
    const API_MESSAGES = Object.freeze({
        'invalid credentials': CODES.E_API_INVALID_CREDENTIALS,
        'unauthorized': CODES.E_API_UNAUTHORIZED,
        'invalid request': CODES.E_API_INVALID_REQUEST,
        'pending token required': CODES.E_API_INVALID_REQUEST,
        'internal server error': CODES.E_API_INTERNAL,
        'method not allowed': CODES.E_API_METHOD_NOT_ALLOWED,
        'not found': CODES.E_API_INVALID_REQUEST,
        'too many requests': CODES.E_API_TOO_MANY_REQUESTS,
        'service unavailable': CODES.E_API_UNAVAILABLE,
        'forbidden': CODES.E_API_FORBIDDEN,
        'unsupported media type': CODES.E_API_INVALID_REQUEST
    });

    // Used when the answer carries no message
    const API_STATUSES = Object.freeze({
        400: CODES.E_API_INVALID_REQUEST,
        401: CODES.E_API_UNAUTHORIZED,
        403: CODES.E_API_FORBIDDEN,
        404: CODES.E_API_INVALID_REQUEST,
        429: CODES.E_API_TOO_MANY_REQUESTS,
        500: CODES.E_API_INTERNAL
    });

    // Texts that are not failures but share the inline status lines and toasts with them
    const NOTICE = Object.freeze({
        DERIVING_KEYS: 'deriving your keys…',
        GENERATING_ACCOUNT_NUMBER: 'Generating your special Account Number',
        SECURING_IDENTIFIER: 'securing your identifier...',
        PREPARING_CHALLENGE: 'preparing security challenge...',
        SECURING_ACCOUNT: 'securing your account...',
        CREATING_ACCOUNT: 'creating your account...',
        ACCOUNT_NUMBER_READY: 'your account number is ready! click continue to create account.',
        INVITE_COPIED: 'invite copied',
        ROOM_CODE_COPIED: 'room code copied',
        COMMAND_COPIED: 'command copied'
    });

    const PLACEHOLDER = /\{([a-z]+)\}/g;
    const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

    function isCode(code) {
        return typeof code === 'string' && has(REGISTRY, code);
    }

    // Fills {name} placeholders; throws on a code that is not registered or a missing parameter
    function format(code, params) {
        if (!isCode(code)) {
            throw new TypeError('unknown error code');
        }
        return REGISTRY[code].text.replace(PLACEHOLDER, (match, name) => {
            if (!params || !has(params, name) || params[name] === undefined || params[name] === null) {
                throw new TypeError('missing parameter');
            }
            return String(params[name]);
        });
    }

    // Never throws: a wrong code or missing parameter becomes the generic sentence under its own code
    function resolve(code, params) {
        if (!isCode(code)) {
            return { code: CODES.E_UNKNOWN_CODE, severity: ERROR, text: REGISTRY.E_UNKNOWN_CODE.text };
        }
        try {
            return { code: code, severity: REGISTRY[code].severity, text: format(code, params) };
        } catch (error) {
            return { code: CODES.E_BAD_PARAMS, severity: ERROR, text: REGISTRY.E_BAD_PARAMS.text };
        }
    }

    // cause (an Error, or { status }) only adds its name and status to the log line
    function logged(code, params, cause) {
        const resolved = resolve(code, params);
        if (resolved.severity === WARNING) {
            Log.warn(resolved.code, cause);
        } else {
            Log.error(resolved.code, cause);
        }
        return resolved;
    }

    // Shows the sentence as a notification
    function report(code, params, cause) {
        const resolved = logged(code, params, cause);
        if (resolved.severity === WARNING) {
            showWarning(resolved.text);
        } else {
            showError(resolved.text);
        }
    }

    // Writes the sentence into an inline status line (#loginError, #registerError, …)
    function inline(element, code, params, cause) {
        element.textContent = logged(code, params, cause).text;
    }

    // Maps a server's error answer to a code; its own text is never shown
    function fromApi(apiMessage, status) {
        if (apiMessage) {
            const key = String(apiMessage).trim().toLowerCase();
            return has(API_MESSAGES, key) ? API_MESSAGES[key] : CODES.E_REQUEST_FAILED;
        }
        return has(API_STATUSES, status) ? API_STATUSES[status] : CODES.E_REQUEST_FAILED;
    }

    // A failed apiCall result ({ status, data, timedOut }) as a code: no answer (status 0) says
    // whether it timed out, any other answer is mapped by fromApi
    function fromResult(result) {
        if (result.status === 0) {
            return result.timedOut ? CODES.E_REQUEST_TIMEOUT : CODES.E_SERVER_UNREACHABLE;
        }
        return fromApi(result.data ? result.data.message : null, result.status);
    }

    return Object.freeze({
        CODES, INTERNAL, NOTICE, REGISTRY, report, inline, fromApi, fromResult, format,
        message: (code, params) => resolve(code, params).text
    });
})();
