// ========================================
// FRONTEND INPUT VALIDATION (UX Layer)
// ========================================
// Security Strategy: WHITELIST every structured token, OUTPUT-ENCODE free text.
// Message text is end-to-end encrypted and rendered with textContent only,
// so it may contain any Unicode except control characters.

const MAX_MESSAGE_CHARS = 2000;
const ACCOUNT_NUMBER_SHAPE = /^[A-Za-z0-9_-]{43}$/;
// Control characters other than \n and \t (C0, DEL, C1) plus bidi overrides
const FORBIDDEN_TEXT_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/;

/**
 * Validates a chat message before encryption
 * @param {string} input - Raw composer value
 * @returns {object} - {valid: boolean, sanitized: string, error: string, params?: object}; error is an Errors code
 */
function validateMessageText(input) {
    if (typeof input !== 'string') {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_INVALID };
    }

    const normalized = input.replace(/\r\n?/g, '\n').trim();

    if (normalized.length === 0) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_EMPTY };
    }

    if ([...normalized].length > MAX_MESSAGE_CHARS) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_TOO_MANY_CHARS, params: { max: MAX_MESSAGE_CHARS } };
    }

    if (FORBIDDEN_TEXT_CHARS.test(normalized)) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_CONTROL_CHARS };
    }

    if (!ElyrnCrypto.payloadFits(normalized)) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_TOO_LONG };
    }

    return { valid: true, sanitized: normalized, error: '' };
}

// Every forbidden character, for replacement in text received from a peer
const FORBIDDEN_TEXT_CHARS_ALL = new RegExp(FORBIDDEN_TEXT_CHARS.source, 'gu');

/**
 * Neutralizes a decrypted peer message before display. The sender's client already refuses
 * these characters, but a modified client can encrypt them anyway: bidi overrides would
 * reorder what is shown (e.g. disguise a file name), so each becomes U+FFFD.
 * @param {string} text - Decrypted message text
 * @returns {string}
 */
function neutralizeReceivedText(text) {
    return String(text).replace(FORBIDDEN_TEXT_CHARS_ALL, '\uFFFD');
}

/**
 * True when a string has the exact shape of a secret AccountNumber.
 * Used to stop users from pasting their account number where an invite belongs.
 * @param {string} input
 * @returns {boolean}
 */
function looksLikeAccountNumber(input) {
    return typeof input === 'string' && ACCOUNT_NUMBER_SHAPE.test(input.trim());
}

/**
 * Validates an invite code (elyrn:<43 base64url chars>; the legacy noaddx: prefix is accepted)
 * @param {string} input
 * @returns {object} - {valid: boolean, sanitized: object|null, error: string}; error is an Errors code
 */
function validateInviteCode(input) {
    const value = typeof input === 'string' ? input.trim() : '';

    if (value.length === 0) {
        return { valid: false, sanitized: null, error: Errors.CODES.E_INVITE_EMPTY };
    }

    if (looksLikeAccountNumber(value)) {
        return { valid: false, sanitized: null, error: Errors.CODES.E_INVITE_IS_ACCOUNT_NUMBER };
    }

    try {
        return { valid: true, sanitized: ElyrnCrypto.parseInviteCode(value), error: '' };
    } catch (e) {
        return { valid: false, sanitized: null, error: Errors.CODES.E_INVITE_INVALID };
    }
}

/**
 * Validates what the join field takes: an invite code (elyrn:…) or a room code (elyrn#…),
 * either also under its legacy noaddx prefix
 * @param {string} input
 * @returns {object} - {valid: boolean, kind: 'invite'|'room', sanitized: object|null, error: string}; error is an Errors code
 */
function validateJoinCode(input) {
    const value = typeof input === 'string' ? input.trim() : '';
    if (value.length === 0) {
        return { valid: false, kind: 'invite', sanitized: null, error: Errors.CODES.E_JOIN_CODE_EMPTY };
    }
    if (ElyrnCrypto.codeBody(value, ElyrnRoomCrypto.CODE_PREFIXES) === null) {
        return Object.assign(validateInviteCode(value), { kind: 'invite' });
    }
    try {
        return { valid: true, kind: 'room', sanitized: ElyrnRoomCrypto.parseRoomCode(value), error: '' };
    } catch (e) {
        return { valid: false, kind: 'room', sanitized: null, error: Errors.CODES.E_ROOM_CODE_INVALID };
    }
}

/**
 * Validates a conversation or message ID (canonical lowercase UUIDv4)
 * @param {any} id
 * @returns {boolean}
 */
function validateConversationId(id) {
    return ElyrnCrypto.isUuidV4(id);
}

// Robot entrance: the command that registers elyrn-agent with an MCP client
const AGENT_COMMAND = 'elyrn-agent mcp --server';
const AGENT_SERVER_EXAMPLE = 'https://your-server';
// What window.location.origin is for an http(s) page: scheme, lowercase host or [IPv6], port
const AGENT_ORIGIN_SHAPE = /^https?:\/\/(?:[a-z0-9-]+(?:\.[a-z0-9-]+)*|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$/;

/**
 * Builds the agent command for this instance's origin
 * @param {any} origin - window.location.origin
 * @returns {string} - the command, or '' when origin is not an http(s) origin
 */
function buildAgentCommand(origin) {
    if (typeof origin !== 'string' || !AGENT_ORIGIN_SHAPE.test(origin)) {
        return '';
    }
    return AGENT_COMMAND + ' ' + origin;
}
