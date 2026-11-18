// ========================================
// FRONTEND INPUT VALIDATION (UX Layer)
// ========================================
// Security Strategy: WHITELIST every structured token, OUTPUT-ENCODE free text.
// Message text is end-to-end encrypted and rendered with textContent only,
// so it may contain any Unicode except control characters.

const MAX_MESSAGE_CHARS = 2000;
// An account number is 32 random bytes in base64url (no padding): the one home of its shape
const ACCOUNT_NUMBER_LEN = 43;
const ACCOUNT_NUMBER_REGEX = new RegExp('^[A-Za-z0-9_-]{' + ACCOUNT_NUMBER_LEN + '}$');
// Control characters other than \n and \t (C0, DEL, C1) plus bidi overrides
const FORBIDDEN_TEXT_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/;

// The only characters trimmed from either end of a message: ECMAScript's WhiteSpace and
// LineTerminator (what String.prototype.trim strips), spelled out so the rule never depends on
// the engine's Unicode version. The agent trims exactly this set (backend/internal/agent
// messages.go messageTrimChars, compared by frontend/tests/validation.fuzz.test.mjs). U+0085 is
// not in it (a C1 control, refused below) and neither is U+200B (content).
const MESSAGE_TRIM_CHARS = '\t\n\v\f\r \u00A0\u1680' +
    '\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200A' +
    '\u2028\u2029\u202F\u205F\u3000\uFEFF';

/**
 * Removes MESSAGE_TRIM_CHARS from both ends (a linear scan: a regular expression anchored at
 * the end would be quadratic on a long inner run of spaces)
 * @param {string} text
 * @returns {string}
 */
function trimMessageText(text) {
    let start = 0;
    let end = text.length;
    while (start < end && MESSAGE_TRIM_CHARS.includes(text[start])) start++;
    while (end > start && MESSAGE_TRIM_CHARS.includes(text[end - 1])) end--;
    return text.slice(start, end);
}

/**
 * Validates a chat message before encryption
 * @param {string} input - Raw composer value
 * @returns {object} - {valid: boolean, sanitized: string, error: string, params?: object}; error is an Errors code
 */
function validateMessageText(input) {
    return checkMessageText(input, {});
}

/**
 * Validates the caption of a file message: as a message, except that it may be empty, and it
 * must fit one frame together with the file's description
 * @param {string} input - Raw composer value
 * @param {string} fileName - the name the file is sent under (isFileName)
 * @returns {object} - as validateMessageText
 */
function validateCaption(input, fileName) {
    return checkMessageText(input, { fileName: fileName });
}

// The message rule; withFile.fileName set: a caption beside that file (may be empty)
function checkMessageText(input, withFile) {
    if (typeof input !== 'string') {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_INVALID };
    }

    const normalized = trimMessageText(input.replace(/\r\n?/g, '\n'));
    const captioned = withFile.fileName !== undefined;

    if (normalized.length === 0 && !captioned) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_EMPTY };
    }

    if ([...normalized].length > MAX_MESSAGE_CHARS) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_TOO_MANY_CHARS, params: { max: MAX_MESSAGE_CHARS } };
    }

    if (FORBIDDEN_TEXT_CHARS.test(normalized)) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_CONTROL_CHARS };
    }

    // A secret pasted into the composer by mistake is never sent (chat.js also empties the composer)
    if (containsAccountNumber(normalized)) {
        return { valid: false, sanitized: '', error: Errors.CODES.E_MESSAGE_IS_ACCOUNT_NUMBER };
    }

    if (!ElyrnCrypto.payloadFits({ text: normalized, fileName: withFile.fileName })) {
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
 * What an account number field holds, read the way login reads it: Unicode look-alikes folded
 * (NFKC: fullwidth digits and letters become ASCII) and surrounding whitespace dropped. The one
 * reading every field uses, so a number refused in one field is recognised in all of them.
 * @param {any} input
 * @returns {string} - '' for anything that is not a string
 */
function normalizeAccountNumber(input) {
    return typeof input === 'string' ? input.normalize('NFKC').trim() : '';
}

/**
 * True when a string, read as normalizeAccountNumber reads it, has the exact shape of a secret
 * AccountNumber. Used to stop users from pasting their account number where it does not belong.
 * @param {any} input
 * @returns {boolean}
 */
function looksLikeAccountNumber(input) {
    return ACCOUNT_NUMBER_REGEX.test(normalizeAccountNumber(input));
}

/**
 * Validates what the login field holds. An invite or a room code pasted there is named as such.
 * @param {any} input
 * @returns {object} - {valid: boolean, value: string, error: string}; value is the account
 *     number to use ('' when invalid), error an Errors code
 */
function parseAccountNumber(input) {
    const value = normalizeAccountNumber(input);
    const refused = (code) => ({ valid: false, value: '', error: code });
    if (value.length === 0) {
        return refused(Errors.CODES.E_LOGIN_EMPTY);
    }
    if (ElyrnCrypto.codeBody(value, ElyrnCrypto.INVITE_PREFIXES) !== null ||
        ElyrnCrypto.codeBody(value, ElyrnRoomCrypto.CODE_PREFIXES) !== null) {
        return refused(Errors.CODES.E_LOGIN_INVITE_PASTED);
    }
    if (!ACCOUNT_NUMBER_REGEX.test(value)) {
        return refused(Errors.CODES.E_LOGIN_FORMAT);
    }
    return { valid: true, value: value, error: '' };
}

// What separates the words of a message when it is searched for an account number
const MESSAGE_WORD_SEPARATOR = /\s+/u;

/**
 * True when any whitespace-separated word of text is an account number (looksLikeAccountNumber).
 * An invite or room code carries its prefix, so sharing one in a message is not refused.
 * @param {string} text
 * @returns {boolean}
 */
function containsAccountNumber(text) {
    return text.normalize('NFKC').split(MESSAGE_WORD_SEPARATOR).some(word => ACCOUNT_NUMBER_REGEX.test(word));
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

// A room member's role (docs/architecture/rooms.md, Member roles): the one home of its rule,
// applied to what is typed before it is sealed and to what a sealed role opens to. Stored
// NFC-normalised; 1 to MAX_ROLE_CHARS code points, each a letter, a digit, '-' or '_'; at most
// MAX_ROLE_BYTES of UTF-8 (ElyrnRoomCrypto's bound); case kept. A word that reads as a built-in
// badge is reserved: compared after NFKC and toLowerCase (so fullwidth or mixed-case spellings
// are caught; a lookalike from another script is not, and proves nothing: only the badge marks
// the owner).
const MAX_ROLE_CHARS = 16;
const ROLE_CHAR_RULE = /^[\p{L}\p{N}_-]+$/u;
const RESERVED_ROLES = Object.freeze(['owner', 'you']);
const roleEncoder = new TextEncoder();

/**
 * Validates a role as typed (without its '#')
 * @param {any} input
 * @returns {object} - {valid: boolean, value: string, error: string, params?: object}; value is the
 *     NFC text to seal ('' when invalid), error an Errors code
 */
function validateRoleText(input) {
    const refused = (code, params) => ({ valid: false, value: '', error: code, params: params });
    if (typeof input !== 'string') {
        return refused(Errors.CODES.E_ROLE_INVALID);
    }
    const value = input.normalize('NFC');
    if (value.length === 0) {
        return refused(Errors.CODES.E_ROLE_EMPTY);
    }
    if ([...value].length > MAX_ROLE_CHARS || roleEncoder.encode(value).length > ElyrnRoomCrypto.MAX_ROLE_BYTES) {
        return refused(Errors.CODES.E_ROLE_TOO_LONG, { max: MAX_ROLE_CHARS });
    }
    if (!ROLE_CHAR_RULE.test(value)) {
        return refused(Errors.CODES.E_ROLE_CHARS);
    }
    if (RESERVED_ROLES.includes(value.normalize('NFKC').toLowerCase())) {
        return refused(Errors.CODES.E_ROLE_RESERVED);
    }
    return { valid: true, value: value, error: '' };
}

/**
 * True when a role opened from its sealed form is one the rule allows, exactly as stored (NFC
 * already): anything else is shown as no role
 * @param {any} text
 * @returns {boolean}
 */
function isRoleText(text) {
    const checked = validateRoleText(text);
    return checked.valid && checked.value === text;
}

// A file's display name (docs/architecture/files.md): the one home of its rule, the same as
// backend/internal/e2e/file.go fileNameValid. NFC as it is (never normalised on reading), 1 to
// MAX_FILE_NAME_CHARS code points, at most MAX_FILE_NAME_BYTES of UTF-8, no leading dot, no path
// separator, no control character (Unicode Cc: C0, DEL, C1) and no bidirectional control.
const MAX_FILE_NAME_CHARS = 128;
const MAX_FILE_NAME_BYTES = 512;
const FILE_NAME_HIDDEN_PREFIX = '.';
const FILE_NAME_REFUSED = /[\p{Cc}\/\\\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;
const FILE_NAME_REFUSED_ALL = new RegExp(FILE_NAME_REFUSED.source, 'gu');
// A lone surrogate is no Unicode text and has no UTF-8 form
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const LONE_SURROGATE_ALL = new RegExp(LONE_SURROGATE.source, 'g');
// What stands in for a refused character, and the name of a file whose name keeps nothing
const FILE_NAME_FILLER = '_';
const FILE_NAME_FALLBACK = 'file';
// Characters common file systems refuse in a name: replaced in the name a file is saved under
const SAVE_NAME_REFUSED = /[<>:"|?*]/g;
const fileNameEncoder = new TextEncoder();

/**
 * True when name is a file name a file message may carry (sent or received)
 * @param {any} name
 * @returns {boolean}
 */
function isFileName(name) {
    if (typeof name !== 'string' || LONE_SURROGATE.test(name)) return false;
    const chars = [...name].length;
    return chars >= 1 && chars <= MAX_FILE_NAME_CHARS && fileNameEncoder.encode(name).length <= MAX_FILE_NAME_BYTES &&
        name.normalize('NFC') === name && !name.startsWith(FILE_NAME_HIDDEN_PREFIX) && !FILE_NAME_REFUSED.test(name);
}

/**
 * The name a chosen file is sent under: NFC, every refused character replaced, leading dots
 * dropped, cut to the bounds keeping its extension where it can. Always passes isFileName.
 * @param {any} raw - the name the browser gives the chosen file
 * @returns {string}
 */
function fileNameForSending(raw) {
    let name = (typeof raw === 'string' ? raw : '').replace(LONE_SURROGATE_ALL, FILE_NAME_FILLER).normalize('NFC')
        .replace(FILE_NAME_REFUSED_ALL, FILE_NAME_FILLER);
    while (name.startsWith(FILE_NAME_HIDDEN_PREFIX)) name = name.slice(FILE_NAME_HIDDEN_PREFIX.length);
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 ? [...name.slice(dot)] : [];
    let kept = [...name];
    if (kept.length > MAX_FILE_NAME_CHARS) kept = kept.slice(0, Math.max(0, MAX_FILE_NAME_CHARS - ext.length)).concat(ext).slice(0, MAX_FILE_NAME_CHARS);
    while (kept.length > 0 && fileNameEncoder.encode(kept.join('')).length > MAX_FILE_NAME_BYTES) {
        kept.splice(Math.max(0, kept.length - ext.length - 1), 1);
    }
    const sent = kept.join('').normalize('NFC');
    return isFileName(sent) ? sent : FILE_NAME_FALLBACK;
}

/**
 * The name a received file is saved under: its (valid) name with the characters common file
 * systems refuse replaced
 * @param {string} name - a name that passed isFileName
 * @returns {string}
 */
function saveName(name) {
    return name.replace(SAVE_NAME_REFUSED, FILE_NAME_FILLER);
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
