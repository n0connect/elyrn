// ========================================
// PROOF OF WORK HELPER FUNCTIONS
// ========================================

// Trusted Types: the CSP allows exactly one policy, and it whitelists exactly one URL
const POW_WORKER_PATH = 'js/pow-worker.js';
const powWorkerPolicy = window.trustedTypes
    // 'noaddx-worker' is the policy name the CSP allows; it is kept across the rename to elyrn.
    ? window.trustedTypes.createPolicy('noaddx-worker', {
        createScriptURL: (url) => {
            if (url !== POW_WORKER_PATH) {
                throw new TypeError('script URL not whitelisted');
            }
            return url;
        }
    })
    : null;

// The most a server may set for message retention and for a room's lifetime: a /me answer
// outside these is refused like a mismatched identity
const MAX_MESSAGE_TTL_DAYS = 365;
const MAX_ROOM_TTL_HOURS = 720;
// The largest message page this client takes from /me (the agent bounds a served page alike)
const MAX_MESSAGE_PAGE_LIMIT = 1000;

// The hardest proof of work this page will run: the server's own maximum (backend config
// maxPoWDifficulty). pow-worker.js refuses anything above it too; a harder challenge is refused here
// first so the user is told why.
const MAX_POW_DIFFICULTY = 24;
// A proof of work still running after this long is abandoned: the server's default challenge
// lifetime, after which a solution would be refused anyway
const POW_TIMEOUT_MS = 300000;

// Every proof of work running now: a timer and a stop, so logout and cancel can end them all
const powRuns = new Set();

// Why a proof of work ended without a solution. code is a registered code to show, or null when
// it was cancelled (the user logged out or left registration: nobody is told).
class PowStopped extends Error {
    constructor(code) {
        super('proof of work stopped');
        this.name = 'PowStopped';
        this.code = code;
    }
}

function powWorkerURL() {
    return powWorkerPolicy ? powWorkerPolicy.createScriptURL(POW_WORKER_PATH) : POW_WORKER_PATH;
}

// Gets a PoW challenge without ever leaving the page, so callers keep what is on screen.
// Returns { challenge, status, timedOut }: challenge is null on failure, status 0 means no answer.
async function getPowChallenge() {
    const result = await apiCall('GET', '/pow/challenge');
    const challenge = result.ok && result.data && result.data.success ? result.data.challenge : null;
    return { challenge: challenge || null, status: result.status, timedOut: result.timedOut };
}

// Solves a PoW challenge in a Web Worker. Rejects with PowStopped when the challenge is harder
// than MAX_POW_DIFFICULTY, on POW_TIMEOUT_MS, or when cancelProofsOfWork() runs; the worker is
// terminated whichever way it ends.
function solvePowChallenge(challenge) {
    return new Promise((resolve, reject) => {
        // A malformed difficulty goes on to the worker, which refuses it as it refuses any bad task
        if (Number.isInteger(challenge.difficulty) && challenge.difficulty > MAX_POW_DIFFICULTY) {
            reject(new PowStopped(Errors.CODES.E_POW_TOO_HARD));
            return;
        }
        const worker = new Worker(powWorkerURL());
        const run = {
            timer: setTimeout(() => finish(new PowStopped(Errors.CODES.E_POW_TIMEOUT)), POW_TIMEOUT_MS),
            stop: () => finish(new PowStopped(null))
        };
        powRuns.add(run);
        // Settles once: the first of solution, failure, timeout or cancel wins
        function finish(error, solution) {
            if (!powRuns.delete(run)) return;
            clearTimeout(run.timer);
            worker.terminate();
            if (error) {
                reject(error);
            } else {
                resolve(solution);
            }
        }

        worker.onmessage = function(e) {
            // Progress updates carry no outcome
            if (e.data.success === true) {
                finish(null, {
                    challenge: challenge.challenge,
                    solution: e.data.solution,
                    timestamp: challenge.timestamp,
                    ttl: challenge.ttl,
                    difficulty: challenge.difficulty,
                    salt: challenge.salt
                });
            } else if (e.data.success === false) {
                finish(new Error('Processing failed'));
            }
        };
        worker.onerror = function(error) {
            finish(error);
        };

        worker.postMessage({
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            salt: challenge.salt
        });
    });
}

// Ends every running proof of work (logout, session end, leaving registration); each caller's
// promise rejects with a cancelled PowStopped, so every lock it holds is released
function cancelProofsOfWork() {
    Array.from(powRuns).forEach(run => run.stop());
}

// The code to show for a failed proof of work, or fallback when it was not the proof of work
// that failed. A cancelled one gives fallback too: callers check isPowCancelled first when they
// can still be on screen.
function powFailureCode(error, fallback) {
    return error instanceof PowStopped && error.code ? error.code : fallback;
}

function isPowCancelled(error) {
    return error instanceof PowStopped && error.code === null;
}

// ========================================
// AUTHENTICATION FUNCTIONS
// ========================================

// Verifies the server holds the same public key this device derived, then opens the app.
// A mismatch means the server (or something in between) swapped the identity key.
// Everything the browser keeps for a session, derived from the account number once
async function deriveSession(accountNumber) {
    const identity = await ElyrnCrypto.deriveIdentity(accountNumber);
    identity.roomsRoot = await ElyrnRoomCrypto.deriveRoomsRoot(accountNumber);
    return identity;
}

function roomLimits(data) {
    const members = data && data.room_max_members;
    const hours = data && data.room_max_ttl_hours;
    if (!Number.isSafeInteger(members) || members < ElyrnRoomCrypto.MIN_MEMBERS || members > ElyrnRoomCrypto.MAX_MEMBERS ||
        !Number.isSafeInteger(hours) || hours < 1 || hours > MAX_ROOM_TTL_HOURS) {
        return null;
    }
    return { maxMembers: members, maxTTLHours: hours, pageLimit: pageLimit(data) };
}

// A server that does not say its page size (older than paging back) gets no "earlier
// messages" control instead of a refused login: 0 turns the control off
function pageLimit(data) {
    const limit = data && data.message_page_limit;
    return Number.isSafeInteger(limit) && limit >= 1 && limit <= MAX_MESSAGE_PAGE_LIMIT ? limit : 0;
}

// How an attempt to open the app ended
const ENTRY = Object.freeze({
    ENTERED: 'entered',
    // no answer from /me (status 0) or a server error: nothing was wiped, the caller offers a retry
    UNREACHABLE: 'unreachable',
    // the session is gone or the server's answer was refused: the stored identity was removed
    REFUSED: 'refused'
});

// Opens the app once /me confirms the session and the identity. Never changes the view on
// failure: each caller knows what its user still needs on screen. Returns { entry, result }.
async function enterApp(identity, persist) {
    const check = await apiCall('GET', '/me');
    if (check.status === 0 || check.status >= 500) {
        return { entry: ENTRY.UNREACHABLE, result: check };
    }
    const ttlDays = check.data && Number.isSafeInteger(check.data.message_ttl_days) ? check.data.message_ttl_days : 0;
    const limits = roomLimits(check.data);
    if (!check.ok || !check.data || check.data.public_key !== identity.publicKey || ttlDays < 1 || ttlDays > MAX_MESSAGE_TTL_DAYS || !limits) {
        // Server-driven: the replay records stay (Keystore.wipeIdentity)
        await Keystore.wipeIdentity();
        if (check.ok) {
            Errors.report(Errors.CODES.E_IDENTITY_MISMATCH);
            await apiCall('POST', '/logout');
        }
        return { entry: ENTRY.REFUSED, result: check };
    }
    if (persist) {
        await Keystore.save(identity);
    }
    await Chat.start(identity, ttlDays, limits);
    return { entry: ENTRY.ENTERED, result: check };
}

async function login() {
    const accountNumberInputElement = document.getElementById('accountNumberInput');
    const errorElement = document.getElementById('loginError');
    const successElement = document.getElementById('loginSuccess');
    const loginBtn = document.getElementById('loginBtn');

    errorElement.textContent = '';
    successElement.textContent = '';

    // Check if eye animation is active and mask smoothly if needed
    if (window.eyeAnimation && window.eyeAnimation.currentZone !== 'none') {
        // Stop animation and get original value
        const originalValue = window.eyeAnimation.originalValue || accountNumberInputElement.value;
        window.eyeAnimation.stopAnimation();
        window.eyeAnimation.currentZone = 'none';
        window.eyeAnimation.resetToMasked();

        // Smoothly mask the input using existing animation
        await animateInputToMask(accountNumberInputElement, originalValue);

        // Restore original value after masking
        accountNumberInputElement.value = originalValue;
        accountNumberInputElement.type = 'password';
    }

    const accountNumberInput = accountNumberInputElement.value.trim();

    if (!accountNumberInput) {
        Errors.inline(errorElement, Errors.CODES.E_LOGIN_EMPTY);
        return;
    }

    // Normalize & validate account number format safely
    const normalizedAccountNumber = String(accountNumberInput)
        .normalize('NFKC')   // Unicode look-alike cleanup
        .trim();             // Remove leading/trailing hidden whitespace

    if (ElyrnCrypto.codeBody(normalizedAccountNumber, ElyrnCrypto.INVITE_PREFIXES) !== null) {
        Errors.inline(errorElement, Errors.CODES.E_LOGIN_INVITE_PASTED);
        return;
    }

    if (
        normalizedAccountNumber.length !== ACCOUNT_NUMBER_LEN ||
        !ACCOUNT_NUMBER_REGEX.test(normalizedAccountNumber)
    ) {
        Errors.inline(errorElement, Errors.CODES.E_LOGIN_FORMAT);
        return;
    }

    loginBtn.disabled = true;
    try {
        // ZERO-KNOWLEDGE: only HKDF(AccountNumber, "noaddx/auth") goes over the wire
        const authKey = await ElyrnCrypto.deriveAuthKey(normalizedAccountNumber);
        const result = await apiCall('POST', '/login', { auth_key: authKey });
        if (!result.ok || !result.data || !result.data.success) {
            // SECURITY: the server's own text is never shown (Errors.fromResult maps it)
            Errors.inline(errorElement, Errors.fromResult(result), null, result);
            return;
        }

        successElement.textContent = Errors.NOTICE.DERIVING_KEYS;
        const identity = await deriveSession(normalizedAccountNumber);
        const opened = await enterApp(identity, true);
        successElement.textContent = '';
        if (opened.entry === ENTRY.UNREACHABLE) {
            // The number stays in the field: pressing login again retries
            Errors.inline(errorElement, Errors.fromResult(opened.result), null, opened.result);
            return;
        }
        accountNumberInputElement.value = '';
        errorElement.textContent = '';
        if (opened.entry === ENTRY.REFUSED) {
            showMainMenu();
        }
    } catch (error) {
        Errors.inline(errorElement, Errors.CODES.E_REQUEST_FAILED, null, error);
    } finally {
        loginBtn.disabled = false;
    }
}

// Global variables for registration state
let stopScramble = null;
let pendingRegistrationAccountNumber = null;
let pendingRegistrationToken = null;  // Zero-trust: token from backend

// Scramble animation: random characters cycle until the real AccountNumber arrives (visual only)
function startAccountNumberScramble(accountNumberElement, successElement, accountNumberDisplay) {
    // Safety checks
    if (!accountNumberElement || !successElement || !accountNumberDisplay) {
        Log.error(Errors.INTERNAL.E_SCRAMBLE_ELEMENTS_MISSING);
        return;
    }
    
    // Show the account number display area first
    accountNumberDisplay.style.display = 'block';
    const accountNumberBox = accountNumberDisplay.querySelector('.account-number-box');
    if (accountNumberBox) accountNumberBox.classList.add('show');
    
    successElement.textContent = Errors.NOTICE.GENERATING_ACCOUNT_NUMBER;
    accountNumberElement.classList.add('generating');

    stopAccountNumberScramble();
    stopScramble = startScramble(accountNumberElement, ACCOUNT_NUMBER_LEN);
}

// Stop the scramble animation
function stopAccountNumberScramble() {
    if (stopScramble) {
        stopScramble();
        stopScramble = null;
    }
}

// Copy button - get real Account Number from backend (but don't create account yet)
// Zero-trust: Backend returns a pending_token that we must use to confirm
async function copyAccountNumber() {
    const accountNumberElement = document.getElementById('generatedAccountNumber');
    const successElement = document.getElementById('registerSuccess');
    const errorElement = document.getElementById('registerError');
    const continueBtn = document.getElementById('continueBtn');
    const copyBtn = document.getElementById('copyBtn');
    // Re-enable copy button on error
    const allowRetry = () => {
        if (copyBtn) {
            copyBtn.disabled = false;
        }
    };

    // Disable copy button immediately to prevent multiple clicks
    if (copyBtn) {
        copyBtn.disabled = true;
    }
    errorElement.textContent = '';

    await maskAccountNumber(accountNumberElement, successElement);

    // First, get PoW challenge from backend
    successElement.textContent = Errors.NOTICE.PREPARING_CHALLENGE;

    try {
        const issued = await requestAccountNumber(accountNumberElement, successElement, errorElement);
        if (!issued) {
            allowRetry();
            return;
        }

        // Store pending AccountNumber and token for account creation on continue
        pendingRegistrationAccountNumber = issued.accountNumber;
        pendingRegistrationToken = issued.pendingToken;

        await revealAccountNumber(accountNumberElement, successElement, issued.accountNumber);
        await copyIssuedAccountNumber(issued.accountNumber);

        // Enable continue button
        continueBtn.disabled = false;

    } catch (error) {
        allowRetry();
        // Registration was left while the proof of work ran: nothing to tell
        if (isPowCancelled(error)) return;
        // SECURITY: Generic error message; the log keeps only the error's name
        Errors.inline(errorElement, powFailureCode(error, Errors.fromApi(null, 500)), null, error);
        accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
    }
}

// Stops the scramble and turns it into asterisks while the real number is fetched
async function maskAccountNumber(accountNumberElement, successElement) {
    // Stop the scramble animation
    stopAccountNumberScramble();

    // Show masking animation
    accountNumberElement.classList.remove('generating');
    accountNumberElement.classList.add('masking');
    successElement.textContent = Errors.NOTICE.SECURING_IDENTIFIER;

    // Animate to all asterisks
    await animateToMask(accountNumberElement);
}

// Registration phase 1: pays a proof of work and has the server issue an account number and
// its pending token. Returns { accountNumber, pendingToken }, or null once the failure has been
// shown; throws only when the proof of work fails (the caller reports it).
async function requestAccountNumber(accountNumberElement, successElement, errorElement) {
    const failed = (code, cause) => {
        Errors.inline(errorElement, code, null, cause);
        accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
        return null;
    };

    const issued = await getPowChallenge();
    if (!issued.challenge) {
        return failed(Errors.fromResult(issued), issued);
    }

    successElement.textContent = Errors.NOTICE.SECURING_ACCOUNT;

    // Solve the PoW challenge
    const powSolution = await solvePowChallenge(issued.challenge);

    successElement.textContent = Errors.NOTICE.GENERATING_ACCOUNT_NUMBER;

    // Get Account Number from backend (Phase 1 - no account creation)
    const result = await apiCall('POST', '/register', { confirm: false, pow: powSolution });
    if (!result.ok || !result.data || !result.data.success) {
        // SECURITY: the server's own text is never shown (Errors.fromResult maps it)
        return failed(Errors.fromResult(result), result);
    }

    const accountNumber = result.data.account_number;
    const pendingToken = result.data.pending_token;

    if (typeof accountNumber !== 'string' || accountNumber.length !== ACCOUNT_NUMBER_LEN ||
        typeof pendingToken !== 'string' || !pendingToken) {
        // SECURITY: Generic error message
        return failed(Errors.fromApi(null, result.status), result);
    }
    return { accountNumber: accountNumber, pendingToken: pendingToken };
}

// Reveal the real AccountNumber with animation, then say it is ready
async function revealAccountNumber(accountNumberElement, successElement, accountNumber) {
    await revealText(accountNumberElement, accountNumber);

    accountNumberElement.classList.remove('masking');
    accountNumberElement.classList.add('revealed');
    successElement.textContent = Errors.NOTICE.ACCOUNT_NUMBER_READY;
}

// Copy to clipboard for the user to save; a refused copy asks them to copy it by hand
async function copyIssuedAccountNumber(accountNumber) {
    try {
        await copyToClipboard(accountNumber);
        showSuccess('Account number copied to clipboard!');
    } catch (e) {
        Errors.report(Errors.CODES.W_ACCOUNT_NUMBER_NOT_COPIED);
    }
}

// Animate input field to all asterisks (for input elements)
function animateInputToMask(inputElement, originalValue) {
    return new Promise((resolve) => {
        const currentValue = inputElement.value || originalValue;
        let masked = currentValue.split('');
        let step = 0;
        
        // Show as text during animation
        inputElement.type = 'text';
        
        const maskInterval = setInterval(() => {
            // Mask 2-3 random characters per step
            for (let i = 0; i < MASK_CHARS_PER_STEP; i++) {
                const randomIndex = Math.floor(Math.random() * masked.length);
                masked[randomIndex] = MASK_CHAR;
            }
            inputElement.value = masked.join('');
            step++;
            
            // Check if all masked
            if (masked.every(c => c === MASK_CHAR) || step > MASK_MAX_STEPS) {
                clearInterval(maskInterval);
                inputElement.value = MASK_CHAR.repeat(masked.length);
                resolve();
            }
        }, MASK_STEP_MS);
    });
}

// Phase 2 never leaves the page. The account number on screen is already saved by the user,
// and the server keeps it redeemable until the account exists, so a failure says so and the
// user presses continue again (with a fresh proof of work).
function failRegistrationStep(status, cause) {
    const code = status === 0 ? Errors.CODES.E_REGISTER_CONNECTION_LOST
        : status === 429 ? Errors.CODES.E_REGISTER_RATE_LIMITED
        : status >= 500 ? Errors.CODES.E_REGISTER_SERVER_BUSY
        : Errors.CODES.E_REGISTER_REFUSED;
    document.getElementById('registerSuccess').textContent = '';
    Errors.inline(document.getElementById('registerError'), code, null, cause || { status: status });
}

async function continueWithAccountNumber() {
    const generatedAccountNumber = document.getElementById('generatedAccountNumber').textContent;
    const successElement = document.getElementById('registerSuccess');
    const errorElement = document.getElementById('registerError');
    const continueBtn = document.getElementById('continueBtn');

    // Validate that we have a real AccountNumber (not masked)
    if (!generatedAccountNumber || generatedAccountNumber.includes(MASK_CHAR) || generatedAccountNumber.length !== ACCOUNT_NUMBER_LEN) {
        Errors.report(Errors.CODES.E_ACCOUNT_NUMBER_MISSING);
        return;
    }

    // Zero-trust: We need the pending token from Phase 1
    if (!pendingRegistrationToken) {
        Errors.report(Errors.CODES.E_REGISTRATION_EXPIRED);
        cancelRegistration();
        return;
    }

    // One attempt at a time: a double click would race two confirmations
    continueBtn.disabled = true;
    successElement.textContent = Errors.NOTICE.PREPARING_CHALLENGE;
    errorElement.textContent = '';

    try {
        // SECURITY: Phase 2 requires separate PoW (prevents Phase 1 replay)
        const issued = await getPowChallenge();
        if (!issued.challenge) {
            failRegistrationStep(issued.status);
            return;
        }

        successElement.textContent = Errors.NOTICE.SECURING_ACCOUNT;
        const powSolution = await solvePowChallenge(issued.challenge);

        successElement.textContent = Errors.NOTICE.CREATING_ACCOUNT;

        // Phase 2: Create account using pending token (not Account Number from frontend);
        // the HttpOnly session cookie is set by the response
        const result = await apiCall('POST', '/register', {
            confirm: true,
            pending_token: pendingRegistrationToken,
            pow: powSolution
        });

        if (result.ok && result.data && result.data.success) {
            await finishRegistration();
        } else if (result.status === 401) {
            await recoverRegistration();
        } else {
            failRegistrationStep(result.status);
        }
    } catch (error) {
        // Registration was left while the proof of work ran: nothing to tell
        if (isPowCancelled(error)) return;
        const powCode = powFailureCode(error, null);
        if (powCode) {
            document.getElementById('registerSuccess').textContent = '';
            Errors.inline(errorElement, powCode, null, error);
        } else {
            // SECURITY: Generic error message; the log keeps only the error's name
            failRegistrationStep(0, error);
        }
    } finally {
        continueBtn.disabled = !pendingRegistrationToken;
    }
}

// Account created: derive the E2E identity locally from the account number we hold. The number
// stays on screen (and pending) until the app has opened: if it does not, the account exists
// anyway and the number is the only way back into it.
async function finishRegistration() {
    const accountNumber = pendingRegistrationAccountNumber;
    const successElement = document.getElementById('registerSuccess');
    successElement.textContent = Errors.NOTICE.DERIVING_KEYS;
    const identity = await deriveSession(accountNumber);
    const opened = await enterApp(identity, true);
    successElement.textContent = '';
    if (opened.entry !== ENTRY.ENTERED) {
        // Continue retries (the server answers 401, recoverRegistration logs in), or log in by hand
        Errors.inline(document.getElementById('registerError'), Errors.CODES.E_ACCOUNT_CREATED_NOT_ENTERED, null, opened.result);
        return;
    }

    // The account number was copied for the user to save; do not leave it in the clipboard
    // (clipboard histories and cross-device sync would keep it). Best effort only: a page
    // without focus may not write the clipboard, and registration must not fail over it.
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText('').catch(error => Log.warn(Errors.INTERNAL.W_CLIPBOARD_NOT_CLEARED, error));
    }

    // Clear pending state
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;
    document.getElementById('generatedAccountNumber').textContent = '';
    showSuccess('welcome to elyrn.');
}

// A 401 means the server no longer holds this registration. Either an earlier attempt created
// the account and only its answer was lost (then the number logs in), or the registration
// expired first: that number will never work, so it is replaced rather than kept.
async function recoverRegistration() {
    const authKey = await ElyrnCrypto.deriveAuthKey(pendingRegistrationAccountNumber);
    const login = await apiCall('POST', '/login', { auth_key: authKey });
    if (login.ok && login.data && login.data.success) {
        await finishRegistration();
        return;
    }
    if (login.status !== 401) {
        failRegistrationStep(login.status);
        return;
    }
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;
    showRegisterForm();
    Errors.inline(document.getElementById('registerError'), Errors.CODES.E_ACCOUNT_NUMBER_EXPIRED);
}

async function logout() {
    // Forget local key material first, then revoke every server session
    Chat.stop();
    await Keystore.wipeAll();
    const result = await apiCall('POST', '/logout');
    showMainMenu();
    document.getElementById('accountNumberInput').value = '';
    if (!result.ok) {
        // This device is logged out either way; say so if other sessions could not be revoked
        Errors.report(Errors.CODES.W_LOGOUT_SERVER_UNREACHABLE, null, result);
    }
}

// Erases this identity once the account number is re-entered. Only its derived auth key is
// sent, and only after it proves to be this identity's: another account's key would let the
// server link the two accounts.
async function deleteIdentity() {
    const input = document.getElementById('deleteAccountInput');
    const accountNumber = String(input.value).normalize('NFKC').trim();
    input.value = '';
    if (accountNumber.length !== ACCOUNT_NUMBER_LEN || !ACCOUNT_NUMBER_REGEX.test(accountNumber)) {
        Errors.report(Errors.CODES.E_DELETE_INVALID_NUMBER);
        return;
    }

    const button = document.getElementById('deleteConfirmBtn');
    button.disabled = true;
    try {
        const identity = await ElyrnCrypto.deriveIdentity(accountNumber);
        if (identity.publicKey !== Chat.publicKey()) {
            Errors.report(Errors.CODES.E_DELETE_WRONG_IDENTITY);
            return;
        }
        const result = await apiCall('DELETE', '/me', { auth_key: await ElyrnCrypto.deriveAuthKey(accountNumber) });
        if (result.status === 429) {
            Errors.report(Errors.CODES.W_TOO_MANY_ATTEMPTS);
            return;
        }
        if (!result.ok) {
            Errors.report(Errors.CODES.E_IDENTITY_NOT_DELETED, null, result);
            return;
        }
        Chat.stop();
        await Keystore.wipeAll();
        showMainMenu();
        showSuccess('identity deleted');
    } catch (error) {
        Errors.report(Errors.CODES.E_IDENTITY_NOT_DELETED, null, error);
    } finally {
        button.disabled = false;
    }
}

// Cancel registration - just go back (no account was created yet)
function cancelRegistration() {
    // Stop the scramble animation and any proof of work still running for this registration
    stopAccountNumberScramble();
    cancelProofsOfWork();

    // Clear any pending state
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;

    // Return to main menu
    showMainMenu();
}
