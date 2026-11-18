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
// Returns { challenge, status, timedOut, tooLarge }: challenge is null on failure, status 0 means
// no usable answer (Errors.fromResult reads the rest).
async function getPowChallenge() {
    const result = await apiCall('GET', '/pow/challenge');
    const served = result.ok && result.data && result.data.success ? result.data.challenge : null;
    // Anything but an object (a string, a number, a list) is no challenge: no worker is started for it
    const challenge = served !== null && typeof served === 'object' && !Array.isArray(served) ? served : null;
    return { challenge: challenge, status: result.status, timedOut: result.timedOut, tooLarge: result.tooLarge };
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
// Everything the browser keeps for a session, derived from the account number once. The sealed
// form is made only where this engine proved it cannot keep the key itself (Keystore.keepsKeys)
async function deriveSession(accountNumber) {
    const sealed = !(await Keystore.keepsKeys());
    const identity = await ElyrnCrypto.deriveIdentity(accountNumber, sealed);
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
    const files = fileMaxBytes(data);
    if (files === null) return null;
    return { maxMembers: members, maxTTLHours: hours, pageLimit: pageLimit(data), fileMaxBytes: files };
}

// The largest file this server takes (MAX_FILE_BYTES): from one stored part to the bound any
// server may set (backend/internal/config); anything else refuses the answer like the room limits
function fileMaxBytes(data) {
    const bytes = data && data.file_max_bytes;
    return Number.isSafeInteger(bytes) && bytes >= ElyrnFileCrypto.FILE_PART_BYTES && bytes <= ElyrnCrypto.MAX_FILE_BYTES_BOUND
        ? bytes : null;
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
    // any answer that says nothing about the session or the identity (no answer, a server error,
    // a 429, a 404 or any other 4xx but 401, settings this app refuses): nothing was wiped, the
    // caller offers a retry with the code for that answer (meVerdict)
    UNREACHABLE: 'unreachable',
    // the session is gone (401) or the server holds another public key: the stored identity was removed
    REFUSED: 'refused',
    // the screen that asked was left meanwhile (alive() false): nothing was saved or opened
    LEFT: 'left'
});

// Whether a /me answer body names exactly this device's public key (the one comparison every
// /me check makes: here, and on a stream reconnect or a return from the back-forward cache)
function sameIdentity(data, publicKey) {
    return Boolean(data) && typeof data === 'object' && typeof data.public_key === 'string' && data.public_key === publicKey;
}

// A /me answer body judged against this device's public key: { code: null, ttlDays, limits }
// when it is taken, else { code } to report. Another key is an attack on the identity
// (E_IDENTITY_MISMATCH); settings out of range are only refused (E_SERVER_LIMITS_INVALID).
function judgeMe(data, publicKey) {
    if (!sameIdentity(data, publicKey)) {
        return { code: Errors.CODES.E_IDENTITY_MISMATCH };
    }
    const ttlDays = Number.isSafeInteger(data.message_ttl_days) ? data.message_ttl_days : 0;
    const limits = roomLimits(data);
    if (ttlDays < 1 || ttlDays > MAX_MESSAGE_TTL_DAYS || !limits) {
        return { code: Errors.CODES.E_SERVER_LIMITS_INVALID };
    }
    return { code: null, ttlDays: ttlDays, limits: limits };
}

// What a /me answer means for the stored identity (C1: only the server's own word ends a session).
// { entry, code }: REFUSED for a 401 (the session is gone) or a 2xx naming another public key (an
// attack on the identity, E_IDENTITY_MISMATCH); UNREACHABLE, keeping the identity, for every
// other answer that is not taken: no answer, any 5xx, a 429, a 404 or any other 4xx, and a 2xx
// with this key whose settings this app refuses (E_SERVER_LIMITS_INVALID), each with the
// registered code for that answer; null code with ENTERED otherwise (judged holds the settings).
function meVerdict(check, publicKey) {
    if (check.status === HTTP_STATUS.UNAUTHORIZED) {
        return { entry: ENTRY.REFUSED, code: null };
    }
    if (!check.ok) {
        return { entry: ENTRY.UNREACHABLE, code: Errors.fromResult(check) };
    }
    const judged = judgeMe(check.data, publicKey);
    if (judged.code === Errors.CODES.E_IDENTITY_MISMATCH) {
        return { entry: ENTRY.REFUSED, code: judged.code };
    }
    if (judged.code) {
        return { entry: ENTRY.UNREACHABLE, code: judged.code };
    }
    return { entry: ENTRY.ENTERED, code: null, judged: judged };
}

// Opens the app once /me confirms the session and the identity. Never changes the view on
// failure: each caller knows what its user still needs on screen. alive() (optional) is asked
// after every wait: once it is false (the screen that asked was left) nothing is wiped, saved,
// shown or opened. Returns { entry, result, code } (code: what to tell for UNREACHABLE).
async function enterApp(identity, persist, alive = () => true) {
    const check = await apiCall('GET', '/me');
    if (!alive()) return { entry: ENTRY.LEFT, result: check, code: null };
    const verdict = meVerdict(check, identity.publicKey);
    if (verdict.entry === ENTRY.UNREACHABLE) {
        return { entry: ENTRY.UNREACHABLE, result: check, code: verdict.code };
    }
    if (verdict.entry === ENTRY.REFUSED) {
        // Server-driven: the replay records stay (Keystore.wipeIdentity)
        await Keystore.wipeIdentity();
        if (verdict.code) {
            Errors.report(verdict.code);
            await apiCall('POST', '/logout');
        }
        return { entry: ENTRY.REFUSED, result: check, code: verdict.code };
    }
    if (persist) {
        await Keystore.save(identity);
        if (!alive()) return { entry: ENTRY.LEFT, result: check, code: null };
    }
    await Chat.start(identity, verdict.judged.ttlDays, verdict.judged.limits);
    return { entry: ENTRY.ENTERED, result: check, code: null };
}

// Raised whenever the login screen is left: a login still in flight then shows and opens nothing
let loginRun = 0;

// Empties the login field and the eye animation's copy of what was typed in it
function clearLoginField() {
    document.getElementById('accountNumberInput').value = '';
    if (window.eyeAnimation) window.eyeAnimation.forget();
}

// The way back from the login screen (its button, its brand title, Escape): the typed number
// goes with it, and a login still in flight is abandoned. A session cookie that login already
// got stays until it expires: /logout would end every session of the account, and the server
// has no per-session revocation (docs/security/threat-model.md, Known Limitations)
function leaveLogin() {
    loginRun++;
    clearLoginField();
    document.getElementById('loginError').textContent = '';
    document.getElementById('loginSuccess').textContent = '';
    showMainMenu();
}

// Enter held down in the field, or a click while it runs, never starts a second login
function login() {
    return once('login', loginNow);
}

async function loginNow() {
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

    // NFKC, trimmed, an invite or room code named as such (validation.js parseAccountNumber)
    const parsed = parseAccountNumber(accountNumberInputElement.value);
    if (!parsed.valid) {
        Errors.inline(errorElement, parsed.error);
        return;
    }

    const run = loginRun;
    loginBtn.disabled = true;
    try {
        // ZERO-KNOWLEDGE: only HKDF(AccountNumber, "noaddx/auth") goes over the wire
        const authKey = await ElyrnCrypto.deriveAuthKey(parsed.value);
        const result = await apiCall('POST', '/login', { auth_key: authKey });
        // The login screen was left meanwhile: nothing is shown and the app is not opened
        if (run !== loginRun) return;
        if (!result.ok || !result.data || !result.data.success) {
            // SECURITY: the server's own text is never shown (Errors.fromResult maps it)
            Errors.inline(errorElement, Errors.fromResult(result), null, result);
            return;
        }

        successElement.textContent = Errors.NOTICE.DERIVING_KEYS;
        const identity = await deriveSession(parsed.value);
        if (run !== loginRun) return;
        const opened = await enterApp(identity, true);
        successElement.textContent = '';
        if (opened.entry === ENTRY.UNREACHABLE) {
            // The number stays in the field: pressing login again retries
            Errors.inline(errorElement, Errors.fromResult(opened.result), null, opened.result);
            return;
        }
        clearLoginField();
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
// Set once a phase 2 request was sent: from then on the account may exist, and the number on
// screen is the only way into it, so leaving takes a second press (cancelRegistration)
let registrationAccountMayExist = false;
// The first press of the way back while the account may exist: the next one leaves
let registrationLeaveArmed = false;
// Raised whenever registration is left: a run still in flight then stops at its next step and
// never holds, shows or copies a number again
let registrationRun = 0;

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
    setCodeState(accountNumberElement, 'generating');

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
function copyAccountNumber() {
    return once(registrationKey(), copyAccountNumberNow);
}

// The lock phase 1 and phase 2 share. It belongs to one registration: a run left behind (still
// waiting on its request) never blocks the next registration's buttons.
function registrationKey() {
    return 'register-' + registrationRun;
}

async function copyAccountNumberNow() {
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
    const run = registrationRun;
    // Every animation step of this run checks it: once registration is left, none writes again
    const alive = () => run === registrationRun;

    await maskAccountNumber(accountNumberElement, successElement, alive);
    if (!alive()) return;

    // First, get PoW challenge from backend
    successElement.textContent = Errors.NOTICE.PREPARING_CHALLENGE;

    try {
        const issued = await requestAccountNumber(run, accountNumberElement, successElement, errorElement);
        // Left meanwhile: the number is never held, shown or copied
        if (run !== registrationRun) return;
        if (!issued) {
            allowRetry();
            return;
        }

        // Store pending AccountNumber and token for account creation on continue
        pendingRegistrationAccountNumber = issued.accountNumber;
        pendingRegistrationToken = issued.pendingToken;

        await revealAccountNumber(accountNumberElement, successElement, issued.accountNumber, alive);
        if (!alive()) return;
        await copyIssuedAccountNumber(issued.accountNumber);

        // Enable continue button
        continueBtn.disabled = false;

    } catch (error) {
        allowRetry();
        // Registration was left while the proof of work ran: nothing to tell
        if (isPowCancelled(error) || run !== registrationRun) return;
        // SECURITY: Generic error message; the log keeps only the error's name
        Errors.inline(errorElement, powFailureCode(error, Errors.fromApi(null, HTTP_STATUS.SERVER_ERROR)), null, error);
        accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
    }
}

// Stops the scramble and turns it into asterisks while the real number is fetched
async function maskAccountNumber(accountNumberElement, successElement, alive) {
    // Stop the scramble animation
    stopAccountNumberScramble();

    // Show masking animation
    setCodeState(accountNumberElement, 'masking');
    successElement.textContent = Errors.NOTICE.SECURING_IDENTIFIER;

    // Animate to all asterisks; a step after leaving writes nothing
    await animateToMask(accountNumberElement, '', alive);
}

// Registration phase 1: pays a proof of work and has the server issue an account number and
// its pending token. Returns { accountNumber, pendingToken }, or null once the failure has been
// shown (or registration was left: run is no longer registrationRun); throws only when the
// proof of work fails (the caller reports it).
async function requestAccountNumber(run, accountNumberElement, successElement, errorElement) {
    const failed = (code, cause) => {
        Errors.inline(errorElement, code, null, cause);
        accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
        return null;
    };

    const issued = await getPowChallenge();
    // Left meanwhile: no proof of work is started for a registration nobody waits for
    if (run !== registrationRun) return null;
    if (!issued.challenge) {
        return failed(Errors.fromResult(issued), issued);
    }

    successElement.textContent = Errors.NOTICE.SECURING_ACCOUNT;

    // Solve the PoW challenge
    const powSolution = await solvePowChallenge(issued.challenge);

    successElement.textContent = Errors.NOTICE.GENERATING_ACCOUNT_NUMBER;

    // Get Account Number from backend (Phase 1 - no account creation)
    const result = await apiCall('POST', '/register', { confirm: false, pow: powSolution });
    if (run !== registrationRun) return null;
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
async function revealAccountNumber(accountNumberElement, successElement, accountNumber, alive) {
    await revealText(accountNumberElement, accountNumber, '', alive);
    if (!alive()) return;

    setCodeState(accountNumberElement, 'revealed');
    successElement.textContent = Errors.NOTICE.ACCOUNT_NUMBER_READY;
}

// Copy to clipboard for the user to save. A copy that failed, or did not settle in time
// (copyToClipboard bounds it), asks them, in the form itself, to select the number on screen and
// copy it by hand before pressing continue: continue is their word that they kept it. Either way
// the number has been shown before continue is offered.
async function copyIssuedAccountNumber(accountNumber) {
    try {
        await copyToClipboard(accountNumber);
        showSuccess(Errors.NOTICE.ACCOUNT_NUMBER_COPIED);
    } catch (error) {
        Errors.inline(document.getElementById('registerError'), Errors.CODES.W_ACCOUNT_NUMBER_NOT_COPIED, null, error);
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
    const code = status === HTTP_STATUS.NO_ANSWER ? Errors.CODES.E_REGISTER_CONNECTION_LOST
        : status === HTTP_STATUS.TOO_MANY_REQUESTS ? Errors.CODES.E_REGISTER_RATE_LIMITED
        : status >= HTTP_STATUS.SERVER_ERROR ? Errors.CODES.E_REGISTER_SERVER_BUSY
        : Errors.CODES.E_REGISTER_REFUSED;
    document.getElementById('registerSuccess').textContent = '';
    Errors.inline(document.getElementById('registerError'), code, null, cause || { status: status });
}

// Shares its key with the copy step: phase 1 and phase 2 never run at once
function continueWithAccountNumber() {
    return once(registrationKey(), continueWithAccountNumberNow);
}

async function continueWithAccountNumberNow() {
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
        leaveRegistration();
        return;
    }

    // One attempt at a time: a double click would race two confirmations
    continueBtn.disabled = true;
    successElement.textContent = Errors.NOTICE.PREPARING_CHALLENGE;
    errorElement.textContent = '';
    // Pressing continue answers a pending "press back again": the next back asks again
    registrationLeaveArmed = false;
    const run = registrationRun;

    try {
        // SECURITY: Phase 2 requires separate PoW (prevents Phase 1 replay)
        const issued = await getPowChallenge();
        if (run !== registrationRun) return;
        if (!issued.challenge) {
            failRegistrationStep(issued.status);
            return;
        }

        successElement.textContent = Errors.NOTICE.SECURING_ACCOUNT;
        const powSolution = await solvePowChallenge(issued.challenge);

        successElement.textContent = Errors.NOTICE.CREATING_ACCOUNT;

        // Phase 2: Create account using pending token (not Account Number from frontend);
        // the HttpOnly session cookie is set by the response. Once sent, the account may exist
        // whatever comes back (a lost answer hides a creation), until registration ends.
        registrationAccountMayExist = true;
        const result = await apiCall('POST', '/register', {
            confirm: true,
            pending_token: pendingRegistrationToken,
            pow: powSolution
        });
        // Left meanwhile, after a second press that accepted the loss: nothing more happens
        if (run !== registrationRun) return;

        if (result.ok && result.data && result.data.success) {
            await finishRegistration(run);
        } else if (result.status === HTTP_STATUS.UNAUTHORIZED) {
            await recoverRegistration(run);
        } else {
            failRegistrationStep(result.status);
        }
    } catch (error) {
        // Registration was left while the proof of work ran: nothing to tell
        if (isPowCancelled(error) || run !== registrationRun) return;
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
async function finishRegistration(run) {
    const accountNumber = pendingRegistrationAccountNumber;
    const successElement = document.getElementById('registerSuccess');
    successElement.textContent = Errors.NOTICE.DERIVING_KEYS;
    const identity = await deriveSession(accountNumber);
    // Left meanwhile (a second press accepted the loss): the app is not opened behind the menu
    if (run !== registrationRun) return;
    const opened = await enterApp(identity, true, () => run === registrationRun);
    if (opened.entry === ENTRY.LEFT) return;
    successElement.textContent = '';
    if (opened.entry !== ENTRY.ENTERED) {
        // Continue retries (the server answers 401, recoverRegistration logs in), or log in by hand
        Errors.inline(document.getElementById('registerError'), Errors.CODES.E_ACCOUNT_CREATED_NOT_ENTERED, null, opened.result);
        return;
    }

    // The account number was copied for the user to save; do not leave it in the clipboard
    // (clipboard histories and cross-device sync would keep it): dropRegistrationSecrets
    dropRegistrationSecrets();
    clearCodeElement(document.getElementById('generatedAccountNumber'));
    showSuccess(Errors.NOTICE.WELCOME);
}

// A 401 means the server no longer holds this registration. Either an earlier attempt created
// the account and only its answer was lost (then the number logs in), or the registration
// expired first: that number will never work, so it is replaced rather than kept.
async function recoverRegistration(run) {
    const authKey = await ElyrnCrypto.deriveAuthKey(pendingRegistrationAccountNumber);
    const login = await apiCall('POST', '/login', { auth_key: authKey });
    if (run !== registrationRun) return;
    if (login.ok && login.data && login.data.success) {
        await finishRegistration(run);
        return;
    }
    if (login.status !== HTTP_STATUS.UNAUTHORIZED) {
        failRegistrationStep(login.status);
        return;
    }
    // The number never opened an account and never will: nothing is lost by dropping it
    dropRegistrationSecrets();
    showRegisterForm();
    Errors.inline(document.getElementById('registerError'), Errors.CODES.E_ACCOUNT_NUMBER_EXPIRED);
}

// Logging out and deleting the identity share one key: a second press, or the other one, while
// either runs is ignored (a double logout would report the server unreachable)
const ACCOUNT_ACTION = 'account';

function logout() {
    return once(ACCOUNT_ACTION, logoutNow);
}

async function logoutNow() {
    // Forget local key material first, then revoke every server session
    Chat.stop();
    await Keystore.wipeAll();
    const result = await apiCall('POST', '/logout');
    showMainMenu();
    clearLoginField();
    if (!result.ok) {
        // This device is logged out either way; say so if other sessions could not be revoked
        Errors.report(Errors.CODES.W_LOGOUT_SERVER_UNREACHABLE, null, result);
    }
}

// Erases this identity once the account number is re-entered. Only its derived auth key is
// sent, and only after it proves to be this identity's: another account's key would let the
// server link the two accounts.
function deleteIdentity() {
    return once(ACCOUNT_ACTION, deleteIdentityNow);
}

async function deleteIdentityNow() {
    const input = document.getElementById('deleteAccountInput');
    // Read as login reads it; any refusal here is one code (the field asks for this identity's number)
    const parsed = parseAccountNumber(input.value);
    input.value = '';
    if (!parsed.valid) {
        Errors.report(Errors.CODES.E_DELETE_INVALID_NUMBER);
        return;
    }
    const accountNumber = parsed.value;

    const button = document.getElementById('deleteConfirmBtn');
    button.disabled = true;
    try {
        const identity = await ElyrnCrypto.deriveIdentity(accountNumber);
        if (identity.publicKey !== Chat.publicKey()) {
            Errors.report(Errors.CODES.E_DELETE_WRONG_IDENTITY);
            return;
        }
        const result = await apiCall('DELETE', '/me', { auth_key: await ElyrnCrypto.deriveAuthKey(accountNumber) });
        if (result.status === HTTP_STATUS.TOO_MANY_REQUESTS) {
            Errors.report(Errors.CODES.W_TOO_MANY_ATTEMPTS);
            return;
        }
        const outcome = result.ok ? DELETION.DELETED : await deletionOutcome(result);
        if (outcome === DELETION.DELETED) {
            Chat.stop();
            await Keystore.wipeAll();
            showMainMenu();
            showSuccess(Errors.NOTICE.IDENTITY_DELETED);
        } else {
            Errors.report(outcome === DELETION.UNKNOWN ? Errors.CODES.E_IDENTITY_DELETE_UNKNOWN : Errors.CODES.E_IDENTITY_NOT_DELETED, null, result);
        }
    } catch (error) {
        Errors.report(Errors.CODES.E_IDENTITY_NOT_DELETED, null, error);
    } finally {
        button.disabled = false;
    }
}

// What a delete that did not answer 2xx did
const DELETION = Object.freeze({ DELETED: 'deleted', KEPT: 'kept', UNKNOWN: 'unknown' });

// A lost answer (no answer, or a server error) may hide a delete that happened: the session
// says which. 401: the identity is gone with it; 200: still there; anything else: unknown.
async function deletionOutcome(result) {
    if (result.status !== HTTP_STATUS.NO_ANSWER && result.status < HTTP_STATUS.SERVER_ERROR) return DELETION.KEPT;
    const check = await apiCall('GET', '/me');
    if (check.status === HTTP_STATUS.UNAUTHORIZED) return DELETION.DELETED;
    return check.ok ? DELETION.KEPT : DELETION.UNKNOWN;
}

// Forgets the account number and pending token this page holds and every flag about them.
// The number was copied for the user to save: it is cleared from the clipboard if the clipboard
// still holds it (best effort, utils.js clearClipboardIfHolds; never throws). Resolves once that
// clipboard attempt settled.
function dropRegistrationSecrets() {
    const accountNumber = pendingRegistrationAccountNumber;
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;
    registrationAccountMayExist = false;
    registrationLeaveArmed = false;
    return accountNumber ? clearClipboardIfHolds(accountNumber) : Promise.resolve();
}

// Gives up the registration in progress, whatever it was doing: every run still in flight stops
// at its next step (registrationRun), its proof of work ends, and its secrets are dropped.
// No DOM is touched here (leaveRegistration clears the screen).
function forgetRegistration() {
    registrationRun++;
    stopAccountNumberScramble();
    cancelProofsOfWork();
    return dropRegistrationSecrets();
}

// What the way back does now: LEAVE, or ASK first because the account may exist and the number
// on screen is the only way into it (a second press then leaves)
const REGISTRATION_EXIT = Object.freeze({ LEAVE: 'leave', ASK: 'ask' });

function registrationExit() {
    return registrationAccountMayExist && !registrationLeaveArmed ? REGISTRATION_EXIT.ASK : REGISTRATION_EXIT.LEAVE;
}

// Leaves registration for the main menu, with nothing of it left on the page
function leaveRegistration() {
    const cleared = forgetRegistration();
    clearCodeElement(document.getElementById('generatedAccountNumber'));
    document.getElementById('registerError').textContent = '';
    document.getElementById('registerSuccess').textContent = '';
    showMainMenu();
    return cleared;
}

// The way back from registration (its button, its brand title, Escape), in both of its steps.
// One press at a time; where the account may already exist the first press only asks.
function cancelRegistration() {
    return once('register-leave', async () => {
        if (registrationExit() === REGISTRATION_EXIT.ASK) {
            registrationLeaveArmed = true;
            document.getElementById('registerSuccess').textContent = '';
            Errors.inline(document.getElementById('registerError'), Errors.CODES.W_REGISTRATION_LEAVE_CONFIRM);
            return;
        }
        await leaveRegistration();
    });
}
