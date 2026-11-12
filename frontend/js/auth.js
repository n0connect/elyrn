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

function powWorkerURL() {
    return powWorkerPolicy ? powWorkerPolicy.createScriptURL(POW_WORKER_PATH) : POW_WORKER_PATH;
}

// Gets a PoW challenge without ever leaving the page, so callers keep what is on screen.
// Returns { challenge, status }: challenge is null on failure, status 0 means no connection.
async function getPowChallenge() {
    const result = await apiCall('GET', '/pow/challenge');
    const challenge = result.ok && result.data && result.data.success ? result.data.challenge : null;
    return { challenge: challenge || null, status: result.status };
}

// Solve PoW challenge using Web Worker
function solvePowChallenge(challenge) {
    return new Promise((resolve, reject) => {
        const worker = new Worker(powWorkerURL());

        worker.postMessage({
            challenge: challenge.challenge,
            difficulty: challenge.difficulty,
            salt: challenge.salt
        });

        worker.onmessage = function(e) {
            // Ignore progress updates, only process success/failure
            if (e.data.progress) {
                return;  // Continue computing
            }

            if (e.data.success === true) {
                resolve({
                    challenge: challenge.challenge,
                    solution: e.data.solution,
                    timestamp: challenge.timestamp,
                    ttl: challenge.ttl,
                    difficulty: challenge.difficulty,
                    salt: challenge.salt
                });
                worker.terminate();
            } else if (e.data.success === false) {
                reject(new Error('Processing failed'));
                worker.terminate();
            }
        };

        worker.onerror = function(error) {
            reject(error);
            worker.terminate();
        };
    });
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
        !Number.isSafeInteger(hours) || hours < 1 || hours > 720) {
        return null;
    }
    return { maxMembers: members, maxTTLHours: hours };
}

async function enterApp(identity, persist) {
    const check = await apiCall('GET', '/me');
    const ttlDays = check.data && Number.isSafeInteger(check.data.message_ttl_days) ? check.data.message_ttl_days : 0;
    const limits = roomLimits(check.data);
    if (!check.ok || !check.data || check.data.public_key !== identity.publicKey || ttlDays < 1 || ttlDays > 365 || !limits) {
        await Keystore.wipe();
        if (check.ok) {
            Errors.report(Errors.CODES.E_IDENTITY_MISMATCH);
            await apiCall('POST', '/logout');
        }
        showMainMenu();
        return false;
    }
    if (persist) {
        await Keystore.save(identity);
    }
    await Chat.start(identity, ttlDays, limits);
    return true;
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
        const response = await fetchWithErrorHandling(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ auth_key: authKey })
        });

        // If fetchWithErrorHandling returned null, it means error was handled and redirected
        if (!response) {
            return;
        }

        const data = await response.json();

        if (!data) {
            Errors.inline(errorElement, Errors.fromApi(null, response.status));
            return;
        }

        if (data.success) {
            successElement.textContent = Errors.NOTICE.DERIVING_KEYS;
            const identity = await deriveSession(normalizedAccountNumber);
            accountNumberInputElement.value = '';
            errorElement.textContent = '';
            successElement.textContent = '';
            await enterApp(identity, true);
        } else {
            // SECURITY: Map API error message to generic user-facing message
            Errors.inline(errorElement, Errors.fromApi(data.message, response.status));
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
    
    // Disable copy button immediately to prevent multiple clicks
    if (copyBtn) {
        copyBtn.disabled = true;
    }
    errorElement.textContent = '';

    // Stop the scramble animation
    stopAccountNumberScramble();
    
    // Show masking animation
    accountNumberElement.classList.remove('generating');
    accountNumberElement.classList.add('masking');
    successElement.textContent = Errors.NOTICE.SECURING_IDENTIFIER;
    
    // Animate to all asterisks
    await animateToMask(accountNumberElement);
    
    // First, get PoW challenge from backend
    successElement.textContent = Errors.NOTICE.PREPARING_CHALLENGE;

    try {
        const issued = await getPowChallenge();
        if (!issued.challenge) {
            throw new Error('Failed to get PoW challenge');
        }

        successElement.textContent = Errors.NOTICE.SECURING_ACCOUNT;

        // Solve the PoW challenge
        const powSolution = await solvePowChallenge(issued.challenge);

        successElement.textContent = Errors.NOTICE.GENERATING_ACCOUNT_NUMBER;

        // Get Account Number from backend (Phase 1 - no account creation)
        const response = await fetchWithErrorHandling(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                confirm: false,
                pow: powSolution
            })
        });

        // If fetchWithErrorHandling returned null, it means error was handled and redirected
        if (!response) {
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }

        const data = await response.json();
        
        if (!data || !data.success) {
            // SECURITY: Map API error message to generic user-facing message
            Errors.inline(errorElement, Errors.fromApi(data?.message, response.status));
            // Logged once, by the line above
            accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }

        const realAccountNumber = data.account_number;
        const pendingToken = data.pending_token;
        
        if (!realAccountNumber || realAccountNumber.length !== ACCOUNT_NUMBER_LEN || !pendingToken) {
            // SECURITY: Generic error message
            Errors.inline(errorElement, Errors.fromApi(null, response.status));
            // Re-enable copy button on error
            if (copyBtn) {
                copyBtn.disabled = false;
            }
            return;
        }
        
        // Store pending AccountNumber and token for account creation on continue
        pendingRegistrationAccountNumber = realAccountNumber;
        pendingRegistrationToken = pendingToken;
        
        // Reveal the real AccountNumber with animation
        await revealText(accountNumberElement, realAccountNumber);
        
        accountNumberElement.classList.remove('masking');
        accountNumberElement.classList.add('revealed');
        successElement.textContent = Errors.NOTICE.ACCOUNT_NUMBER_READY;
        
        // Copy to clipboard
        try {
            await copyToClipboard(realAccountNumber);
            showSuccess('Account number copied to clipboard!');
        } catch (e) {
            Errors.report(Errors.CODES.W_ACCOUNT_NUMBER_NOT_COPIED);
        }
        
        // Enable continue button
        continueBtn.disabled = false;
        
    } catch (error) {
        // SECURITY: Generic error message; the log keeps only the error's name
        Errors.inline(errorElement, Errors.fromApi(null, 500), null, error);
        accountNumberElement.textContent = Errors.message(Errors.CODES.E_ACCOUNT_NUMBER_FAILED);
        // Re-enable copy button on error
        if (copyBtn) {
            copyBtn.disabled = false;
        }
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
            for (let i = 0; i < 3; i++) {
                const randomIndex = Math.floor(Math.random() * masked.length);
                masked[randomIndex] = '*';
            }
            inputElement.value = masked.join('');
            step++;
            
            // Check if all masked
            if (masked.every(c => c === '*') || step > 20) {
                clearInterval(maskInterval);
                inputElement.value = '*'.repeat(masked.length);
                resolve();
            }
        }, 50);
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
    if (!generatedAccountNumber || generatedAccountNumber.includes('*') || generatedAccountNumber.length !== ACCOUNT_NUMBER_LEN) {
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
        // SECURITY: Generic error message; the log keeps only the error's name
        failRegistrationStep(0, error);
    } finally {
        continueBtn.disabled = !pendingRegistrationToken;
    }
}

// Account created: derive the E2E identity locally from the account number we hold
async function finishRegistration() {
    const accountNumber = pendingRegistrationAccountNumber;
    document.getElementById('registerSuccess').textContent = Errors.NOTICE.DERIVING_KEYS;
    const identity = await deriveSession(accountNumber);

    // The account number was copied for the user to save; do not leave it in the clipboard
    // (clipboard histories and cross-device sync would keep it). Best effort only.
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText('').catch(() => {});
    }

    // Clear pending state
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;
    document.getElementById('generatedAccountNumber').textContent = '';

    if (await enterApp(identity, true)) {
        showSuccess('welcome to elyrn.');
    }
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
    await Keystore.wipe();
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
        await Keystore.wipe();
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
    // Stop the scramble animation
    stopAccountNumberScramble();
    
    // Clear any pending state
    pendingRegistrationAccountNumber = null;
    pendingRegistrationToken = null;

    // Return to main menu
    showMainMenu();
}
