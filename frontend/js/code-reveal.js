// ========================================
// CODE REVEAL (scramble, mask and reveal of a code element)
// ========================================
// One job: animates an element that shows a secret code (account number, invite, room code)
// while the code is made and when it arrives. Visual only, no network, no crypto.

// Scramble, mask and reveal pacing (the mask is shared with auth.js's input field)
const MASK_CHAR = '*';
const SCRAMBLE_MASK_CHANCE = 0.08;
const SCRAMBLE_STEP_MS = 120;
const MASK_CHARS_PER_STEP = 3;
const MASK_MAX_STEPS = 20;
const MASK_STEP_MS = 50;
const REVEAL_CHARS_PER_STEP = 3;
const REVEAL_STEP_MS = 40;

// Visual only: the noise is Math.random and never key material, and the real value is
// written only after it has arrived. A fixed prefix (the invite's "elyrn:") stays readable.

const SCRAMBLE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

// Cycles random base64url characters (and an occasional '*') until the returned function is called
function startScramble(element, length, prefix = '') {
    const draw = () => {
        let scrambled = prefix;
        for (let i = 0; i < length; i++) {
            scrambled += Math.random() < SCRAMBLE_MASK_CHANCE ? MASK_CHAR : SCRAMBLE_CHARS.charAt(Math.floor(Math.random() * SCRAMBLE_CHARS.length));
        }
        element.textContent = scrambled;
    };
    draw();
    const timer = setInterval(draw, SCRAMBLE_STEP_MS);
    return () => clearInterval(timer);
}

// The states a scrambled, masked and revealed code element passes through (account number,
// invite, room code)
const CODE_STATES = ['generating', 'masking', 'revealed'];

// Empties a code element and takes it out of every animation state
function clearCodeElement(element) {
    element.textContent = '';
    element.classList.remove(...CODE_STATES);
}

// Puts a code element into one animation state (CODE_STATES), out of the others
function setCodeState(element, state) {
    element.classList.remove(...CODE_STATES);
    element.classList.add(state);
}

// Masks the scramble, then reveals the real code after its prefix: the account number's sequence.
// Resolves to alive(): false when the screen was left meanwhile and nothing more was drawn.
async function maskThenReveal(element, code, prefix, alive) {
    setCodeState(element, 'masking');
    await animateToMask(element, prefix, alive);
    await revealText(element, code, prefix, alive);
    if (!alive()) return false;
    setCodeState(element, 'revealed');
    return true;
}

// Every animation step asks alive() first: once the screen it draws for was left, the step
// stops the animation and resolves without writing, so nothing lands after the screen was cleared
const ALWAYS_ALIVE = () => true;

// Turns the characters after the prefix into '*', a few per step (until alive() turns false)
function animateToMask(element, prefix = '', alive = ALWAYS_ALIVE) {
    return new Promise((resolve) => {
        const masked = element.textContent.slice(prefix.length).split('');
        let step = 0;
        const timer = setInterval(() => {
            if (!alive()) {
                clearInterval(timer);
                resolve();
                return;
            }
            for (let i = 0; i < MASK_CHARS_PER_STEP; i++) {
                const index = Math.floor(Math.random() * masked.length);
                if (masked[index] !== undefined) {
                    masked[index] = MASK_CHAR;
                }
            }
            element.textContent = prefix + masked.join('');
            step++;
            if (masked.every(c => c === MASK_CHAR) || step > MASK_MAX_STEPS) {
                clearInterval(timer);
                element.textContent = prefix + MASK_CHAR.repeat(masked.length);
                resolve();
            }
        }, MASK_STEP_MS);
    });
}

// Replaces the mask with the real value in a random order, a few characters per step (until
// alive() turns false: animateToMask)
function revealText(element, value, prefix = '', alive = ALWAYS_ALIVE) {
    return new Promise((resolve) => {
        const body = value.slice(prefix.length);
        const shown = MASK_CHAR.repeat(body.length).split('');
        const order = Array.from(shown.keys());
        for (let i = order.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [order[i], order[j]] = [order[j], order[i]];
        }
        let step = 0;
        const timer = setInterval(() => {
            if (!alive()) {
                clearInterval(timer);
                resolve();
                return;
            }
            for (let i = 0; i < REVEAL_CHARS_PER_STEP && step < order.length; i++, step++) {
                shown[order[step]] = body[order[step]];
            }
            element.textContent = prefix + shown.join('');
            if (step >= order.length) {
                clearInterval(timer);
                element.textContent = value;
                resolve();
            }
        }, REVEAL_STEP_MS);
    });
}
