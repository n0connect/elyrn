// ========================================
// ROBOT DOOR (the theatre in front of the robot entrance)
// ========================================
// THIS IS THEATRE, NOT A SECURITY CONTROL. It protects nothing: the command behind the door is
// public, anyone can press "i'm human" or open the page source, and the server has no robot flag
// (docs/architecture/agents.md, "The door is theatre").
//
// PRIVACY: the pointer trail and every measurement taken from it live only in this module's
// memory. They are never sent (this file makes no network request), never stored (no
// IndexedDB, localStorage or cookies), never logged (not through log.js either), and the caller
// discards them when the main menu or the verdict screen is left.
//
// Pure logic only: no DOM. ui.js and app.js do the wiring.

const RobotDoor = (() => {
    'use strict';

    // The trail keeps this many pointer moves (x, y, t), the oldest dropped first
    const TRAIL_CAPACITY = 256;
    // A click counts as a person's when at least this many moves happened ...
    const MIN_TRAIL_POINTS = 8;
    // ... within this long before it
    const RECENT_WINDOW_MS = 5000;
    // Below this straight-line distance the pointer came back where it started: no detour ratio
    const MIN_STRAIGHT_PX = 4;
    // A detour below this is a ruler-straight path
    const STRAIGHT_DETOUR_MAX = 1.05;
    // A wait this long between the last move and the click is a pause for thought
    const LONG_PAUSE_MS = 1500;
    // The challenge: a nonce of this many random bytes, answered with this many hex characters
    const NONCE_BYTES = 16;
    const ANSWER_HEX_CHARS = 8;
    const HEX_RADIX = 16;
    const HEX_BYTE_CHARS = 2;
    const DETOUR_DECIMALS = 1;
    const ANSWER_SHAPE = new RegExp('^[0-9a-f]{' + ANSWER_HEX_CHARS + '}$');

    // Which way the robot room greets: a robot that passed, or a person sent by their robot
    const MODE = Object.freeze({ ROBOT: 'robot', OPERATOR: 'operator' });

    // How a press of the door was judged
    const REASON = Object.freeze({
        TOUCH: 'touch',          // a finger
        PEN: 'pen',              // a stylus
        TRAIL: 'trail',          // a mouse that moved like a hand first
        NO_POINTER: 'no-pointer', // keyboard, or a click dispatched by script
        NO_TRAIL: 'no-trail'     // a mouse click out of nowhere, as browser automation produces
    });

    const LINES = Object.freeze({
        TOUCH: "you used a finger. robots don't have those.",
        PEN: "you used a pen. robots don't sign things.",
        WOBBLE: "a robot wouldn't wobble. you are almost certainly human.",
        STRAIGHT: 'suspiciously straight. still, you hesitated.',
        PAUSE: 'you stopped to think first. robots rarely do.',
        LOOP: 'you came back to where you started. very human.',
        HONEST: 'honesty. very human.',
        WRONG: 'wrong answer. reassuringly human.'
    });

    const GREETINGS = Object.freeze({
        [MODE.ROBOT]: 'welcome. no form here: you get a key file, not a password.',
        [MODE.OPERATOR]: "you're its human. tell it this:"
    });

    // ---------- the trail ----------

    // A ring buffer of the last TRAIL_CAPACITY moves; non-finite values are ignored
    function createTrail(capacity = TRAIL_CAPACITY) {
        const xs = new Float64Array(capacity);
        const ys = new Float64Array(capacity);
        const ts = new Float64Array(capacity);
        let next = 0;
        let size = 0;

        function push(x, y, t) {
            if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(t)) return;
            xs[next] = x;
            ys[next] = y;
            ts[next] = t;
            next = (next + 1) % capacity;
            size = Math.min(size + 1, capacity);
        }

        // Oldest first
        function points() {
            const out = [];
            const start = (next - size + capacity) % capacity;
            for (let i = 0; i < size; i++) {
                const at = (start + i) % capacity;
                out.push({ x: xs[at], y: ys[at], t: ts[at] });
            }
            return out;
        }

        function clear() {
            xs.fill(0);
            ys.fill(0);
            ts.fill(0);
            next = 0;
            size = 0;
        }

        return Object.freeze({ push, points, clear, size: () => size, capacity });
    }

    // ---------- measuring ----------

    // The moves within RECENT_WINDOW_MS before `at`
    function recent(points, at) {
        return points.filter(p => p.t <= at && at - p.t <= RECENT_WINDOW_MS);
    }

    // points (oldest first, at least one) and the click's time: the dry numbers on the verdict
    function measure(points, at) {
        let path = 0;
        for (let i = 1; i < points.length; i++) {
            path += Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
        }
        const first = points[0];
        const last = points[points.length - 1];
        const straight = Math.hypot(last.x - first.x, last.y - first.y);
        return Object.freeze({
            points: points.length,
            pathPx: path,
            straightPx: straight,
            detour: straight >= MIN_STRAIGHT_PX ? path / straight : null,
            hesitationMs: Math.max(0, Math.round(at - last.t))
        });
    }

    // click: { pointerType, detail, at } (at on the same clock as the trail's t)
    // Returns { human, reason, measurements } (measurements only for REASON.TRAIL)
    function classify(click, points) {
        const judged = (human, reason, measurements = null) => Object.freeze({ human, reason, measurements });
        if (click.pointerType === 'touch') return judged(true, REASON.TOUCH);
        if (click.pointerType === 'pen') return judged(true, REASON.PEN);
        if (click.detail === 0) return judged(false, REASON.NO_POINTER);
        const moves = recent(points, click.at);
        if (moves.length >= MIN_TRAIL_POINTS) return judged(true, REASON.TRAIL, measure(moves, click.at));
        return judged(false, REASON.NO_TRAIL);
    }

    // One line per verdict, chosen by the measurements alone (no randomness, so it is testable)
    function verdictLine(judged) {
        if (judged.reason === REASON.TOUCH) return LINES.TOUCH;
        if (judged.reason === REASON.PEN) return LINES.PEN;
        const m = judged.measurements;
        if (!m) return LINES.HONEST;
        if (m.detour === null) return LINES.LOOP;
        if (m.detour < STRAIGHT_DETOUR_MAX) return LINES.STRAIGHT;
        if (m.hesitationMs >= LONG_PAUSE_MS) return LINES.PAUSE;
        return LINES.WOBBLE;
    }

    function measurementLines(m) {
        if (!m) return [];
        return [
            `points: ${m.points}`,
            m.detour === null ? 'detour: round trip' : `detour: ${m.detour.toFixed(DETOUR_DECIMALS)}x`,
            `hesitation: ${m.hesitationMs} ms`
        ];
    }

    // ---------- the challenge ----------

    function toHex(bytes) {
        return Array.from(bytes, b => b.toString(HEX_RADIX).padStart(HEX_BYTE_CHARS, '0')).join('');
    }

    function newNonce() {
        return toHex(crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
    }

    // The first ANSWER_HEX_CHARS hex characters of SHA-256 over the nonce's ASCII bytes
    async function expectedAnswer(nonce) {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(nonce));
        return toHex(new Uint8Array(digest)).slice(0, ANSWER_HEX_CHARS);
    }

    // Trims and ignores case; a malformed answer is wrong without hashing anything.
    // Throws only when this browser cannot hash (crypto.subtle missing outside https).
    async function checkAnswer(nonce, answer) {
        const given = String(answer).trim().toLowerCase();
        if (!ANSWER_SHAPE.test(given)) return false;
        return given === await expectedAnswer(nonce);
    }

    return Object.freeze({
        TRAIL_CAPACITY, MIN_TRAIL_POINTS, RECENT_WINDOW_MS, MIN_STRAIGHT_PX, STRAIGHT_DETOUR_MAX,
        LONG_PAUSE_MS, NONCE_BYTES, ANSWER_HEX_CHARS, MODE, REASON, LINES,
        createTrail, measure, classify, verdictLine, measurementLines,
        newNonce, expectedAnswer, checkAnswer,
        greeting: (mode) => GREETINGS[mode] || GREETINGS[MODE.ROBOT]
    });
})();
