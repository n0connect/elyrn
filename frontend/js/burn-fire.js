// ========================================
// BURN FIRE (the burned view goes up in flames, for the person who burned, once the server confirmed it)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. On a coarse grid of big square cells, in four steps of the app's frame clock
// (--frame-ms in styles.css, read at start):
// 1. the burned view fades to black in three ordered-dither steps (a pixel fade, no opacity);
// 2. a few very large tongues of flame rise from the bottom edge in three layers, back to front:
//    the destructive red (tallest), "orange" (a one-cell checker of red and yellow, no new colour)
//    and the warning yellow (the short hot core); each tongue is a pointed arch around its centre
//    that narrows with height, its tip leaning and swaying a cell from frame to frame;
// 3. the whole window is flame: at the first such frame the app switches to the home view
//    underneath (play's onCovered) and the black is dropped;
// 4. the flames leave upward, their lower edge lifting off the bottom as inverted tongues, until
//    nothing is painted and the canvas is removed.
// The geometry is pure (tongues from a seed, a cell's layer from the frame); colours are custom
// properties of the stylesheet. Drawn on one canvas made for the length of the animation and
// removed afterwards: no markup string, no inline style, nothing the CSP or Trusted Types refuse.

const BurnFire = (() => {
    'use strict';

    // A cell is CELL_PX css pixels (four aura pixels), CELL_PX_NARROW under NARROW_PX; capped
    const CELL_PX = 16;
    const CELL_PX_NARROW = 12;
    const NARROW_PX = 480;
    const MAX_COLS = 240;
    const MAX_ROWS = 135;
    // The app's frame clock (styles.css): every stepped animation steps at it
    const FRAME_PROPERTY = '--frame-ms';
    // The frame plan: fade, rise, cover, exit; the hard stop comes one frame after the last
    const FADE_FRAMES = 3;
    const RISE_FRAMES = 5;
    const COVER_FRAMES = 2;
    const EXIT_FRAMES = 4;
    const RISE_START = FADE_FRAMES;
    const COVER_START = RISE_START + RISE_FRAMES;
    const EXIT_START = COVER_START + COVER_FRAMES;
    const TOTAL_FRAMES = EXIT_START + EXIT_FRAMES;
    // Tongues: TONGUES_MIN..TONGUES_MAX a layer, evenly spread with a little jitter; a layer's
    // tongues are its half share of the window's width either side of their centre at the base
    // (the red about a third wide, overlapping; the front layers narrower, so the colours stand
    // as flames inside flames, not bands) and min..max window heights tall when grown
    const TONGUES_MIN = 5;
    const TONGUES_MAX = 7;
    const JITTER_SHARE = 0.25;
    const LAYERS = Object.freeze([
        { name: 'red', half: 0.18, min: 1.5, max: 2.1 },
        { name: 'orange', half: 0.13, min: 0.8, max: 1.2 },
        { name: 'yellow', half: 0.08, min: 0.35, max: 0.65 }
    ]);
    const LEAN_MAX = 3;
    // A pointed arch: the half width at height h of a tongue of height H is half * (1 - h/H)^ARCH
    const ARCH = 0.7;
    // The sway of a tip, by frame: a cell left, none, a cell right, none
    const SWAY = Object.freeze([0, 1, 0, -1]);
    // Leaving: the lower edge lifts a quarter of the window a frame, highest between the tongues
    // and up to GAP_REACH window heights lower under them (inverted tongues), less so as it goes
    const GAP_REACH = 0.5;
    // What covers a cell
    const NONE = 0;
    const BLACK = 1;
    const RED = 2;
    const ORANGE = 3;
    const YELLOW = 4;
    // Paint: the palette's index for each layer (orange is a checker of red and yellow)
    const PALETTE = Object.freeze(['--fire-fringe', '--fire-flame', '--fire-glow']);
    const NOT_PAINTED = -1;
    // Ordered 2x2 dither: a cell is black at fade level n (1..3) when its rank is below RANKS[n]
    const BAYER = Object.freeze([0, 2, 3, 1]);
    const FADE_RANKS = Object.freeze([0, 1, 2, 4]);
    const CANVAS_CLASS = 'burn-fire';
    const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';
    const SEED_RANGE = 0x100000000;

    // mulberry32: a small seeded generator, so a seed gives one fire (never anything secret)
    function seeded(seed) {
        let state = seed >>> 0;
        return () => {
            state = (state + 0x6d2b79f5) >>> 0;
            let t = state;
            t = Math.imul(t ^ (t >>> 15), t | 1);
            t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
            return ((t ^ (t >>> 14)) >>> 0) / SEED_RANGE;
        };
    }

    const between = (random, min, max) => min + random() * (max - min);
    const whole = (random, min, max) => min + Math.floor(random() * (max - min + 1));

    // The tongues of every layer for a grid cols wide: [[{ x, half, height, lean, phase }]], back
    // to front; height in window heights. Pure: the same arguments give the same tongues.
    function tongues(cols, seed) {
        const random = seeded(seed);
        return LAYERS.map(layer => {
            const count = whole(random, TONGUES_MIN, TONGUES_MAX);
            const spacing = cols / count;
            return Array.from({ length: count }, (_, i) => ({
                x: (i + 0.5) * spacing + between(random, -JITTER_SHARE, JITTER_SHARE) * spacing,
                half: cols * layer.half,
                height: between(random, layer.min, layer.max),
                lean: between(random, -LEAN_MAX, LEAN_MAX),
                phase: whole(random, 0, SWAY.length - 1)
            }));
        });
    }

    // Whether a tongue grown to share of its height covers the cell at col, h cells above the
    // bottom row, at frame (its tip sways)
    function covers(tongue, share, rows, frame, col, h) {
        const height = tongue.height * share * rows;
        if (h >= height) return false;
        const rise = h / height;
        const centre = tongue.x + (tongue.lean + SWAY[(frame + tongue.phase) % SWAY.length]) * rise;
        return Math.abs(col + 0.5 - centre) <= tongue.half * Math.pow(1 - rise, ARCH);
    }

    // The fade's dither level at frame: 1, 2, 3 while fading, 3 (solid) while rising, else 0
    function fadeLevel(frame) {
        if (frame < FADE_FRAMES) return frame + 1;
        return frame < COVER_START ? FADE_FRAMES : 0;
    }

    // How far the flames have grown at frame: 0 before the rise, 1 from the cover on
    function riseShare(frame) {
        if (frame < RISE_START) return 0;
        return Math.min(1, (frame - RISE_START + 1) / RISE_FRAMES);
    }

    // What covers the cell at col, row (from the top) at frame: NONE, BLACK, RED, ORANGE or YELLOW
    function layerAt(plan, frame, col, row) {
        const { layers, rows, cols } = plan;
        if (frame >= TOTAL_FRAMES) return NONE;
        const h = rows - 1 - row;
        if (frame >= EXIT_START) {
            // the lower edge lifts, highest between the tongues (inverted tongues)
            const lift = (frame - EXIT_START + 1) / EXIT_FRAMES;
            const red = layers[0];
            let gap = 0;
            for (let i = 0; i + 1 < red.length; i++) {
                const mid = (red[i].x + red[i + 1].x) / 2;
                const width = (red[i + 1].x - red[i].x) / 2;
                gap = Math.max(gap, 1 - Math.abs(col + 0.5 - mid) / width);
            }
            const cut = rows * (lift - (1 - gap) * GAP_REACH * (1 - lift));
            if (h < cut || lift >= 1) return NONE;
        }
        const share = riseShare(frame);
        for (let layer = layers.length - 1; layer >= 0; layer--) {
            if (share > 0 && layers[layer].some(t => covers(t, share, rows, frame, col, h))) return RED + layer;
        }
        // from the cover on, the window is flame: the back layer fills what its tongues leave
        if (frame >= COVER_START) return RED;
        const level = fadeLevel(frame);
        return level && BAYER[(row % 2) * 2 + (col % 2)] < FADE_RANKS[level] ? BLACK : NONE;
    }

    // A layer's paint at col, row: the palette's index, or NOT_PAINTED
    function paint(layer, col, row) {
        if (layer === NONE) return NOT_PAINTED;
        if (layer === BLACK) return 0;
        if (layer === RED) return 1;
        if (layer === YELLOW) return 2;
        return (col + row) % 2 === 0 ? 1 : 2;
    }

    // Whether the fire plays at all: never under reduced motion, never on a hidden page, never
    // without the app's frame clock
    function shouldPlay(reducedMotion, hidden, frameMs = 1) {
        return !reducedMotion && !hidden && Number.isFinite(frameMs) && frameMs > 0;
    }

    // Whether frame is the one at which the app switches to the home view underneath
    function coversAt(frame) {
        return frame === COVER_START;
    }

    // The grid for a window of width x height css pixels
    function gridSize(width, height) {
        const base = width < NARROW_PX ? CELL_PX_NARROW : CELL_PX;
        const cell = Math.max(base, Math.ceil(width / MAX_COLS), Math.ceil(height / MAX_ROWS));
        return { cell, cols: Math.ceil(width / cell), rows: Math.ceil(height / cell) };
    }

    // How long the fire may stand at most: one frame after the last
    function hardStopMs(frameMs) {
        return (TOTAL_FRAMES + 1) * frameMs;
    }

    function readStyle() {
        const style = getComputedStyle(document.documentElement);
        return {
            colours: PALETTE.map(name => style.getPropertyValue(name).trim()),
            frameMs: parseFloat(style.getPropertyValue(FRAME_PROPERTY))
        };
    }

    function draw(context, plan, frame, cell, colours) {
        const { cols, rows } = plan;
        context.clearRect(0, 0, cols * cell, rows * cell);
        const paints = new Int8Array(cols * rows);
        for (let row = 0; row < rows; row++) {
            for (let col = 0; col < cols; col++) paints[row * cols + col] = paint(layerAt(plan, frame, col, row), col, row);
        }
        colours.forEach((colour, index) => {
            context.fillStyle = colour;
            for (let i = 0; i < paints.length; i++) {
                if (paints[i] === index) context.fillRect((i % cols) * cell, Math.floor(i / cols) * cell, cell, cell);
            }
        });
    }

    // Burns the window: onCovered (the switch to the home view) runs exactly once, at the first
    // fully covered frame, or at once when the fire does not play, or when anything ends it early
    // (the last frame, a key or a press, the hard stop, an error). The promise always resolves,
    // once the canvas is gone.
    function play(onCovered) {
        let covered = false;
        const cover = () => {
            if (covered) return;
            covered = true;
            try {
                if (onCovered) onCovered();
            } catch (err) {
                Log.error(Errors.INTERNAL.E_FIRE_FAILED, err);
            }
        };
        let reducedMotion = true;
        try {
            reducedMotion = window.matchMedia(REDUCED_MOTION).matches;
        } catch (err) {
            Log.warn(Errors.INTERNAL.W_FIRE_MOTION_UNKNOWN, err);
        }
        const hidden = document.visibilityState === 'hidden';
        if (!shouldPlay(reducedMotion, hidden)) {
            cover();
            return Promise.resolve();
        }
        return new Promise(resolve => {
            let canvas = null;
            let timer = 0;
            let hardStop = 0;
            const end = () => {
                clearTimeout(timer);
                clearTimeout(hardStop);
                window.removeEventListener('keydown', end, true);
                window.removeEventListener('pointerdown', end, true);
                if (canvas) canvas.remove();
                cover();
                resolve();
            };
            try {
                const look = readStyle();
                const context = shouldPlay(reducedMotion, hidden, look.frameMs) ? openCanvas() : null;
                if (!context) return end();
                canvas = context.canvas;
                const size = gridSize(window.innerWidth, window.innerHeight);
                const plan = { cols: size.cols, rows: size.rows, layers: tongues(size.cols, Math.floor(Math.random() * SEED_RANGE)) };
                let frame = 0;
                const tick = () => {
                    try {
                        if (frame >= TOTAL_FRAMES) return end();
                        draw(context, plan, frame, size.cell, look.colours);
                        if (coversAt(frame)) cover();
                        frame++;
                        timer = setTimeout(tick, look.frameMs);
                    } catch (err) {
                        Log.error(Errors.INTERNAL.E_FIRE_FAILED, err);
                        end();
                    }
                };
                canvas.width = size.cols * size.cell;
                canvas.height = size.rows * size.cell;
                window.addEventListener('keydown', end, true);
                window.addEventListener('pointerdown', end, true);
                hardStop = setTimeout(end, hardStopMs(look.frameMs));
                tick();
            } catch (err) {
                Log.error(Errors.INTERNAL.E_FIRE_FAILED, err);
                end();
            }
        });
    }

    // The overlay canvas, above everything, hidden from assistive technology; null if the
    // browser gives no 2d context (the burn then completes without fire)
    function openCanvas() {
        const canvas = document.createElement('canvas');
        canvas.className = CANVAS_CLASS;
        canvas.setAttribute('aria-hidden', 'true');
        const context = canvas.getContext('2d');
        if (!context) return null;
        document.body.appendChild(canvas);
        return context;
    }

    return Object.freeze({
        play, tongues, layerAt, paint, fadeLevel, riseShare, shouldPlay, coversAt, gridSize, hardStopMs,
        PALETTE, NOT_PAINTED, NONE, BLACK, RED, ORANGE, YELLOW, FRAME_PROPERTY,
        RISE_START, COVER_START, EXIT_START, TOTAL_FRAMES
    });
})();
