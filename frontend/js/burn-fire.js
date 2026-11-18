// ========================================
// BURN FIRE (the pixel fire the person who burns sees, once the server confirmed the burn)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. A grid of heat values runs the classic cellular fire: every step each cell takes the
// heat of a cell below it (straight, or one column to either side) minus a small random decay;
// the bottom row is the heat source, on while the flames rise and hold, off while they burn out.
// Heat maps to four steps of the app's own palette, read from the stylesheet's custom properties.
// Drawn on one canvas made for the length of the animation and removed afterwards: no markup
// string, no inline style, nothing the CSP or Trusted Types refuse.

const BurnFire = (() => {
    'use strict';

    // A cell is CELL_PX css pixels; the grid is the window divided by the cell, capped
    const CELL_PX = 8;
    const MAX_COLS = 240;
    const MAX_ROWS = 135;
    // Stepped frames, about 12 a second: rise, hold, burn out (16 frames, 1.33 s); a frame is
    // a timer, not an animation frame, so the steps keep their pace
    const FRAME_MS = 83;
    const RISE_FRAMES = 6;
    const HOLD_FRAMES = 3;
    const BURN_FRAMES = 7;
    const TOTAL_FRAMES = RISE_FRAMES + HOLD_FRAMES + BURN_FRAMES;
    // The hard stop: the overlay goes even if a frame callback never fires
    const HARD_STOP_MS = 1400;
    // Each step a cell loses DECAY_STEP heat with DECAY_CHANCE; the source is hot enough for
    // flames HEAT_REACH times the window's height
    const DECAY_CHANCE = 0.5;
    const DECAY_STEP = 1;
    // Neighbouring cells share their decay in runs of TONGUE_CELLS, so flames rise as tongues
    // that wide instead of single-pixel noise
    const TONGUE_CELLS = 2;
    const HEAT_REACH = 1.6;
    // The rise steps RISE_SPAN times the grid height, the source ramping up over the first
    // RAMP_SPAN of it, so the ragged cool tips pass out at the top and the hot body covers the
    // window; the burn out steps as long, the source ramping down, so the flames leave ragged too
    const RISE_SPAN = 1.5;
    const BURN_SPAN = 1.5;
    const RAMP_SPAN = 0.5;
    // Hold frames step the fire this many times a frame
    const HOLD_STEPS = 2;
    // The palette, coolest to hottest: custom properties of styles.css
    const PALETTE = Object.freeze(['--fire-smoke', '--fire-flame', '--fire-glow', '--fire-core']);
    // Of the heat range, the share below which a cell is each step (the rest is the core)
    const THRESHOLDS = Object.freeze([0.45, 0.65, 0.88]);
    const CANVAS_CLASS = 'burn-fire';
    const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

    // A grid of cols x rows heat values, every cell cold
    function createGrid(cols, rows) {
        return { cols, rows, heat: new Uint16Array(cols * rows) };
    }

    // The source heat that lets flames reach HEAT_REACH times rows high
    function sourceHeat(rows) {
        return Math.ceil(rows * DECAY_CHANCE * DECAY_STEP * HEAT_REACH) + PALETTE.length;
    }

    // One step of the fire: grid in, new grid out. source is the bottom row's heat (0 when off);
    // every row takes the row below it, drifted sideways by at most one cell (one drift a row, so a
    // column keeps its own line of decay and flames form as tongues), minus a random decay drawn
    // once per TONGUE_CELLS cells. random() returns a number in [0, 1) and is the only chance used.
    function step(grid, source, random) {
        const { cols, rows, heat } = grid;
        const next = createGrid(cols, rows);
        const out = next.heat;
        const decay = () => (random() < DECAY_CHANCE ? DECAY_STEP : 0);
        const bottom = (rows - 1) * cols;
        for (let x = 0; x < cols; x++) out[bottom + x] = Math.max(0, source - decay());
        for (let y = 0; y < rows - 1; y++) {
            const drift = Math.floor(random() * 3) - 1;
            let loss = 0;
            for (let x = 0; x < cols; x++) {
                if (x % TONGUE_CELLS === 0) loss = decay();
                const from = Math.min(cols - 1, Math.max(0, x + drift));
                out[y * cols + x] = Math.max(0, heat[(y + 1) * cols + from] - loss);
            }
        }
        return next;
    }

    // The palette step (0 to 3) a heat value is drawn in, or -1 for a cold cell (not drawn)
    function paletteStep(value, maxHeat) {
        if (value <= 0) return -1;
        const share = value / maxHeat;
        const index = THRESHOLDS.findIndex(limit => share < limit);
        return index === -1 ? PALETTE.length - 1 : index;
    }

    // Whether the fire plays at all: never under reduced motion, never on a hidden page
    function shouldPlay(reducedMotion, hidden) {
        return !reducedMotion && !hidden;
    }

    // The grid for a window of width x height css pixels: the cell grows past CELL_PX when the
    // grid would pass its cap
    function gridSize(width, height) {
        const cell = Math.max(CELL_PX, Math.ceil(width / MAX_COLS), Math.ceil(height / MAX_ROWS));
        return { cell, cols: Math.ceil(width / cell), rows: Math.ceil(height / cell) };
    }

    // The source heat of every step frame takes: ramping up while rising, full while holding,
    // ramping down to nothing while burning out
    function frameSources(frame, rows, maxHeat) {
        const ramp = Math.ceil(rows * RAMP_SPAN);
        const phase = (frames, span, first, heatAt) => {
            const steps = Math.ceil(Math.ceil(rows * span) / frames);
            return Array.from({ length: steps }, (_, i) => heatAt((frame - first) * steps + i));
        };
        if (frame < RISE_FRAMES) {
            return phase(RISE_FRAMES, RISE_SPAN, 0, k => Math.min(maxHeat, Math.round(maxHeat * k / ramp)));
        }
        if (frame < RISE_FRAMES + HOLD_FRAMES) return Array(HOLD_STEPS).fill(maxHeat);
        return phase(BURN_FRAMES, BURN_SPAN, RISE_FRAMES + HOLD_FRAMES,
            k => Math.max(0, Math.round(maxHeat * (1 - k / ramp))));
    }

    function readPalette() {
        const style = getComputedStyle(document.documentElement);
        return PALETTE.map(name => style.getPropertyValue(name).trim());
    }

    function draw(context, grid, size, colours, maxHeat) {
        const { cols, rows, heat } = grid;
        context.clearRect(0, 0, cols * size.cell, rows * size.cell);
        colours.forEach((colour, index) => {
            context.fillStyle = colour;
            for (let i = 0; i < heat.length; i++) {
                if (paletteStep(heat[i], maxHeat) !== index) continue;
                context.fillRect((i % cols) * size.cell, Math.floor(i / cols) * size.cell, size.cell, size.cell);
            }
        });
    }

    // Plays the fire over the whole window. onCovered runs exactly once: when the flames cover the
    // window, or at once when the fire does not play, or when it is ended early. The promise
    // always resolves, after the canvas is gone.
    function play(onCovered) {
        let covered = false;
        const cover = () => {
            if (covered) return;
            covered = true;
            try {
                if (onCovered) onCovered();
            } catch (err) {
                Log.error(Errors.INTERNAL.E_FIRE_COVER_FAILED, err);
            }
        };
        let reducedMotion = true;
        try {
            reducedMotion = window.matchMedia(REDUCED_MOTION).matches;
        } catch (err) {
            Log.warn(Errors.INTERNAL.W_FIRE_MOTION_UNKNOWN, err);
        }
        const context = shouldPlay(reducedMotion, document.visibilityState === 'hidden') ? openCanvas() : null;
        if (!context) {
            cover();
            return Promise.resolve();
        }
        return new Promise(resolve => {
            const canvas = context.canvas;
            const size = gridSize(window.innerWidth, window.innerHeight);
            const maxHeat = sourceHeat(size.rows);
            const colours = readPalette();
            let grid = createGrid(size.cols, size.rows);
            let frame = 0;
            let timer = 0;
            let hardStop = 0;
            const end = () => {
                clearTimeout(timer);
                clearTimeout(hardStop);
                window.removeEventListener('keydown', end, true);
                window.removeEventListener('pointerdown', end, true);
                canvas.remove();
                cover();
                resolve();
            };
            const tick = () => {
                if (frame >= TOTAL_FRAMES) return end();
                for (const source of frameSources(frame, size.rows, maxHeat)) grid = step(grid, source, Math.random);
                draw(context, grid, size, colours, maxHeat);
                frame++;
                if (frame === RISE_FRAMES) cover();
                timer = setTimeout(tick, FRAME_MS);
            };
            canvas.width = size.cols * size.cell;
            canvas.height = size.rows * size.cell;
            window.addEventListener('keydown', end, true);
            window.addEventListener('pointerdown', end, true);
            hardStop = setTimeout(end, HARD_STOP_MS);
            tick();
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
        play, step, createGrid, sourceHeat, paletteStep, shouldPlay, gridSize, frameSources,
        PALETTE, CELL_PX, FRAME_MS, RISE_FRAMES, TOTAL_FRAMES, HARD_STOP_MS
    });
})();
