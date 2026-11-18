// ========================================
// BURN FIRE (the pixel fire the person who burns sees, once the server confirmed the burn)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. A grid of heat values runs the classic cellular fire: every step each cell's heat
// moves up one row, drifting sideways by at most one cell, and loses a random 0 to MAX_DECAY; a cell nothing moved into keeps its heat less one. The
// bottom row is the heat source: clusters of hot columns with much cooler gaps between them,
// drawn again every SOURCE_FRAMES frames, so the flames rise as separate tongues of different
// heights that lean into each other and cover the window. While they burn out every cell cools
// more each step, so the tips go first: the tongues shrink back down and break up. Heat maps to three
// steps of the app's own palette (read from the stylesheet's custom properties); a cell with no
// heat is not painted. Drawn on one canvas made for the length of the animation and removed
// afterwards: no markup string, no inline style, nothing the CSP or Trusted Types refuse.

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
    // Each step a cell's heat loses 0 to MAX_DECAY, evenly; the hottest source is hot enough for
    // flames HEAT_REACH times the window's height; a cell nothing moved into loses STALE_DECAY
    const MAX_DECAY = 3;
    const MEAN_DECAY = MAX_DECAY / 2;
    const HEAT_REACH = 1.6;
    const STALE_DECAY = 1;
    // The sources: hot clusters CLUSTER_MIN..CLUSTER_MAX columns wide, gaps GAP_MIN..GAP_MAX wide
    // at GAP_SHARE of the heat (short: their flames die low, the clusters' lean over them)
    const CLUSTER_MIN = 6;
    const CLUSTER_MAX = 14;
    const GAP_MIN = 3;
    const GAP_MAX = 8;
    const GAP_SHARE = 0.5;
    const SOURCE_FRAMES = 3;
    // The rise steps RISE_SPAN times the grid height: the tongues grow out of the bottom, the
    // clusters' past the gaps', and cover the window
    const RISE_SPAN = 1.5;
    // Hold frames step the fire HOLD_STEPS times a frame, burn out frames BURN_STEPS times
    const HOLD_STEPS = 2;
    const BURN_STEPS = 4;
    // The palette, coolest to hottest: custom properties of styles.css; a cell below the first
    // threshold's share of the heat is the flame red, below the second the glow yellow, else white
    const PALETTE = Object.freeze(['--fire-flame', '--fire-glow', '--fire-core']);
    const THRESHOLDS = Object.freeze([0.4, 0.92]);
    // paletteStep's answer for a cell with no heat: not painted, the page shows through
    const NO_PAINT = -1;
    const CANVAS_CLASS = 'burn-fire';
    const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

    // A grid of cols x rows heat values, every cell cold
    function createGrid(cols, rows) {
        return { cols, rows, heat: new Uint16Array(cols * rows) };
    }

    // The hottest source heat: flames from it reach HEAT_REACH times rows high
    function sourceHeat(rows) {
        return Math.ceil(rows * MEAN_DECAY * HEAT_REACH) + PALETTE.length;
    }

    // One bottom row of sources for cols columns: hot clusters at heat, cooler gaps between them
    function sourceRow(cols, heat, random) {
        const row = new Uint16Array(cols);
        const width = (min, max) => min + Math.floor(random() * (max - min + 1));
        let x = 0;
        let hot = random() < 0.5;
        while (x < cols) {
            const run = hot ? width(CLUSTER_MIN, CLUSTER_MAX) : width(GAP_MIN, GAP_MAX);
            row.fill(hot ? heat : Math.round(heat * GAP_SHARE), x, Math.min(cols, x + run));
            x += run;
            hot = !hot;
        }
        return row;
    }

    // One step of the fire: grid in, new grid out. sources holds the bottom row's heat per column
    // (all 0 when off). Every cell above the bottom row starts from its own heat less STALE_DECAY;
    // then every cell's heat moves up one row, into its own column or one to either side (clamped
    // to the grid), less a random 0 to MAX_DECAY; cooling (0 but while burning out) is taken from
    // every cell. random() returns a number in [0, 1) and is the only chance used.
    function step(grid, sources, random, cooling = 0) {
        const { cols, rows, heat } = grid;
        const next = createGrid(cols, rows);
        const out = next.heat;
        for (let i = 0; i < out.length; i++) out[i] = Math.max(0, heat[i] - STALE_DECAY - cooling);
        const bottom = (rows - 1) * cols;
        for (let x = 0; x < cols; x++) out[bottom + x] = Math.max(0, sources[x] - cooling);
        for (let y = 1; y < rows; y++) {
            for (let x = 0; x < cols; x++) {
                const decay = Math.floor(random() * (MAX_DECAY + 1));
                const to = Math.min(cols - 1, Math.max(0, x + Math.floor(random() * 3) - 1));
                out[(y - 1) * cols + to] = Math.max(0, heat[y * cols + x] - decay - cooling);
            }
        }
        return next;
    }

    // The palette step (0 to 2) a heat value is drawn in, or NO_PAINT for a cell with no heat
    function paletteStep(value, maxHeat) {
        if (value <= 0) return NO_PAINT;
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

    // The steps a frame takes, each { share, cooling }: share scales the sources (whole while
    // rising and holding, ramping down over the burn out) and cooling is taken from every cell,
    // growing over the burn out to the hottest heat there is, so the coolest tips go first and
    // nothing is left after the last step
    function frameSteps(frame, rows, maxHeat) {
        if (frame < RISE_FRAMES) {
            const steps = Math.ceil(Math.ceil(rows * RISE_SPAN) / RISE_FRAMES);
            return Array(steps).fill({ share: 1, cooling: 0 });
        }
        if (frame < RISE_FRAMES + HOLD_FRAMES) return Array(HOLD_STEPS).fill({ share: 1, cooling: 0 });
        const total = BURN_FRAMES * BURN_STEPS;
        return Array.from({ length: BURN_STEPS }, (_, i) => {
            const k = (frame - RISE_FRAMES - HOLD_FRAMES) * BURN_STEPS + i + 1;
            return { share: 1 - k / total, cooling: Math.ceil(maxHeat * (k / total) ** 2) };
        });
    }

    // The sources at a share of their heat
    function scaled(sources, share) {
        return sources.map(value => Math.round(value * share));
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
            let sources = null;
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
                if (frame % SOURCE_FRAMES === 0) sources = sourceRow(size.cols, maxHeat, Math.random);
                for (const { share, cooling } of frameSteps(frame, size.rows, maxHeat)) {
                    grid = step(grid, scaled(sources, share), Math.random, cooling);
                }
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
        play, step, createGrid, sourceHeat, sourceRow, scaled, paletteStep, shouldPlay, gridSize, frameSteps,
        PALETTE, NO_PAINT, SOURCE_FRAMES, CELL_PX, FRAME_MS, RISE_FRAMES, TOTAL_FRAMES, HARD_STOP_MS
    });
})();
