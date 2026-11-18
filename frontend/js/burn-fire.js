// ========================================
// BURN FIRE (the pixel fire the person who burns sees, once the server confirmed the burn)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. A row of separate tongues of flame: a few sources stand along the bottom row, unevenly
// spaced, each with its own strength that changes slowly and a place that sways a cell from frame
// to frame; a source's heat falls off with the distance from it, so each makes one tongue, wide at
// the base and pointed at the tip, with the page visible between the tongues. Every step each row
// takes the row below it, drifted sideways by at most one cell (one drift a step for the whole
// grid, so a tongue keeps its shape while it leans and sways), less a decay drawn once per
// BLOCK_CELLS cells (neighbours keep one colour).
// Burning out, the sources weaken and every cell cools, so the tongues shrink and break up. Heat
// maps to three steps of the app's own palette (read from the stylesheet's custom properties):
// a black fringe at the edges, the red body, the yellow core; a cell with no heat is not painted.
// The frame duration is the app's one frame clock, --frame-ms in styles.css, read at start.
// Drawn on one canvas made for the length of the animation and removed afterwards: no markup
// string, no inline style, nothing the CSP or Trusted Types refuse.

const BurnFire = (() => {
    'use strict';

    // A cell is CELL_PX css pixels; the grid is the window divided by the cell, capped
    const CELL_PX = 8;
    const MAX_COLS = 240;
    const MAX_ROWS = 135;
    // The app's frame clock (styles.css): every stepped animation steps at it
    const FRAME_PROPERTY = '--frame-ms';
    // Frames: rise, hold, burn out; the hard stop comes one frame after the last
    const RISE_FRAMES = 5;
    const HOLD_FRAMES = 3;
    const BURN_FRAMES = 5;
    const TOTAL_FRAMES = RISE_FRAMES + HOLD_FRAMES + BURN_FRAMES;
    // Steps a frame takes: rising, the tongues grow RISE_SPAN times the grid height in all
    const RISE_SPAN = 1.2;
    const HOLD_STEPS = 3;
    const BURN_STEPS = 6;
    // Each step a block of BLOCK_CELLS cells of a row loses DECAY_MIN..DECAY_MAX heat
    const BLOCK_CELLS = 2;
    const DECAY_MIN = 1;
    const DECAY_MAX = 2;
    const MEAN_DECAY = (DECAY_MIN + DECAY_MAX) / 2;
    // The strongest source's flame reaches HEAT_REACH times the window's height
    const HEAT_REACH = 1.2;
    // Sources: one per SPACING_MIN..SPACING_MAX cells, a tongue HALF_MIN..HALF_MAX cells either side
    // of its source at the base, strength STRENGTH_MIN..1 of the source heat, changing by at most
    // STRENGTH_STEP a frame, its place swaying by at most SWAY cells a frame
    const SPACING_MIN = 12;
    const SPACING_MAX = 20;
    const HALF_MIN = 5;
    const HALF_MAX = 9;
    const STRENGTH_MIN = 0.45;
    const STRENGTH_STEP = 0.06;
    const SWAY = 1;
    // The palette, coolest to hottest: custom properties of styles.css. Below FRINGE_HEAT a cell
    // is the black fringe (one or two cells at a tongue's edge), below CORE_SHARE of the source
    // heat the red body, else the yellow core. Nothing is white: the page is.
    const PALETTE = Object.freeze(['--fire-fringe', '--fire-flame', '--fire-glow']);
    const FRINGE_HEAT = 4;
    const CORE_SHARE = 0.45;
    // paletteStep's answer for a cell with no heat: not painted, the page shows through
    const NO_PAINT = -1;
    const CANVAS_CLASS = 'burn-fire';
    const REDUCED_MOTION = '(prefers-reduced-motion: reduce)';

    // A grid of cols x rows heat values, every cell cold
    function createGrid(cols, rows) {
        return { cols, rows, heat: new Uint16Array(cols * rows) };
    }

    // The strongest source's heat: its flame reaches HEAT_REACH times rows high
    function sourceHeat(rows) {
        return Math.ceil(rows * MEAN_DECAY * HEAT_REACH) + FRINGE_HEAT;
    }

    const between = (random, min, max) => min + random() * (max - min);
    const whole = (random, min, max) => min + Math.floor(random() * (max - min + 1));

    // The sources along a bottom row of cols cells: [{ x, half, strength }], unevenly spaced
    function placeSources(cols, random) {
        const sources = [];
        for (let x = whole(random, 0, SPACING_MIN / 2); x < cols; x += whole(random, SPACING_MIN, SPACING_MAX)) {
            sources.push({ x, half: whole(random, HALF_MIN, HALF_MAX), strength: between(random, STRENGTH_MIN, 1) });
        }
        // the strongest starts at full strength, so the tallest tongue passes the top
        const strongest = sources.reduce((a, b) => (b.strength > a.strength ? b : a));
        strongest.strength = 1;
        return sources;
    }

    // The sources one frame later: each sways by at most SWAY cells and its strength changes by
    // at most STRENGTH_STEP, staying within STRENGTH_MIN..1
    function swaySources(sources, random) {
        return sources.map(({ x, half, strength }) => ({
            x: x + whole(random, -SWAY, SWAY),
            half,
            strength: Math.min(1, Math.max(STRENGTH_MIN, strength + between(random, -STRENGTH_STEP, STRENGTH_STEP)))
        }));
    }

    // The bottom row the sources make at share of their strength: each source's heat falls off
    // with the distance from it, to nothing past its half width, so a tongue's edges die low and
    // its middle stands tall: wide at the base, pointed at the tip; where two meet, the hotter wins
    function sourceRow(cols, sources, maxHeat, share) {
        const row = new Uint16Array(cols);
        for (const { x, half, strength } of sources) {
            for (let dx = -half; dx <= half; dx++) {
                const at = x + dx;
                if (at < 0 || at >= cols) continue;
                const value = Math.round(maxHeat * strength * share * (1 - Math.abs(dx) / (half + 1)));
                if (value > row[at]) row[at] = value;
            }
        }
        return row;
    }

    // One step of the fire: grid in, new grid out. bottom is the bottom row's heat per column (all
    // 0 when off); every row takes the row below it, drifted sideways by at most one cell (one
    // drift a step; heat from beyond the grid's edge is none), less a decay drawn once per BLOCK_CELLS cells, less cooling (0 but while
    // burning out). random() returns a number in [0, 1) and is the only chance used.
    function step(grid, bottom, random, cooling = 0) {
        const { cols, rows, heat } = grid;
        const next = createGrid(cols, rows);
        const out = next.heat;
        const last = (rows - 1) * cols;
        for (let x = 0; x < cols; x++) out[last + x] = Math.max(0, bottom[x] - cooling);
        const drift = whole(random, -1, 1);
        for (let y = 0; y < rows - 1; y++) {
            let decay = 0;
            for (let x = 0; x < cols; x++) {
                if (x % BLOCK_CELLS === 0) decay = whole(random, DECAY_MIN, DECAY_MAX);
                const from = x + drift;
                const below = from < 0 || from >= cols ? 0 : heat[(y + 1) * cols + from];
                out[y * cols + x] = Math.max(0, below - decay - cooling);
            }
        }
        return next;
    }

    // The palette step (0 to 2) a heat value is drawn in, or NO_PAINT for a cell with no heat
    function paletteStep(value, maxHeat) {
        if (value <= 0) return NO_PAINT;
        if (value < FRINGE_HEAT) return 0;
        return value < maxHeat * CORE_SHARE ? 1 : 2;
    }

    // Whether the fire plays at all: never under reduced motion, never on a hidden page, never
    // without the app's frame clock
    function shouldPlay(reducedMotion, hidden, frameMs = 1) {
        return !reducedMotion && !hidden && Number.isFinite(frameMs) && frameMs > 0;
    }

    // The grid for a window of width x height css pixels: the cell grows past CELL_PX when the
    // grid would pass its cap
    function gridSize(width, height) {
        const cell = Math.max(CELL_PX, Math.ceil(width / MAX_COLS), Math.ceil(height / MAX_ROWS));
        return { cell, cols: Math.ceil(width / cell), rows: Math.ceil(height / cell) };
    }

    // The steps a frame takes, each { share, cooling }: share scales the sources (whole while
    // rising and holding, falling to none over the burn out) and cooling, growing over the burn
    // out to the source heat, is taken from every cell, so nothing is left after the last step
    function frameSteps(frame, rows, maxHeat) {
        if (frame < RISE_FRAMES) {
            return Array(Math.ceil(rows * RISE_SPAN / RISE_FRAMES)).fill({ share: 1, cooling: 0 });
        }
        if (frame < RISE_FRAMES + HOLD_FRAMES) return Array(HOLD_STEPS).fill({ share: 1, cooling: 0 });
        const total = BURN_FRAMES * BURN_STEPS;
        return Array.from({ length: BURN_STEPS }, (_, i) => {
            const k = (frame - RISE_FRAMES - HOLD_FRAMES) * BURN_STEPS + i + 1;
            return { share: 1 - k / total, cooling: Math.ceil(maxHeat * (k / total) ** 2) };
        });
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

    // Plays the fire over the whole window. onCovered runs exactly once: when the flames stand at
    // their height, or at once when the fire does not play, or when it is ended early. The promise
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
        const hidden = document.visibilityState === 'hidden';
        const look = shouldPlay(reducedMotion, hidden) ? readStyle() : null;
        const context = look && shouldPlay(reducedMotion, hidden, look.frameMs) ? openCanvas() : null;
        if (!context) {
            cover();
            return Promise.resolve();
        }
        return new Promise(resolve => {
            const canvas = context.canvas;
            const size = gridSize(window.innerWidth, window.innerHeight);
            const maxHeat = sourceHeat(size.rows);
            let grid = createGrid(size.cols, size.rows);
            let sources = placeSources(size.cols, Math.random);
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
                for (const { share, cooling } of frameSteps(frame, size.rows, maxHeat)) {
                    grid = step(grid, sourceRow(size.cols, sources, maxHeat, share), Math.random, cooling);
                }
                sources = swaySources(sources, Math.random);
                draw(context, grid, size, look.colours, maxHeat);
                frame++;
                if (frame === RISE_FRAMES) cover();
                timer = setTimeout(tick, look.frameMs);
            };
            canvas.width = size.cols * size.cell;
            canvas.height = size.rows * size.cell;
            window.addEventListener('keydown', end, true);
            window.addEventListener('pointerdown', end, true);
            hardStop = setTimeout(end, hardStopMs(look.frameMs));
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
        play, step, createGrid, sourceHeat, placeSources, swaySources, sourceRow, paletteStep,
        shouldPlay, gridSize, frameSteps, hardStopMs,
        PALETTE, NO_PAINT, FRAME_PROPERTY, CELL_PX, RISE_FRAMES, HOLD_FRAMES, TOTAL_FRAMES
    });
})();
