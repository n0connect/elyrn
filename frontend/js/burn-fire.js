// ========================================
// BURN FIRE (the burned view goes up in flames, for the person who burned, once the server confirmed it)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. Many separate flames move as one body and die as pieces. A flame is a sprite on a
// grid of big square cells: a teardrop (a rounded belly at a third of its height, narrowing to a
// single pointed tip that leans to one side in a slight S) with a smaller teardrop inside, the
// core, sitting low in the belly. On the app's frame clock (--frame-ms in styles.css, read at
// start):
// the burned view fades to black in an ordered dither (half, then solid) while a stream of flames
// passes through the window: each enters from below the bottom edge, big ones first, and rises on
// every frame, faster on each (travel: it starts slowly and leaves the top fastest), swaying with
// all the others by the same cell, until it is out through the top. They overlap into one mass while
// they cross; the slower and later ones trail behind as lone flames. On the frame with the most
// flame (the cover) the app switches to the home view underneath (play's onCovered), unseen under
// the solid black; two frames later the black lifts in dither steps, so the stragglers burn over
// a dimmed home view and the last frame is the clean home view. Nothing stands still.
// The geometry is pure (flames from a seed, a flame's cells at a frame, a cell's paint at a
// frame); colours are custom properties of the stylesheet. Drawn on one canvas made for the
// length of the animation and removed afterwards: no markup string, no inline style, nothing
// the CSP or Trusted Types refuse.

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
    // The stream: flames start up to STARTS_MAX frames apart (big ones first) and each crosses in
    // its own N_MIN..N_MAX frames, accelerating (travel); the frame plan is every flame's crossing
    // and one clean last frame; the hard stop one frame after
    const STARTS_MAX = 3;
    const N_MIN = 4;
    const N_MAX = 6;
    // the STRAGGLERS smallest start one frame apart from STRAGGLER_START and cross slowest
    const STRAGGLERS = 2;
    const STRAGGLER_START = STARTS_MAX - 1;
    const TOTAL_FRAMES = STRAGGLER_START + STRAGGLERS - 1 + N_MAX + 1;
    // Rear flames that make the cover frame whole: REAR_HEIGHT of the window tall, at least
    // REAR_WIDTH of it wide; past REAR_MAX of them each next one is wider
    const REAR_HEIGHT = 1.1;
    const REAR_LOW = 0.45;
    const REAR_STEP = 0.05;
    const REAR_REACH = 0.6;
    const REAR_WIDTH = 0.3;
    const REAR_MAX = 8;
    const LAST_FRAME = TOTAL_FRAMES - 1;
    // The black's dither level (quarters of the cells): half on the first frame, solid from the
    // second until SOLID_AFTER frame past the cover, then half, a quarter and none (the last frame)
    const SOLID_AFTER = 1;
    const LIFT_LEVELS = Object.freeze([2, 1, 0]);
    // Flames: FLAMES_MIN..FLAMES_MAX in two kinds, as shares of the window's height and width: tall
    // and wide ones behind, shorter and narrower ones in front
    const FLAMES_MIN = 12;
    const FLAMES_MAX = 16;
    const KINDS = Object.freeze([
        { height: [0.9, 1.1], width: [0.27, 0.3] },
        { height: [0.5, 0.85], width: [0.22, 0.3] }
    ]);
    // The silhouette: belly at BELLY of the height; the tip leans LEAN widths over, with an S of
    // S_CURVE widths the other way low down; the core is CORE_SCALE of the flame, same base
    const BELLY = 1 / 3;
    const TAPER = 0.8;
    const LEAN = 0.3;
    const S_CURVE = 0.08;
    const CORE_SCALE = 0.5;
    // All flames sway together by the same cell on the same frame
    const SWAY = Object.freeze([0, 1, 0, -1]);
    // Paint: the palette's index of the black, the two bodies and the core
    const PALETTE = Object.freeze(['--fire-fringe', '--fire-flame', '--fire-orange', '--fire-glow']);
    const BLACK = 0;
    const RED = 1;
    const ORANGE = 2;
    const CORE = 3;
    const NOT_PAINTED = -1;
    // Ordered 2x2 dither ranks
    const BAYER = Object.freeze([0, 2, 3, 1]);
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

    // The flames for a cols x rows grid, back to front (taller and redder behind): [{ x, height,
    // width, lean, body, start, frames }] in cells and frames. Pure.
    function flames(cols, rows, seed) {
        const random = seeded(seed);
        const count = whole(random, FLAMES_MIN, FLAMES_MAX);
        const list = [];
        KINDS.forEach((kind, k) => {
            const n = k === 0 ? Math.ceil(count / 2) : Math.floor(count / 2);
            const spacing = cols / n;
            for (let i = 0; i < n; i++) {
                const height = between(random, ...kind.height);
                list.push({
                    x: (i + 0.5 * (k + 1)) * spacing + between(random, -0.3, 0.3) * spacing,
                    share: height,
                    height: height * rows,
                    width: between(random, ...kind.width) * cols,
                    lean: random() < 0.5 ? -1 : 1
                });
            }
        });
        list.sort((a, b) => b.share - a.share);
        const middle = list[Math.floor(list.length / 2)].share;
        // big ones first: the start follows the order; the big ones cross slowest, so the stream
        // meets in one mass; the last few are stragglers, after it and slow
        list.forEach((f, k) => {
            f.body = f.share > middle ? RED : ORANGE;
            const planned = Math.round(k * STARTS_MAX / (list.length - 1));
            const straggler = k - (list.length - STRAGGLERS);
            f.start = straggler >= 0 ? STRAGGLER_START + straggler : planned;
            f.frames = straggler >= 0 ? N_MAX : N_MAX - Math.round(k * (N_MAX - N_MIN) / (list.length - 1));
        });
        return fillCover({ cols, rows, list }).list;
    }

    // The cover frame must be all flame, and only it: while a cell is uncovered on it, a large red
    // rear flame is added behind the others, timed so that on that frame its belly stands on the
    // middle of the largest uncovered region; past REAR_MAX of them the rear flames widen
    function fillCover(plan) {
        const cover = coverFrame(plan);
        for (let added = 0; flameShare(plan, cover) < 1; added++) {
            const region = largestGap(plan, cover);
            const width = Math.min(plan.cols, Math.max(region.width + 2, REAR_WIDTH * plan.cols) * (added < REAR_MAX ? 1 : 1 + (added - REAR_MAX + 1) / 2));
            // the crossing (n frames, k of them gone on the cover frame) and the height that put the
            // flame's wide part over the region's middle row then
            let best = null;
            for (let n = N_MIN; n <= N_MAX; n++) {
                for (let k = 1; k < n; k++) {
                    const start = cover - k;
                    if (start < 0 || start + n - 1 >= LAST_FRAME) continue;
                    // for each height, how far the region's middle row is from the flame's wide
                    // part (from its belly up to REAR_REACH of its height): the nearest, the
                    // tallest of equals
                    const p = travel(k, n);
                    for (let share = REAR_HEIGHT; share >= REAR_LOW; share -= REAR_STEP) {
                        const height = share * plan.rows;
                        const base = (plan.rows + height) * (1 - p);
                        const miss = Math.max(0, (base - height * REAR_REACH) - region.row, region.row - (base - height * BELLY));
                        if (!best || miss < best.miss - 0.5) best = { miss, height, start, n };
                    }
                }
            }
            plan.list.unshift({
                x: region.col - SWAY[cover % SWAY.length], share: best.height / plan.rows, height: best.height, width, lean: 0,
                body: RED, start: best.start, frames: best.n, rear: true
            });
            if (added > REAR_MAX * 4) throw new Error('fire cover not reached');
        }
        return plan;
    }

    // The largest connected region of cells with no flame at frame: its middle { col, row } and width
    function largestGap(plan, frame) {
        const { cols, rows, list } = plan;
        const lit = new Uint8Array(cols * rows);
        for (const flame of list) for (const { col, row } of flameCells(flame, frame, cols, rows)) lit[row * cols + col] = 1;
        let best = null;
        const seen = new Uint8Array(cols * rows);
        for (let i = 0; i < lit.length; i++) {
            if (lit[i] || seen[i]) continue;
            const stack = [i];
            seen[i] = 1;
            let count = 0;
            let sumX = 0;
            let sumY = 0;
            let minX = cols;
            let maxX = 0;
            while (stack.length) {
                const at = stack.pop();
                const x = at % cols;
                const y = Math.floor(at / cols);
                count++;
                sumX += x;
                sumY += y;
                minX = Math.min(minX, x);
                maxX = Math.max(maxX, x);
                for (const [nx, ny] of [[x + 1, y], [x - 1, y], [x, y + 1], [x, y - 1]]) {
                    const next = ny * cols + nx;
                    if (nx < 0 || ny < 0 || nx >= cols || ny >= rows || lit[next] || seen[next]) continue;
                    seen[next] = 1;
                    stack.push(next);
                }
            }
            if (!best || count > best.count) best = { count, col: sumX / count + 0.5, row: sumY / count + 0.5, width: maxX - minX + 1 };
        }
        return best;
    }

    // The teardrop's half width at t (0 at the base, 1 at the tip), as a share of its width / 2
    function profile(t) {
        if (t < BELLY) return Math.sqrt(1 - ((BELLY - t) / BELLY) ** 2);
        return Math.pow((1 - t) / (1 - BELLY), TAPER);
    }

    // The centre's offset at t, in widths: an S low down, the lean high up
    function bend(t, lean) {
        return lean * (LEAN * t * t - S_CURVE * Math.sin(Math.PI * t));
    }

    // The cells of one teardrop: base row (from the top, may be past the grid), height and width
    // in cells, centre x and lean; one cell at least in every row, so the tip is a single point
    function teardrop(cols, rows, x, base, height, width, lean, out, core) {
        const top = Math.ceil(base - height);
        let tip = true;
        for (let row = Math.max(0, top); row <= Math.min(rows - 1, Math.floor(base)); row++) {
            const t = (base - row - 0.5) / height;
            if (t < 0 || t >= 1) continue;
            const centre = x + bend(t, lean) * width;
            const half = profile(t) * width / 2;
            // the tip, and where the teardrop is narrower than two cells, is the one centre cell
            const point = tip && top >= 0;
            tip = false;
            if (point || half < 1) {
                const col = Math.floor(centre);
                if (col >= 0 && col < cols) out.push({ col, row, core });
                continue;
            }
            for (let col = Math.max(0, Math.floor(centre - half)); col <= Math.min(cols - 1, Math.ceil(centre + half)); col++) {
                if (Math.abs(col + 0.5 - centre) < half || col === Math.floor(centre)) out.push({ col, row, core });
            }
        }
    }

    // The motion law, its one home: how far along its whole path a flame is on the k-th frame of a
    // crossing of n frames: k(k+1) / (n(n+1)), so each step is larger than the one before (with
    // n = 4: 0, 0.1, 0.3, 0.6, 1); it starts slowly at the bottom and leaves the top fastest
    function travel(k, n) {
        return (k * (k + 1)) / (n * (n + 1));
    }

    // A flame's place and size at frame: { x, base, height, width } in cells, or null when it is
    // not on screen. Its path runs from just below the bottom edge (its tip at the edge) to just
    // out through the top (its base at the edge); it is on its path from its start, frames frames.
    function pose(flame, frame, rows) {
        const k = frame - flame.start;
        if (k < 1 || k >= flame.frames) return null;
        const base = (rows + flame.height) * (1 - travel(k, flame.frames));
        return { x: flame.x + SWAY[frame % SWAY.length], base, height: flame.height, width: flame.width };
    }

    // A flame's cells at frame: [{ col, row, core }] (core cells after the body's)
    function flameCells(flame, frame, cols, rows) {
        const at = pose(flame, frame, rows);
        const out = [];
        if (!at) return out;
        teardrop(cols, rows, at.x, at.base, at.height, at.width, flame.lean, out, false);
        teardrop(cols, rows, at.x, at.base, at.height * CORE_SCALE, at.width * CORE_SCALE, flame.lean, out, true);
        return out;
    }

    // The share of the window that is flame at frame
    function flameShare(plan, frame) {
        const { cols, rows, list } = plan;
        const lit = new Uint8Array(cols * rows);
        for (const flame of list) for (const { col, row } of flameCells(flame, frame, cols, rows)) lit[row * cols + col] = 1;
        return lit.reduce((sum, v) => sum + v, 0) / lit.length;
    }

    // The cover frame: the one with the most flame (the first of equals)
    function coverFrame(plan) {
        let best = 0;
        let most = -1;
        for (let frame = 0; frame < TOTAL_FRAMES; frame++) {
            const share = flameShare(plan, frame);
            if (share > most) {
                most = share;
                best = frame;
            }
        }
        return best;
    }

    // The black's dither level at frame (quarters of the cells), given the cover frame
    function blackLevel(frame, cover) {
        if (frame === 0) return 2;
        const past = frame - cover - SOLID_AFTER;
        if (past <= 0) return 4;
        return past <= LIFT_LEVELS.length ? LIFT_LEVELS[past - 1] : 0;
    }

    // Whether the black covers the cell at col, row at frame (an ordered dither)
    function blackAt(frame, cover, col, row) {
        return BAYER[(row % 2) * 2 + (col % 2)] < blackLevel(frame, cover);
    }

    // Every cell's paint at frame, row by row: NOT_PAINTED, BLACK, RED, ORANGE or CORE
    function paintGrid(plan, frame) {
        const { cols, rows, list } = plan;
        const grid = new Int8Array(cols * rows).fill(NOT_PAINTED);
        if (frame > LAST_FRAME) return grid;
        for (let row = 0; row < rows; row++) {
            for (let col = 0; col < cols; col++) if (blackAt(frame, plan.cover, col, row)) grid[row * cols + col] = BLACK;
        }
        for (const flame of list) {
            for (const { col, row, core } of flameCells(flame, frame, cols, rows)) grid[row * cols + col] = core ? CORE : flame.body;
        }
        return grid;
    }

    // Whether the fire plays at all: never under reduced motion, never on a hidden page, never
    // without the app's frame clock
    function shouldPlay(reducedMotion, hidden, frameMs = 1) {
        return !reducedMotion && !hidden && Number.isFinite(frameMs) && frameMs > 0;
    }

    // Whether frame is the one at which the app switches to the home view underneath
    function coversAt(frame, cover) {
        return frame === cover;
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
        const paints = paintGrid(plan, frame);
        colours.forEach((colour, index) => {
            context.fillStyle = colour;
            for (let i = 0; i < paints.length; i++) {
                if (paints[i] === index) context.fillRect((i % cols) * cell, Math.floor(i / cols) * cell, cell, cell);
            }
        });
    }

    // Burns the window: onCovered (the switch to the home view) runs exactly once, at the first
    // hold frame, or at once when the fire does not play, or when anything ends it early (the
    // last frame, a key or a press, the hard stop, an error). The promise always resolves, once
    // the canvas is gone.
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
                const plan = { cols: size.cols, rows: size.rows, list: flames(size.cols, size.rows, Math.floor(Math.random() * SEED_RANGE)) };
                plan.cover = coverFrame(plan);
                let frame = 0;
                const tick = () => {
                    try {
                        if (frame >= TOTAL_FRAMES) return end();
                        draw(context, plan, frame, size.cell, look.colours);
                        if (coversAt(frame, plan.cover)) cover();
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
        play, flames, travel, pose, flameCells, flameShare, coverFrame, paintGrid, blackLevel, blackAt, shouldPlay, coversAt,
        gridSize, hardStopMs, PALETTE, NOT_PAINTED, BLACK, RED, ORANGE, CORE, FRAME_PROPERTY, LAST_FRAME, TOTAL_FRAMES
    });
})();
