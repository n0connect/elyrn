// ========================================
// BURN FIRE (the burned view goes up in flames, for the person who burned, once the server confirmed it)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. Many separate flames move as one body, like a liquid. A flame is a teardrop (a
// rounded belly at a third of its height, narrowing to a single pointed tip) with a smaller
// teardrop inside, the core, low in the belly; both are drawn row by row on a grid of small
// square cells. Its shape is alive on every frame: it is longer and narrower the faster it moves
// (a drop being pulled, its area kept), and its centre line is a travelling wave, small at the
// belly and growing toward the tip, running up the flame from frame to frame; the shared sway is
// the common part of that wave. Flames of one colour merge where they overlap, and the cores are
// drawn over all the bodies, so neighbouring cores fuse. On the app's frame clock (--frame-ms in
// styles.css, read at start): the burned view fades to black in an ordered dither (half, then
// solid) while a stream of flames passes through the window: each enters from below the bottom
// edge, big ones first, and rises on every frame, faster on each (travel), until its lowest cell
// is out through the top; nothing is ever removed while any of it is inside the window. On the
// frame with the most flame (the cover, the only one that is all flame) the app switches to the
// home view underneath (play's onCovered), unseen under the solid black; the black stays solid
// until the last flame has left, then lifts in two dither steps, and the last frame is the clean
// home view. The sequence's length is derived from the plan, never fixed.
// The geometry is pure (a plan from a seed, a flame's runs at a frame, a cell's paint at a
// frame); colours are custom properties of the stylesheet. Drawn on one canvas made for the
// length of the animation and removed afterwards: no markup string, no inline style, nothing
// the CSP or Trusted Types refuse.

const BurnFire = (() => {
    'use strict';

    // A cell is CELL_PX css pixels (two aura pixels), CELL_PX_NARROW under NARROW_PX; the grid
    // is capped, the cell growing past the cap, so the work per frame stays bounded
    const CELL_PX = 8;
    const CELL_PX_NARROW = 6;
    const NARROW_PX = 480;
    const MAX_COLS = 480;
    const MAX_ROWS = 270;
    // The app's frame clock (styles.css): every stepped animation steps at it
    const FRAME_PROPERTY = '--frame-ms';
    // The stream: flames start up to STARTS_MAX frames apart (big ones first) and each crosses in
    // its own N_MIN..N_MAX frames, accelerating (travel)
    const STARTS_MAX = 3;
    const N_MIN = 6;
    const N_MAX = 8;
    // the STRAGGLERS smallest start one frame apart from STRAGGLER_START and cross in
    // STRAGGLER_N frames, so the tail stays short
    const STRAGGLERS = 2;
    const STRAGGLER_START = STARTS_MAX - 1;
    const STRAGGLER_N = N_MAX - 1;
    // A flame's path starts with its base ENTRY of its resting height below the bottom edge
    const ENTRY = 0.4;
    // Rear flames that make the cover frame whole: REAR_HEIGHT of the window tall, at least
    // REAR_WIDTH of it wide; past REAR_MAX of them each next one is wider
    const REAR_HEIGHT = 1.1;
    const REAR_LOW = 0.45;
    const REAR_STEP = 0.05;
    const REAR_REACH = 0.6;
    const REAR_WIDTH = 0.3;
    const REAR_MAX = 8;
    // The black's dither level (quarters of the cells): half on the first frame, solid until the
    // last flame has left, then LIFT_LEVELS (half, a quarter) and the clean last frame
    const LIFT_LEVELS = Object.freeze([2, 1]);
    const FIRST_LEVEL = 2;
    const SOLID = 4;
    const CLEAN = 0;
    // The hard stop: HARD_STOP_MARGIN frames after the last
    const HARD_STOP_MARGIN = 1;
    // Flames: FLAMES_MIN..FLAMES_MAX in two kinds, as shares of the window's height and width: tall
    // and wide ones behind, shorter and narrower ones in front
    const FLAMES_MIN = 12;
    const FLAMES_MAX = 16;
    const KINDS = Object.freeze([
        { height: [0.9, 1.1], width: [0.27, 0.3] },
        { height: [0.5, 0.85], width: [0.22, 0.3] }
    ]);
    // The silhouette: belly at BELLY of the length, the taper's exponent; the core is CORE_LENGTH
    // of the flame long and CORE_WIDTH of it wide, on the same base and centre line
    const BELLY = 1 / 3;
    const TAPER = 0.8;
    const CORE_LENGTH = 0.5;
    const CORE_WIDTH = 0.5;
    // Stretch: a flame's length is its resting length times (its step on the frame over its mean
    // step) to the STRETCH; its width shrinks by the same factor, so its area holds
    const STRETCH = 0.75;
    // The wave through the centre line, in resting widths: WAVE_BELLY at the base growing by
    // WAVE_TIP toward the tip, WAVE_CYCLES along the flame, moving WAVE_SPEED cycles up per frame
    const WAVE_BELLY = 0.03;
    const WAVE_TIP = 0.3;
    const WAVE_CYCLES = 0.9;
    const WAVE_SPEED = 0.3;
    const TURN = 2 * Math.PI;
    // All flames sway together by the same cells on the same frame (the wave's common part)
    const SWAY = Object.freeze([0, 2, 0, -2]);
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
    const PLAN_TRIES = 4;

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

    // The plan for a cols x rows grid: { cols, rows, list, cover, exit, length }. list is the
    // flames back to front (taller and redder behind): [{ x, share, height, width, phase, body,
    // start, frames }] in cells and frames; cover the one all-flame frame; exit the first frame
    // on which every flame is out through the top; length the frames played. Pure. A draft with a
    // second all-flame frame is drawn again from the next seed, up to PLAN_TRIES times.
    function plan(cols, rows, seed) {
        let fire = null;
        for (let tries = 0; tries < PLAN_TRIES; tries++) {
            fire = draft(cols, rows, (seed + tries) >>> 0);
            let full = 0;
            for (let frame = 0; frame < fire.length; frame++) if (flameShare(fire, frame) === 1) full++;
            if (full === 1) return fire;
        }
        return fire;
    }

    function draft(cols, rows, seed) {
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
                    phase: random()
                });
            }
        });
        list.sort((a, b) => b.share - a.share);
        const middle = list[Math.floor(list.length / 2)].share;
        // big ones first: the start follows the order; the big ones cross slowest, so the stream
        // meets in one mass; the last few are stragglers, after it
        list.forEach((f, k) => {
            f.body = f.share > middle ? RED : ORANGE;
            const planned = Math.round(k * STARTS_MAX / (list.length - 1));
            const straggler = k - (list.length - STRAGGLERS);
            f.start = straggler >= 0 ? STRAGGLER_START + straggler : planned;
            f.frames = straggler >= 0 ? STRAGGLER_N : N_MAX - Math.round(k * (N_MAX - N_MIN) / (list.length - 1));
        });
        const result = { cols, rows, list, exit: exitFrame(list) };
        result.length = sequenceLength(result.exit);
        fillCover(result);
        return result;
    }

    // The first frame on which every flame is out through the top (a flame's base reaches the top
    // edge on its last frame of travel, frames after its start)
    function exitFrame(list) {
        return Math.max(...list.map(f => f.start + f.frames));
    }

    // The frames played: up to the exit, the lift steps from it, and the clean last frame
    function sequenceLength(exit) {
        return exit + LIFT_LEVELS.length + 1;
    }

    // The cover frame must be all flame, and only it: while a cell is uncovered on it, a large red
    // rear flame is added behind the others (never leaving after the stream), timed so that on that
    // frame its belly stands on the middle of the largest uncovered region; past REAR_MAX of them
    // the rear flames widen
    function fillCover(fire) {
        const cover = coverFrame(fire);
        for (let added = 0; flameShare(fire, cover) < 1; added++) {
            const region = largestGap(fire, cover);
            const width = Math.min(fire.cols, Math.max(region.width + 2, REAR_WIDTH * fire.cols) * (added < REAR_MAX ? 1 : 1 + (added - REAR_MAX + 1) / 2));
            // the crossing (n frames, k of them gone on the cover frame) and the height that put the
            // flame's wide part (its pose on the cover frame, stretched as drawn) over the region's
            // middle row then, its centre line on the region's middle
            let best = null;
            for (let n = N_MIN; n <= N_MAX; n++) {
                for (let k = 1; k < n; k++) {
                    const start = cover - k;
                    if (start < 0 || start + n > fire.exit) continue;
                    for (let share = REAR_HEIGHT; share >= REAR_LOW; share -= REAR_STEP) {
                        const flame = { x: 0, share, height: share * fire.rows, width, phase: 0, body: RED, start, frames: n, rear: true };
                        const at = pose(flame, cover, fire.rows);
                        const miss = Math.max(0, (at.base - at.length * REAR_REACH) - region.row, region.row - (at.base - at.length * BELLY));
                        if (!best || miss < best.miss - 0.5) best = { miss, flame, at };
                    }
                }
            }
            const { flame, at } = best;
            flame.x = region.col - at.x - wave(at, (at.base - region.row) / at.length);
            fire.list.unshift(flame);
            if (added > REAR_MAX * 4) throw new Error('fire cover not reached');
        }
        fire.cover = coverFrame(fire);
        return fire;
    }

    // Marks every flame cell of frame in a cols x rows array
    function litGrid(fire, frame) {
        const { cols, rows, list } = fire;
        const lit = new Uint8Array(cols * rows);
        for (const flame of list) {
            for (const { row, from, to } of flameRuns(flame, frame, cols, rows)) lit.fill(1, row * cols + from, row * cols + to + 1);
        }
        return lit;
    }

    // The largest connected region of cells with no flame at frame: its middle { col, row } and width
    function largestGap(fire, frame) {
        const { cols, rows } = fire;
        const lit = litGrid(fire, frame);
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

    // The centre line's offset at t of the flame (0 at the base, 1 at the tip) on frame, in
    // cells: a travelling wave, small at the belly and growing toward the tip, moving up
    function wave(at, t) {
        return (WAVE_BELLY + WAVE_TIP * t) * at.rest * Math.sin(TURN * (WAVE_CYCLES * t - WAVE_SPEED * at.frame + at.phase));
    }

    // The one silhouette, body and core alike: for each row of a teardrop scale.length of the
    // flame long and scale.width of it wide, on the flame's base and centre line, its run of
    // cells { row, from, to }; one cell at least in every row, so the tip is a single point
    function silhouette(at, scale, cols, rows, core, out) {
        const length = at.length * scale.length;
        const width = at.width * scale.width;
        const top = Math.ceil(at.base - length);
        let tip = true;
        for (let row = Math.max(0, top); row <= Math.min(rows - 1, Math.floor(at.base)); row++) {
            const above = at.base - row - 0.5;
            const t = above / length;
            if (t < 0 || t >= 1) continue;
            const centre = at.x + wave(at, above / at.length);
            const half = profile(t) * width / 2;
            const middle = Math.floor(centre);
            // the tip, and where the teardrop is narrower than two cells, is the one centre cell
            const point = tip && top >= 0;
            tip = false;
            const from = point || half < 1 ? middle : Math.min(middle, Math.floor(centre - half - 0.5) + 1);
            const to = point || half < 1 ? middle : Math.max(middle, Math.ceil(centre + half - 0.5) - 1);
            const left = Math.max(0, from);
            const right = Math.min(cols - 1, to);
            if (left <= right) out.push({ row, from: left, to: right, core });
        }
        return out;
    }

    // The motion law, its one home: how far along its whole path a flame is on the k-th frame of a
    // crossing of n frames: k(k+1) / (n(n+1)), so each step is larger than the one before (with
    // n = 4: 0, 0.1, 0.3, 0.6, 1); it starts slowly at the bottom and leaves the top fastest
    function travel(k, n) {
        return (k * (k + 1)) / (n * (n + 1));
    }

    // A flame's place and shape at frame: { x, base, length, width, rest, phase, frame } in
    // cells, or null when it is not on its path: before its start, or once its base (its lowest
    // point) has reached the top edge. Its path runs from just below the bottom edge to out
    // through the top. Its length follows the step it makes on this frame, and is never shorter
    // than that step (a stream, never a jump: on its last frame it reaches the top edge, so it
    // is seen leaving); its width goes the other way.
    function pose(flame, frame, rows) {
        const k = frame - flame.start;
        if (k < 0 || k >= flame.frames) return null;
        const path = pathLength(flame.height, rows);
        const base = path * (1 - travel(k, flame.frames));
        const moved = step(flame, frame, rows);
        const stretch = Math.max(Math.pow(moved * flame.frames / path, STRETCH), moved / flame.height);
        return {
            x: flame.x + SWAY[frame % SWAY.length], base, length: flame.height * stretch, width: flame.width / stretch,
            rest: flame.width, phase: flame.phase, frame
        };
    }

    // The step a flame makes from frame to the next, in cells (0 when it is not on its path)
    function step(flame, frame, rows) {
        const k = frame - flame.start;
        if (k < 0 || k >= flame.frames) return 0;
        return pathLength(flame.height, rows) * (travel(k + 1, flame.frames) - travel(k, flame.frames));
    }

    // The path of a flame of height (resting) through a window rows tall, in cells: from its base
    // ENTRY of its height below the bottom edge (the slow, short flame of the first frame just
    // under it) to its base at the top edge
    function pathLength(height, rows) {
        return rows + height * ENTRY;
    }

    const BODY_SCALE = Object.freeze({ length: 1, width: 1 });
    const CORE_SCALE = Object.freeze({ length: CORE_LENGTH, width: CORE_WIDTH });

    // A flame's runs at frame: [{ row, from, to, core }], the body's then the core's
    function flameRuns(flame, frame, cols, rows) {
        const at = pose(flame, frame, rows);
        const out = [];
        if (!at) return out;
        silhouette(at, BODY_SCALE, cols, rows, false, out);
        silhouette(at, CORE_SCALE, cols, rows, true, out);
        return out;
    }

    // A flame's cells at frame: [{ col, row, core }] (core cells after the body's)
    function flameCells(flame, frame, cols, rows) {
        const out = [];
        for (const { row, from, to, core } of flameRuns(flame, frame, cols, rows)) {
            for (let col = from; col <= to; col++) out.push({ col, row, core });
        }
        return out;
    }

    // The share of the window that is flame at frame
    function flameShare(fire, frame) {
        return litGrid(fire, frame).reduce((sum, v) => sum + v, 0) / (fire.cols * fire.rows);
    }

    // The cover frame: the one with the most flame (the first of equals)
    function coverFrame(fire) {
        let best = 0;
        let most = -1;
        for (let frame = 0; frame < fire.exit; frame++) {
            const share = flameShare(fire, frame);
            if (share > most) {
                most = share;
                best = frame;
            }
        }
        return best;
    }

    // The black's dither level at frame (quarters of the cells), given the exit frame
    function blackLevel(frame, exit) {
        if (frame === 0) return FIRST_LEVEL;
        if (frame < exit) return SOLID;
        const lift = frame - exit;
        return lift < LIFT_LEVELS.length ? LIFT_LEVELS[lift] : CLEAN;
    }

    // Whether the black covers the cell at col, row at frame (an ordered dither)
    function blackAt(frame, exit, col, row) {
        return BAYER[(row % 2) * 2 + (col % 2)] < blackLevel(frame, exit);
    }

    // Every cell's paint at frame: NOT_PAINTED, BLACK, RED, ORANGE or CORE; the bodies back to
    // front, then every core over them, so neighbouring cores fuse
    function paintGrid(fire, frame) {
        const { cols, rows, list } = fire;
        const grid = new Int8Array(cols * rows).fill(NOT_PAINTED);
        if (frame >= fire.length) return grid;
        if (blackLevel(frame, fire.exit) > CLEAN) {
            for (let row = 0; row < rows; row++) {
                for (let col = 0; col < cols; col++) if (blackAt(frame, fire.exit, col, row)) grid[row * cols + col] = BLACK;
            }
        }
        const cores = [];
        for (const flame of list) {
            for (const run of flameRuns(flame, frame, cols, rows)) {
                if (run.core) cores.push(run);
                else grid.fill(flame.body, run.row * cols + run.from, run.row * cols + run.to + 1);
            }
        }
        for (const run of cores) grid.fill(CORE, run.row * cols + run.from, run.row * cols + run.to + 1);
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

    // How long the fire may stand at most: the sequence and a margin
    function hardStopMs(length, frameMs) {
        return (length + HARD_STOP_MARGIN) * frameMs;
    }

    function readStyle() {
        const style = getComputedStyle(document.documentElement);
        return {
            colours: PALETTE.map(name => style.getPropertyValue(name).trim()),
            frameMs: parseFloat(style.getPropertyValue(FRAME_PROPERTY))
        };
    }

    // Paints frame: each row's runs of one paint as one rectangle
    function draw(context, fire, frame, cell, colours) {
        const { cols, rows } = fire;
        context.clearRect(0, 0, cols * cell, rows * cell);
        const paints = paintGrid(fire, frame);
        for (let row = 0; row < rows; row++) {
            const at = row * cols;
            for (let col = 0; col < cols;) {
                const paint = paints[at + col];
                let end = col + 1;
                while (end < cols && paints[at + end] === paint) end++;
                if (paint !== NOT_PAINTED) {
                    context.fillStyle = colours[paint];
                    context.fillRect(col * cell, row * cell, (end - col) * cell, cell);
                }
                col = end;
            }
        }
    }

    // Burns the window: onCovered (the switch to the home view) runs exactly once, at the cover
    // frame, or at once when the fire does not play, or when anything ends it early (the last
    // frame, a key or a press, the hard stop, an error). The promise always resolves, once the
    // canvas is gone.
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
                const fire = plan(size.cols, size.rows, Math.floor(Math.random() * SEED_RANGE));
                let frame = 0;
                const tick = () => {
                    try {
                        if (frame >= fire.length) return end();
                        draw(context, fire, frame, size.cell, look.colours);
                        if (coversAt(frame, fire.cover)) cover();
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
                hardStop = setTimeout(end, hardStopMs(fire.length, look.frameMs));
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
        play, plan, travel, pose, step, flameRuns, flameCells, flameShare, coverFrame, paintGrid, blackLevel, blackAt,
        shouldPlay, coversAt, gridSize, hardStopMs, sequenceLength, PALETTE, NOT_PAINTED, BLACK, RED, ORANGE, CORE,
        FRAME_PROPERTY, CELL_PX
    });
})();
