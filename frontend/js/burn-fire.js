// ========================================
// BURN FIRE (the burned view goes up in flames, for the person who burned, once the server confirmed it)
// ========================================
// Decoration only: it starts after the burn request has answered and never delays or decides
// anything. About thirteen separate flames move as one body, like a liquid, and no two look
// alike: each is one of eight silhouettes (a needle blade, an S-leaf, a slender twin, a fat
// teardrop, a broad three-tongue, a four-tip crown, a low mass with two horns, a small leaf
// pointed at both ends), optionally mirrored, in one of four planned size classes (giant, large,
// medium, small). A silhouette is a union of lobes (a belly and its tongues of unequal height),
// drawn row by row on a grid of small square cells and coloured in three flat bands along its
// length (yellow at the root, orange, red at the tips), each flame with its own proportions,
// the band edges waving, its sides rimmed one cell wide in the next band's colour so it reads
// apart from the flames behind it. Its shape is alive on every frame: it is longer and narrower
// the faster it moves (a drop being pulled, its area kept), and its centre line is a travelling
// wave, small
// at the root and growing toward the tips, running up from frame to frame; the shared sway is
// the common part of that wave. On the app's frame clock (--frame-ms in styles.css, read at
// start): the burned view fades to black in an ordered dither (half, then solid) while the
// flames pass through the window, giants and large ones first, each entering from below the
// bottom edge and rising on every frame, faster on each (travel), until its lowest cell is out
// through the top; nothing is ever removed while any of it is inside the window. On the frame
// with the most flame (the cover, the only one that is all flame) the app switches to the home
// view underneath (play's onCovered), unseen under the solid black. The last flame, the small
// leaf, snakes sideways as it rises and is alone over the black for its last frames; once it has
// left, the black lifts in two dither steps and the last frame is the clean home view. The
// sequence's length is derived from the plan, never fixed.
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
    // Crossings are N_MIN..N_MAX frames, accelerating (travel)
    const N_MIN = 6;
    const N_MAX = 8;
    // A flame's path starts with its base ENTRY of its resting height below the bottom edge
    const ENTRY = 0.4;
    // A lobe's shape: its defaults (offset dx and width w in flame widths, height h in flame
    // lengths, belly position, taper exponents of the left and right flank, base kind (round,
    // broad: round with full shoulders, or pointed), lean and S-curve in flame widths)
    const LOBE = Object.freeze({ dx: 0, w: 1, h: 1, belly: 1 / 3, taper: [0.8, 0.8], base: 'round', lean: 0, s: 0 });
    // a broad root's shoulders: (1 - u^2) to BROAD, fuller than the round root's square root
    const BROAD = 0.3;
    const lobe = (o) => Object.freeze(Object.assign({}, LOBE, o));
    // The eight silhouettes, each a union of lobes standing on one root; and the rear flame's
    const PRESETS = Object.freeze({
        needle: [lobe({ belly: 0.08, base: 'broad', taper: [1.25, 1.1], lean: 0.3 })],
        leafS: [lobe({ belly: 0.35, taper: [0.6, 1.4], s: 0.2, lean: -0.15 })],
        twin: [lobe({ dx: -0.2, w: 0.62, belly: 0.3, taper: [0.9, 0.9], lean: -0.12 }), lobe({ dx: 0.22, w: 0.56, h: 0.6, belly: 0.3, lean: 0.18 })],
        fat: [lobe({ belly: 0.4, taper: [0.55, 0.55], base: 'broad' })],
        tongues: [
            lobe({ h: 0.42, belly: 0.45, base: 'broad', taper: [0.6, 0.6] }),
            lobe({ dx: -0.3, w: 0.4, h: 0.72, lean: -0.15 }), lobe({ dx: 0.04, w: 0.48, lean: 0.05 }), lobe({ dx: 0.32, w: 0.36, h: 0.56, lean: 0.2 })
        ],
        crown: [
            lobe({ h: 0.38, belly: 0.5, base: 'broad', taper: [0.5, 0.5] }),
            lobe({ dx: -0.37, w: 0.26, lean: -0.1 }), lobe({ dx: -0.12, w: 0.28, h: 0.62 }),
            lobe({ dx: 0.13, w: 0.28, h: 0.84 }), lobe({ dx: 0.37, w: 0.24, h: 0.5, lean: 0.15 })
        ],
        mass: [
            lobe({ h: 0.55, belly: 0.4, base: 'broad', taper: [0.45, 0.45] }),
            lobe({ dx: -0.37, w: 0.28, lean: -0.2, taper: [1.1, 0.7] }), lobe({ dx: 0.36, w: 0.26, h: 0.78, lean: 0.22, taper: [0.7, 1.1] })
        ],
        leaf: [lobe({ belly: 0.3, taper: [1, 1], base: 'pointed' })],
        rear: [lobe({})]
    });
    const STREAM_PRESETS = Object.freeze(['needle', 'leafS', 'twin', 'fat', 'tongues', 'crown', 'mass', 'leaf']);
    const REAR_PRESET = 'rear';
    // The planned sizes, as shares of the window's width and height: each class's presets (one
    // flame each), its starts (back to front), crossing and yellow root (the ones behind mostly red,
    // the ones in front mostly yellow, so they read apart); the last small one is the lone leaf
    const CLASSES = Object.freeze([
        { name: 'giant', width: [0.45, 0.54], height: [1.02, 1.23], presets: ['mass', 'crown'], starts: [0, 0], frames: 8, yellow: [0.08, 0.22] },
        { name: 'large', width: [0.3, 0.45], height: [0.8, 1.1], presets: ['tongues', 'fat', 'twin', 'leafS'], starts: [0, 0, 1, 1], frames: 8, yellow: [0.18, 0.38] },
        { name: 'medium', width: [0.15, 0.3], height: [0.6, 0.95], presets: ['needle', 'twin', 'leafS', 'fat'], starts: [1, 1, 2, 2], frames: 7, yellow: [0.32, 0.52] },
        { name: 'small', width: [0.11, 0.15], height: [0.43, 0.7], presets: ['needle', 'twin'], starts: [2, 2], frames: 7, yellow: [0.42, 0.62] }
    ].map(Object.freeze));
    // The lone leaf: small, last, crossing in its own frames from its own start, so it is alone
    // for its last frames (the cover's rear flames are gone by then too); it snakes by SNAKE of
    // its width, SNAKE_STEP radians a frame
    const LAST = Object.freeze({ name: 'small', preset: 'leaf', start: 4, frames: 7 });
    const SNAKE = 0.7;
    const SNAKE_STEP = 1.4;
    // Placing along x: SHUFFLES tries for an order where no neighbours share a class and the leaf
    // stands at least INNER slots in from either edge (so its snaking stays in the window);
    // JITTER of a slot
    const SHUFFLES = 200;
    const JITTER = 0.25;
    const INNER = 2;
    // The bands: the yellow root ends at its class's yellow share of the length, the orange
    // ORANGE_SPAN later;
    // their edges wave by BAND_WAVE of the length, BAND_CYCLES across a resting width
    const ORANGE_SPAN = Object.freeze([0.15, 0.35]);
    const BAND_WAVE = 0.06;
    const BAND_CYCLES = 1.5;
    // Rear flames that make the cover frame whole: REAR_HEIGHT of the window tall, at least
    // REAR_WIDTH of it wide; past REAR_MAX of them each next one is wider
    const REAR_HEIGHT = 0.7;
    const REAR_LOW = 0.3;
    const REAR_STEP = 0.05;
    const REAR_REACH = 0.6;
    const REAR_WIDTH = 0.12;
    const REAR_MAX = 8;
    // The black's dither level (quarters of the cells): half on the first frame, solid until the
    // last flame has left, then LIFT_LEVELS (half, a quarter) and the clean last frame
    const LIFT_LEVELS = Object.freeze([2, 1]);
    const FIRST_LEVEL = 2;
    const SOLID = 4;
    const CLEAN = 0;
    // The hard stop: HARD_STOP_MARGIN frames after the last
    const HARD_STOP_MARGIN = 1;
    // Stretch: a flame's length is its resting length times (its step on the frame over its mean
    // step) to the STRETCH; its width shrinks by the same factor, so its area holds
    const STRETCH = 0.75;
    // The wave through the centre line, in resting widths: WAVE_BELLY at the root growing by
    // WAVE_TIP toward the tips, WAVE_CYCLES along the flame, moving WAVE_SPEED cycles up per frame
    const WAVE_BELLY = 0.03;
    const WAVE_TIP = 0.3;
    const WAVE_CYCLES = 0.9;
    const WAVE_SPEED = 0.3;
    // the wave's scale: the resting width, at most WAVE_REACH of the resting length
    const WAVE_REACH = 0.3;
    const TURN = 2 * Math.PI;
    // All flames sway together by the same cells on the same frame (the wave's common part)
    const SWAY = Object.freeze([0, 2, 0, -2]);
    // Paint: the palette's index of the black, the red tips, the orange middle and the yellow root
    const PALETTE = Object.freeze(['--fire-fringe', '--fire-flame', '--fire-orange', '--fire-glow']);
    const BLACK = 0;
    const RED = 1;
    const ORANGE = 2;
    const YELLOW = 3;
    const NOT_PAINTED = -1;
    // A stream flame's rim: the one cell at each side of each of its runs takes the next band's
    // colour (red beside red takes orange), so a flame reads apart from the one behind it
    const RIM = Object.freeze({ [YELLOW]: ORANGE, [ORANGE]: RED, [RED]: ORANGE });
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

    // Seeded Fisher-Yates, in place
    function shuffle(random, list) {
        for (let i = list.length - 1; i > 0; i--) {
            const j = Math.floor(random() * (i + 1));
            [list[i], list[j]] = [list[j], list[i]];
        }
        return list;
    }

    // The plan for a cols x rows grid: { cols, rows, list, cover, exit, length }. list is the
    // flames back to front (giants behind, the lone leaf in front, the rear cover flames behind
    // all): [{ x, cls, preset, mirror, share, height, width, phase, bands, start, frames, snake }]
    // in cells and frames; cover the one all-flame frame; exit the first frame on which every
    // flame is out through the top; length the frames played. Pure. A draft with a second
    // all-flame frame is drawn again from the next seed, up to PLAN_TRIES times.
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

    // One stream flame of class cls and preset at its start and crossing
    function streamFlame(random, cols, rows, cls, preset, start, frames) {
        const yellow = between(random, ...cls.yellow);
        const share = between(random, ...cls.height);
        return {
            x: 0, cls: cls.name, preset, mirror: random() < 0.5, share, height: share * rows,
            width: between(random, ...cls.width) * cols, phase: random(),
            bands: [yellow, yellow + between(random, ...ORANGE_SPAN)], start, frames, snake: false
        };
    }

    function draft(cols, rows, seed) {
        const random = seeded(seed);
        const list = [];
        for (const cls of CLASSES) {
            shuffle(random, cls.presets.slice()).forEach((preset, i) => list.push(streamFlame(random, cols, rows, cls, preset, cls.starts[i], cls.frames)));
        }
        const last = streamFlame(random, cols, rows, CLASSES.find(c => c.name === LAST.name), LAST.preset, LAST.start, LAST.frames);
        last.snake = true;
        list.push(last);
        // along x: an order in which no two neighbours share a class
        let order = list.slice();
        for (let tries = 0; tries < SHUFFLES; tries++) {
            const candidate = shuffle(random, list.slice());
            const leaf = candidate.findIndex(f => f.snake);
            if (leaf >= INNER && leaf < candidate.length - INNER && candidate.every((f, i) => i === 0 || f.cls !== candidate[i - 1].cls)) {
                order = candidate;
                break;
            }
        }
        const slot = cols / order.length;
        order.forEach((f, i) => { f.x = (i + 0.5 + between(random, -JITTER, JITTER)) * slot; });
        const fire = { cols, rows, list, exit: exitFrame(list) };
        fire.length = sequenceLength(fire.exit);
        fillCover(fire, exitFrame(list.slice(0, -1)));
        return fire;
    }

    // The first frame on which every flame of list is out through the top (a flame's base reaches
    // the top edge on its last frame of travel, frames after its start)
    function exitFrame(list) {
        return Math.max(...list.map(f => f.start + f.frames));
    }

    // The frames played: up to the exit, the lift steps from it, and the clean last frame
    function sequenceLength(exit) {
        return exit + LIFT_LEVELS.length + 1;
    }

    // The cover frame must be all flame, and only it: while a cell is uncovered on it, a large red
    // rear flame is added behind the others (gone by before, so the lone leaf stays alone), timed
    // so that on that frame its belly stands on the middle of the largest uncovered region; past
    // REAR_MAX of them the rear flames widen
    function fillCover(fire, before) {
        const cover = coverFrame(fire);
        const belly = PRESETS[REAR_PRESET][0].belly;
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
                    if (start < 0 || start + n > before) continue;
                    for (let share = REAR_HEIGHT; share >= REAR_LOW; share -= REAR_STEP) {
                        const flame = {
                            x: 0, cls: REAR_PRESET, preset: REAR_PRESET, mirror: false, share, height: share * fire.rows, width,
                            phase: 0, bands: null, start, frames: n, snake: false, rear: true
                        };
                        const at = pose(flame, cover, fire.rows);
                        const miss = Math.max(0, (at.base - at.length * REAR_REACH) - region.row, region.row - (at.base - at.length * belly));
                        if (!best || miss < best.miss - 0.5) best = { miss, flame, at };
                    }
                }
            }
            if (!best || added > REAR_MAX * 4) throw new Error('fire cover not reached');
            const { flame, at } = best;
            flame.x = region.col - at.x - wave(at, (at.base - region.row) / at.length);
            fire.list.unshift(flame);
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

    // A lobe's half width on one flank at t (0 at the root, 1 at its tip), as a share of its
    // width / 2: below the belly round, broad (full-shouldered) or pointed; above it the flank's taper
    function profile(part, t, flank) {
        if (t < part.belly) {
            const u = (part.belly - t) / part.belly;
            if (part.base === 'pointed') return 1 - u;
            const round = Math.sqrt(1 - u * u);
            return part.base === 'broad' ? Math.pow(1 - u * u, BROAD) : round;
        }
        return Math.pow((1 - t) / (1 - part.belly), part.taper[flank]);
    }

    // The centre line's offset at t of the flame (0 at the root, 1 at the tip) on frame, in
    // cells: a travelling wave, small at the root and growing toward the tips, moving up
    function wave(at, t) {
        return (WAVE_BELLY + WAVE_TIP * t) * at.reach * Math.sin(TURN * (WAVE_CYCLES * t - WAVE_SPEED * at.frame + at.phase));
    }

    // The one silhouette: for each row, every lobe's span of cells on the flame's root and
    // centre line (one cell at least where a lobe is narrower), merged into runs
    // { row, from, to, t, centre } with t the row's height on the flame and centre its centre line
    function silhouette(at, lobes, mirror, cols, rows, out) {
        const side = mirror ? -1 : 1;
        const top = Math.ceil(at.base - at.length);
        for (let row = Math.max(0, top); row <= Math.min(rows - 1, Math.floor(at.base)); row++) {
            const above = at.base - row - 0.5;
            const t = above / at.length;
            if (t < 0 || t >= 1) continue;
            const centre = at.x + wave(at, t);
            const spans = [];
            for (const part of lobes) {
                const tl = t / part.h;
                if (tl >= 1) continue;
                const c = centre + side * (part.dx + part.lean * tl * tl + part.s * Math.sin(Math.PI * tl)) * at.width;
                const width = part.w * at.width / 2;
                const left = profile(part, tl, mirror ? 1 : 0) * width;
                const right = profile(part, tl, mirror ? 0 : 1) * width;
                const middle = Math.floor(c);
                const from = left + right < 2 ? middle : Math.min(middle, Math.floor(c - left - 0.5) + 1);
                const to = left + right < 2 ? middle : Math.max(middle, Math.ceil(c + right - 0.5) - 1);
                spans.push([from, to]);
            }
            spans.sort((a, b) => a[0] - b[0]);
            let run = null;
            for (const [from, to] of spans) {
                if (run && from <= run[1] + 1) run[1] = Math.max(run[1], to);
                else {
                    if (run) push(out, row, run, t, centre, cols);
                    run = [from, to];
                }
            }
            if (run) push(out, row, run, t, centre, cols);
        }
        return out;
    }

    // Adds one run, clipped to the grid
    function push(out, row, [from, to], t, centre, cols) {
        const left = Math.max(0, from);
        const right = Math.min(cols - 1, to);
        if (left <= right) out.push({ row, from: left, to: right, t, centre });
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
    // is seen leaving); its width goes the other way. The lone leaf also snakes sideways.
    function pose(flame, frame, rows) {
        const k = frame - flame.start;
        if (k < 0 || k >= flame.frames) return null;
        const path = pathLength(flame.height, rows);
        const base = path * (1 - travel(k, flame.frames));
        const moved = step(flame, frame, rows);
        const stretch = Math.max(Math.pow(moved * flame.frames / path, STRETCH), moved / flame.height);
        const snake = flame.snake ? SNAKE * flame.width * Math.sin(SNAKE_STEP * k) : 0;
        return {
            x: flame.x + SWAY[frame % SWAY.length] + snake, base, length: flame.height * stretch, width: flame.width / stretch,
            rest: flame.width, reach: Math.min(flame.width, WAVE_REACH * flame.height), phase: flame.phase, frame
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

    // A flame's runs at frame: [{ row, from, to, t, centre }]
    function flameRuns(flame, frame, cols, rows) {
        const at = pose(flame, frame, rows);
        return at ? silhouette(at, PRESETS[flame.preset], flame.mirror, cols, rows, []) : [];
    }

    // The band of a flame's cell at col of a run on frame: yellow at the root, orange, red at the
    // tips, the edges waving across the flame; a rear flame is all red
    function band(flame, run, col, frame) {
        if (!flame.bands) return RED;
        const t = run.t + BAND_WAVE * Math.sin(TURN * ((col - run.centre) / flame.width * BAND_CYCLES + flame.phase + WAVE_SPEED * frame));
        if (t < flame.bands[0]) return YELLOW;
        return t < flame.bands[1] ? ORANGE : RED;
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

    // Every cell's paint at frame: NOT_PAINTED, BLACK, RED, ORANGE or YELLOW; the flames back to
    // front, each in its bands, a stream flame's side cells in its rim colour
    function paintGrid(fire, frame) {
        const { cols, rows, list } = fire;
        const grid = new Int8Array(cols * rows).fill(NOT_PAINTED);
        if (frame >= fire.length) return grid;
        if (blackLevel(frame, fire.exit) > CLEAN) {
            for (let row = 0; row < rows; row++) {
                for (let col = 0; col < cols; col++) if (blackAt(frame, fire.exit, col, row)) grid[row * cols + col] = BLACK;
            }
        }
        for (const flame of list) {
            for (const run of flameRuns(flame, frame, cols, rows)) {
                for (let col = run.from; col <= run.to; col++) {
                    const paint = band(flame, run, col, frame);
                    grid[run.row * cols + col] = flame.bands && (col === run.from || col === run.to) ? RIM[paint] : paint;
                }
            }
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
        play, plan, travel, pose, step, flameRuns, flameShare, coverFrame, paintGrid, blackLevel, blackAt,
        shouldPlay, coversAt, gridSize, hardStopMs, sequenceLength, STREAM_PRESETS, CLASSES, LAST, PALETTE,
        NOT_PAINTED, BLACK, RED, ORANGE, YELLOW, FRAME_PROPERTY, CELL_PX
    });
})();
