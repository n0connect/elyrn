// ========================================
// PIXELS (every pixel glyph the page draws: the aura and the action icons)
// ========================================
// One way of drawing pixels: a bitmap of rows ('#' a pixel, '.' none) becomes an inline svg of
// crisp rects in currentColor, so a glyph takes its colour from its control (and inverts with
// it on hover). Built with createElementNS and setAttribute only: no markup string, no inline
// style, nothing the CSP or Trusted Types refuse.
//
// The icon table is the one home of every icon. An icon is ICON_GRID x ICON_GRID pixels, half
// the aura's pixel (the aura is 5x5 in the same box), and has FRAMES frames written side by side
// on each line: frame 0 is the icon at rest, frames 1 and 2 the steps styles.css plays on hover
// (.pixel-frame). The words that name a control are UI_TEXT's (ui.js), never this module's.

const Pixels = (() => {
    'use strict';

    const SVG_NS = 'http://www.w3.org/2000/svg';
    const ON = '#';
    const OFF = '.';
    const ICON_GRID = 10;
    const FRAMES = 3;
    const FRAME_CLASS = 'pixel-frame';
    const ICON_CLASS = 'icon';
    // A control asks for its icons here (space separated names); install() draws them into it
    const ICON_ATTRIBUTE = 'data-icon';

    const TABLE = Object.freeze({
        'bell-on': [
            '....##....  ...##.....  .....##...',
            '...####...  ..####....  ....####..',
            '..######..  .######...  ...######.',
            '#.######.#  .######..#  #..######.',
            '..######..  .######...  ...######.',
            '..######..  .######...  ...######.',
            '.########.  ########..  ..########',
            '##########  #########.  .#########',
            '..........  ..........  ..........',
            '....##....  .....##...  ...##.....'
        ],
        'bell-off': [
            '#...##....  #...##....  #...##....',
            '.#.#..#...  .#.#..#...  .#.#..#...',
            '..#....#..  ..#....#..  ..#....#..',
            '..##...#..  ..##...#..  ..##...#..',
            '..#.#..#..  ..#.#..#..  ..#.#..#..',
            '..#..#.#..  ..#..#.#..  ..#..#.#..',
            '.#....#.#.  .#....#.#.  .#....#.#.',
            '##########  ##########  ##########',
            '........#.  ........#.  ........#.',
            '....##...#  .....##..#  ...##....#'
        ],
        'logout': [
            '#####.....  #####.....  #####.....',
            '#.........  #.........  #.........',
            '#.....#...  #......#..  #......#..',
            '#.....##..  #......##.  #......##.',
            '#.#######.  #..#######  #..#######',
            '#.#######.  #..#######  #..#######',
            '#.....##..  #......##.  #......##.',
            '#.....#...  #......#..  #......#..',
            '#.........  #.........  #.........',
            '#####.....  #####.....  #####.....'
        ],
        'members': [
            '..........  ..........  ..........',
            '.##....##.  .......##.  .##.......',
            '####..####  .##...####  ####...##.',
            '####..####  ####..####  ####..####',
            '.##....##.  ####...##.  .##...####',
            '..........  .##.......  .......##.',
            '.##....##.  .##....##.  .##....##.',
            '####..####  ####..####  ####..####',
            '####..####  ####..####  ####..####',
            '####..####  ####..####  ####..####'
        ],
        'code': [
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '.###......  .###..##.#  .###......',
            '##.##.....  ##.##.##.#  ##.##.....',
            '#...######  #...######  #...######',
            '##.##.##.#  ##.##.....  ##.##.##.#',
            '.###..##.#  .###......  .###..##.#',
            '..........  ..........  ..........',
            '..........  ..........  ..........'
        ],
        'burn': [
            '....#.....  .....#....  ...#......',
            '...##.....  ....##....  ..##......',
            '...###.#..  ....###.#.  ..###.#...',
            '..####.##.  ..####.##.  .####.##..',
            '..#######.  ..#######.  ..#######.',
            '.####.###.  .####.###.  .####.###.',
            '.###..###.  .###..###.  .###..###.',
            '.##.##.##.  .##.##.##.  .##.##.##.',
            '..#.##.#..  ..#.##.#..  ..#.##.#..',
            '...####...  ...####...  ...####...'
        ],
        'back': [
            '..........  ..........  ..........',
            '....#.....  ...#......  ....#.....',
            '...##.....  ..##......  ...##.....',
            '..##......  .##.......  ..##......',
            '.########.  ########..  .########.',
            '.########.  ########..  .########.',
            '..##......  .##.......  ..##......',
            '...##.....  ..##......  ...##.....',
            '....#.....  ...#......  ....#.....',
            '..........  ..........  ..........'
        ],
        'send': [
            '..........  ..........  ..........',
            '.....#....  ......#...  .....#....',
            '.....##...  ......##..  .....##...',
            '......##..  .......##.  ......##..',
            '.########.  ..########  .########.',
            '.########.  ..########  .########.',
            '......##..  .......##.  ......##..',
            '.....##...  ......##..  .....##...',
            '.....#....  ......#...  .....#....',
            '..........  ..........  ..........'
        ],
        'attach': [
            '..........  ..........  ..........',
            '....##....  ..........  ....##....',
            '....##....  ....##....  ....##....',
            '....##....  ....##....  ....##....',
            '.########.  ..######..  .########.',
            '.########.  ..######..  .########.',
            '....##....  ....##....  ....##....',
            '....##....  ....##....  ....##....',
            '....##....  ..........  ....##....',
            '..........  ..........  ..........'
        ],
        'copy': [
            '######....  ..........  ######....',
            '#....#....  ######....  #....#....',
            '#..######.  #....#....  #..######.',
            '#..#....#.  #..######.  #..#....#.',
            '#..#....#.  #..#....#.  #..#....#.',
            '####....#.  #..#....#.  ####....#.',
            '...#....#.  ####....#.  ...#....#.',
            '...#....#.  ...#....#.  ...#....#.',
            '...######.  ...#....#.  ...######.',
            '..........  ...######.  ..........'
        ],
        'close': [
            '..........  ..........  ..........',
            '.##....##.  ..........  .##....##.',
            '.###..###.  ..##..##..  .###..###.',
            '..######..  ..######..  ..######..',
            '...####...  ...####...  ...####...',
            '...####...  ...####...  ...####...',
            '..######..  ..######..  ..######..',
            '.###..###.  ..##..##..  .###..###.',
            '.##....##.  ..........  .##....##.',
            '..........  ..........  ..........'
        ],
        'chevron': [
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '...##.....  ....##....  ...##.....',
            '....##....  .....##...  ....##....',
            '.....##...  ......##..  .....##...',
            '.....##...  ......##..  .....##...',
            '....##....  .....##...  ....##....',
            '...##.....  ....##....  ...##.....',
            '..........  ..........  ..........',
            '..........  ..........  ..........'
        ],
        'verify': [
            '..........  ..........  ..........',
            '..........  ........##  ..........',
            '........##  .......##.  ........##',
            '.......##.  ##....##..  .......##.',
            '##....##..  .##..##...  ##....##..',
            '.##..##...  ..####....  .##..##...',
            '..####....  ...##.....  ..####....',
            '...##.....  ..........  ...##.....',
            '..........  ..........  ..........',
            '..........  ..........  ..........'
        ],
        'role': [
            '...##.##..  ....##.##.  ...##.##..',
            '...##.##..  ....##.##.  ...##.##..',
            '.########.  ..########  .########.',
            '.########.  ..########  .########.',
            '..##.##...  ...##.##..  ..##.##...',
            '..##.##...  ...##.##..  ..##.##...',
            '########..  .########.  ########..',
            '########..  .########.  ########..',
            '.##.##....  ..##.##...  .##.##....',
            '.##.##....  ..##.##...  .##.##....'
        ],
        'clear': [
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '.########.  ..######..  .########.',
            '.########.  ..######..  .########.',
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '..........  ..........  ..........',
            '..........  ..........  ..........'
        ]
    });

    // name -> its frames, each a list of rows, read once from the table
    const ICONS = Object.freeze(Object.fromEntries(Object.entries(TABLE).map(([name, lines]) => [name,
        Object.freeze(Array.from({ length: FRAMES }, (_, frame) =>
            Object.freeze(lines.map(line => line.trim().split(/\s+/)[frame]))))])));

    function svgElement(tag) {
        return document.createElementNS(SVG_NS, tag);
    }

    // One rect per horizontal run of pixels
    function appendRows(parent, rows) {
        rows.forEach((row, y) => {
            let x = 0;
            while (x < row.length) {
                if (row[x] !== ON) {
                    x++;
                    continue;
                }
                const start = x;
                while (x < row.length && row[x] === ON) x++;
                const rect = svgElement('rect');
                rect.setAttribute('x', String(start));
                rect.setAttribute('y', String(y));
                rect.setAttribute('width', String(x - start));
                rect.setAttribute('height', '1');
                parent.appendChild(rect);
            }
        });
    }

    // Draws frames (lists of rows of one size) into svg, replacing what it held. Only an icon's
    // frames are FRAME_CLASS groups (the ones styles.css steps through on hover); a glyph is data
    // and its one drawing is a plain group that no frame or inversion rule can reach.
    function draw(svg, frames, frameClass = FRAME_CLASS) {
        while (svg.firstChild) svg.removeChild(svg.firstChild);
        const height = frames[0].length;
        const width = frames[0][0].length;
        svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
        svg.setAttribute('shape-rendering', 'crispEdges');
        svg.setAttribute('aria-hidden', 'true');
        svg.setAttribute('focusable', 'false');
        frames.forEach(rows => {
            const group = svgElement('g');
            if (frameClass) group.setAttribute('class', frameClass);
            appendRows(group, rows);
            svg.appendChild(group);
        });
        return svg;
    }

    // A boolean grid (the aura's) as rows
    function rowsOf(grid) {
        return grid.map(row => row.map(cell => (cell ? ON : OFF)).join(''));
    }

    // The aura glyph: drawn into an existing svg, or a new one
    function drawGlyph(svg, grid) {
        return draw(svg, [rowsOf(grid)], null);
    }

    function glyph(grid, className) {
        const svg = svgElement('svg');
        svg.setAttribute('class', className);
        return drawGlyph(svg, grid);
    }

    function icon(name) {
        const frames = ICONS[name];
        if (!frames) throw new Error('no icon ' + name);
        const svg = svgElement('svg');
        svg.setAttribute('class', `${ICON_CLASS} ${ICON_CLASS}-${name}`);
        return draw(svg, frames);
    }

    // Puts the named icons (space separated) into element, replacing the ones it held
    function setIcons(element, names) {
        element.setAttribute(ICON_ATTRIBUTE, names);
        element.querySelectorAll(`svg.${ICON_CLASS}`).forEach(old => old.remove());
        const first = element.firstChild;
        names.split(' ').filter(Boolean).forEach(name => element.insertBefore(icon(name), first));
    }

    // Every element in root that asks for icons gets them
    function install(root) {
        root.querySelectorAll(`[${ICON_ATTRIBUTE}]`).forEach(element => setIcons(element, element.getAttribute(ICON_ATTRIBUTE)));
    }

    return Object.freeze({ ON, OFF, ICON_GRID, FRAMES, ICONS, rowsOf, draw, drawGlyph, glyph, icon, setIcons, install });
})();
