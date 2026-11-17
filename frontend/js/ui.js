// ========================================
// UI FUNCTIONS
// ========================================
// Rendering only: no network, no crypto. Every user- or server-supplied string
// reaches the DOM through textContent (never innerHTML).

// startView is the page's first view (index.html): the brand line while app.js decides
const START_VIEW_ID = 'startView';
const VIEW_IDS = [START_VIEW_ID, 'mainMenu', 'loginContainer', 'registerContainer', 'doorVerdictContainer',
    'doorChallengeContainer', 'robotContainer', 'appContainer'];
// The robot side of the other door: these views turn the page black (one class on <body>)
const ROBOT_SIDE_VIEWS = new Set(['doorVerdictContainer', 'doorChallengeContainer', 'robotContainer']);
const ROBOT_SIDE_CLASS = 'robot-side';

// Time units: an hour is the room code's own unit (room-crypto.js)
const SECOND_MS = 1000;
const HOUR_MS = ElyrnRoomCrypto.HOUR_MS;
const HOURS_PER_DAY = 24;
const DAY_MS = HOURS_PER_DAY * HOUR_MS;
// A time left reads in days from two days on, in hours below that
const DAYS_SHOWN_FROM_HOURS = 48;

// The login page focuses its field once the eye animation has been set up again
const LOGIN_FOCUS_DELAY_MS = 100;
// Scramble, mask and reveal pacing (the mask is shared with auth.js's input field)
const MASK_CHAR = '*';
const SCRAMBLE_MASK_CHANCE = 0.08;
const SCRAMBLE_STEP_MS = 120;
const MASK_CHARS_PER_STEP = 3;
const MASK_MAX_STEPS = 20;
const MASK_STEP_MS = 50;
const REVEAL_CHARS_PER_STEP = 3;
const REVEAL_STEP_MS = 40;

// A gap notice repeats a count only up to here: the count comes from the sender's counter
const MAX_GAP_SHOWN = 999;
// The message list follows new messages while it is scrolled within this of the bottom
const PINNED_SLACK_PX = 48;
// The composer grows with its text up to this height, then scrolls
const COMPOSER_MAX_HEIGHT_PX = 140;
// What the room form offers first, within the server's limits
const DEFAULT_ROOM_MEMBERS = 8;
const DEFAULT_ROOM_TTL_HOURS = 24;

// Elements marked data-hidden start hidden through the stylesheet; the view code reads and
// toggles element.style.display, so mirror that state into it once (CSSOM, CSP-safe).
document.querySelectorAll('[data-hidden]').forEach(element => {
    element.style.display = 'none';
});
// The start view is the one view shown from the start (isShown reads this)
document.getElementById(START_VIEW_ID).style.display = 'block';

// Every view change passes here, so any way out of the robot side (buttons, brand title, Escape,
// logging in) turns the page white again, and the pointer trail exists only on the main menu
function setView(activeId) {
    VIEW_IDS.forEach(id => {
        document.getElementById(id).style.display = id === activeId ? 'block' : 'none';
    });
    document.body.classList.toggle(ROBOT_SIDE_CLASS, ROBOT_SIDE_VIEWS.has(activeId));
    watchDoorTrail(activeId === 'mainMenu');
    if (activeId !== 'doorVerdictContainer') clearDoorVerdict();
}

// Whether a view (VIEW_IDS, shown by setView) or a pair panel (PAIR_PANELS) is shown
function isShown(id) {
    return document.getElementById(id).style.display === 'block';
}

function isRobotSide() {
    return document.body.classList.contains(ROBOT_SIDE_CLASS);
}

// ---------- the other door ----------
// Theatre, not a gate (js/robot-door.js). The trail is kept in memory while the main menu is
// shown, read once when the robot door is pressed, and dropped as soon as the menu is left.

const doorTrail = RobotDoor.createTrail();

function recordDoorTrail(event) {
    doorTrail.push(event.clientX, event.clientY, event.timeStamp);
}

function watchDoorTrail(watching) {
    if (watching) {
        document.addEventListener('pointermove', recordDoorTrail, { passive: true });
    } else {
        document.removeEventListener('pointermove', recordDoorTrail);
        doorTrail.clear();
    }
}

// The click on the robot door, judged against the trail (read before the view changes clears it)
function judgeDoorPress(event) {
    return RobotDoor.classify(
        { pointerType: event.pointerType, detail: event.detail, at: event.timeStamp },
        doorTrail.points());
}

// The verdict for a person: measured lines (none for an honest or wrong answer) and one line.
// Written after the view is shown, so the live region announces it.
function showDoorVerdict(line, measurements) {
    setView('doorVerdictContainer');
    clearDoorVerdict();
    const list = document.getElementById('doorMeasurements');
    measurements.forEach(text => {
        const item = document.createElement('li');
        item.textContent = text;
        list.appendChild(item);
    });
    document.getElementById('doorVerdictLine').textContent = line;
    // Focus lands on the heading, never on an action: the keystroke that opened this screen
    // (Enter in the challenge) must not go on to press the button it lands on
    document.getElementById('doorVerdictHeading').focus();
}

// Measurements are forgotten as soon as the verdict screen is left
function clearDoorVerdict() {
    clearChildren(document.getElementById('doorMeasurements'));
    document.getElementById('doorVerdictLine').textContent = '';
}

// A fresh nonce each time; a browser without a random source skips the show
function showDoorChallenge() {
    let nonce;
    try {
        nonce = RobotDoor.newNonce();
    } catch (e) {
        Errors.report(Errors.CODES.W_DOOR_CHECK_UNAVAILABLE, null, e);
        showRobot(RobotDoor.MODE.ROBOT);
        return;
    }
    setView('doorChallengeContainer');
    document.getElementById('doorNonce').textContent = nonce;
    const input = document.getElementById('doorAnswerInput');
    input.value = '';
    input.focus();
}

function showMainMenu() {
    setView('mainMenu');
}

// Fails open: a page still on the start view goes to the main menu; any other view stays
function leaveStartView() {
    if (isShown(START_VIEW_ID)) showMainMenu();
}

// A script that fails to load (it would never decide) still leaves the start view, with the reason
// on the main menu's own status line: the notification container is not parsed yet at that point.
// Load failures reach window only in the capture phase; thrown errors are app.js's.
window.addEventListener('error', event => {
    if (!(event.target instanceof HTMLScriptElement)) return;
    leaveStartView();
    Errors.inline(document.getElementById('resumeError'), Errors.CODES.E_UNEXPECTED);
}, true);

function showLogin() {
    setView('loginContainer');
    document.getElementById('accountNumberInput').value = '';
    document.getElementById('loginError').textContent = '';
    document.getElementById('loginSuccess').textContent = '';

    // Re-initialize eye animation when login page is shown
    // This ensures animation works even if login page is dynamically displayed
    setTimeout(() => {
        if (typeof initEyeAnimation === 'function') {
            initEyeAnimation();
        }
        document.getElementById('accountNumberInput').focus();
    }, LOGIN_FOCUS_DELAY_MS);
}

function showRegisterForm() {
    setView('registerContainer');
    document.getElementById('registerError').textContent = '';
    document.getElementById('registerSuccess').textContent = '';

    // Reset Account Number display state
    const accountNumberElement = document.getElementById('generatedAccountNumber');
    const continueBtn = document.getElementById('continueBtn');
    const copyBtn = document.getElementById('copyBtn');
    const accountNumberBox = document.querySelector('.account-number-box');

    clearCodeElement(accountNumberElement);
    continueBtn.disabled = true;
    if (copyBtn) {
        copyBtn.disabled = false;
    }
    if (accountNumberBox) accountNumberBox.classList.add('show');

    // Start the scramble animation immediately
    startAccountNumberScramble(
        accountNumberElement,
        document.getElementById('registerSuccess'),
        document.getElementById('accountNumberDisplay')
    );
}

// Robot entrance: explains how an AI agent connects to this instance; no account, no network.
// mode (RobotDoor.MODE) only picks the greeting: a robot that passed, or its person.
function showRobot(mode) {
    setView('robotContainer');
    document.getElementById('robotGreeting').textContent = RobotDoor.greeting(mode);
    document.getElementById('robotCommand').textContent =
        buildAgentCommand(window.location.origin) || buildAgentCommand(AGENT_SERVER_EXAMPLE);
    // Focus lands on the greeting, not the copy button: entering never copies anything, the
    // clipboard is written only when copy itself is pressed
    document.getElementById('robotGreeting').focus();
}

function showApp() {
    // Entering the app settles any resume that could not reach the server
    clearResumeFailure();
    setView('appContainer');
}

// The main menu after a resume that got no answer: the reason, and a retry
function showResumeFailure(code, cause) {
    Errors.inline(document.getElementById('resumeError'), code, null, cause);
    document.getElementById('retryResumeBtn').style.display = 'inline-block';
}

function clearResumeFailure() {
    document.getElementById('resumeError').textContent = '';
    document.getElementById('retryResumeBtn').style.display = 'none';
}

function clearChildren(element) {
    while (element.firstChild) {
        element.removeChild(element.firstChild);
    }
}

// ---------- scramble ----------
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

// ---------- aura ----------

// Draws a mirrored 5x5 pixel glyph; CSS scales it up with image-rendering: pixelated
function drawGlyph(canvas, grid) {
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const size = ElyrnCrypto.AURA_GRID_SIZE;
    ctx.clearRect(0, 0, size, size);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--fg').trim() || '#000';
    for (let row = 0; row < size; row++) {
        for (let col = 0; col < size; col++) {
            if (grid[row][col]) {
                ctx.fillRect(col, row, 1, 1);
            }
        }
    }
}

function createGlyph(grid) {
    const canvas = document.createElement('canvas');
    canvas.width = ElyrnCrypto.AURA_GRID_SIZE;
    canvas.height = ElyrnCrypto.AURA_GRID_SIZE;
    canvas.className = 'aura-glyph';
    drawGlyph(canvas, grid);
    return canvas;
}

// The 16-bit code that follows a name wherever both are shown
function auraCode(aura) {
    return '·' + aura.code;
}

// Glyph, name and code: what tells two members apart (a name alone carries only 12 bits)
function appendAura(parent, aura) {
    parent.appendChild(createGlyph(aura.grid));
    const name = document.createElement('span');
    name.className = 'aura-name';
    name.textContent = aura.name;
    parent.appendChild(name);
    const code = document.createElement('span');
    code.className = 'aura-code';
    code.textContent = auraCode(aura);
    parent.appendChild(code);
}

function renderMe(aura) {
    drawGlyph(document.getElementById('meGlyph'), aura.grid);
    document.getElementById('meName').textContent = aura.name;
    document.getElementById('meBadge').title = 'you are ' + aura.name + ' · ' + aura.code;
}

// ---------- home ----------

function showHome() {
    document.getElementById('chatView').style.display = 'none';
    document.getElementById('homeView').style.display = 'block';
}

const PAIR_PANELS = ['invitePanel', 'roomPanel', 'joinPanel', 'deletePanel'];

// Opens panelId alone, or closes every pair panel when it is already open (or null)
function togglePairPanel(panelId) {
    PAIR_PANELS.forEach(id => {
        const panel = document.getElementById(id);
        panel.style.display = id === panelId && panel.style.display === 'none' ? 'block' : 'none';
    });
}

// Opens panelId and closes the others, whatever was open
function showPairPanel(panelId) {
    PAIR_PANELS.forEach(id => {
        document.getElementById(id).style.display = id === panelId ? 'block' : 'none';
    });
}

// While the proof of work runs, the invite scrambles exactly like a new account number does.
// Returns the function that stops the scramble.
function showInviteGenerating() {
    const codeElement = document.getElementById('inviteCode');
    setCodeState(codeElement, 'generating');
    document.getElementById('inviteBox').classList.add('show');
    document.getElementById('newInviteBtn').disabled = true;
    document.getElementById('copyInviteBtn').disabled = true;
    document.getElementById('inviteHint').style.display = 'none';
    document.getElementById('inviteStatus').style.display = 'block';
    showPairPanel('invitePanel');
    return startScramble(codeElement, ElyrnCrypto.INVITE_BODY_CHARS, ElyrnCrypto.INVITE_PREFIX);
}

// Masks the noise, then reveals the real code while alive() holds. Resolves to whether it was
// shown; when not, nothing was drawn after alive() turned false.
async function revealInvite(code, expiresAtSeconds, alive) {
    if (!(await maskThenReveal(document.getElementById('inviteCode'), code, ElyrnCrypto.INVITE_PREFIX, alive))) return false;
    document.getElementById('inviteExpiry').textContent = formatExpiry(expiresAtSeconds);
    document.getElementById('inviteStatus').style.display = 'none';
    document.getElementById('inviteHint').style.display = 'block';
    document.getElementById('copyInviteBtn').disabled = false;
    document.getElementById('newInviteBtn').disabled = false;
    return true;
}

// Puts the invite panel away and forgets the code it showed
function resetInvitePanel() {
    clearCodeElement(document.getElementById('inviteCode'));
    document.getElementById('invitePanel').style.display = 'none';
    document.getElementById('inviteStatus').style.display = 'none';
    document.getElementById('inviteHint').style.display = 'block';
    document.getElementById('copyInviteBtn').disabled = false;
    document.getElementById('newInviteBtn').disabled = false;
}

// items: [{ id, aura, unread, verified, room }] in display order; an item marked unverified
// ({ id, aura, owner, unverified }) is a room that failed verification: onLeave(id) is its only action
function renderConversationList(items, onOpen, onLeave) {
    const list = document.getElementById('conversationList');
    clearChildren(list);

    if (items.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = 'no conversations yet — invite someone you trust, or open a room and share its code';
        list.appendChild(empty);
        return;
    }

    items.forEach(item => {
        if (item.unverified) {
            list.appendChild(createUnverifiedRow(item, onLeave));
            return;
        }
        const row = document.createElement('li');
        row.className = 'conversation-item' + (item.unread ? ' unread' : '');
        row.tabIndex = 0;
        row.dataset.id = item.id;

        const name = document.createElement('span');
        name.className = 'aura-name';
        name.textContent = item.room ? roomName(item.aura) : item.aura.name;

        const code = document.createElement('span');
        code.className = 'aura-code';
        code.textContent = item.room ? roomMeta(item.room) : auraCode(item.aura);

        const marker = document.createElement('span');
        marker.className = 'unread-marker';
        marker.textContent = item.unread ? 'new' : (item.room && item.room.notes > 0 ? 'request' : '›');

        row.appendChild(createGlyph(item.aura.grid));
        row.appendChild(name);
        row.appendChild(code);
        if (item.verified) {
            const verified = document.createElement('span');
            verified.className = 'verified-mark';
            verified.title = 'safety number verified on this device';
            verified.textContent = '✓';
            row.appendChild(verified);
        }
        row.appendChild(marker);
        row.addEventListener('click', () => onOpen(item.id));
        row.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') onOpen(item.id);
        });
        list.appendChild(row);
    });
}

const UNVERIFIED_MARK = '⚠ failed verification · cannot be opened';

// A room that failed verification: named from its id, marked, never opened. Its one action
// (leave; burn for its owner, as the server says) asks first, in the row, as burning does.
function createUnverifiedRow(item, onLeave) {
    const row = document.createElement('li');
    row.className = 'conversation-item';
    row.dataset.id = item.id;
    row.appendChild(createGlyph(item.aura.grid));
    const name = document.createElement('span');
    name.className = 'aura-name';
    name.textContent = roomName(item.aura);
    row.appendChild(name);
    const mark = document.createElement('span');
    mark.className = 'aura-code member-broken';
    mark.textContent = UNVERIFIED_MARK;
    row.appendChild(mark);
    const actions = document.createElement('span');
    actions.className = 'unread-marker';
    row.appendChild(actions);

    const room = { owner: item.owner };
    const offer = () => {
        clearChildren(actions);
        actions.appendChild(actionButton(burnLabel(room), '', ask));
    };
    const ask = () => {
        clearChildren(actions);
        const question = document.createElement('span');
        question.textContent = burnQuestion(room) + ' ';
        actions.appendChild(question);
        actions.appendChild(actionButton(burnLabel(room), 'burn-yes', () => onLeave(item.id)));
        actions.appendChild(actionButton(KEEP_LABEL, '', offer));
    };
    offer();
    return row;
}

function actionButton(text, extraClass, onClick) {
    const button = document.createElement('button');
    button.className = extraClass ? 'menu-opt ' + extraClass : 'menu-opt';
    button.textContent = text;
    button.addEventListener('click', onClick);
    return button;
}

// ---------- chat ----------

function showChatView(aura, room) {
    drawGlyph(document.getElementById('peerGlyph'), aura.grid);
    document.getElementById('peerName').textContent = room ? roomName(aura) : aura.name;
    document.getElementById('peerCode').textContent = room ? '' : auraCode(aura);
    document.getElementById('safetyPanel').style.display = 'none';
    document.getElementById('burnConfirm').style.display = 'none';
    hideRoomPanels();
    // A room has members, a code and a member list; a pair has a safety number
    ['roomMeta', 'membersBtn', 'roomCodeBtn'].forEach(id => {
        document.getElementById(id).style.display = room ? 'inline' : 'none';
    });
    document.getElementById('verifyBtn').style.display = room ? 'none' : 'inline';
    document.getElementById('peerVerified').style.display = 'none';
    const burnButton = document.getElementById('burnBtn');
    burnButton.textContent = burnLabel(room);
    burnButton.title = room && !room.owner ? 'Leave room' : (room ? 'Burn room for everyone' : 'Burn conversation');
    clearChildren(document.getElementById('messageList'));
    setEarlierControl(false, false);
    document.getElementById('homeView').style.display = 'none';
    document.getElementById('chatView').style.display = 'block';
}

function setVerifiedState(verified) {
    document.getElementById('peerVerified').style.display = verified ? 'inline' : 'none';
    const button = document.getElementById('markVerifiedBtn');
    button.textContent = verified ? '✓ verified — unmark' : 'mark as verified';
    button.classList.toggle('active', verified);
}

function renderSafetyNumber(groups) {
    const box = document.getElementById('safetyNumber');
    clearChildren(box);
    groups.forEach(group => {
        const cell = document.createElement('span');
        cell.textContent = group;
        box.appendChild(cell);
    });
}

// Who a counter warning is about: a room sender by name and code, else the peer, or this device
const PEER_LABEL = 'them';
const SELF_LABEL = 'you';

function senderLabel(from, mine) {
    if (mine) return SELF_LABEL;
    return from ? from.name + auraCode(from) : PEER_LABEL;
}

// A gap in a sender's counter: the server withheld, delayed or deleted their messages
// from: the room sender's aura (absent one-to-one)
function createGapElement(missing, from) {
    const item = document.createElement('li');
    item.className = 'msg-gap';
    const who = senderLabel(from, false);
    // The count comes from the sender's own counter; cap what we repeat back
    item.textContent = missing === 1
        ? `⚠ 1 message from ${who} never arrived`
        : missing <= MAX_GAP_SHOWN ? `⚠ ${missing} messages from ${who} never arrived` : `⚠ messages from ${who} never arrived`;
    return item;
}

// A counter the sender already used: an old message served again or out of order. Its text is
// not shown, so a replay can never pass as something said now.
function createReplayElement(from, mine) {
    const item = document.createElement('li');
    item.className = 'msg-gap msg-replay';
    item.textContent = Errors.message(Errors.CODES.W_MESSAGE_REPLAYED, { who: senderLabel(from, mine) });
    return item;
}

function createMessageListItem(message) {
    if (message.gap) return createGapElement(message.gap, message.from);
    if (message.replay) return createReplayElement(message.from, message.mine);
    return createMessageElement(message);
}

// What a message that does not open says instead of its text: one a newer elyrn wrote is not
// shown as tampered with
const UNREADABLE_MARK = '⚠ unreadable — integrity check failed';

function unreadableText(message) {
    return message.newer ? Errors.message(Errors.CODES.W_MESSAGE_FROM_NEWER) : UNREADABLE_MARK;
}

function createMessageElement(message) {
    const item = document.createElement('li');
    const state = !message.broken ? '' : message.newer ? ' newer' : ' broken';
    item.className = 'msg ' + (message.mine ? 'mine' : 'theirs') + state;
    item.dataset.seq = String(message.seq);

    // In a room, every message from someone else says who: glyph, name and code in this room only
    if (message.from && !message.broken) {
        const sender = document.createElement('div');
        sender.className = 'msg-sender';
        sender.dataset.sender = message.sender;
        appendAura(sender, message.from);
        const role = RoleControl.tag(message.role);
        if (role) sender.appendChild(role);
        if (message.left) {
            const left = document.createElement('span');
            left.textContent = LEFT_MARK;
            sender.appendChild(left);
        }
        item.appendChild(sender);
    }

    const text = document.createElement('div');
    text.className = 'msg-text';
    text.textContent = message.broken ? unreadableText(message) : neutralizeReceivedText(message.text);
    item.appendChild(text);

    if (!message.broken) {
        const time = document.createElement('div');
        time.className = 'msg-time';
        time.textContent = formatTime(message.sentAt);
        item.appendChild(time);
    }
    return item;
}

// The "say hello" line goes once there is something to show
function dropEmptyNotice(list, messages) {
    const empty = list.querySelector('.empty-message');
    if (empty && messages.length > 0) {
        empty.remove();
    }
}

// Appends messages (already sorted by seq) and keeps the view pinned to the bottom
function appendMessages(messages) {
    const list = document.getElementById('messageList');
    const pinned = list.scrollHeight - list.scrollTop - list.clientHeight < PINNED_SLACK_PX;
    dropEmptyNotice(list, messages);
    messages.forEach(message => list.appendChild(createMessageListItem(message)));
    if (pinned || messages.some(m => m.mine)) {
        list.scrollTop = list.scrollHeight;
    }
}

// Puts an earlier page (sorted by seq) above what is shown; the distance from the bottom is
// kept, so the messages being read stay where they were instead of jumping down
function prependMessages(messages) {
    const list = document.getElementById('messageList');
    const fromBottom = list.scrollHeight - list.scrollTop;
    dropEmptyNotice(list, messages);
    const page = document.createDocumentFragment();
    messages.forEach(message => page.appendChild(createMessageListItem(message)));
    list.insertBefore(page, list.firstChild);
    list.scrollTop = list.scrollHeight - fromBottom;
}

// The "earlier messages" control: shown while more history may exist, disabled while loading
function setEarlierControl(shown, busy) {
    const button = document.getElementById('earlierBtn');
    button.style.display = shown ? 'block' : 'none';
    button.disabled = Boolean(busy);
}

// A conversation that loaded and holds nothing; it replaces a load failure shown before
function renderEmptyConversation(ttlDays, room) {
    const list = document.getElementById('messageList');
    const failure = list.querySelector('.load-failed');
    if (failure) failure.remove();
    if (list.children.length === 0) {
        const empty = document.createElement('li');
        empty.className = 'empty-message';
        empty.textContent = room
            ? `encrypted for exactly the members listed. you only see what was sent after you joined. the room vanishes ${formatTimeLeft(room.expiresAt)}.`
            : `end-to-end encrypted. messages vanish after ${ttlDays} days. say hello.`;
        list.appendChild(empty);
    }
}

// In place of the empty-conversation text when nothing could be loaded: the reason and a retry.
// It carries .empty-message too, so the first messages to arrive remove it (dropEmptyNotice).
function renderLoadFailure(onRetry) {
    const list = document.getElementById('messageList');
    if (list.children.length > 0) return;
    const item = document.createElement('li');
    item.className = 'empty-message load-failed';
    const reason = document.createElement('div');
    Errors.inline(reason, Errors.CODES.E_MESSAGES_NOT_LOADED);
    const retry = document.createElement('button');
    retry.className = 'menu-opt';
    retry.textContent = 'retry';
    retry.addEventListener('click', onRetry);
    item.appendChild(reason);
    item.appendChild(retry);
    list.appendChild(item);
}

function setComposerHint(ttlDays) {
    document.getElementById('composerHint').textContent =
        `vanishes after ${ttlDays} days · enter to send · shift+enter for a new line`;
}

// Messages go with the room, or after the usual retention if that comes first
function setRoomComposerHint(expiresAt, ttlDays) {
    const vanish = Math.min(expiresAt, Date.now() + ttlDays * DAY_MS);
    document.getElementById('composerHint').textContent =
        `vanishes ${formatTimeLeft(vanish)} · enter to send · shift+enter for a new line`;
}

function updateComposerMeta() {
    const input = document.getElementById('messageInput');
    document.getElementById('charCount').textContent = `${[...input.value].length}/${MAX_MESSAGE_CHARS}`;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, COMPOSER_MAX_HEIGHT_PX) + 'px';
}

// ---------- formatting ----------

function formatTime(ms) {
    const date = new Date(ms);
    // A sender's clock past what a Date holds (a modified client can seal any safe integer):
    // no time is shown rather than "Invalid Date"
    if (!Number.isFinite(date.getTime())) return '';
    const now = new Date();
    const hhmm = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    if (date.toDateString() === now.toDateString()) {
        return hhmm;
    }
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + hhmm;
}

// "in 5h", "in 3d", "within the hour", "now"
function formatTimeLeft(atMs) {
    const left = atMs - Date.now();
    if (left <= 0) return 'now';
    const hours = Math.floor(left / HOUR_MS);
    if (hours >= DAYS_SHOWN_FROM_HOURS) return `in ${Math.floor(hours / HOURS_PER_DAY)}d`;
    return hours >= 1 ? `in ${hours}h` : 'within the hour';
}

function formatExpiry(expiresAtSeconds) {
    const hours = Math.max(0, Math.round((expiresAtSeconds * SECOND_MS - Date.now()) / HOUR_MS));
    return hours >= 1 ? `in ${hours}h` : 'within the hour';
}

// ---------- rooms ----------
// A room's name comes from its id (the same for every member); people in it have their own
// per-room auras, which link to nothing outside the room.

function roomName(aura) {
    return '#' + aura.name;
}

function roomMeta(room) {
    return `${room.members}/${room.maxMembers} · ${formatTimeLeft(room.expiresAt)}`;
}

const ROOM_PANELS = ['membersPanel', 'notesPanel', 'roomCodePanel'];
const LOOKALIKE_TAG = 'same name as another member';
const LEFT_MARK = '· left';

function hideRoomPanels() {
    ROOM_PANELS.forEach(id => {
        document.getElementById(id).style.display = 'none';
    });
}

// Opens panelId alone (the notes panel stays as it is); returns whether it is now open
function toggleRoomPanel(panelId) {
    const panel = document.getElementById(panelId);
    const opening = panel.style.display === 'none';
    ['membersPanel', 'roomCodePanel', 'safetyPanel', 'burnConfirm'].forEach(id => {
        document.getElementById(id).style.display = 'none';
    });
    panel.style.display = opening ? 'block' : 'none';
    return opening;
}

function renderRoomHeader(room) {
    document.getElementById('roomMeta').textContent = roomMeta(room);
    const burnButton = document.getElementById('burnBtn');
    burnButton.textContent = burnLabel(room);
}

const KEEP_LABEL = 'keep';

// What burning asks, and its button: a pair (room null) and a room's owner burn, others leave
function burnQuestion(room) {
    return !room
        ? 'burn for both sides? this cannot be undone.'
        : room.owner
            ? 'burn this room for everyone? this cannot be undone.'
            : 'leave this room? you can come back with the code while a seat is free.';
}

function burnLabel(room) {
    return room && !room.owner ? 'leave' : 'burn';
}

function setBurnConfirm(room) {
    document.getElementById('burnConfirmText').textContent = burnQuestion(room);
    document.getElementById('burnYesBtn').textContent = burnLabel(room);
}

// The creator's choices, within what this server allows
function setRoomLimits(maxMembers, ttlChoices) {
    const members = document.getElementById('roomMembersSelect');
    clearChildren(members);
    for (let n = ElyrnRoomCrypto.MIN_MEMBERS; n <= maxMembers; n++) {
        const option = document.createElement('option');
        option.value = String(n);
        option.textContent = `${n} people`;
        option.selected = n === Math.min(DEFAULT_ROOM_MEMBERS, maxMembers);
        members.appendChild(option);
    }
    const ttl = document.getElementById('roomTtlSelect');
    clearChildren(ttl);
    ttlChoices.forEach(hours => {
        const option = document.createElement('option');
        option.value = String(hours);
        option.textContent = hours === 1 ? '1 hour'
            : hours % HOURS_PER_DAY === 0 ? `${hours / HOURS_PER_DAY} day${hours === HOURS_PER_DAY ? '' : 's'}` : `${hours} hours`;
        option.selected = hours === DEFAULT_ROOM_TTL_HOURS || ttlChoices.length === 1;
        ttl.appendChild(option);
    });
}

// While the proof of work runs the room code scrambles, as invites and account numbers do
function showRoomGenerating() {
    const codeElement = document.getElementById('roomCode');
    setCodeState(codeElement, 'generating');
    document.getElementById('roomBox').style.display = 'flex';
    document.getElementById('roomBox').classList.add('show');
    document.getElementById('roomForm').style.display = 'none';
    document.getElementById('newRoomBtn').disabled = true;
    document.getElementById('copyRoomBtn').disabled = true;
    document.getElementById('roomHint').style.display = 'none';
    document.getElementById('roomStatus').style.display = 'block';
    showPairPanel('roomPanel');
    return startScramble(codeElement, ElyrnRoomCrypto.CODE_CHARS - ElyrnRoomCrypto.CODE_PREFIX.length, ElyrnRoomCrypto.CODE_PREFIX);
}

// Whether the room panel still shows the box a new code is drawn into: closing the panel, or
// reopening it for another room (resetRoomPanel), puts the box away
function roomCodeBoxShown() {
    return isShown('roomPanel') && document.getElementById('roomBox').style.display !== 'none';
}

// As revealInvite: resolves to whether the code was shown
async function revealRoomCode(code, expiresAtSeconds, alive) {
    if (!(await maskThenReveal(document.getElementById('roomCode'), code, ElyrnRoomCrypto.CODE_PREFIX, alive))) return false;
    document.getElementById('roomExpiry').textContent = formatTimeLeft(expiresAtSeconds * SECOND_MS);
    document.getElementById('roomStatus').style.display = 'none';
    document.getElementById('roomHint').style.display = 'block';
    document.getElementById('copyRoomBtn').disabled = false;
    document.getElementById('newRoomBtn').disabled = false;
    return true;
}

// Puts the room panel away and forgets the code it showed
function resetRoomPanel() {
    clearCodeElement(document.getElementById('roomCode'));
    document.getElementById('roomPanel').style.display = 'none';
    document.getElementById('roomBox').style.display = 'none';
    document.getElementById('roomForm').style.display = 'flex';
    document.getElementById('roomStatus').style.display = 'none';
    document.getElementById('roomHint').style.display = 'block';
    document.getElementById('roomExpiry').textContent = 'when its time is up';
    document.getElementById('copyRoomBtn').disabled = false;
    document.getElementById('newRoomBtn').disabled = false;
}

function showRoomCode(code, expiresAt) {
    document.getElementById('roomCodeShown').textContent = code;
    document.getElementById('roomCodeHint').textContent =
        `anyone holding this code can join while a seat is free · the room vanishes ${formatTimeLeft(expiresAt)} · share it only over a channel you trust`;
}

function memberRow(entry) {
    const row = document.createElement('li');
    row.className = 'member-item';
    appendAura(row, entry.aura);
    return row;
}

function memberTag(text) {
    const tag = document.createElement('span');
    tag.className = 'member-tag';
    tag.textContent = text;
    return tag;
}

function lookalikeTag() {
    const tag = memberTag(LOOKALIKE_TAG);
    tag.classList.add('lookalike-tag');
    return tag;
}

// keys: public keys whose name another key shares; tags (or untags) every message from them
function markLookalikes(keys) {
    document.querySelectorAll('#messageList .msg-sender').forEach(sender => {
        const tag = sender.querySelector('.lookalike-tag');
        const lookalike = keys.has(sender.dataset.sender);
        if (lookalike && !tag) {
            sender.appendChild(lookalikeTag());
        } else if (!lookalike && tag) {
            tag.remove();
        }
    });
}

// entries: verified roster; skipped: cards that failed to open (shown, never written to);
// lookalikes: public keys whose name another key shares; roleControl(entry): the role control
// for that entry, or null where this account may not change its role (RoleControl.control)
function renderMembers({ entries, skipped, requested, lookalikes, onBefriend, roleControl }) {
    const list = document.getElementById('memberList');
    clearChildren(list);
    entries.forEach(entry => {
        const row = memberRow(entry);
        const role = RoleControl.tag(entry.role);
        if (role) row.appendChild(role);
        if (entry.mine) row.appendChild(memberTag('you'));
        if (entry.owner) row.appendChild(memberTag('owner'));
        if (lookalikes.has(entry.publicKey)) row.appendChild(lookalikeTag());
        const control = roleControl(entry);
        if (control) row.appendChild(control);
        if (!entry.mine) {
            const button = document.createElement('button');
            button.className = 'menu-opt member-action';
            const asked = requested.has(entry.publicKey);
            button.textContent = asked ? 'request sent' : 'befriend';
            button.disabled = asked;
            button.title = 'send them an invite only they can open';
            button.addEventListener('click', () => onBefriend(entry));
            row.appendChild(button);
        }
        list.appendChild(row);
    });
    if (skipped > 0) {
        const row = document.createElement('li');
        row.className = 'member-item member-broken';
        row.textContent = skipped === 1
            ? '⚠ 1 member card failed verification — nothing is encrypted for it'
            : `⚠ ${skipped} member cards failed verification — nothing is encrypted for them`;
        list.appendChild(row);
    }
}

function renderRoomSafety(groups) {
    const box = document.getElementById('roomSafetyNumber');
    clearChildren(box);
    groups.forEach(group => {
        const cell = document.createElement('span');
        cell.textContent = group;
        box.appendChild(cell);
    });
}

// notes: [{ id, aura, from }] friend requests addressed to this member
function renderNotes(notes, onAccept, onIgnore) {
    const panel = document.getElementById('notesPanel');
    const list = document.getElementById('noteList');
    clearChildren(list);
    panel.style.display = notes.length > 0 ? 'block' : 'none';
    notes.forEach(note => {
        const row = memberRow({ aura: note.aura });
        row.appendChild(memberTag(note.from ? 'wants to be friends' : 'left · wants to be friends'));
        const accept = document.createElement('button');
        accept.className = 'menu-opt member-action';
        accept.textContent = 'accept';
        accept.addEventListener('click', () => onAccept(note));
        const ignore = document.createElement('button');
        ignore.className = 'menu-opt';
        ignore.textContent = 'ignore';
        ignore.addEventListener('click', () => onIgnore(note));
        row.appendChild(accept);
        row.appendChild(ignore);
        list.appendChild(row);
    });
}
