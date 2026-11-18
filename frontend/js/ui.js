// ========================================
// UI FUNCTIONS
// ========================================
// Rendering only: no network, no crypto. Every user- or server-supplied string
// reaches the DOM through textContent (never innerHTML).

const AURA_GLYPH_CLASS = 'aura-glyph';

// startView is the page's first view (index.html): the brand line while app.js decides
const START_VIEW_ID = 'startView';
const VIEW_IDS = [START_VIEW_ID, 'mainMenu', 'loginContainer', 'registerContainer', 'doorVerdictContainer',
    'doorChallengeContainer', 'robotContainer', 'appContainer'];
// The robot side of the other door: these views turn the page black (one class on <body>)
const ROBOT_SIDE_VIEWS = new Set(['doorVerdictContainer', 'doorChallengeContainer', 'robotContainer']);
const ROBOT_SIDE_CLASS = 'robot-side';
// While a conversation is shown the page fits the window and only the message list scrolls
const CONVERSATION_CLASS = 'in-conversation';

// Time units: an hour is the room code's own unit (room-crypto.js)
const SECOND_MS = 1000;
const HOUR_MS = ElyrnRoomCrypto.HOUR_MS;
const HOURS_PER_DAY = 24;
const DAY_MS = HOURS_PER_DAY * HOUR_MS;
// A time left reads in days from two days on, in hours below that
const DAYS_SHOWN_FROM_HOURS = 48;

// The login page focuses its field once the eye animation has been set up again
const LOGIN_FOCUS_DELAY_MS = 100;
// A gap notice repeats a count only up to here: the count comes from the sender's counter
const MAX_GAP_SHOWN = 999;
// The message list follows new messages while it is scrolled within this of the bottom
const PINNED_SLACK_PX = 48;
// The composer grows with its text up to this height, then scrolls
const COMPOSER_MAX_HEIGHT_PX = 140;
// What the room form offers first, within the server's limits
const DEFAULT_ROOM_MEMBERS = 8;
const DEFAULT_ROOM_TTL_HOURS = 24;

// Every word ui.js, alerts.js, file-card.js and file-composer.js write into the page that is no failure or
// warning (those are errors.js's, by code): control labels, tags, marks, titles, hints, progress
// and the empty-state sentences.
// A text with a part filled in is a function of that part.
const UI_TEXT = Object.freeze({
    // conversation list
    NO_CONVERSATIONS: 'no conversations yet — invite someone you trust, or open a room and share its code',
    UNREAD_MARK: 'new',
    NOTES_MARK: 'request',
    VERIFIED_MARK: '✓',
    VERIFIED_TITLE: 'safety number verified on this device',
    // names: a member's 16-bit code follows the name; a room's name is marked as a room's
    AURA_CODE_PREFIX: '·',
    ROOM_NAME_PREFIX: '#',
    ME_TITLE: (name, code) => 'you are ' + name + ' · ' + code,
    // the app header's alerts bell (alerts.js): its name, and a title that also says what it does
    ALERTS_ON: 'alerts on',
    ALERTS_OFF: 'alerts off',
    // icon controls: each one's accessible name and the caption its tile shows on hover and focus;
    // burnBtn's are the burn and leave texts below
    LOGOUT: 'logout',
    BACK: 'back',
    MEMBERS: 'members',
    MEMBERS_TITLE: 'members of this room',
    ROOM_CODE: 'code',
    ROOM_CODE_TITLE: 'room code',
    VERIFY: 'verify',
    VERIFY_TITLE: 'verify safety number',
    COPY: 'copy',
    ATTACH: 'attach a file',
    SEND: 'send',
    ROOM_META: (members, maxMembers, left) => `${members}/${maxMembers} · ${left}`,
    // the open conversation
    VERIFIED_ON: '✓ verified — unmark',
    VERIFIED_OFF: 'mark as verified',
    // who a counter warning is about: a room sender by name and code, else the peer, or this device
    PEER: 'them',
    SELF: 'you',
    LEFT_MARK: '· left',
    RETRY: 'retry',
    EMPTY_ROOM: (left) => `encrypted for exactly the members listed. you only see what was sent after you joined. the room vanishes ${left}.`,
    EMPTY_PAIR: (ttlDays) => `end-to-end encrypted. messages vanish after ${ttlDays} days. say hello.`,
    COMPOSER_HINT: (ttlDays) => `vanishes after ${ttlDays} days · enter to send · shift+enter for a new line`,
    ROOM_COMPOSER_HINT: (left) => `vanishes ${left} · enter to send · shift+enter for a new line`,
    // burning and leaving: a pair and a room's owner burn, others leave
    BURN: 'burn',
    LEAVE: 'leave',
    KEEP: 'keep',
    BURN_PAIR_TITLE: 'Burn conversation',
    BURN_ROOM_TITLE: 'Burn room for everyone',
    LEAVE_ROOM_TITLE: 'Leave room',
    // deleting the identity: the identity panel's last row (its button opens the delete panel)
    DELETE: 'delete',
    DELETE_IDENTITY: 'delete identity',
    NO_UNDO: 'there is no undo',
    BURN_PAIR_QUESTION: 'burn for both sides? this cannot be undone.',
    BURN_ROOM_QUESTION: 'burn this room for everyone? this cannot be undone.',
    LEAVE_ROOM_QUESTION: 'leave this room? you can come back with the code while a seat is free.',
    // rooms
    MEMBERS_OPTION: (n) => `${n} people`,
    ONE_HOUR_OPTION: '1 hour',
    DAYS_OPTION: (days) => `${days} day${days === 1 ? '' : 's'}`,
    HOURS_OPTION: (hours) => `${hours} hours`,
    ROOM_EXPIRY_UNKNOWN: 'when its time is up',
    ROOM_CODE_HINT: (left) => `anyone holding this code can join while a seat is free · the room vanishes ${left} · share it only over a channel you trust`,
    // a passive mark beside a name: plain text after the middle dot, never framed
    MARK: (text) => `· ${text}`,
    YOU_TAG: 'you',
    OWNER_TAG: 'owner',
    BEFRIEND: 'befriend',
    REQUEST_SENT: 'request sent',
    BEFRIEND_TITLE: 'send them an invite only they can open',
    WANTS_FRIENDS: 'wants to be friends',
    LEFT_WANTS_FRIENDS: 'left · wants to be friends',
    ACCEPT: 'accept',
    IGNORE: 'ignore',
    // a member's role: the tile that opens its editor, and the editor's cells
    ROLE: 'role',
    ROLE_TITLE: 'role: a short label shown beside this member to everyone in the room',
    ROLE_INPUT: 'role',
    ROLE_SET: 'set',
    ROLE_SET_TITLE: 'set this role',
    ROLE_CLEAR: 'clear',
    ROLE_CLEAR_TITLE: 'clear this role',
    ROLE_CANCEL: 'cancel',
    ROLE_CANCEL_TITLE: 'cancel without changing the role',
    // files: the received card (file-card.js) and the chosen file's chip (file-composer.js)
    FILE_SAVE: 'save',
    FILE_FETCHING: 'fetching',
    FILE_PREPARING: 'preparing',
    FILE_UPLOADING: 'uploading',
    FILE_PROGRESS: (word, done, total) => `${word} ${done}/${total}`,
    FILE_REMOVE: 'remove',
    FILE_REMOVE_TITLE: 'remove the file',
    // sizes and times
    BYTES: (bytes) => `${bytes} ${bytes === 1 ? 'byte' : 'bytes'}`,
    NOW: 'now',
    WITHIN_THE_HOUR: 'within the hour',
    IN_HOURS: (hours) => `in ${hours}h`,
    IN_DAYS: (days) => `in ${days}d`
});

// Elements marked data-hidden start hidden through the stylesheet; the view code reads and
// toggles element.style.display, so mirror that state into it once (CSSOM, CSP-safe).
document.querySelectorAll('[data-hidden]').forEach(element => {
    element.style.display = 'none';
});
// Icon controls (index.html data-icon, drawn by pixels.js): [id, accessible name, caption or null].
// A tile carries no visible word: it shows its caption under itself on hover and keyboard focus
// (styles.css, the one CAPTION_ATTRIBUTE rule) and has no title, so two tooltips never show
// together. A control without a caption (the composer's attach and send) keeps its title.
const CAPTION_ATTRIBUTE = 'data-caption';
const ICON_BUTTONS = Object.freeze([
    ['logoutBtn', UI_TEXT.LOGOUT, UI_TEXT.LOGOUT],
    ['backToListBtn', UI_TEXT.BACK, UI_TEXT.BACK],
    ['membersBtn', UI_TEXT.MEMBERS_TITLE, UI_TEXT.MEMBERS],
    ['roomCodeBtn', UI_TEXT.ROOM_CODE_TITLE, UI_TEXT.ROOM_CODE],
    ['verifyBtn', UI_TEXT.VERIFY_TITLE, UI_TEXT.VERIFY],
    ['burnBtn', UI_TEXT.BURN_PAIR_TITLE, UI_TEXT.BURN],
    ['copyBtn', UI_TEXT.COPY, UI_TEXT.COPY],
    ['copyRobotBtn', UI_TEXT.COPY, UI_TEXT.COPY],
    ['copyInviteBtn', UI_TEXT.COPY, UI_TEXT.COPY],
    ['copyRoomBtn', UI_TEXT.COPY, UI_TEXT.COPY],
    ['copyRoomCodeBtn', UI_TEXT.COPY, UI_TEXT.COPY],
    ['fileRemoveBtn', UI_TEXT.FILE_REMOVE_TITLE, UI_TEXT.FILE_REMOVE],
    ['attachBtn', UI_TEXT.ATTACH, null],
    ['sendBtn', UI_TEXT.SEND, null]
]);

// Names an icon control: its accessible name, and its caption, or else its title
function nameIconButton(button, name, caption) {
    button.setAttribute('aria-label', name);
    if (caption) {
        button.setAttribute(CAPTION_ATTRIBUTE, caption);
        button.removeAttribute('title');
    } else {
        button.title = name;
    }
}

// An icon control made in code, named the same way: a tile (iconTile) or a cell of a joined box
// (boxCell)
function iconButton(className, holderClass, icon, name, caption) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    const holder = document.createElement('span');
    holder.className = holderClass;
    Pixels.setIcons(holder, icon);
    button.appendChild(holder);
    nameIconButton(button, name, caption);
    return button;
}

function iconTile(icon, name, caption) {
    return iconButton('icon-btn', 'icon-tile', icon, name, caption);
}

function boxCell(icon, name, caption) {
    return iconButton('box-cell', 'icon-bare', icon, name, caption);
}

Pixels.install(document);
ICON_BUTTONS.forEach(([id, name, caption]) => nameIconButton(document.getElementById(id), name, caption));
// The identity panel's delete row: what it does at the left, as a member row's marks say it, and
// the confirmation bar's red word button at the right
document.getElementById('deleteIdentityText').textContent = UI_TEXT.DELETE_IDENTITY + ' ' + UI_TEXT.MARK(UI_TEXT.NO_UNDO);
document.getElementById('deleteIdentityBtn').textContent = UI_TEXT.DELETE;

// The start view is the one view shown from the start (isShown reads this)
document.getElementById(START_VIEW_ID).style.display = 'block';

// Every view change passes here, so any way out of the robot side (buttons, brand title, Escape,
// logging in) turns the page white again, and the pointer trail exists only on the main menu
function setView(activeId) {
    VIEW_IDS.forEach(id => {
        document.getElementById(id).style.display = id === activeId ? 'block' : 'none';
    });
    document.body.classList.toggle(ROBOT_SIDE_CLASS, ROBOT_SIDE_VIEWS.has(activeId));
    setConversationShown(activeId === 'appContainer' && isShown('chatView'));
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

// ---------- aura ----------

// The mirrored 5x5 aura glyph, drawn by the one pixel renderer (pixels.js) in currentColor
function drawGlyph(svg, grid) {
    Pixels.drawGlyph(svg, grid);
}

function createGlyph(grid) {
    return Pixels.glyph(grid, AURA_GLYPH_CLASS);
}

// The 16-bit code that follows a name wherever both are shown
function auraCode(aura) {
    return UI_TEXT.AURA_CODE_PREFIX + aura.code;
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

// The header badge (glyph and name; on a phone the glyph alone, so its name is set explicitly)
// and the identity panel it opens (glyph, name and code)
function renderMe(aura) {
    drawGlyph(document.getElementById('meGlyph'), aura.grid);
    document.getElementById('meName').textContent = aura.name;
    const badge = document.getElementById('meBadge');
    badge.title = UI_TEXT.ME_TITLE(aura.name, aura.code);
    badge.setAttribute('aria-label', badge.title);
    const line = document.getElementById('identityAura');
    clearChildren(line);
    appendAura(line, aura);
}

// ---------- home ----------

function showHome() {
    document.getElementById('chatView').style.display = 'none';
    document.getElementById('homeView').style.display = 'block';
    setConversationShown(false);
}

// Focus on the home view's first control (after the burn fire, which held the page)
function focusHome() {
    const first = document.querySelector('#homeView button');
    if (first) first.focus();
}

function setConversationShown(shown) {
    document.body.classList.toggle(CONVERSATION_CLASS, shown);
}

// What a conversation row ends with when nothing is new: the list chevron
const OPEN_ICON = 'chevron';
// Icon controls take part in the row's flex layout when shown
const ICON_BUTTON_DISPLAY = 'inline-flex';

const PAIR_PANELS = ['identityPanel', 'invitePanel', 'roomPanel', 'joinPanel', 'deletePanel'];

// The one place a pair panel is shown or hidden by these two: a control that names the panel in
// aria-controls (the identity badge) says whether it is open
function setPairPanel(id, shown) {
    document.getElementById(id).style.display = shown ? 'block' : 'none';
    document.querySelectorAll(`[aria-controls="${id}"]`).forEach(control => {
        control.setAttribute('aria-expanded', shown ? 'true' : 'false');
    });
}

// Opens panelId alone, or closes every pair panel when it is already open (or null)
function togglePairPanel(panelId) {
    const opening = panelId !== null && !isShown(panelId);
    PAIR_PANELS.forEach(id => setPairPanel(id, opening && id === panelId));
}

// Opens panelId and closes the others, whatever was open
function showPairPanel(panelId) {
    PAIR_PANELS.forEach(id => setPairPanel(id, id === panelId));
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
        empty.textContent = UI_TEXT.NO_CONVERSATIONS;
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
        const mark = item.unread ? UI_TEXT.UNREAD_MARK : (item.room && item.room.notes > 0 ? UI_TEXT.NOTES_MARK : null);
        if (mark) marker.textContent = mark;
        else Pixels.setIcons(marker, OPEN_ICON);

        row.appendChild(createGlyph(item.aura.grid));
        row.appendChild(name);
        row.appendChild(code);
        if (item.verified) {
            const verified = document.createElement('span');
            verified.className = 'verified-mark';
            verified.title = UI_TEXT.VERIFIED_TITLE;
            verified.textContent = UI_TEXT.VERIFIED_MARK;
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
    mark.textContent = Errors.message(Errors.CODES.W_ROOM_CANNOT_OPEN);
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
        actions.appendChild(actionButton(UI_TEXT.KEEP, '', offer));
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
    // A phone may cut a long name short (styles.css): its title keeps it whole
    const peerName = document.getElementById('peerName');
    peerName.textContent = room ? roomName(aura) : aura.name;
    peerName.title = peerName.textContent;
    document.getElementById('peerCode').textContent = room ? '' : auraCode(aura);
    document.getElementById('safetyPanel').style.display = 'none';
    document.getElementById('burnConfirm').style.display = 'none';
    hideRoomPanels();
    // A room has members, a code and a member list; a pair has a safety number
    ['roomMeta', 'membersBtn', 'roomCodeBtn'].forEach(id => {
        document.getElementById(id).style.display = room ? ICON_BUTTON_DISPLAY : 'none';
    });
    document.getElementById('verifyBtn').style.display = room ? 'none' : ICON_BUTTON_DISPLAY;
    document.getElementById('peerVerified').style.display = 'none';
    renderBurnButton(room);
    clearChildren(document.getElementById('messageList'));
    setEarlierControl(false, false);
    document.getElementById('homeView').style.display = 'none';
    document.getElementById('chatView').style.display = 'block';
    setConversationShown(true);
}

function setVerifiedState(verified) {
    document.getElementById('peerVerified').style.display = verified ? 'inline' : 'none';
    const button = document.getElementById('markVerifiedBtn');
    button.textContent = verified ? UI_TEXT.VERIFIED_ON : UI_TEXT.VERIFIED_OFF;
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
function senderLabel(from, mine) {
    if (mine) return UI_TEXT.SELF;
    return from ? from.name + auraCode(from) : UI_TEXT.PEER;
}

// A gap in a sender's counter: the server withheld, delayed or deleted their messages
// from: the room sender's aura (absent one-to-one)
function createGapElement(missing, from) {
    const item = document.createElement('li');
    item.className = 'msg-gap';
    const who = senderLabel(from, false);
    // The count comes from the sender's own counter; cap what we repeat back
    item.textContent = missing === 1
        ? Errors.message(Errors.CODES.W_MESSAGE_MISSING, { who })
        : missing <= MAX_GAP_SHOWN ? Errors.message(Errors.CODES.W_MESSAGES_MISSING, { count: missing, who })
            : Errors.message(Errors.CODES.W_MESSAGES_MISSING_UNCOUNTED, { who });
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
function unreadableText(message) {
    return Errors.message(message.newer ? Errors.CODES.W_MESSAGE_FROM_NEWER : Errors.CODES.W_MESSAGE_UNREADABLE);
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
        if (message.disputed) sender.appendChild(disputedTag());
        if (message.left) {
            const left = document.createElement('span');
            left.textContent = UI_TEXT.LEFT_MARK;
            sender.appendChild(left);
        }
        item.appendChild(sender);
    }

    // A file message shows its file (file-card.js) and its caption, if it has one
    if (message.file && !message.broken) item.appendChild(FileCard.create(message));
    if (message.broken || !message.file || message.text !== '') {
        const text = document.createElement('div');
        text.className = 'msg-text';
        text.textContent = message.broken ? unreadableText(message) : neutralizeReceivedText(message.text);
        item.appendChild(text);
    }

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
        empty.textContent = room ? UI_TEXT.EMPTY_ROOM(formatTimeLeft(room.expiresAt)) : UI_TEXT.EMPTY_PAIR(ttlDays);
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
    retry.textContent = UI_TEXT.RETRY;
    retry.addEventListener('click', onRetry);
    item.appendChild(reason);
    item.appendChild(retry);
    list.appendChild(item);
}

function setComposerHint(ttlDays) {
    document.getElementById('composerHint').textContent = UI_TEXT.COMPOSER_HINT(ttlDays);
}

// Messages go with the room, or after the usual retention if that comes first
function setRoomComposerHint(expiresAt, ttlDays) {
    const vanish = Math.min(expiresAt, Date.now() + ttlDays * DAY_MS);
    document.getElementById('composerHint').textContent = UI_TEXT.ROOM_COMPOSER_HINT(formatTimeLeft(vanish));
}

function updateComposerMeta() {
    const input = document.getElementById('messageInput');
    document.getElementById('charCount').textContent = `${[...input.value].length}/${MAX_MESSAGE_CHARS}`;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, COMPOSER_MAX_HEIGHT_PX) + 'px';
}

// ---------- formatting ----------

// A file's size for people: whole bytes below one KiB, else one decimal in the largest unit
const SIZE_STEP = 1024;
const SIZE_UNITS = ['KB', 'MB', 'GB'];

function formatFileSize(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return '';
    if (bytes < SIZE_STEP) return UI_TEXT.BYTES(bytes);
    let value = bytes / SIZE_STEP;
    let unit = 0;
    while (value >= SIZE_STEP && unit < SIZE_UNITS.length - 1) {
        value /= SIZE_STEP;
        unit++;
    }
    return `${value.toFixed(1).replace(/\.0$/, '')} ${SIZE_UNITS[unit]}`;
}

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
    if (left <= 0) return UI_TEXT.NOW;
    const hours = Math.floor(left / HOUR_MS);
    if (hours >= DAYS_SHOWN_FROM_HOURS) return UI_TEXT.IN_DAYS(Math.floor(hours / HOURS_PER_DAY));
    return hoursLeft(hours);
}

function formatExpiry(expiresAtSeconds) {
    const hours = Math.max(0, Math.round((expiresAtSeconds * SECOND_MS - Date.now()) / HOUR_MS));
    return hoursLeft(hours);
}

// Whole hours left as read: "in 5h", or "within the hour" below one
function hoursLeft(hours) {
    return hours >= 1 ? UI_TEXT.IN_HOURS(hours) : UI_TEXT.WITHIN_THE_HOUR;
}

// ---------- rooms ----------
// A room's name comes from its id (the same for every member); people in it have their own
// per-room auras, which link to nothing outside the room.

function roomName(aura) {
    return UI_TEXT.ROOM_NAME_PREFIX + aura.name;
}

function roomMeta(room) {
    return UI_TEXT.ROOM_META(room.members, room.maxMembers, formatTimeLeft(room.expiresAt));
}

const ROOM_PANELS = ['membersPanel', 'notesPanel', 'roomCodePanel'];

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
    renderBurnButton(room);
}

// Burning (a pair, a room's owner) shows the flame; leaving a room shows the door going out
function renderBurnButton(room) {
    const button = document.getElementById('burnBtn');
    const leaving = Boolean(room && !room.owner);
    Pixels.setIcons(button.querySelector('.icon-tile'), leaving ? LEAVE_ICON : BURN_ICON);
    nameIconButton(button, leaving ? UI_TEXT.LEAVE_ROOM_TITLE : (room ? UI_TEXT.BURN_ROOM_TITLE : UI_TEXT.BURN_PAIR_TITLE), burnLabel(room));
}

// What burning asks, and its button: a pair (room null) and a room's owner burn, others leave
function burnQuestion(room) {
    return !room
        ? UI_TEXT.BURN_PAIR_QUESTION
        : room.owner
            ? UI_TEXT.BURN_ROOM_QUESTION
            : UI_TEXT.LEAVE_ROOM_QUESTION;
}

const BURN_ICON = 'burn';
const LEAVE_ICON = 'logout';

function burnLabel(room) {
    return room && !room.owner ? UI_TEXT.LEAVE : UI_TEXT.BURN;
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
        option.textContent = UI_TEXT.MEMBERS_OPTION(n);
        option.selected = n === Math.min(DEFAULT_ROOM_MEMBERS, maxMembers);
        members.appendChild(option);
    }
    const ttl = document.getElementById('roomTtlSelect');
    clearChildren(ttl);
    ttlChoices.forEach(hours => {
        const option = document.createElement('option');
        option.value = String(hours);
        option.textContent = hours === 1 ? UI_TEXT.ONE_HOUR_OPTION
            : hours % HOURS_PER_DAY === 0 ? UI_TEXT.DAYS_OPTION(hours / HOURS_PER_DAY) : UI_TEXT.HOURS_OPTION(hours);
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
    document.getElementById('roomExpiry').textContent = UI_TEXT.ROOM_EXPIRY_UNKNOWN;
    document.getElementById('copyRoomBtn').disabled = false;
    document.getElementById('newRoomBtn').disabled = false;
}

function showRoomCode(code, expiresAt) {
    document.getElementById('roomCodeShown').textContent = code;
    document.getElementById('roomCodeHint').textContent = UI_TEXT.ROOM_CODE_HINT(formatTimeLeft(expiresAt));
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
    tag.textContent = UI_TEXT.MARK(text);
    return tag;
}

function lookalikeTag() {
    const tag = memberTag(Errors.message(Errors.CODES.W_LOOKALIKE_MEMBER));
    tag.classList.add('lookalike-tag');
    return tag;
}

// The tag on a member more than one seat claims (Rooms.disputed), in the panel and on bubbles
function disputedTag() {
    const tag = memberTag(Errors.message(Errors.CODES.W_MEMBER_DISPUTED));
    tag.classList.add('lookalike-tag', 'disputed-tag');
    return tag;
}

// Tags (or untags) every message whose sender's key isMarked(key) says, with the tag makeTag()
// draws (found again by its class tagClass)
function markSenders(isMarked, tagClass, makeTag) {
    document.querySelectorAll('#messageList .msg-sender').forEach(sender => {
        const tag = sender.querySelector('.' + tagClass);
        const marked = isMarked(sender.dataset.sender);
        if (marked && !tag) {
            sender.appendChild(makeTag());
        } else if (!marked && tag) {
            tag.remove();
        }
    });
}

// keys: public keys whose name another key shares; tags (or untags) every message from them
function markLookalikes(keys) {
    markSenders(key => keys.has(key), 'lookalike-tag:not(.disputed-tag):not(.unrecorded-tag)', lookalikeTag);
}

// keys: public keys more than one seat claims; tags (or untags) every message from them
function markDisputed(keys) {
    markSenders(key => keys.has(key), 'disputed-tag', disputedTag);
}

// The tag on each message from a sender the full counter record did not take
function unrecordedTag() {
    const tag = memberTag(Errors.message(Errors.CODES.W_SENDER_NOT_RECORDED));
    tag.classList.add('lookalike-tag', 'unrecorded-tag');
    return tag;
}

// isUnrecorded(key): whether the room's counter record did not take that sender
// (CounterRecords.isUnrecorded); tags (or untags) every message from them
function markUnrecorded(isUnrecorded) {
    markSenders(isUnrecorded, 'unrecorded-tag', unrecordedTag);
}

// entries: verified roster (one entry per key); skipped: cards that failed to open (shown, never
// written to); lookalikes: public keys whose name another key shares; disputed(entry),
// mayBefriend(entry), roleShown(entry): rooms.js's judgements, the one home of each;
// roleControl(entry): the role control for that entry, or null where this account may not
// change its role (RoleControl.control)
function renderMembers({ entries, skipped, requested, lookalikes, disputed, mayBefriend, roleShown, onBefriend, roleControl }) {
    const list = document.getElementById('memberList');
    clearChildren(list);
    entries.forEach(entry => {
        const row = memberRow(entry);
        const role = RoleControl.tag(roleShown(entry));
        if (role) row.appendChild(role);
        if (entry.mine) row.appendChild(memberTag(UI_TEXT.YOU_TAG));
        if (entry.owner) row.appendChild(memberTag(UI_TEXT.OWNER_TAG));
        if (disputed(entry)) row.appendChild(disputedTag());
        if (lookalikes.has(entry.publicKey)) row.appendChild(lookalikeTag());
        const control = roleControl(entry);
        if (control) row.appendChild(control);
        if (mayBefriend(entry)) {
            const button = document.createElement('button');
            button.className = 'menu-opt member-action';
            const asked = requested.has(entry.publicKey);
            button.textContent = asked ? UI_TEXT.REQUEST_SENT : UI_TEXT.BEFRIEND;
            button.disabled = asked;
            button.title = UI_TEXT.BEFRIEND_TITLE;
            button.addEventListener('click', () => onBefriend(entry));
            row.appendChild(button);
        }
        list.appendChild(row);
    });
    if (skipped > 0) {
        const row = document.createElement('li');
        row.className = 'member-item member-broken';
        row.textContent = skipped === 1
            ? Errors.message(Errors.CODES.W_MEMBER_CARD_UNVERIFIED)
            : Errors.message(Errors.CODES.W_MEMBER_CARDS_UNVERIFIED, { count: skipped });
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

// The code of what a friend request that cannot be accepted says instead (null: it can be
// accepted): one a newer elyrn wrote, or one sent before binders (Rooms.notes). The panel shows
// it and chat.js's accept refuses with it.
function noteRefusal(note) {
    if (note.newer) return Errors.CODES.W_MESSAGE_FROM_NEWER;
    if (!note.binder) return Errors.CODES.W_FRIEND_REQUEST_OUTDATED;
    return null;
}

// notes: [{ id, aura, from, binder, newer }] friend requests addressed to this member; one that
// cannot be accepted (noteRefusal) says why and offers ignore only
function renderNotes(notes, onAccept, onIgnore) {
    const panel = document.getElementById('notesPanel');
    const list = document.getElementById('noteList');
    clearChildren(list);
    panel.style.display = notes.length > 0 ? 'block' : 'none';
    notes.forEach(note => {
        const row = memberRow({ aura: note.aura });
        row.appendChild(memberTag(note.from ? UI_TEXT.WANTS_FRIENDS : UI_TEXT.LEFT_WANTS_FRIENDS));
        const refusal = noteRefusal(note);
        if (refusal) {
            const reason = memberTag(Errors.message(refusal));
            reason.classList.add('lookalike-tag');
            row.appendChild(reason);
        } else {
            const accept = document.createElement('button');
            accept.className = 'menu-opt member-action';
            accept.textContent = UI_TEXT.ACCEPT;
            accept.addEventListener('click', () => onAccept(note));
            row.appendChild(accept);
        }
        const ignore = document.createElement('button');
        ignore.className = 'menu-opt';
        ignore.textContent = UI_TEXT.IGNORE;
        ignore.addEventListener('click', () => onIgnore(note));
        row.appendChild(ignore);
        list.appendChild(row);
    });
}
