// ========================================
// MAIN APPLICATION INITIALIZATION
// ========================================

// Check if current URL is a valid frontend route
function isValidFrontendRoute() {
    const path = window.location.pathname;

    // Allow root path
    if (path === '/' || path === '') {
        return true;
    }

    // Reject any other path (including /api/*): nginx serves this app at / only, and the
    // status page (STATUS_PAGES.NOT_FOUND) is static HTML that never loads this script
    return false;
}

// Resume a session: needs both the stored (non-extractable) identity key and a live cookie.
// Only a 401 or a /me naming another public key ends it (auth.js meVerdict): a server that cannot
// be reached, is busy (429), answers 404 or any other refusal logs nobody out: the identity stays
// stored and a retry is offered, with the code for that answer. A stored identity this browser
// cannot read back opens the main menu saying so (W_IDENTITY_UNREADABLE): logging in once
// restores everything.
async function resumeSession() {
    const stored = await Keystore.load();
    const identity = stored.identity;
    if (!identity) {
        showMainMenu();
        if (stored.unreadable) Errors.report(Errors.CODES.W_IDENTITY_UNREADABLE);
        return;
    }
    const opened = await enterApp(identity, false);
    if (opened.entry === ENTRY.UNREACHABLE) {
        showMainMenu();
        showResumeFailure(opened.code, opened.result);
    } else if (opened.entry === ENTRY.REFUSED) {
        showMainMenu();
    }
}

function retryResume() {
    return once('resume', retryResumeNow);
}

async function retryResumeNow() {
    const button = document.getElementById('retryResumeBtn');
    button.disabled = true;
    clearResumeFailure();
    try {
        await resumeSession();
    } finally {
        button.disabled = false;
    }
}

// Anything thrown and not caught anywhere else: reported under one code. The log keeps only the
// error's name (Log never takes a message, which could carry what the user typed).
window.addEventListener('error', event => {
    Errors.report(Errors.CODES.E_UNEXPECTED, null, event.error);
});
window.addEventListener('unhandledrejection', event => {
    Errors.report(Errors.CODES.E_UNEXPECTED, null, event.reason);
});

// Initialize event listeners when DOM is ready. The page opens on the start view (the brand line
// alone) and boot leaves it for the main menu or the app; whatever boot throws, the page still
// fails open to the main menu, and the throw itself is reported (unhandledrejection above).
document.addEventListener('DOMContentLoaded', async function() {
    try {
        await boot();
    } finally {
        leaveStartView();
    }
});

async function boot() {
    // Check if current URL is valid for frontend
    if (!isValidFrontendRoute()) {
        // Redirect to 404 page for invalid routes
        window.location.replace(STATUS_PAGES.NOT_FOUND);
        return;
    }

    setupEventListeners();

    // WebCrypto X25519 + secure context are hard requirements (no JS crypto fallbacks)
    if (!window.isSecureContext || !(await ElyrnCrypto.isSupported())) {
        showMainMenu();
        Errors.inline(document.getElementById('unsupportedNotice'), Errors.CODES.E_BROWSER_UNSUPPORTED);
        document.getElementById('showLoginBtn').disabled = true;
        document.getElementById('showRegisterFormBtn').disabled = true;
        // The robot entrance needs no crypto here, so it stays usable
        return;
    }

    await resumeSession();
}

// Wires every control once, area by area, in the page's order
function setupEventListeners() {
    setupMenuListeners();
    setupPreLoginExits();
    setupLoginListeners();
    setupRegisterListeners();
    setupAccountListeners();
    setupPairingListeners();
    setupRoomListeners();
    setupConversationListeners();
    setupComposerListeners();
    setupGlobalListeners();
}

// A click handler that copies the text shown in sourceId and confirms with notice; accepts
// (optional) rejects text that is not yet the real value; clearLater clears a secret from the
// clipboard afterwards (copyWithNotice). One copy per button at a time.
function copyShownText(sourceId, notice, accepts, clearLater) {
    return () => once('copy-' + sourceId, async () => {
        const text = document.getElementById(sourceId).textContent;
        if (!text || (accepts && !accepts(text))) return;
        await copyWithNotice(text, notice, Boolean(clearLater));
    });
}

// The robot door: a person is told so and shown the way back; anything else gets the challenge.
// Theatre only (js/robot-door.js): the robot entrance behind it is public either way.
function pressRobotDoor(event) {
    const judged = judgeDoorPress(event);
    if (judged.human) {
        showDoorVerdict(RobotDoor.verdictLine(judged), RobotDoor.measurementLines(judged.measurements));
    } else {
        showDoorChallenge();
    }
}

// Checked here, in this page: nothing is sent. Wrong or malformed is a person; right is a robot.
function answerDoorChallenge() {
    return once('door', answerDoorChallengeNow);
}

async function answerDoorChallengeNow() {
    const button = document.getElementById('doorAnswerBtn');
    button.disabled = true;
    try {
        const right = await RobotDoor.checkAnswer(
            document.getElementById('doorNonce').textContent,
            document.getElementById('doorAnswerInput').value);
        if (right) {
            showRobot(RobotDoor.MODE.ROBOT);
        } else {
            showDoorVerdict(RobotDoor.LINES.WRONG, []);
        }
    } catch (e) {
        Errors.report(Errors.CODES.W_DOOR_CHECK_UNAVAILABLE, null, e);
        showRobot(RobotDoor.MODE.ROBOT);
    } finally {
        button.disabled = false;
    }
}

// The two door screens in front of the robot entrance
function setupDoorListeners() {
    document.getElementById('showRobotBtn').addEventListener('click', pressRobotDoor);
    document.getElementById('humanDoorBtn').addEventListener('click', showMainMenu);
    document.getElementById('operatorDoorBtn').addEventListener('click', () => showRobot(RobotDoor.MODE.OPERATOR));
    document.getElementById('doorHumanBtn').addEventListener('click', () => showDoorVerdict(RobotDoor.LINES.HONEST, []));
    document.getElementById('doorAnswerBtn').addEventListener('click', answerDoorChallenge);
    document.getElementById('doorAnswerInput').addEventListener('keydown', (e) => {
        // The Enter is consumed here, so it cannot reach whatever is focused once the check settles
        if (e.key !== 'Enter') return;
        e.preventDefault();
        answerDoorChallenge();
    });
    ['verdictBrandTitle', 'challengeBrandTitle', 'robotBrandTitle'].forEach(id => {
        document.getElementById(id).addEventListener('click', showMainMenu);
    });
}

// Main menu, the robot entrance, and the brand titles that lead back to the menu
function setupMenuListeners() {
    document.getElementById('showLoginBtn').addEventListener('click', showLogin);
    document.getElementById('showRegisterFormBtn').addEventListener('click', showRegisterForm);
    setupDoorListeners();
    document.getElementById('backToMenuFromRobot').addEventListener('click', showMainMenu);
    document.getElementById('copyRobotBtn').addEventListener('click', copyShownText('robotCommand', Errors.NOTICE.COMMAND_COPIED));
    document.getElementById('retryResumeBtn').addEventListener('click', retryResume);
}

// The pre-login screens' way back, as on the robot side: a "← back to main menu" button and the
// brand title (Escape: setupGlobalListeners). Leaving login drops the typed number; leaving
// registration ends it (and asks first where the account may already exist).
function setupPreLoginExits() {
    [['backToMenuFromLogin', leaveLogin], ['loginBrandTitle', leaveLogin],
        ['cancelRegistration', cancelRegistration], ['registerBrandTitle', cancelRegistration]].forEach(([id, leave]) => {
        document.getElementById(id).addEventListener('click', leave);
    });
}

// Login page
function setupLoginListeners() {
    document.getElementById('loginBtn').addEventListener('click', login);
    document.getElementById('accountNumberInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') login();
    });
}

// Register page
function setupRegisterListeners() {
    document.getElementById('copyBtn').addEventListener('click', copyAccountNumber);
    document.getElementById('continueBtn').addEventListener('click', continueWithAccountNumber);
}

const IDENTITY_PANEL = 'identityPanel';
const IDENTITY_BADGE = 'meBadge';

function isChatShown() {
    return document.getElementById('chatView').style.display !== 'none';
}

// The identity badge opens the identity panel on the home view (from a conversation it goes home
// first, open); a second press closes it
function toggleIdentityPanel() {
    if (isChatShown()) {
        Chat.backToList();
        showPairPanel(IDENTITY_PANEL);
        return;
    }
    togglePairPanel(IDENTITY_PANEL);
}

// Escape closes the identity panel and gives focus back to the badge that opened it
function closeIdentityPanel() {
    togglePairPanel(null);
    document.getElementById(IDENTITY_BADGE).focus();
}

// App header: the identity badge (its panel holds deleting the identity), alerts and logging out
function setupAccountListeners() {
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('alertsBtn').addEventListener('click', Alerts.toggle);
    document.getElementById(IDENTITY_BADGE).addEventListener('click', toggleIdentityPanel);
    document.getElementById('deleteIdentityBtn').addEventListener('click', () => {
        showPairPanel('deletePanel');
        document.getElementById('deleteAccountInput').focus();
    });
    document.getElementById('closeDeleteBtn').addEventListener('click', () => {
        document.getElementById('deleteAccountInput').value = '';
        togglePairPanel(null);
    });
    document.getElementById('deleteConfirmBtn').addEventListener('click', deleteIdentity);
    document.getElementById('deleteAccountInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') deleteIdentity();
    });
}

// Invites: making one, copying it, and joining with one (or with a room code)
function setupPairingListeners() {
    document.getElementById('newInviteBtn').addEventListener('click', () => Chat.createInvite());
    document.getElementById('showJoinBtn').addEventListener('click', () => {
        togglePairPanel('joinPanel');
        document.getElementById('inviteInput').focus();
    });
    document.getElementById('closeJoinBtn').addEventListener('click', () => togglePairPanel(null));
    document.getElementById('copyInviteBtn').addEventListener('click', copyShownText('inviteCode', Errors.NOTICE.INVITE_COPIED,
        null, true));
    document.getElementById('joinBtn').addEventListener('click', () => Chat.join());
}

// Rooms: creating one, copying its code, and the open room's members and code panels
function setupRoomListeners() {
    document.getElementById('newRoomBtn').addEventListener('click', () => {
        resetRoomPanel();
        togglePairPanel('roomPanel');
    });
    document.getElementById('closeRoomBtn').addEventListener('click', () => resetRoomPanel());
    document.getElementById('createRoomBtn').addEventListener('click', () => Chat.createRoom());
    document.getElementById('copyRoomBtn').addEventListener('click', copyShownText('roomCode', Errors.NOTICE.ROOM_CODE_COPIED,
        code => code.startsWith(ElyrnRoomCrypto.CODE_PREFIX), true));
    document.getElementById('membersBtn').addEventListener('click', () => Chat.toggleMembers());
    document.getElementById('roomCodeBtn').addEventListener('click', () => Chat.toggleRoomCode());
    document.getElementById('copyRoomCodeBtn').addEventListener('click', () => Chat.copyRoomCode());
    // The join field takes a room code as well as an invite
    document.getElementById('inviteInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') Chat.join();
    });
}

// The open conversation's header: back, safety number, verification and burning
function setupConversationListeners() {
    document.getElementById('backToListBtn').addEventListener('click', () => Chat.backToList());
    document.getElementById('verifyBtn').addEventListener('click', () => Chat.showSafety());
    document.getElementById('markVerifiedBtn').addEventListener('click', () => Chat.toggleVerified());
    document.getElementById('burnBtn').addEventListener('click', () => Chat.askBurn(true));
    document.getElementById('burnNoBtn').addEventListener('click', () => Chat.askBurn(false));
    document.getElementById('burnYesBtn').addEventListener('click', () => Chat.burn());
    document.getElementById('sendBtn').addEventListener('click', () => Chat.send());
    document.getElementById('earlierBtn').addEventListener('click', () => Chat.earlier());
}

// Composer: Enter to send, Shift+Enter for a new line
function setupComposerListeners() {
    // A file chosen, pasted or dropped on the open conversation (file-composer.js)
    FileComposer.install();
    const messageInput = document.getElementById('messageInput');
    messageInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
            e.preventDefault();
            Chat.send();
        }
    });
    messageInput.addEventListener('input', updateComposerMeta);
}

// Keys and page events that apply whatever is on screen
function setupGlobalListeners() {
    // Escape leaves a conversation, the robot side (its doors and the robot entrance), a
    // pre-login screen (the same way as its back button), or the identity panel
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape' || e.isComposing) return;
        if (isRobotSide()) {
            showMainMenu();
        } else if (isShown('loginContainer')) {
            leaveLogin();
        } else if (isShown('registerContainer')) {
            cancelRegistration();
        } else if (isChatShown()) {
            Chat.backToList();
        } else if (isShown(IDENTITY_PANEL)) {
            closeIdentityPanel();
        }
    });

    // Catch up after the tab was hidden or the machine slept; a content-free alert is done with
    document.addEventListener('visibilitychange', () => {
        Alerts.onVisible();
        Chat.onVisible();
    });

    // Back from the back-forward cache: the session is checked again before anything is trusted
    window.addEventListener('pageshow', event => {
        if (event.persisted) Chat.onRestored();
    });

    // What the user copies or cuts here replaces what the page copied (clearClipboardIfHolds)
    document.addEventListener('copy', noteUserCopy);
    document.addEventListener('cut', noteUserCopy);
}
