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

    // Allow status pages (UUID HTML files) - these are handled by nginx
    const statusPagePattern = /^\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.html$/i;
    if (statusPagePattern.test(path)) {
        return true;
    }

    // Reject any other paths (including /api/*) - they don't exist in this SPA
    return false;
}

// Resume a session: needs both the stored (non-extractable) identity key and a live cookie
async function resumeSession() {
    const identity = await Keystore.load();
    if (!identity) {
        showMainMenu();
        return;
    }
    if (!(await enterApp(identity, false))) {
        showMainMenu();
    }
}

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', async function() {
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
        document.getElementById('unsupportedNotice').textContent =
            'this browser cannot run elyrn. securely (needs https and WebCrypto X25519). update your browser.';
        document.getElementById('showLoginBtn').disabled = true;
        document.getElementById('showRegisterFormBtn').disabled = true;
        // The robot entrance needs no crypto here, so it stays usable
        return;
    }

    await resumeSession();
});

// Wires every control once, area by area, in the page's order
function setupEventListeners() {
    setupMenuListeners();
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
// (optional) rejects text that is not yet the real value
function copyShownText(sourceId, notice, accepts) {
    return async () => {
        const text = document.getElementById(sourceId).textContent;
        if (!text || (accepts && !accepts(text))) return;
        try {
            await copyToClipboard(text);
            showSuccess(notice);
        } catch (e) {
            Errors.report(Errors.CODES.W_COPY_MANUALLY);
        }
    };
}

// Main menu, the robot entrance, and the brand titles that lead back to the menu
function setupMenuListeners() {
    document.getElementById('showLoginBtn').addEventListener('click', showLogin);
    document.getElementById('showRegisterFormBtn').addEventListener('click', showRegisterForm);
    document.getElementById('backToMenuFromLogin').addEventListener('click', showMainMenu);
    document.getElementById('showRobotBtn').addEventListener('click', showRobot);
    document.getElementById('backToMenuFromRobot').addEventListener('click', showMainMenu);
    document.getElementById('robotBrandTitle').addEventListener('click', showMainMenu);
    document.getElementById('copyRobotBtn').addEventListener('click', copyShownText('robotCommand', 'command copied'));

    // Brand title click - go back to main menu
    const loginBrandTitle = document.getElementById('loginBrandTitle');
    const registerBrandTitle = document.getElementById('registerBrandTitle');
    if (loginBrandTitle) {
        loginBrandTitle.addEventListener('click', showMainMenu);
    }
    if (registerBrandTitle) {
        registerBrandTitle.addEventListener('click', function() {
            // Cancel any pending registration first
            cancelRegistration();
        });
    }
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
    document.getElementById('cancelRegistration').addEventListener('click', cancelRegistration);
}

// App header: logging out and deleting the identity
function setupAccountListeners() {
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('deleteIdentityBtn').addEventListener('click', () => {
        Chat.backToList();
        togglePairPanel('deletePanel');
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
    document.getElementById('copyInviteBtn').addEventListener('click', copyShownText('inviteCode', Errors.NOTICE.INVITE_COPIED));
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
        code => code.startsWith(ElyrnRoomCrypto.CODE_PREFIX)));
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
}

// Composer: Enter to send, Shift+Enter for a new line
function setupComposerListeners() {
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
    // Escape leaves a conversation, or the robot entrance
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape') return;
        if (document.getElementById('robotContainer').style.display !== 'none') {
            showMainMenu();
        } else if (document.getElementById('chatView').style.display !== 'none') {
            Chat.backToList();
        }
    });

    // Catch up after the tab was hidden or the machine slept
    document.addEventListener('visibilitychange', () => Chat.onVisible());
}
