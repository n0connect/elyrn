// ========================================
// ALERTS (the browser's own notification, without content)
// ========================================
// One job: tell the user that something arrived while this page is not being looked at. The
// page raises the browser's notification itself: no service worker, no push service, no
// request of any kind, so it works only while elyrn. is open in some tab and nothing leaves the
// device. The text is fixed and says nothing (never a sender, a room, a count or any content):
// whoever sees the screen learns only that elyrn. got a message.
//
// Off by default; the bell in the account header turns it on (asking the browser's
// permission inside that click) and the choice is kept on this device with the identity
// (Keystore.loadAlerts / saveAlerts; every wipe of the identity forgets it). One notification at
// a time under a fixed tag, and none again until the page was visible; clicking it focuses the
// tab, and the page becoming visible closes it. A browser without the Notification API never
// shows the control. In-page toasts are notifications.js, not this.

const Alerts = (() => {
    'use strict';

    // The only words a notification ever carries
    const TITLE = 'elyrn.';
    const BODY = 'new message';
    // Replaced, never stacked: every tab and every raise share it
    const TAG = 'elyrn-new-message';
    const CONTROL_ID = 'alertsBtn';
    // The control is a pixel bell (index.html): its two shapes follow aria-pressed in styles.css,
    // its words (name and title) are UI_TEXT's
    const CONTROL_DISPLAY = 'inline-flex';
    // Notification.permission's answers
    const GRANTED = 'granted';
    const DENIED = 'denied';
    const ASK = 'default';

    let session = false;    // between start() and stop(): a logged-in page
    let on = false;         // the user turned alerts on, and the browser allows them
    let raised = false;     // one was raised since the page was last visible
    let shown = null;       // the notification on screen, if any

    function supported() {
        return typeof window.Notification === 'function' && typeof window.Notification.requestPermission === 'function';
    }

    function control() {
        return document.getElementById(CONTROL_ID);
    }

    // What the control shows for a state (the pure part of render, tested on its own): hidden
    // outside a session or without the API; pressed, named and titled by whether alerts are on
    function controlState({ session, supported, on }) {
        const pressed = on === true;
        const name = pressed ? UI_TEXT.ALERTS_ON : UI_TEXT.ALERTS_OFF;
        return Object.freeze({
            shown: session === true && supported === true,
            pressed: pressed ? 'true' : 'false',
            name,
            title: UI_TEXT.ALERTS_TITLE(name)
        });
    }

    function render() {
        const button = control();
        const state = controlState({ session, supported: supported(), on });
        button.style.display = state.shown ? CONTROL_DISPLAY : 'none';
        button.setAttribute('aria-pressed', state.pressed);
        button.setAttribute('aria-label', state.name);
        button.title = state.title;
    }

    // Whether a raise now shows a notification (the pure part of raise, tested on its own)
    function due({ session, on, raised, visible, permission }) {
        return session === true && on === true && raised !== true && visible !== true && permission === GRANTED;
    }

    // A logged-in page: the control appears (where the API exists) showing the kept choice. A
    // choice kept from before that the browser no longer allows is turned off and said why.
    async function start() {
        session = true;
        on = false;
        raised = false;
        if (!supported()) {
            Log.warn(Errors.INTERNAL.W_ALERTS_UNSUPPORTED);
            render();
            return;
        }
        const kept = await Keystore.loadAlerts();
        if (!session) return;
        if (kept && window.Notification.permission !== GRANTED) {
            await revoked();
            return;
        }
        on = kept;
        render();
    }

    function stop() {
        session = false;
        on = false;
        raised = false;
        close();
        render();
    }

    function close() {
        if (shown) shown.close();
        shown = null;
    }

    // The browser withdrew its permission: alerts go off here and in storage, and the user is told
    async function revoked() {
        on = false;
        render();
        Errors.report(Errors.CODES.W_ALERTS_REVOKED);
        await Keystore.saveAlerts(false);
    }

    // The control: one change at a time (a double click asks once)
    function toggle() {
        return once(CONTROL_ID, toggleNow);
    }

    async function toggleNow() {
        if (!session || !supported()) return;
        if (on) {
            await choose(false);
            return;
        }
        let permission = window.Notification.permission;
        if (permission === ASK) {
            // Asked inside the click (no await before this point): browsers refuse it otherwise
            try {
                permission = await askPermission();
            } catch (error) {
                Errors.report(Errors.CODES.E_ALERTS_UNAVAILABLE, null, error);
                return;
            }
        }
        if (permission !== GRANTED) {
            Errors.report(permission === DENIED ? Errors.CODES.W_ALERTS_DENIED : Errors.CODES.W_ALERTS_NOT_ALLOWED);
            return;
        }
        await choose(true);
    }

    // Notification.requestPermission answers by promise, or (older Safari) only by callback
    function askPermission() {
        return new Promise((resolve, reject) => {
            const answer = window.Notification.requestPermission(resolve);
            if (answer && typeof answer.then === 'function') answer.then(resolve, reject);
        });
    }

    async function choose(value) {
        on = value;
        if (!on) close();
        render();
        // A storage failure is told by Keystore once; the choice still holds for this page
        await Keystore.saveAlerts(value);
    }

    // Something arrived (a live msg event, or a poll that found a newer message while hidden)
    function raise() {
        if (!supported()) return;
        const permission = window.Notification.permission;
        if (session && on && permission !== GRANTED) {
            revoked();
            return;
        }
        if (!due({ session, on, raised, visible: isPageVisible(), permission })) return;
        raised = true;
        try {
            const notification = new window.Notification(TITLE, { body: BODY, tag: TAG });
            notification.onclick = () => {
                window.focus();
                notification.close();
            };
            shown = notification;
        } catch (error) {
            // A browser that has the API and refuses to show one from a page (some need a
            // service worker): logged, and not tried again until the page was visible
            Log.warn(Errors.INTERNAL.W_ALERT_NOT_SHOWN, error);
        }
    }

    // The page is seen: what the notification said is known now
    function onVisible() {
        if (!isPageVisible()) return;
        raised = false;
        close();
    }

    return Object.freeze({ TITLE, BODY, TAG, start, stop, toggle, raise, onVisible, due, controlState });
})();
