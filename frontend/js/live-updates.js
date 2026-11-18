// ========================================
// LIVE UPDATES (the event stream, and polling while it is silent)
// ========================================
// One job: tells the chat (chat.js) when the server may hold something new for this page, through
// the event stream while it delivers, by polling while it is silent (a proxy buffering or holding
// it). What is new, and fetching it, stays with the chat: it hands in its hooks once (create).

const LiveUpdates = (() => {
    'use strict';

    const MAX_RECONNECT_ATTEMPTS = 8;
    const RECONNECT_BASE_MS = 1000;
    const RECONNECT_MAX_MS = 30000;
    // The server sends a named heartbeat right after a stream opens (backend handlers/events.go):
    // a (re)connected stream that has not shown it this long is not delivering (a proxy buffers
    // or holds it), and the page polls instead of waiting longer
    const STREAM_FIRST_PROOF_MS = 5 * SECOND_MS;
    // ...and one every 10 s after (sseKeepAlive): a stream that proved itself and then went silent
    // for two of them and some slack has stopped delivering
    const STREAM_SILENCE_LIMIT_MS = 25 * SECOND_MS;
    // How often the watchdog looks, and so how often a silent stream's page fetches its updates:
    // at most 5 requests per poll per visible tab (1 when no conversation is open), so 4 visible
    // tabs stay at 4 r/s, inside nginx's 20 r/s with burst 40 per client
    const POLL_INTERVAL_MS = 5 * SECOND_MS;
    // A hidden page behind a silent stream polls too, this much less often: it is not being read
    // (nothing is marked read while hidden), it only has to learn that something arrived
    const HIDDEN_POLL_INTERVAL_MS = 30 * SECOND_MS;
    // Every named event the stream sends; any one of them proves it is delivering
    const STREAM_EVENTS = Object.freeze(['ping', 'msg', 'conv']);

    // hooks: { api (the chat's, which ends the session on a 401), loggedIn(), catchUp() (fetches
    // what the stream would have poked; resolves once the open conversation's sync settled),
    // onMessage(conversationId), onConversations() }
    function create(hooks) {
        let events = null;
        let reconnectAttempts = 0;
        let reconnectTimer = null;
        let pollTimer = null;             // the watchdog's next look (watchStream), from start to stop
        let lastStreamEventAt = 0;        // performance.now() of the last stream event, or of the last (re)connect
        let streamLimitMs = STREAM_FIRST_PROOF_MS;  // the silence allowed since then: first proof, or the heartbeat limit
        let polling = false;              // the watchdog is fetching for a silent stream (logged once per silence)
        let lastPollAt = -Infinity;       // performance.now() of the watchdog's last poll (none yet: due)
        let outageShown = false;          // a fetch failed while polling and was shown: polls stay quiet until one succeeds

        function start() {
            connectEvents();
            armWatchdog();
        }

        function stop() {
            closeEvents();
            clearTimeout(pollTimer);
            polling = false;
            lastPollAt = -Infinity;
            outageShown = false;
        }

        // A fetch succeeded: the outage reportFetchFailure keeps quiet about, if any, is over
        function endOutage() {
            outageShown = false;
        }

        // ---------- realtime ----------

        function closeEvents() {
            clearTimeout(reconnectTimer);
            if (events) {
                events.close();
                events = null;
            }
        }

        function connectEvents() {
            closeEvents();
            if (!hooks.loggedIn()) return;
            // The new stream has STREAM_FIRST_PROOF_MS to show its first heartbeat before the watchdog
            // polls (also while it backs off and reconnects: the page is not left waiting)
            lastStreamEventAt = performance.now();
            streamLimitMs = STREAM_FIRST_PROOF_MS;
            events = new EventSource(`${API_BASE_URL}/events`);
            // 'open' proves nothing: a buffering proxy sends the headers and holds every event after
            // them, and a proxy that opens and drops would otherwise reconnect forever. It catches up
            // (resync); only an event that arrived proves the stream (noteStreamEvent).
            events.addEventListener('open', () => resync());
            STREAM_EVENTS.forEach(kind => events.addEventListener(kind, noteStreamEvent));
            events.addEventListener('msg', onMessageEvent);
            events.addEventListener('conv', hooks.onConversations);
            // Never rely on the browser's built-in retry (fixed interval, unlimited attempts):
            // every drop goes through our bounded exponential backoff (RULES.md §17.1)
            events.onerror = () => {
                scheduleReconnect();
            };
        }

        function scheduleReconnect() {
            closeEvents();
            if (!hooks.loggedIn()) return;
            const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** reconnectAttempts);
            if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                // Nothing to show: the watchdog keeps fetching (no stream event can arrive now; less
                // often while the tab is hidden), and showing the tab again retries the stream (onVisible)
                Log.warn(Errors.INTERNAL.W_LIVE_STREAM_GAVE_UP);
                return;
            }
            reconnectAttempts++;
            reconnectTimer = setTimeout(reconnect, delay);
        }

        // Only reconnect while the session is still valid (a 401 ends the session instead)
        async function reconnect() {
            if (!hooks.loggedIn()) return;
            const check = await hooks.api('GET', '/me');
            if (!hooks.loggedIn() || check.status === 401) return;
            if (!check.ok) {
                scheduleReconnect();
                return;
            }
            connectEvents();
        }

        function onMessageEvent(event) {
            let data;
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                // An event that is no JSON names no conversation: dropped unlogged like one of the
                // wrong shape just below (the server could fill the console with them); the next
                // event, poll or list refresh still catches up
                return;
            }
            if (!data || Object.keys(data).length !== 1 || !validateConversationId(data.c)) return;
            hooks.onMessage(data.c);
        }

        // fromPoll: the watchdog asked, so a failure already shown in this outage stays quiet
        // (reportFetchFailure); any other resync shows its failure again, as it always did.
        function resync(fromPoll = false) {
            if (!hooks.loggedIn()) return Promise.resolve();
            if (!fromPoll) outageShown = false;
            return hooks.catchUp();
        }

        // ---------- watchdog: polling while the stream is silent ----------

        // Any stream event proves the stream delivers: the watchdog stops polling, the stream's next
        // silence may last the heartbeat limit, and the reconnect backoff starts again from the bottom
        function noteStreamEvent() {
            lastStreamEventAt = performance.now();
            streamLimitMs = STREAM_SILENCE_LIMIT_MS;
            polling = false;
            reconnectAttempts = 0;
        }

        // A fetch failure the watchdog would repeat on every poll while the server is down: shown once
        // per outage while polling (outageShown, cleared by the next fetch that succeeds or by any
        // resync not from a poll), logged every time. Outside polling it is shown every time.
        function reportFetchFailure(code, cause) {
            if (polling && outageShown) {
                Log.warn(code, cause);
                return;
            }
            if (polling) outageShown = true;
            Errors.report(code, null, cause);
        }

        // The one owner of pollTimer: at most one look is pending, from start() until stop()
        function armWatchdog() {
            clearTimeout(pollTimer);
            if (!hooks.loggedIn()) return;
            pollTimer = setTimeout(watchStream, POLL_INTERVAL_MS);
        }

        // One look: a page whose stream proved nothing within its limit fetches what the stream would
        // have poked (resync, an authenticated request, which also keeps the session sliding), then
        // looks again. It keeps fetching until a stream event arrives: at every look while visible,
        // every HIDDEN_POLL_INTERVAL_MS while hidden (streamNeedsPolling).
        async function watchStream() {
            const now = performance.now();
            if (streamNeedsPolling({
                now: now, lastEventAt: lastStreamEventAt, silenceLimitMs: streamLimitMs, visible: isPageVisible(),
                loggedIn: hooks.loggedIn(), lastPollAt: lastPollAt, hiddenIntervalMs: HIDDEN_POLL_INTERVAL_MS
            })) {
                if (!polling) Log.warn(Errors.INTERNAL.W_LIVE_STREAM_SILENT);
                polling = true;
                lastPollAt = now;
                await resync(true);
            }
            armWatchdog();
        }

        // The page came back from the back-forward cache: the session may have ended meanwhile. A 401
        // ends it here as anywhere (sessionLost); a live one reconnects its event stream.
        async function onRestored() {
            if (!hooks.loggedIn()) return;
            // The look pending when the page was frozen is restarted from now
            armWatchdog();
            const check = await hooks.api('GET', '/me');
            if (!hooks.loggedIn() || check.status === 401) return;
            if (!check.ok) {
                scheduleReconnect();
                return;
            }
            reconnectAttempts = 0;
            connectEvents();
        }

        function onVisible() {
            if (!hooks.loggedIn() || !isPageVisible()) return;
            if (!events) {
                reconnectAttempts = 0;
                connectEvents();
            } else {
                resync();
            }
        }

        return Object.freeze({ start, stop, endOutage, reportFetchFailure, onRestored, onVisible });
    }

    return Object.freeze({ create });
})();
