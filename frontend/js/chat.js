// ========================================
// CHAT (conversations, messages, pairing and rooms)
// ========================================
// The server is treated as an untrusted relay: every response is shape-checked,
// every message is authenticated by AES-GCM + AAD, peer keys from invites are
// verified against the fingerprint embedded in the invite code, and each sender's
// encrypted message counter exposes messages the server withheld, replayed or reordered,
// across reloads too (counters.js; the record this device keeps lives in Keystore).
// Rooms (rooms.js) are conversations too: a room conversation carries `room` and no peer key.

const Chat = (() => {
    'use strict';

    const MAX_CIPHERTEXT_CHARS = 11000;
    // A roster can change between fetching it and sending (412): fetch, re-encrypt, retry, bounded
    const MAX_ROSTER_RETRIES = 2;
    // Live events arrive in bursts: one list refresh per burst, this long after its last event
    const REFRESH_DEBOUNCE_MS = 250;
    // How far the server lets a new room's expiry stray from its own clock (backend chat
    // expirySkew): a device clock further off than this explains a refused room
    const SERVER_CLOCK_SKEW_MS = 10 * 60 * SECOND_MS;
    // The page title, prefixed by the unread count when there is one
    const APP_TITLE = 'elyrn.';

    let me = null;                    // { privateKey, publicKey, roomsRoot, aura, ttlDays, limits }
    const conversations = new Map();  // id -> conversation state
    let order = [];                   // server order: newest conversation first
    let recent = [];                  // ids with activity this session, most recent first (memory only)
    let activeId = null;
    let refreshTimer = null;
    let listLoaded = false;           // distinguishes the first load from live additions
    let inviteRun = null;             // { stopScramble } while an invite is paid for and revealed
    let unsent = null;                // a send whose answer never came: { convId, text, id, counter, ciphertext }
    let roomRun = null;               // { stopScramble } while a room is paid for and revealed
    const drafts = new Map();         // id -> composer text typed for it and not sent (memory only, never stored)
    const unverified = new Map();     // id -> { id, aura, owner }: listed rooms that failed verification
    const reportedRooms = new Set();  // ids of rooms whose failed verification was reported (once each)
    // id -> the last counter record of a conversation dropped from this session but not burned by
    // the user (a listing omitted it, a 404): it judges again if the server lists it again, also
    // when storage failed (counters.js KEEPING RECORDS)
    const parked = new Map();
    let evictionWarned = false;       // W_COUNTER_RECORDS_EVICTED is logged once per page load
    // Raised by every local change to the set of conversations (a join, a burn, a leave, the end
    // of the session): a list fetched before it is stale and is never applied (refreshNow)
    let listGeneration = 0;
    // The event stream and the watchdog behind it (live-updates.js): they say when to catch up
    const live = LiveUpdates.create({
        api, loggedIn: () => me !== null, catchUp, onMessage: messageArrived, onConversations: scheduleRefresh
    });

    // ---------- plumbing ----------

    async function api(method, path, body) {
        const result = await apiCall(method, path, body);
        if (result.status === 401) {
            sessionLost();
        }
        return result;
    }

    function sessionLost() {
        if (!me) return;
        stop();
        // Server-driven: the identity goes, the replay records stay (Keystore.wipeIdentity)
        Keystore.wipeIdentity();
        Errors.report(Errors.CODES.W_SESSION_ENDED);
        showLogin();
    }

    function isSeq(value) {
        return Number.isSafeInteger(value) && value >= 0;
    }

    function isPublicKey(value) {
        try {
            ElyrnCrypto.b64urlDecode(value, 32);
            return true;
        } catch (e) {
            return false;
        }
    }

    function conversationKey(conv) {
        if (!conv.key) {
            conv.key = ElyrnCrypto.conversationKey(me.privateKey, conv.peerPublicKey, conv.id);
        }
        return conv.key;
    }

    // The open conversation counts too while the page is hidden: what arrived then is not read
    function updateTitle() {
        let unread = 0;
        conversations.forEach(conv => {
            if ((conv.id !== activeId || !isPageVisible()) && conv.lastSeq > conv.readSeq) unread++;
        });
        document.title = unread > 0 ? `(${unread}) ${APP_TITLE}` : APP_TITLE;
    }

    // The server keeps no cross-conversation recency, so ordering is decided here:
    // unread first, then activity seen during this session, then newest conversation
    function renderList() {
        const rank = id => {
            const r = recent.indexOf(id);
            return r === -1 ? recent.length + order.indexOf(id) : r;
        };
        const items = order.filter(id => conversations.has(id) || unverified.has(id)).map(id => {
            const conv = conversations.get(id);
            if (!conv) return Object.assign({ unread: false, unverified: true }, unverified.get(id));
            return { id: conv.id, aura: conv.aura, unread: conv.lastSeq > conv.readSeq, verified: conv.verified, room: conv.room };
        });
        items.sort((a, b) => (b.unread - a.unread) || (rank(a.id) - rank(b.id)));
        renderConversationList(items, open, leaveUnverified);
        updateTitle();
    }

    // A message newer than any known in conv was found (a poll, or a sync): on a hidden page that
    // is worth a content-free alert (Alerts.raise decides)
    function noteNewer(conv, seq) {
        if (listLoaded && seq > conv.lastSeq) Alerts.raise();
    }

    function bump(id) {
        recent = [id].concat(recent.filter(other => other !== id));
    }

    // ---------- lifecycle ----------

    async function start(identity, ttlDays, limits) {
        me = {
            privateKey: identity.privateKey,
            publicKey: identity.publicKey,
            roomsRoot: identity.roomsRoot,
            aura: await ElyrnCrypto.aura(identity.publicKey),
            ttlDays: ttlDays,
            limits: limits,
            pageLimit: limits.pageLimit  // 0: the server did not say, so no paging back
        };
        renderMe(me.aura);
        await Alerts.start();
        FileComposer.start({ maxBytes: limits.fileMaxBytes, activeConversation: () => activeId });
        setComposerHint(ttlDays);
        setRoomLimits(limits.maxMembers, Rooms.ttlChoices(limits.maxTTLHours));
        showHome();
        showApp();
        await refreshConversations();
        live.start();
    }

    function stop() {
        // A list refresh still in flight belongs to this session: it is never applied
        listGeneration++;
        // A proof of work still running belongs to this session: end it, which releases its lock
        cancelProofsOfWork();
        Alerts.stop();
        RoleControl.reset();
        FileComposer.stop();
        live.stop();
        clearTimeout(refreshTimer);
        conversations.clear();
        order = [];
        recent = [];
        activeId = null;
        listLoaded = false;
        unsent = null;
        unverified.clear();
        reportedRooms.clear();
        parked.clear();
        drafts.clear();
        me = null;
        clearChildren(document.getElementById('conversationList'));
        clearChildren(document.getElementById('messageList'));
        if (inviteRun) {
            inviteRun.stopScramble();
            inviteRun = null;
        }
        if (roomRun) {
            roomRun.stopScramble();
            roomRun = null;
        }
        resetInvitePanel();
        resetRoomPanel();
        hideRoomPanels();
        togglePairPanel(null);
        document.getElementById('inviteInput').value = '';
        document.getElementById('deleteAccountInput').value = '';
        setComposer('');
        document.title = APP_TITLE;
    }

    // ---------- conversations ----------

    // One refresh in flight at a time; a request arriving meanwhile gets exactly one more run
    // after it (singleFlight), so the debounce timer, a join and an accepted note never overlap
    const refreshConversations = singleFlight(refreshNow);

    // Brings the local list in line with the server's: merges what is listed, drops what is
    // gone, re-renders, and puts away an invite someone has just redeemed. A list that went stale
    // while it was fetched or verified (listGeneration moved) is dropped unapplied.
    async function refreshNow() {
        if (!me) return;
        const generation = listGeneration;
        const result = await api('GET', '/conversations');
        if (generation !== listGeneration) return;
        if (!result.ok || !result.data || !Array.isArray(result.data.conversations)) {
            if (result.status !== 401) live.reportFetchFailure(Errors.CODES.E_CONVERSATIONS_NOT_LOADED, result);
            return;
        }
        live.endOutage();

        const listed = await mergeListed(result.data.conversations, generation);
        if (!listed) return;
        dropUnlisted(listed.seen);
        order = listed.order;
        if (!listLoaded) pruneMarks(listed.seen);
        listLoaded = true;
        renderList();
        const active = conversations.get(activeId);
        if (active && listed.reopen) {
            open(active.id);
        } else if (active && active.room) {
            refreshActiveRoom(active);
        }

        // Someone redeemed an invite: the code on screen is spent, so put it away
        // (unless a new one is being made, which nobody can have redeemed yet)
        if (listed.joined && !inviteRun && document.getElementById('invitePanel').style.display !== 'none') {
            togglePairPanel(null);
            showSuccess(Errors.NOTICE.INVITE_REDEEMED);
        }
    }

    // Takes in the server's listed conversations: new ones are verified and added, known ones
    // are checked for tampering and their sequence numbers advanced. Returns { seen, order,
    // joined, reopen }, or null when the list went stale while a conversation was being verified.
    async function mergeListed(items, generation) {
        const seen = new Set();
        const nextOrder = [];
        let joined = false;
        let reopen = false;  // the open room was verified again: rebuild its view
        for (const item of items) {
            const isRoom = Boolean(item && item.room);
            if (!item || !validateConversationId(item.id) || (!isRoom && !isPublicKey(item.peer_public_key)) ||
                !isSeq(item.last_seq) || !isSeq(item.read_seq) || seen.has(item.id)) {
                continue;
            }
            seen.add(item.id);
            nextOrder.push(item.id);
            let existing = conversations.get(item.id);
            // Joining again (from another device) re-seals this account's vault: verify the new
            // one from scratch instead of taking the change for tampering
            if (existing && isRoom && existing.room && item.room.vault !== existing.room.vault) {
                parked.set(item.id, existing.mark);
                conversations.delete(item.id);
                existing = null;
                reopen = reopen || activeId === item.id;
            }
            if (existing) {
                // A conversation's kind, peer key and room code can never change; treat as tampering
                if (isRoom !== Boolean(existing.room) ||
                    (isRoom ? !Rooms.refreshView(existing.room, item) : existing.peerPublicKey !== item.peer_public_key)) {
                    Errors.report(isRoom ? Errors.CODES.E_ROOM_DATA_CHANGED : Errors.CODES.E_PEER_KEY_CHANGED);
                    forget(item.id);
                    continue;
                }
                noteNewer(existing, item.last_seq);
                existing.lastSeq = Math.max(existing.lastSeq, item.last_seq);
                existing.readSeq = Math.max(existing.readSeq, item.read_seq);
                continue;
            }
            const state = await newConversationState(item, isRoom);
            if (generation !== listGeneration) return null;
            if (!state) continue;
            unverified.delete(item.id);
            joined = joined || (listLoaded && !isRoom);
            conversations.set(item.id, state);
        }
        return { seen: seen, order: nextOrder, joined: joined, reopen: reopen };
    }

    // Drops every conversation the server no longer lists from this session; leaving the open one
    // says why. Its counter record stays (the server's word is no fact to forget it on): if the
    // server lists it again, its old messages are still judged against what this device saw.
    function dropUnlisted(seen) {
        for (const id of Array.from(unverified.keys())) {
            if (!seen.has(id)) unverified.delete(id);
        }
        for (const id of Array.from(conversations.keys())) {
            if (!seen.has(id)) {
                const gone = conversations.get(id);
                forget(id);
                if (activeId === id) {
                    activeId = null;
                    setComposer('');
                    showHome();
                    Errors.report(gone.room ? Errors.CODES.W_ROOM_GONE : Errors.CODES.W_CONVERSATION_BURNED);
                }
            }
        }
    }

    // Verifies a listed conversation once (a room against the code in its vault); null keeps it
    // out of the conversations (a room that fails is held apart as unverified)
    async function newConversationState(item, isRoom) {
        const state = {
            id: item.id,
            peerPublicKey: null,
            room: null,
            aura: null,
            verified: false,
            myMaxN: 0,                  // this device's highest counter here: never spent twice
            spare: 0,                   // a counter taken for a send the server refused: taken again next
            ledger: Counters.ledger(Counters.EMPTY),  // senders' counters in the loaded sequence
            // the last record saved (kept in memory when storage fails), or the one kept when this
            // conversation was dropped from the session earlier (parked)
            mark: parked.get(item.id) || Counters.EMPTY,
            markLoad: Promise.resolve(Counters.EMPTY),  // the record read when last opened
            lastSeq: item.last_seq,
            readSeq: item.read_seq,
            maxSeq: 0,
            firstSeq: 0,                // the lowest seq loaded since open: where paging back starts
            earlier: false,             // the server may hold messages below firstSeq
            above: new Map(),           // senders' lowest counters on the earlier pages loaded
            seqs: new Set(),
            ids: new Set(),
            loaded: false,
            key: null,
            syncChain: Promise.resolve()
        };
        if (!isRoom) {
            state.peerPublicKey = item.peer_public_key;
            state.aura = await ElyrnCrypto.aura(item.peer_public_key);
            state.verified = await Keystore.isVerified(item.id, item.peer_public_key);
            return state;
        }
        try {
            state.room = await Rooms.adopt(me.roomsRoot, item);
        } catch (e) {
            await holdUnverified(item, e);
            return null;
        }
        // Expired long ago by its own code: its counter record may be gone, so it is never shown
        if (Counters.expiredLongAgo(state.room.expiresAt, Date.now())) return null;
        state.aura = await Rooms.aura(item.id);
        return state;
    }

    // A listed room that failed verification: never opened, listed apart under the name its id
    // gives, with leaving as its only action (leaveUnverified). Reported once per room, not on
    // every refresh. The owner flag is the server's word, used only to word the action.
    async function holdUnverified(item, error) {
        if (!reportedRooms.has(item.id)) {
            reportedRooms.add(item.id);
            Errors.report(Errors.CODES.E_ROOM_UNVERIFIED, null, error);
        }
        if (!unverified.has(item.id)) {
            const owner = Boolean(item.room && item.room.owner === true);
            unverified.set(item.id, { id: item.id, aura: await Rooms.aura(item.id), owner: owner });
        }
    }

    // Leaves a room that failed verification (DELETE, as burn() does: its owner burns it), once
    // its row's confirmation was answered
    function leaveUnverified(id) {
        return once('leave-' + id, async () => {
            const held = unverified.get(id);
            if (!held) return;
            const result = await api('DELETE', `/conversations/${id}`);
            if (result.status === 204 || result.status === 404) {
                listGeneration++;
                unverified.delete(id);
                if (result.status === 204) await forgetRecord(id);
                renderList();
                showSuccess(held.owner ? Errors.NOTICE.BURNED : Errors.NOTICE.ROOM_LEFT);
                scheduleRefresh();
            } else if (result.status !== 401) {
                Errors.report(Errors.CODES.E_ROOM_NOT_LEFT, null, result);
            }
        });
    }

    // Drops a conversation from this session, with the draft typed for it; its counter record is
    // parked, never forgotten (only forgetMark forgets it)
    function forget(id) {
        const conv = conversations.get(id);
        if (conv) parked.set(id, conv.mark);
        conversations.delete(id);
        drafts.delete(id);
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(refreshConversations, REFRESH_DEBOUNCE_MS);
    }

    async function open(id) {
        const conv = conversations.get(id);
        if (!conv) return;
        stashDraft();
        activeId = id;
        showChatView(conv.aura, conv.room);
        setComposer(drafts.get(id) || '');
        conv.seqs = new Set();
        conv.ids = new Set();
        conv.maxSeq = 0;
        conv.firstSeq = 0;
        conv.earlier = false;
        conv.above = new Map();
        // myMaxN is kept: this device's counter only ever grows
        conv.loaded = false;
        // Read now, before any await, so every sync and send of this open waits for the same record
        conv.markLoad = loadMark(conv);
        if (conv.room) {
            renderRoomHeader(conv.room);
            setRoomComposerHint(conv.room.expiresAt, me.ttlDays);
            if (!(await loadRoster(conv))) return;
            await refreshRoomPanels(conv);
        } else {
            setComposerHint(me.ttlDays);
            setVerifiedState(conv.verified);
        }
        const loaded = await sync(conv);
        if (activeId === id) {
            // Nothing could be loaded: say so, with a retry, never "say hello" over it
            if (!loaded) renderLoadFailure(() => open(id));
            composer().focus();
        }
    }

    function backToList() {
        stashDraft();
        activeId = null;
        setComposer('');
        showHome();
        renderList();
    }

    // ---------- composer (one input, a draft per conversation) ----------

    function composer() {
        return document.getElementById('messageInput');
    }

    // The composer is reset for another conversation (or emptied after a send): a chosen file
    // belongs to the conversation it was chosen in, so it goes too, its upload cancelled
    function setComposer(text) {
        composer().value = text;
        updateComposerMeta();
        FileComposer.clear();
    }

    // Keeps what is typed for the open conversation until it is opened again
    function stashDraft() {
        if (!activeId) return;
        const text = composer().value;
        if (text) {
            drafts.set(activeId, text);
        } else {
            drafts.delete(activeId);
        }
    }

    // A sent text leaves the composer only where it still is: the same conversation, unchanged.
    // Typed on after sending, or moved elsewhere, the text stays; a draft equal to it goes.
    function clearSent(convId, text) {
        if (activeId === convId && composer().value === text) {
            setComposer('');
        }
        if (drafts.get(convId) === text) {
            drafts.delete(convId);
        }
    }

    // ---------- messages ----------

    // Serialised per conversation so SSE pokes and manual opens never interleave. The chain stays
    // usable after a failure: the next poke or open syncs from where this one stopped. Resolves to
    // false when the sync failed (open() then shows a retry when nothing could be loaded).
    function sync(conv) {
        conv.syncChain = conv.syncChain.then(() => syncNow(conv)).catch(error => {
            if (me && activeId === conv.id && conv.loaded) {
                live.reportFetchFailure(Errors.CODES.E_MESSAGES_NOT_LOADED, error);
            } else {
                Log.error(Errors.INTERNAL.E_SYNC_FAILED, error);
            }
            return false;
        });
        return conv.syncChain;
    }

    // Fetches the messages after the last one held, admits them, and shows them if the
    // conversation is still open
    async function syncNow(conv) {
        const path = conv.loaded
            ? `/conversations/${conv.id}/messages?after=${conv.maxSeq}`
            : `/conversations/${conv.id}/messages`;
        const result = await api('GET', path);
        if (!me || activeId !== conv.id) return true;
        if (result.status === 404) {
            scheduleRefresh();
            return true;
        }
        if (!result.ok || !result.data || !Array.isArray(result.data.messages)) {
            // A first load that fails is shown in the conversation itself, by open()
            if (conv.loaded) live.reportFetchFailure(Errors.CODES.E_MESSAGES_NOT_LOADED, result);
            else Log.error(Errors.INTERNAL.E_SYNC_FAILED, result);
            return false;
        }
        live.endOutage();
        if (!conv.loaded) {
            // A new loaded sequence starts from what this device remembers (counters.js, rule 2)
            const record = await conv.markLoad;
            conv.ledger = Counters.ledger(record);
            conv.myMaxN = Math.max(conv.myMaxN, record.mine);
        }
        const first = !conv.loaded;
        conv.loaded = true;

        const page = await admitMessages(conv, result.data.messages, { ledger: conv.ledger, after: conv.maxSeq, before: Infinity });
        conv.maxSeq = page.last;
        if (first) {
            // The latest page: anything below it is reached by paging back
            conv.firstSeq = page.first;
            conv.earlier = mayHaveEarlier(result.data.messages.length, page.first);
        }
        // Once per sync, never per message; kept even if the user moved on meanwhile
        await saveMark(conv);
        if (activeId !== conv.id) return true;

        appendMessages(page.fresh);
        // Says hello only to a conversation that loaded and holds nothing (and replaces a retry)
        renderEmptyConversation(me.ttlDays, conv.room);
        if (first) setEarlierControl(conv.earlier, false);
        if (conv.room) checkLookalikes(conv);
        noteNewer(conv, conv.maxSeq);
        conv.lastSeq = Math.max(conv.lastSeq, conv.maxSeq);
        await markRead(conv);
        return true;
    }

    // A page that came back full may have more below it; a shorter one is the beginning
    function mayHaveEarlier(served, first) {
        return me.pageLimit > 0 && served >= me.pageLimit && first > 1;
    }

    // Opens each well-formed message not seen before, in ascending seq inside the range
    // (after < seq < before), and judges its counter on range.ledger. Returns what to show
    // (messages, gap notices, replay warnings in place of replays) and the lowest and highest
    // seq taken (0 and range.after when none was).
    async function admitMessages(conv, messages, range) {
        const key = conv.room ? null : await conversationKey(conv);
        const fresh = [];
        let replayed = false;
        let first = 0;
        let last = range.after;
        for (const raw of messages) {
            if (!raw || !ElyrnCrypto.isUuidV4(raw.id) || !isSeq(raw.seq) || raw.seq === 0 ||
                typeof raw.mine !== 'boolean' || typeof raw.ciphertext !== 'string' ||
                raw.ciphertext.length > MAX_CIPHERTEXT_CHARS || conv.seqs.has(raw.seq) || raw.seq <= last ||
                raw.seq >= range.before || conv.ids.has(raw.id)) {
                // Unknown shape, out of order or range, or a message id seen before (a server
                // re-serving an old ciphertext)
                continue;
            }
            const message = await openMessage(conv, key, raw);
            conv.seqs.add(raw.seq);
            conv.ids.add(raw.id);
            first = first || raw.seq;
            last = raw.seq;
            if (!message.broken) {
                replayed = checkCounter(conv, range.ledger, message, fresh) || replayed;
            }
            if (!message.replayed) fresh.push(message);
        }
        if (replayed) Log.warn(Errors.CODES.W_MESSAGE_REPLAYED);
        return { fresh: fresh, first: first, last: last };
    }

    // ---------- earlier messages (paging back) ----------

    // Loads the page just below the lowest message shown, queued with the syncs
    function earlier() {
        const conv = conversations.get(activeId);
        if (!conv || !conv.earlier) return Promise.resolve();
        setEarlierControl(true, true);
        conv.syncChain = conv.syncChain.then(() => earlierNow(conv)).catch(error => {
            // The control is shared by every conversation: only the one still open gets it back
            if (activeId === conv.id) setEarlierControl(conv.earlier, false);
            Log.error(Errors.INTERNAL.E_SYNC_FAILED, error);
        });
        return conv.syncChain;
    }

    // An earlier page is history: judged on its own ledger (counters.js, EARLIER PAGES), so it
    // never moves conv.ledger, conv.maxSeq or the stored record; only firstSeq moves down
    async function earlierNow(conv) {
        const opened = conv.markLoad;  // a new open replaces it: this page then belongs to nobody
        if (!conv.earlier || activeId !== conv.id) return;
        const before = conv.firstSeq;
        const result = await api('GET', `/conversations/${conv.id}/messages?before=${before}`);
        if (!me || activeId !== conv.id || conv.markLoad !== opened) return;
        if (result.status === 404) {
            scheduleRefresh();
            return;
        }
        if (!result.ok || !result.data || !Array.isArray(result.data.messages)) {
            setEarlierControl(true, false);
            if (result.status !== 401) Errors.report(Errors.CODES.E_MESSAGES_NOT_LOADED, null, result);
            return;
        }
        const ledger = Counters.history(await opened, Counters.lowest(conv.above, conv.ledger));
        const page = await admitMessages(conv, result.data.messages, { ledger: ledger, after: 0, before: before });
        if (activeId !== conv.id || conv.markLoad !== opened) return;
        conv.above = Counters.lowest(conv.above, ledger);
        conv.firstSeq = page.first || before;
        conv.earlier = mayHaveEarlier(result.data.messages.length, page.first);
        prependMessages(page.fresh);
        if (conv.room) checkLookalikes(conv);
        setEarlierControl(conv.earlier, false);
    }

    // Decrypts and authenticates one message: { seq, mine, text, sentAt, sender, counter, from? },
    // or { seq, mine, broken, newer } when anything fails: shown as unreadable, or, for an
    // authentic payload a newer elyrn wrote (newer), as such (ElyrnCrypto.isNewerPayload)
    async function openMessage(conv, key, raw) {
        try {
            return conv.room ? await openRoomMessage(conv, raw) : await openPairMessage(conv, key, raw);
        } catch (e) {
            return { seq: raw.seq, mine: raw.mine, broken: true, newer: ElyrnCrypto.isNewerPayload(e) };
        }
    }

    // The sender is bound into the AAD: a flipped `mine` names the wrong key and fails to open
    async function openPairMessage(conv, key, raw) {
        const sender = raw.mine ? me.publicKey : conv.peerPublicKey;
        const plain = await ElyrnCrypto.decryptMessage(key, conv.id, raw.id, sender, raw.ciphertext);
        return withFile(conv, { seq: raw.seq, mine: raw.mine, text: plain.text, sentAt: plain.sentAt, sender: sender, counter: plain.counter }, plain.file);
    }

    // A message announcing a file can fetch it on request (file-card.js; nothing before)
    function withFile(conv, message, file) {
        if (!file) return message;
        return Object.assign(message, {
            file: file,
            fetchFile: ({ onProgress, cancelled }) => FileTransfer.download({ api, conversationId: conv.id, file, onProgress, cancelled })
        });
    }

    // Verifies a room message's sender against the server's `mine` and names who sent it
    async function openRoomMessage(conv, raw) {
        const plain = await Rooms.open(conv, raw);
        const mine = plain.sender === conv.room.member.publicKey;
        if (mine !== raw.mine) {
            throw new Error('the server misattributes a message');
        }
        const message = withFile(conv, { seq: raw.seq, mine: mine, text: plain.text, sentAt: plain.sentAt, sender: plain.sender, counter: plain.counter }, plain.file);
        if (mine) return message;
        const entry = Rooms.senderOf(conv.room, plain.sender);
        const aura = entry ? entry.aura : await ElyrnCrypto.aura(plain.sender);
        if (!entry) {
            // Off the roster, yet a lookalike all the same: its name is compared too
            conv.room.outsiders.set(plain.sender, { publicKey: plain.sender, aura: aura });
        }
        return Object.assign(message, { from: aura, left: !entry, role: entry ? entry.role : '' });
    }

    // Judges an authenticated message's counter on a ledger (counters.js), the same way for pairs
    // and rooms. A replay is marked so the caller shows a warning in its place; a gap is pushed
    // before it. Returns whether it was a replay. myMaxN only ever rises, from any page.
    function checkCounter(conv, ledger, message, fresh) {
        const verdict = Counters.judge(ledger, message.sender, message.counter, message.seq);
        if (verdict.replay) {
            message.replayed = true;
            fresh.push({ replay: true, mine: message.mine, from: message.from });
            return true;
        }
        Counters.admit(ledger, message.sender, message.counter);
        if (message.mine) {
            conv.myMaxN = Math.max(conv.myMaxN, message.counter);
        } else if (verdict.gap > 0) {
            fresh.push({ gap: verdict.gap, from: message.from });
        }
        return false;
    }

    // ---------- the counter record (Keystore) ----------

    // What this device remembers of a conversation; the in-memory copy stands in when storage fails
    async function loadMark(conv) {
        return Counters.merge(Counters.parse(await Keystore.loadCounters(conv.id)), conv.mark);
    }

    // Records only grow (each field is a high-water mark), so a save merges with the record as
    // stored now, read under the counter lock every tab shares: another tab's higher record is
    // never overwritten, and a save made before the first sync of a reload never lowers it
    async function saveMark(conv) {
        if (!me || conversations.get(conv.id) !== conv) return;
        const raised = Counters.merge(await conv.markLoad, Counters.snapshot(conv.ledger, conv.maxSeq, conv.myMaxN));
        await Keystore.withCounterLock(conv.id, async () => {
            const stored = await storedMark(conv);
            await writeMark(conv, stored, Counters.merge(Counters.merge(stored, conv.mark), raised));
        });
    }

    // The record as stored right now (Counters.EMPTY when there is none or storage failed)
    async function storedMark(conv) {
        return Counters.parse(await Keystore.loadCounters(conv.id));
    }

    // Keeps record as this tab's last one (it stands in when storage fails) and stores it unless
    // the stored one already says the same
    async function writeMark(conv, stored, record) {
        conv.mark = record;
        if (!Counters.same(record, stored)) {
            await Keystore.saveCounters(conv.id, record, conv.room ? conv.room.expiresAt : 0);
        }
    }

    // Takes this account's next counter in a conversation, under the counter lock every tab
    // shares: the stored record is read fresh inside it and raised to the new counter before the
    // message is posted (write-ahead), so a second tab, hidden or behind on its syncs, never takes
    // the same one. A counter given back by a send the server refused (releaseCounter) is taken
    // again, as long as no tab has gone past it since.
    async function allocateCounter(conv) {
        const opened = await conv.markLoad;
        return Keystore.withCounterLock(conv.id, async () => {
            const stored = await storedMark(conv);
            const known = Counters.merge(Counters.merge(stored, conv.mark), opened);
            const top = Math.max(conv.myMaxN, known.mine);
            const counter = conv.spare > 0 && conv.spare === top ? top : top + 1;
            conv.spare = 0;
            conv.myMaxN = counter;
            await writeMark(conv, stored, Counters.merge(known, Counters.parse({ seq: 0, mine: counter, senders: [] })));
            return counter;
        });
    }

    // A send the server settled as not stored gives its counter back for the next one, unless an
    // earlier attempt of it went unanswered (the server may hold that one) or a later one was taken
    function releaseCounter(conv, attempt) {
        if (!attempt.lost && conv.myMaxN === attempt.counter) {
            conv.spare = attempt.counter;
        }
    }

    // The user's own burn or leave, confirmed by the server (204): the only time a conversation's
    // counter record is forgotten before its room expires (counters.js KEEPING RECORDS). Queued
    // behind the conversation's syncs so a save in flight cannot land after the removal.
    function forgetMark(conv) {
        conv.syncChain = conv.syncChain.then(() => forgetRecord(conv.id));
    }

    function forgetRecord(id) {
        parked.delete(id);
        return Keystore.forgetCounters(id);
    }

    // Once per session, on its first listing: drops the records of rooms expired long ago and,
    // past the bound, the least recently used (the conversations listed now last)
    async function pruneMarks(listedIds) {
        if (await Keystore.pruneCounters(Date.now(), listedIds) && !evictionWarned) {
            evictionWarned = true;
            Log.warn(Errors.INTERNAL.W_COUNTER_RECORDS_EVICTED);
        }
    }

    // Nothing is read while nobody can see it: a hidden page shows what arrived and marks it read
    // only once it is shown again (onVisible resyncs, and that sync lands here)
    async function markRead(conv) {
        if (isPageVisible() && conv.maxSeq > conv.readSeq) {
            conv.readSeq = conv.maxSeq;
            await api('POST', `/conversations/${conv.id}/read`, { seq: conv.maxSeq });
        }
        updateTitle();
    }

    // Enter held down or a double click sends once
    function send() {
        return once('send', sendNow);
    }

    async function sendNow() {
        const conv = conversations.get(activeId);
        const input = composer();
        const sendBtn = document.getElementById('sendBtn');
        if (!conv) return;

        // What the composer held when sent: it is cleared later only if it still holds exactly this
        const typed = input.value;
        // A chosen file still being read or cleaned waits (the send control is off meanwhile)
        const attached = FileComposer.attached(conv.id);
        if (attached && !attached.ready) return;
        const validation = attached ? validateCaption(typed, attached.name) : validateMessageText(typed);
        if (!validation.valid) {
            if (validation.error !== Errors.CODES.E_MESSAGE_EMPTY) Errors.report(validation.error, validation.params);
            // An account number pasted here is not kept: not in the composer, not as a draft
            if (validation.error === Errors.CODES.E_MESSAGE_IS_ACCOUNT_NUMBER) clearSent(conv.id, typed);
            return;
        }

        if (conv.room && Rooms.expired(conv.room)) {
            Errors.report(Errors.CODES.W_ROOM_EXPIRED);
            return;
        }

        sendBtn.disabled = true;
        try {
            if (conv.room && !conv.room.roster && !(await loadRoster(conv))) return;
            // A file's parts go first; its message is sent like any other (412, 409, counters)
            const owner = me;
            const file = attached
                ? await FileComposer.upload({ api, conv, cancelled: () => me !== owner || activeId !== conv.id })
                : null;
            if (attached && !file) return;
            await deliver(conv, typed, validation.sanitized, file);
        } catch (e) {
            Errors.report(Errors.CODES.E_MESSAGE_NOT_SENT, null, e);
        } finally {
            sendBtn.disabled = false;
            if (activeId) input.focus();
        }
    }

    // Posts one text and settles the outcome. A new text takes a counter (allocateCounter); a
    // retry of a send whose answer was lost resends the same id, counter and ciphertext, so if
    // the lost one was stored the server refuses the duplicate id (409 "Conflict") instead of
    // delivering the message twice. A 409 counts as stored only then: a fresh id cannot exist yet.
    // A 409 "Id taken" (Errors.idTaken) is never stored: the id is held by something else, so the
    // text goes again under a fresh id and counter, MAX_ID_REDRAWS times at most.
    async function deliver(conv, typed, text, file) {
        const sameFile = (attempt) => (attempt.file ? Boolean(file) && attempt.file.id === file.id : !file);
        const resumed = unsent && unsent.convId === conv.id && unsent.text === text && sameFile(unsent) ? unsent : null;
        let outcome = await exchange(conv, resumed || await freshAttempt(conv, text, file));
        for (let redraw = 0; !outcome.rosterLost && Errors.idTaken(outcome.result) && redraw < MAX_ID_REDRAWS; redraw++) {
            outcome = await exchange(conv, await freshAttempt(conv, text, file));
        }
        // The roster could not be fetched again: that failure was shown
        if (outcome.rosterLost) return;
        const { attempt, result } = outcome;
        const taken = Errors.idTaken(result);

        const stored = (result.ok && result.data && isSeq(result.data.seq) && result.data.seq > 0) ||
            (result.status === 409 && attempt.lost && !taken);
        // Only a lost answer leaves the outcome open; any other answer settles it. The counter is
        // spent either way (written ahead): a retry keeps it, and the peer sees a gap at worst.
        const pending = !stored && (result.status === 0 || result.status >= 500);
        attempt.lost = attempt.lost || pending;
        unsent = pending ? attempt : null;

        if (stored) {
            if (file) FileComposer.sent(file);
            clearSent(conv.id, typed);
            bump(conv.id);
            await sync(conv);
        } else if (taken) {
            Errors.report(Errors.CODES.E_MESSAGE_ID_TAKEN, null, result);
        } else if (result.status === 409) {
            Errors.report(Errors.CODES.E_MESSAGE_ID_CONFLICT, null, result);
        } else if (result.status === 429) {
            Errors.report(Errors.CODES.W_MESSAGE_RATE_LIMITED);
        } else if (result.status === 404) {
            scheduleRefresh();
        } else if (result.status !== 401) {
            Errors.report(Errors.CODES.E_MESSAGE_NOT_SENT, null, result);
        }
    }

    // A new send of text (and file, if any): a fresh id and the next counter, sealed on its first post
    async function freshAttempt(conv, text, file) {
        const attempt = { convId: conv.id, text: text, file: file || null, id: ElyrnCrypto.newMessageId(), counter: 0, ciphertext: null, lost: false };
        attempt.counter = await allocateCounter(conv);
        return attempt;
    }

    // Posts one attempt, re-encrypting for a changed roster (412), and returns
    // { attempt, result, rosterLost }
    async function exchange(conv, attempt) {
        let result = null;
        let rosterLost = false;  // the roster could not be fetched again: that failure was shown
        try {
            if (!attempt.ciphertext) attempt.ciphertext = await sealAttempt(conv, attempt);
            result = await postAttempt(conv, attempt);
            // Someone joined or left since the roster was fetched: encrypt for the new one
            for (let retry = 0; conv.room && result.status === 412 && retry < MAX_ROSTER_RETRIES; retry++) {
                if (!(await loadRoster(conv))) {
                    rosterLost = true;
                    break;
                }
                attempt.ciphertext = await sealAttempt(conv, attempt);
                result = await postAttempt(conv, attempt);
            }
        } finally {
            // Nothing posted, or refused before any attempt could have been stored
            if (!result || settledUnstored(result)) releaseCounter(conv, attempt);
        }
        return { attempt, result, rosterLost };
    }

    function postAttempt(conv, attempt) {
        return api('POST', `/conversations/${conv.id}/messages`, { id: attempt.id, ciphertext: attempt.ciphertext });
    }

    // A client error stores nothing, except a 409 "Conflict" (a duplicate id: an earlier attempt
    // may be held); a 409 "Id taken" stores nothing either
    function settledUnstored(result) {
        return result.status >= 400 && result.status < 500 && (result.status !== 409 || Errors.idTaken(result));
    }

    function sealAttempt(conv, attempt) {
        if (conv.room) {
            return Rooms.seal({ conv, id: attempt.id, text: attempt.text, counter: attempt.counter, file: attempt.file });
        }
        return conversationKey(conv).then(key =>
            ElyrnCrypto.encryptMessage({
                key, conversationId: conv.id, messageId: attempt.id, senderPublicKey: me.publicKey,
                text: attempt.text, sentAt: Date.now(), counter: attempt.counter, file: attempt.file
            }));
    }

    // ---------- pairing ----------

    // Pays for an invite with a proof of work (as registration does) and builds its code.
    // Returns { code, expiresAt }, or null once the reason has been shown.
    async function requestInvite(owner) {
        const issued = await api('GET', '/pow/challenge');
        if (me !== owner) return null;
        if (!issued.ok || !issued.data || !issued.data.challenge) {
            if (issued.status === 429) Errors.report(Errors.CODES.W_POW_RATE_LIMITED);
            else if (issued.status !== 401) Errors.report(Errors.CODES.E_INVITE_NOT_CREATED, null, issued);
            return null;
        }
        const pow = await solvePowChallenge(issued.data.challenge);
        if (me !== owner) return null;

        const result = await api('POST', '/invites', { pow: pow });
        if (me !== owner) return null;
        if (result.status === 429) {
            Errors.report(Errors.CODES.W_INVITE_LIMIT);
            return null;
        }
        if (!result.ok || !result.data || typeof result.data.token !== 'string' || !Number.isSafeInteger(result.data.expires_at)) {
            if (result.status !== 401) Errors.report(Errors.CODES.E_INVITE_NOT_CREATED, null, result);
            return null;
        }
        try {
            return {
                code: await ElyrnCrypto.buildInviteCode(result.data.token, owner.publicKey),
                expiresAt: result.data.expires_at
            };
        } catch (e) {
            Errors.report(Errors.CODES.E_INVITE_MALFORMED, null, e);
            return null;
        }
    }

    function createInvite() {
        return once('invite', createInviteNow);
    }

    async function createInviteNow() {
        if (inviteRun || !me) return;  // one proof of work at a time
        const owner = me;
        const run = { stopScramble: showInviteGenerating() };
        inviteRun = run;
        // This request still owns the panel: the same session, still the current run, panel open.
        // Every reveal step checks it, so the code is never drawn after any of them ends.
        const alive = () => me === owner && inviteRun === run && isShown('invitePanel');

        let invite = null;
        try {
            invite = await requestInvite(owner);
        } catch (e) {
            // The proof of work failed, timed out or was too hard (a cancelled one ended the session)
            if (me === owner) Errors.report(powFailureCode(e, Errors.CODES.E_INVITE_NOT_CREATED), null, e);
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!invite) {
            inviteRun = null;
            resetInvitePanel();
            return;
        }

        const shown = await revealInvite(invite.code, invite.expiresAt, alive);
        if (me !== owner) return;  // stop() put the panel away
        inviteRun = null;
        if (!shown) {
            // The panel was closed meanwhile: the code is neither shown nor copied
            resetInvitePanel();
            return;
        }
        await copyWithNotice(invite.code, Errors.NOTICE.INVITE_COPIED, true);
    }

    // The join field takes an invite code or a room code; a second press while one runs is
    // ignored (a spent invite would otherwise be reported after the first one succeeded)
    function join() {
        return once('join', joinNow);
    }

    async function joinNow() {
        const input = document.getElementById('inviteInput');
        const validation = validateJoinCode(input.value);
        if (!validation.valid) {
            Errors.report(validation.error, validation.params);
            return;
        }
        const id = validation.kind === 'room' ? await joinRoom(validation.sanitized) : await redeemInvite(validation.sanitized);
        if (!id || !me) return;
        // A list fetched before the join cannot hold it: never apply one
        listGeneration++;
        input.value = '';
        togglePairPanel(null);
        await refreshConversations();
        await open(id);
    }

    // Redeems an invite and checks the peer key against its fingerprint. Returns the new
    // conversation id, or null once the reason has been shown.
    async function redeemInvite(invite) {
        if (await ElyrnCrypto.fingerprintMatches(invite, me.publicKey)) {
            Errors.report(Errors.CODES.W_OWN_INVITE);
            return null;
        }
        const result = await api('POST', '/invites/redeem', { token: invite.token });
        if (result.status === 404) {
            Errors.report(Errors.CODES.E_INVITE_SPENT);
            return null;
        }
        if (result.status === 429) {
            Errors.report(Errors.CODES.W_TOO_MANY_ATTEMPTS);
            return null;
        }
        const conv = result.data && result.data.conversation;
        if (!result.ok || !conv || !validateConversationId(conv.id) || !isPublicKey(conv.peer_public_key)) {
            if (result.status !== 401) Errors.report(Errors.CODES.E_JOIN_FAILED, null, result);
            return null;
        }
        // The server chose which key we got; the invite code says which key we should get
        if (!(await ElyrnCrypto.fingerprintMatches(invite, conv.peer_public_key))) {
            await api('DELETE', `/conversations/${conv.id}`);
            Errors.report(Errors.CODES.E_PEER_KEY_SUBSTITUTED);
            return null;
        }
        showSuccess(Errors.NOTICE.CONNECTED);
        return conv.id;
    }

    // ---------- rooms ----------

    // Fetches and verifies the active room's member list. Returns false once the reason was shown:
    // a failed request by its own code, the alarm only for a list that failed verification.
    async function loadRoster(conv) {
        try {
            await Rooms.loadRoster(api, conv);
        } catch (e) {
            if (!me) return false;
            if (!e.result) {
                Errors.report(Errors.CODES.E_ROSTER_UNVERIFIED, null, e);
            } else if (e.result.status === 404) {
                scheduleRefresh();
            } else if (e.result.status !== 401) {
                Errors.report(Errors.fromResult(e.result), null, e.result);
            }
            return false;
        }
        checkLookalikes(conv);
        if (activeId === conv.id) {
            renderRoomHeader(conv.room);
            RoleControl.markBubbles(new Map(conv.room.roster.map(entry => [entry.publicKey, entry.role])));
        }
        return true;
    }

    // Different keys under one name: one of them may have been ground to pass as the other.
    // Tags them wherever shown; the toast comes once per key per session, not on every refresh.
    function checkLookalikes(conv) {
        const room = conv.room;
        room.lookalikes = Rooms.nameCollisions(room.roster || [], room.outsiders.values());
        if (activeId !== conv.id) return;
        const unseen = [...room.lookalikes].filter(key => !room.warned.has(key));
        unseen.forEach(key => room.warned.add(key));
        if (unseen.length > 0) Errors.report(Errors.CODES.W_LOOKALIKE_MEMBERS);
        markLookalikes(room.lookalikes);
    }

    // Someone joined, left or sent a note: refresh what the open room shows
    async function refreshActiveRoom(conv) {
        if (await loadRoster(conv) && activeId === conv.id) {
            await refreshRoomPanels(conv);
        }
    }

    async function refreshRoomPanels(conv) {
        if (!conv.room.roster || activeId !== conv.id) return;
        if (document.getElementById('membersPanel').style.display !== 'none') {
            renderMemberList(conv);
            renderRoomSafety(await Rooms.safetyNumber(conv));
        }
        const notes = conv.room.notes > 0 ? await Rooms.notes(api, conv) : [];
        if (activeId !== conv.id) return;
        renderNotes(notes, note => acceptNote(conv, note), note => ignoreNote(conv, note));
    }

    function renderMemberList(conv) {
        if (activeId !== conv.id || !conv.room.roster) return;
        renderMembers({
            entries: conv.room.roster, skipped: conv.room.skipped, requested: conv.room.requested,
            lookalikes: conv.room.lookalikes, onBefriend: entry => befriend(conv, entry),
            roleControl: entry => RoleControl.control({
                room: conv.room, entry, save: text => saveRole(conv, entry, text), rerender: () => renderMemberList(conv)
            })
        });
    }

    // Stores a member's role (RoleControl); a stored one shows at once, before the conv event
    async function saveRole(conv, entry, text) {
        const saved = await RoleControl.save({ api, conv, entry, text });
        if (saved && me) await refreshActiveRoom(conv);
        return saved;
    }

    async function joinRoom(code) {
        if (Date.now() >= code.expiresHour * HOUR_MS) {
            Errors.report(Errors.CODES.E_ROOM_CODE_EXPIRED);
            return null;
        }
        // A room this account is in, pasted with other limits, is a doctored code: rejoining
        // with it would only replace the verified vault, so nothing is sent
        const known = conversations.get(await Rooms.roomIdOf(code));
        if (known && known.room && !Rooms.sameLimits(known.room.code, code)) {
            Errors.report(Errors.CODES.E_ROOM_CODE_INVALID);
            return null;
        }
        const result = await Rooms.join(api, me.roomsRoot, code);
        if (result.id) {
            showSuccess(result.status === 201 ? Errors.NOTICE.ROOM_JOINED : Errors.NOTICE.ROOM_ALREADY_JOINED);
            return result.id;
        }
        if (result.status === 404) {
            Errors.report(Errors.CODES.E_ROOM_NOT_FOUND);
        } else if (result.status === 409) {
            Errors.report(Errors.CODES.W_ROOM_FULL);
        } else if (result.status === 429) {
            Errors.report(Errors.CODES.W_ROOM_JOIN_RATE_LIMITED);
        } else if (result.status !== 401) {
            Errors.report(Errors.CODES.E_ROOM_JOIN_FAILED, null, result);
        }
        return null;
    }

    function createRoom() {
        return once('room', createRoomNow);
    }

    async function createRoomNow() {
        if (roomRun || !me) return;  // one proof of work at a time
        const owner = me;
        const maxMembers = Number(document.getElementById('roomMembersSelect').value);
        const ttlHours = Number(document.getElementById('roomTtlSelect').value);
        const run = { stopScramble: showRoomGenerating() };
        roomRun = run;
        // As createInviteNow: the room panel still shows this request's box (not closed, not reopened)
        const alive = () => me === owner && roomRun === run && roomCodeBoxShown();
        // The challenge's refusal, if any, and the server's clock as the last challenge gave it
        const clock = { refused: null, serverSeconds: null, at: 0 };
        const solve = async () => {
            const issued = await api('GET', '/pow/challenge');
            if (me !== owner) return null;
            if (!issued.ok || !issued.data || !issued.data.challenge) {
                clock.refused = issued;
                return null;
            }
            clock.serverSeconds = issued.data.challenge.timestamp;
            clock.at = Date.now();
            return solvePowChallenge(issued.data.challenge);
        };
        let created;
        try {
            created = await Rooms.create(api, owner.roomsRoot, maxMembers, ttlHours, solve);
        } catch (e) {
            created = { status: 0, failure: e };
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!created.code) {
            roomRun = null;
            resetRoomPanel();
            const failed = clock.refused || created;
            if (failed.status !== 401) {
                Errors.report(roomFailureCode(created, clock), null, created.failure || failed);
            }
            return;
        }
        const expiresAtSeconds = ElyrnRoomCrypto.parseRoomCode(created.code).expiresHour * HOUR_MS / SECOND_MS;
        const shown = await revealRoomCode(created.code, expiresAtSeconds, alive);
        if (me !== owner) return;  // stop() put the panel away
        roomRun = null;
        // The room exists either way: the list shows it, and its code panel shows the code
        scheduleRefresh();
        if (!shown) {
            resetRoomPanel();
            return;
        }
        await copyWithNotice(created.code, Errors.NOTICE.ROOM_CODE_COPIED, true);
    }

    // Why a room was not created: a refused challenge or answer by its own code. The server checks
    // a new room's expiry against its own clock, so a 400 names the device clock only when it
    // disagrees with the server's (as the challenge stated it) by more than the server allows.
    function roomFailureCode(created, clock) {
        if (clock.refused) {
            return clock.refused.status === 429 ? Errors.CODES.W_ROOM_CREATE_RATE_LIMITED : Errors.fromResult(clock.refused);
        }
        if (created.status === 429) return Errors.CODES.W_ROOM_CREATE_RATE_LIMITED;
        if (created.status === 400) {
            const skewed = Number.isSafeInteger(clock.serverSeconds) &&
                Math.abs(clock.at - clock.serverSeconds * SECOND_MS) > SERVER_CLOCK_SKEW_MS;
            return skewed ? Errors.CODES.E_ROOM_CLOCK_REFUSED : Errors.CODES.E_ROOM_LIMITS_REFUSED;
        }
        return powFailureCode(created.failure, Errors.CODES.E_ROOM_NOT_CREATED);
    }

    function activeRoom() {
        const conv = conversations.get(activeId);
        return conv && conv.room ? conv : null;
    }

    async function toggleMembers() {
        const conv = activeRoom();
        if (!conv) return;
        if (toggleRoomPanel('membersPanel')) {
            await refreshRoomPanels(conv);
        }
    }

    function toggleRoomCode() {
        const conv = activeRoom();
        if (!conv) return;
        if (toggleRoomPanel('roomCodePanel')) {
            showRoomCode(Rooms.codeText(conv), conv.room.expiresAt);
        }
    }

    function copyRoomCode() {
        const conv = activeRoom();
        if (!conv) return Promise.resolve();
        return once('copy-room-code', () => copyWithNotice(Rooms.codeText(conv), Errors.NOTICE.ROOM_CODE_COPIED, true));
    }

    // Sends a member an invite inside the room, sealed for them alone (a proof of work, as any invite)
    // One friend request (a proof of work) at a time
    function befriend(conv, entry) {
        return once('befriend', () => befriendNow(conv, entry));
    }

    async function befriendNow(conv, entry) {
        if (!me) return;
        const owner = me;
        showSuccess(Errors.NOTICE.FRIEND_REQUEST_PREPARING);
        try {
            const invite = await requestInvite(owner);
            if (!invite || me !== owner) return;
            const result = await Rooms.befriend(api, conv, entry, invite.code);
            if (result.status === 201) {
                conv.room.requested.add(entry.publicKey);
                showSuccess(Errors.notice(Errors.NOTICE.FRIEND_REQUEST_SENT, { name: entry.aura.name }));
            } else if (result.status === 409) {
                Errors.report(Errors.CODES.W_FRIEND_REQUEST_PENDING);
            } else if (result.status === 404) {
                Errors.report(Errors.CODES.W_FRIEND_GONE);
            } else if (result.status !== 401) {
                Errors.report(Errors.CODES.E_FRIEND_REQUEST_NOT_SENT, null, result);
            }
        } catch (e) {
            if (me === owner) Errors.report(powFailureCode(e, Errors.CODES.E_FRIEND_REQUEST_NOT_SENT), null, e);
        } finally {
            if (me === owner) await refreshRoomPanels(conv);
        }
    }

    // A note is answered once: accept and ignore share its key, so a double click never redeems
    // its invite twice (the second would report a spent invite after the first succeeded)
    function noteKey(note) {
        return 'note-' + note.id;
    }

    // Accepting redeems the invite inside the note, with the usual fingerprint check
    function acceptNote(conv, note) {
        return once(noteKey(note), () => acceptNoteNow(conv, note));
    }

    async function acceptNoteNow(conv, note) {
        const validation = validateInviteCode(note.invite);
        if (!validation.valid) {
            Errors.report(Errors.CODES.E_FRIEND_REQUEST_MALFORMED);
            await dismissNote(conv, note);
            return;
        }
        const id = await redeemInvite(validation.sanitized);
        if (!id || !me) return;
        listGeneration++;
        await Rooms.dismissNote(api, conv, note.id);
        showSuccess(Errors.NOTICE.FRIENDS_NOW);
        await refreshConversations();
        await open(id);
    }

    function ignoreNote(conv, note) {
        return once(noteKey(note), () => dismissNote(conv, note));
    }

    async function dismissNote(conv, note) {
        await Rooms.dismissNote(api, conv, note.id);
        conv.room.notes = Math.max(0, conv.room.notes - 1);
        await refreshRoomPanels(conv);
    }

    // ---------- conversation actions ----------

    function toggleVerified() {
        return once('verify', toggleVerifiedNow);
    }

    async function toggleVerifiedNow() {
        const conv = conversations.get(activeId);
        if (!conv) return;
        const next = !conv.verified;
        if (!(await Keystore.setVerified(conv.id, conv.peerPublicKey, next))) {
            Errors.report(Errors.CODES.W_VERIFICATION_NOT_SAVED);
            return;
        }
        conv.verified = next;
        setVerifiedState(next);
        if (next) showSuccess(Errors.NOTICE.MARKED_VERIFIED);
    }

    async function showSafety() {
        const conv = conversations.get(activeId);
        const panel = document.getElementById('safetyPanel');
        if (!conv) return;
        if (panel.style.display !== 'none') {
            panel.style.display = 'none';
            return;
        }
        renderSafetyNumber(await ElyrnCrypto.safetyNumber(me.publicKey, conv.peerPublicKey));
        panel.style.display = 'block';
    }

    function askBurn(show) {
        const conv = conversations.get(activeId);
        setBurnConfirm(conv ? conv.room : null);
        document.getElementById('burnConfirm').style.display = show ? 'flex' : 'none';
    }

    // A pair is burned for both sides; a room is burned by its owner and left by anyone else
    function burn() {
        return once('burn', burnNow);
    }

    async function burnNow() {
        const id = activeId;
        const conv = conversations.get(id);
        const leaving = Boolean(conv && conv.room && !conv.room.owner);
        askBurn(false);
        if (!id) return;
        const result = await api('DELETE', `/conversations/${id}`);
        if (result.status === 204 || result.status === 404) {
            listGeneration++;
            forget(id);
            // Only a burn or leave the server confirmed forgets the record; a 404 is its word only
            if (conv && result.status === 204) forgetMark(conv);
            // Nothing typed for a burned conversation is kept
            setComposer('');
            backToList();
            showSuccess(leaving ? Errors.NOTICE.ROOM_LEFT : Errors.NOTICE.BURNED);
            scheduleRefresh();
        } else if (result.status !== 401) {
            Errors.report(leaving ? Errors.CODES.E_ROOM_NOT_LEFT : Errors.CODES.E_CONVERSATION_NOT_BURNED, null, result);
        }
    }

    // ---------- live updates (live-updates.js says when) ----------

    // A message arrived in conversation id (an event the stream delivered)
    function messageArrived(id) {
        Alerts.raise();
        const conv = conversations.get(id);
        if (!conv) {
            scheduleRefresh();
            return;
        }
        bump(conv.id);
        // The open conversation is fetched and shown even on a hidden page (a window behind
        // another, a background tab): only marking it read waits for the page to be seen
        if (activeId === conv.id) {
            sync(conv);
        } else {
            scheduleRefresh();
        }
    }

    // Resolves once the open conversation's sync has settled (the list refresh runs on its own
    // debounce, one at a time), so the watchdog never queues a poll behind one still running.
    function catchUp() {
        scheduleRefresh();
        const conv = conversations.get(activeId);
        return conv ? sync(conv) : Promise.resolve();
    }

    return Object.freeze({
        start, stop, open, backToList, send, earlier, createInvite, join, createRoom,
        toggleMembers, toggleRoomCode, copyRoomCode,
        showSafety, toggleVerified, askBurn, burn, onVisible: live.onVisible, onRestored: live.onRestored,
        isActive: () => me !== null,
        publicKey: () => (me ? me.publicKey : null)
    });
})();
