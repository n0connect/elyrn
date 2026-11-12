// ========================================
// CHAT (state, sync, realtime)
// ========================================
// The server is treated as an untrusted relay: every response is shape-checked,
// every message is authenticated by AES-GCM + AAD, peer keys from invites are
// verified against the fingerprint embedded in the invite code, and each sender's
// encrypted message counter exposes messages the server withheld, replayed or reordered,
// across reloads too (counters.js; the record this device keeps lives in Keystore).
// Rooms (rooms.js) are conversations too: a room conversation carries `room` and no peer key.

const Chat = (() => {
    'use strict';

    const MAX_RECONNECT_ATTEMPTS = 8;
    const RECONNECT_BASE_MS = 1000;
    const RECONNECT_MAX_MS = 30000;
    const MAX_CIPHERTEXT_CHARS = 11000;
    // A roster can change between fetching it and sending (412): fetch, re-encrypt, retry, bounded
    const MAX_ROSTER_RETRIES = 2;

    let me = null;                    // { privateKey, publicKey, roomsRoot, aura, ttlDays, limits }
    const conversations = new Map();  // id -> conversation state
    let order = [];                   // server order: newest conversation first
    let recent = [];                  // ids with activity this session, most recent first (memory only)
    let activeId = null;
    let events = null;
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    let refreshTimer = null;
    let listLoaded = false;           // distinguishes the first load from live additions
    let inviteRun = null;             // { stopScramble } while an invite is paid for and revealed
    let unsent = null;                // a send whose answer never came: { convId, text, id, counter, ciphertext }
    let roomRun = null;               // { stopScramble } while a room is paid for and revealed
    let friendRun = false;            // one friend request (a proof of work) at a time
    const rejectedRooms = new Set();  // "id vault" pairs that failed verification: warned about once

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
        Keystore.wipe();
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

    function updateTitle() {
        let unread = 0;
        conversations.forEach(conv => {
            if (conv.id !== activeId && conv.lastSeq > conv.readSeq) unread++;
        });
        document.title = unread > 0 ? `(${unread}) elyrn.` : 'elyrn.';
    }

    // The server keeps no cross-conversation recency, so ordering is decided here:
    // unread first, then activity seen during this session, then newest conversation
    function renderList() {
        const rank = id => {
            const r = recent.indexOf(id);
            return r === -1 ? recent.length + order.indexOf(id) : r;
        };
        const items = order.filter(id => conversations.has(id)).map(id => {
            const conv = conversations.get(id);
            return { id: conv.id, aura: conv.aura, unread: conv.lastSeq > conv.readSeq, verified: conv.verified, room: conv.room };
        });
        items.sort((a, b) => (b.unread - a.unread) || (rank(a.id) - rank(b.id)));
        renderConversationList(items, open);
        updateTitle();
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
            limits: limits
        };
        renderMe(me.aura);
        setComposerHint(ttlDays);
        setRoomLimits(limits.maxMembers, Rooms.ttlChoices(limits.maxTTLHours));
        showHome();
        showApp();
        await refreshConversations();
        connectEvents();
    }

    function stop() {
        closeEvents();
        clearTimeout(refreshTimer);
        conversations.clear();
        order = [];
        recent = [];
        activeId = null;
        listLoaded = false;
        unsent = null;
        rejectedRooms.clear();
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
        friendRun = false;
        resetInvitePanel();
        resetRoomPanel();
        hideRoomPanels();
        togglePairPanel(null);
        document.getElementById('inviteInput').value = '';
        document.getElementById('deleteAccountInput').value = '';
        document.getElementById('messageInput').value = '';
        document.title = 'elyrn.';
    }

    // ---------- conversations ----------

    async function refreshConversations() {
        const result = await api('GET', '/conversations');
        if (!me) return;
        if (!result.ok || !result.data || !Array.isArray(result.data.conversations)) {
            if (result.status !== 401) Errors.report(Errors.CODES.E_CONVERSATIONS_NOT_LOADED, null, result);
            return;
        }

        const seen = new Set();
        const nextOrder = [];
        let joined = false;
        let reopen = false;  // the open room was verified again: rebuild its view
        for (const item of result.data.conversations) {
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
                conversations.delete(item.id);
                existing = null;
                reopen = reopen || activeId === item.id;
            }
            if (existing) {
                // A conversation's kind, peer key and room code can never change; treat as tampering
                if (isRoom !== Boolean(existing.room) ||
                    (isRoom ? !Rooms.refreshView(existing.room, item) : existing.peerPublicKey !== item.peer_public_key)) {
                    Errors.report(isRoom ? Errors.CODES.E_ROOM_DATA_CHANGED : Errors.CODES.E_PEER_KEY_CHANGED);
                    conversations.delete(item.id);
                    continue;
                }
                existing.lastSeq = Math.max(existing.lastSeq, item.last_seq);
                existing.readSeq = Math.max(existing.readSeq, item.read_seq);
                continue;
            }
            const state = await newConversationState(item, isRoom);
            if (!me) return;
            if (!state) continue;
            joined = joined || (listLoaded && !isRoom);
            conversations.set(item.id, state);
        }

        for (const id of Array.from(conversations.keys())) {
            if (!seen.has(id)) {
                const gone = conversations.get(id);
                conversations.delete(id);
                forgetMark(gone);
                if (activeId === id) {
                    activeId = null;
                    showHome();
                    Errors.report(gone.room ? Errors.CODES.W_ROOM_GONE : Errors.CODES.W_CONVERSATION_BURNED);
                }
            }
        }
        order = nextOrder;
        listLoaded = true;
        renderList();
        const active = conversations.get(activeId);
        if (active && reopen) {
            open(active.id);
        } else if (active && active.room) {
            refreshActiveRoom(active);
        }

        // Someone redeemed an invite: the code on screen is spent, so put it away
        // (unless a new one is being made, which nobody can have redeemed yet)
        if (joined && !inviteRun && document.getElementById('invitePanel').style.display !== 'none') {
            togglePairPanel(null);
            showSuccess('someone joined with your invite');
        }
    }

    // Verifies a listed conversation once (a room against the code in its vault); null hides it
    async function newConversationState(item, isRoom) {
        const state = {
            id: item.id,
            peerPublicKey: null,
            room: null,
            aura: null,
            verified: false,
            myMaxN: 0,                  // this device's highest counter here: never spent twice
            ledger: Counters.ledger(Counters.EMPTY),  // senders' counters in the loaded sequence
            mark: Counters.EMPTY,       // the last record saved: kept in memory when storage fails
            markLoad: Promise.resolve(Counters.EMPTY),  // the record read when last opened
            lastSeq: item.last_seq,
            readSeq: item.read_seq,
            maxSeq: 0,
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
            const seen = item.id + ' ' + (item.room && item.room.vault);
            if (!rejectedRooms.has(seen)) {
                rejectedRooms.add(seen);
                Errors.report(Errors.CODES.E_ROOM_UNVERIFIED, null, e);
            }
            return null;
        }
        state.aura = await Rooms.aura(item.id);
        return state;
    }

    function scheduleRefresh() {
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(refreshConversations, 250);
    }

    async function open(id) {
        const conv = conversations.get(id);
        if (!conv) return;
        activeId = id;
        showChatView(conv.aura, conv.room);
        conv.seqs = new Set();
        conv.ids = new Set();
        conv.maxSeq = 0;
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
        await sync(conv);
        if (activeId === id) {
            renderEmptyConversation(me.ttlDays, conv.room);
            document.getElementById('messageInput').focus();
        }
    }

    function backToList() {
        activeId = null;
        showHome();
        renderList();
    }

    // ---------- messages ----------

    // Serialised per conversation so SSE pokes and manual opens never interleave. A failed sync
    // is logged and the chain stays usable: the next poke or open syncs from where this one stopped.
    function sync(conv) {
        conv.syncChain = conv.syncChain.then(() => syncNow(conv)).catch(error => Log.error(Errors.INTERNAL.E_SYNC_FAILED, error));
        return conv.syncChain;
    }

    async function syncNow(conv) {
        const path = conv.loaded
            ? `/conversations/${conv.id}/messages?after=${conv.maxSeq}`
            : `/conversations/${conv.id}/messages`;
        const result = await api('GET', path);
        if (!me || activeId !== conv.id) return;
        if (result.status === 404) {
            scheduleRefresh();
            return;
        }
        if (!result.ok || !result.data || !Array.isArray(result.data.messages)) {
            Errors.report(Errors.CODES.E_MESSAGES_NOT_LOADED, null, result);
            return;
        }
        if (!conv.loaded) {
            // A new loaded sequence starts from what this device remembers (counters.js, rule 2)
            const record = await conv.markLoad;
            conv.ledger = Counters.ledger(record);
            conv.myMaxN = Math.max(conv.myMaxN, record.mine);
        }
        conv.loaded = true;

        const key = conv.room ? null : await conversationKey(conv);
        const fresh = [];
        let replayed = false;
        for (const raw of result.data.messages) {
            if (!raw || !ElyrnCrypto.isUuidV4(raw.id) || !isSeq(raw.seq) || raw.seq === 0 ||
                typeof raw.mine !== 'boolean' || typeof raw.ciphertext !== 'string' ||
                raw.ciphertext.length > MAX_CIPHERTEXT_CHARS || conv.seqs.has(raw.seq) || raw.seq <= conv.maxSeq ||
                conv.ids.has(raw.id)) {
                // Unknown shape, or a message id seen before (a server re-serving an old ciphertext)
                continue;
            }
            const message = await openMessage(conv, key, raw);
            conv.seqs.add(raw.seq);
            conv.ids.add(raw.id);
            conv.maxSeq = raw.seq;
            if (!message.broken) {
                replayed = checkCounter(conv, message, fresh) || replayed;
            }
            if (!message.replayed) fresh.push(message);
        }
        if (replayed) Log.warn(Errors.CODES.W_MESSAGE_REPLAYED);
        // Once per sync, never per message; kept even if the user moved on meanwhile
        await saveMark(conv);
        if (activeId !== conv.id) return;

        appendMessages(fresh);
        if (conv.room) checkLookalikes(conv);
        conv.lastSeq = Math.max(conv.lastSeq, conv.maxSeq);
        await markRead(conv);
    }

    // Decrypts and authenticates one message: { seq, mine, text, sentAt, sender, counter, from? },
    // or { seq, mine, broken } when anything fails (shown as unreadable)
    async function openMessage(conv, key, raw) {
        try {
            return conv.room ? await openRoomMessage(conv, raw) : await openPairMessage(conv, key, raw);
        } catch (e) {
            return { seq: raw.seq, mine: raw.mine, broken: true };
        }
    }

    // The sender is bound into the AAD: a flipped `mine` names the wrong key and fails to open
    async function openPairMessage(conv, key, raw) {
        const sender = raw.mine ? me.publicKey : conv.peerPublicKey;
        const plain = await ElyrnCrypto.decryptMessage(key, conv.id, raw.id, sender, raw.ciphertext);
        return { seq: raw.seq, mine: raw.mine, text: plain.text, sentAt: plain.sentAt, sender: sender, counter: plain.counter };
    }

    // Verifies a room message's sender against the server's `mine` and names who sent it
    async function openRoomMessage(conv, raw) {
        const plain = await Rooms.open(conv, raw);
        const mine = plain.sender === conv.room.member.publicKey;
        if (mine !== raw.mine) {
            throw new Error('the server misattributes a message');
        }
        const message = { seq: raw.seq, mine: mine, text: plain.text, sentAt: plain.sentAt, sender: plain.sender, counter: plain.counter };
        if (mine) return message;
        const entry = Rooms.senderOf(conv.room, plain.sender);
        const aura = entry ? entry.aura : await ElyrnCrypto.aura(plain.sender);
        if (!entry) {
            // Off the roster, yet a lookalike all the same: its name is compared too
            conv.room.outsiders.set(plain.sender, { publicKey: plain.sender, aura: aura });
        }
        return Object.assign(message, { from: aura, left: !entry });
    }

    // Judges an authenticated message's counter (counters.js), the same way for pairs and rooms.
    // A replay is marked so the caller shows a warning in its place; a gap is pushed before it.
    // Returns whether it was a replay.
    function checkCounter(conv, message, fresh) {
        const verdict = Counters.judge(conv.ledger, message.sender, message.counter, message.seq);
        if (verdict.replay) {
            message.replayed = true;
            fresh.push({ replay: true, mine: message.mine, from: message.from });
            return true;
        }
        Counters.admit(conv.ledger, message.sender, message.counter);
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

    // Records only grow (each field is a high-water mark), so the one read at open is merged in:
    // a save made before the first sync of a reload can never lower what was stored
    async function saveMark(conv) {
        if (!me || conversations.get(conv.id) !== conv) return;
        const record = Counters.merge(await conv.markLoad, Counters.snapshot(conv.ledger, conv.maxSeq, conv.myMaxN));
        if (Counters.same(record, conv.mark)) return;
        conv.mark = record;
        await Keystore.saveCounters(conv.id, record);
    }

    // A save outside a sync (a send whose answer was lost), queued in order with the syncs
    function persistMark(conv) {
        conv.syncChain = conv.syncChain.then(() => saveMark(conv));
    }

    // Queued behind the conversation's syncs so a save in flight cannot land after the removal
    function forgetMark(conv) {
        conv.syncChain = conv.syncChain.then(() => Keystore.forgetCounters(conv.id));
    }

    async function markRead(conv) {
        if (conv.maxSeq > conv.readSeq) {
            conv.readSeq = conv.maxSeq;
            await api('POST', `/conversations/${conv.id}/read`, { seq: conv.maxSeq });
        }
        updateTitle();
    }

    async function send() {
        const conv = conversations.get(activeId);
        const input = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        if (!conv || sendBtn.disabled) return;

        const validation = validateMessageText(input.value);
        if (!validation.valid) {
            if (input.value.trim() !== '') Errors.report(validation.error, validation.params);
            return;
        }

        if (conv.room && Rooms.expired(conv.room)) {
            Errors.report(Errors.CODES.W_ROOM_EXPIRED);
            return;
        }
        if (conv.room && !conv.room.roster && !(await loadRoster(conv))) return;

        sendBtn.disabled = true;
        try {
            // Retrying a send whose answer was lost resends the same id and ciphertext: if the
            // first attempt was stored, the server refuses the duplicate id (409) instead of
            // delivering the message twice
            const text = validation.sanitized;
            let attempt = unsent && unsent.convId === conv.id && unsent.text === text ? unsent : null;
            if (!attempt) {
                // After a reload the server may withhold this device's last messages: the stored
                // counter still counts, so none is ever spent twice
                conv.myMaxN = Math.max(conv.myMaxN, (await conv.markLoad).mine);
                const id = ElyrnCrypto.newMessageId();
                attempt = { convId: conv.id, text: text, id: id, counter: conv.myMaxN + 1, ciphertext: null };
                attempt.ciphertext = await sealAttempt(conv, attempt);
            }
            let result = await api('POST', `/conversations/${conv.id}/messages`, { id: attempt.id, ciphertext: attempt.ciphertext });
            // Someone joined or left since the roster was fetched: encrypt for the new one
            for (let retry = 0; conv.room && result.status === 412 && retry < MAX_ROSTER_RETRIES; retry++) {
                if (!(await loadRoster(conv))) return;
                attempt.ciphertext = await sealAttempt(conv, attempt);
                result = await api('POST', `/conversations/${conv.id}/messages`, { id: attempt.id, ciphertext: attempt.ciphertext });
            }
            const stored = (result.ok && result.data && isSeq(result.data.seq) && result.data.seq > 0) || result.status === 409;
            // Only a lost answer leaves the outcome open; any other answer settles it
            unsent = !stored && (result.status === 0 || result.status >= 500) ? attempt : null;

            if (stored || unsent) {
                // A counter the server may hold is spent: it never repeats, even if the server
                // withholds this message from the next sync (the peer then sees a gap, not a
                // reused counter). A retry of the same attempt keeps its id and counter.
                conv.myMaxN = Math.max(conv.myMaxN, attempt.counter);
            }
            if (stored) {
                input.value = '';
                updateComposerMeta();
                bump(conv.id);
                await sync(conv);
            } else if (result.status === 429) {
                Errors.report(Errors.CODES.W_MESSAGE_RATE_LIMITED);
            } else if (result.status === 404) {
                scheduleRefresh();
            } else if (result.status !== 401) {
                Errors.report(Errors.CODES.E_MESSAGE_NOT_SENT, null, result);
            }
            if (unsent) persistMark(conv);
        } catch (e) {
            Errors.report(Errors.CODES.E_MESSAGE_NOT_SENT, null, e);
        } finally {
            sendBtn.disabled = false;
            input.focus();
        }
    }

    function sealAttempt(conv, attempt) {
        if (conv.room) {
            return Rooms.seal(conv, attempt.id, attempt.text, attempt.counter);
        }
        return conversationKey(conv).then(key =>
            ElyrnCrypto.encryptMessage(key, conv.id, attempt.id, me.publicKey, attempt.text, Date.now(), attempt.counter));
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

    async function createInvite() {
        if (inviteRun || !me) return;  // one proof of work at a time
        const owner = me;
        const run = { stopScramble: showInviteGenerating() };
        inviteRun = run;

        let invite = null;
        try {
            invite = await requestInvite(owner);
        } catch (e) {
            // The worker refused the challenge or found no solution within its budget
            if (me === owner) Errors.report(Errors.CODES.E_INVITE_NOT_CREATED, null, e);
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!invite) {
            inviteRun = null;
            resetInvitePanel();
            return;
        }

        await revealInvite(invite.code, invite.expiresAt);
        if (me !== owner) {
            // Logged out mid-reveal: the last animation frame wrote the code back
            document.getElementById('inviteCode').textContent = '';
            return;
        }
        inviteRun = null;
        try {
            await copyToClipboard(invite.code);
            showSuccess(Errors.NOTICE.INVITE_COPIED);
        } catch (e) {
            Errors.report(Errors.CODES.W_COPY_MANUALLY);
        }
    }

    // The join field takes an invite code or a room code
    async function join() {
        const input = document.getElementById('inviteInput');
        const validation = validateJoinCode(input.value);
        if (!validation.valid) {
            Errors.report(validation.error, validation.params);
            return;
        }
        const id = validation.kind === 'room' ? await joinRoom(validation.sanitized) : await redeemInvite(validation.sanitized);
        if (!id || !me) return;
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
        showSuccess('connected');
        return conv.id;
    }

    // ---------- rooms ----------

    // Fetches and verifies the active room's member list. Returns false once the reason was shown.
    async function loadRoster(conv) {
        try {
            await Rooms.loadRoster(api, conv);
        } catch (e) {
            if (!me) return false;
            if (e.status === 404) {
                scheduleRefresh();
            } else if (e.status !== 401) {
                Errors.report(Errors.CODES.E_ROSTER_UNVERIFIED, null, e);
            }
            return false;
        }
        checkLookalikes(conv);
        if (activeId === conv.id) {
            renderRoomHeader(conv.room);
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
            renderMembers(conv.room.roster, conv.room.skipped, conv.room.requested, conv.room.lookalikes,
                entry => befriend(conv, entry));
            renderRoomSafety(await Rooms.safetyNumber(conv));
        }
        const notes = conv.room.notes > 0 ? await Rooms.notes(api, conv) : [];
        if (activeId !== conv.id) return;
        renderNotes(notes, note => acceptNote(conv, note), note => ignoreNote(conv, note));
    }

    async function joinRoom(code) {
        if (Date.now() >= code.expiresHour * 3600000) {
            Errors.report(Errors.CODES.E_ROOM_CODE_EXPIRED);
            return null;
        }
        const result = await Rooms.join(api, me.roomsRoot, code);
        if (result.id) {
            showSuccess(result.status === 201 ? 'you joined the room' : 'you are already in this room');
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

    async function createRoom() {
        if (roomRun || !me) return;  // one proof of work at a time
        const owner = me;
        const maxMembers = Number(document.getElementById('roomMembersSelect').value);
        const ttlHours = Number(document.getElementById('roomTtlSelect').value);
        const run = { stopScramble: showRoomGenerating() };
        roomRun = run;
        const solve = async () => {
            const issued = await api('GET', '/pow/challenge');
            if (me !== owner || !issued.ok || !issued.data || !issued.data.challenge) return null;
            return solvePowChallenge(issued.data.challenge);
        };
        let created = { status: 0 };
        try {
            created = await Rooms.create(api, owner.roomsRoot, maxMembers, ttlHours, solve);
        } catch (e) {
            created = { status: 0 };
        }
        if (me !== owner) return;  // stop() ended this run and put the panel away
        run.stopScramble();
        if (!created.code) {
            roomRun = null;
            resetRoomPanel();
            if (created.status === 429) Errors.report(Errors.CODES.W_ROOM_CREATE_RATE_LIMITED);
            else if (created.status === 400) Errors.report(Errors.CODES.E_ROOM_CLOCK_REFUSED);
            else if (created.status !== 401) Errors.report(Errors.CODES.E_ROOM_NOT_CREATED, null, created);
            return;
        }
        await revealRoomCode(created.code, ElyrnRoomCrypto.parseRoomCode(created.code).expiresHour * 3600);
        if (me !== owner) {
            document.getElementById('roomCode').textContent = '';
            return;
        }
        roomRun = null;
        scheduleRefresh();
        try {
            await copyToClipboard(created.code);
            showSuccess(Errors.NOTICE.ROOM_CODE_COPIED);
        } catch (e) {
            Errors.report(Errors.CODES.W_COPY_MANUALLY);
        }
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

    async function copyRoomCode() {
        const conv = activeRoom();
        if (!conv) return;
        try {
            await copyToClipboard(Rooms.codeText(conv));
            showSuccess(Errors.NOTICE.ROOM_CODE_COPIED);
        } catch (e) {
            Errors.report(Errors.CODES.W_COPY_MANUALLY);
        }
    }

    // Sends a member an invite inside the room, sealed for them alone (a proof of work, as any invite)
    async function befriend(conv, entry) {
        if (friendRun || !me) return;
        friendRun = true;
        const owner = me;
        showSuccess('preparing a friend request · solving a proof of work');
        try {
            const invite = await requestInvite(owner);
            if (!invite || me !== owner) return;
            const result = await Rooms.befriend(api, conv, entry, invite.code);
            if (result.status === 201) {
                conv.room.requested.add(entry.publicKey);
                showSuccess(`friend request sent to ${entry.aura.name}`);
            } else if (result.status === 409) {
                Errors.report(Errors.CODES.W_FRIEND_REQUEST_PENDING);
            } else if (result.status === 404) {
                Errors.report(Errors.CODES.W_FRIEND_GONE);
            } else if (result.status !== 401) {
                Errors.report(Errors.CODES.E_FRIEND_REQUEST_NOT_SENT, null, result);
            }
        } catch (e) {
            if (me === owner) Errors.report(Errors.CODES.E_FRIEND_REQUEST_NOT_SENT, null, e);
        } finally {
            friendRun = false;
            if (me === owner) await refreshRoomPanels(conv);
        }
    }

    // Accepting redeems the invite inside the note, with the usual fingerprint check
    async function acceptNote(conv, note) {
        const validation = validateInviteCode(note.invite);
        if (!validation.valid) {
            Errors.report(Errors.CODES.E_FRIEND_REQUEST_MALFORMED);
            await ignoreNote(conv, note);
            return;
        }
        const id = await redeemInvite(validation.sanitized);
        if (!id || !me) return;
        await Rooms.dismissNote(api, conv, note.id);
        showSuccess('you are now friends — a private conversation opened');
        await refreshConversations();
        await open(id);
    }

    async function ignoreNote(conv, note) {
        await Rooms.dismissNote(api, conv, note.id);
        conv.room.notes = Math.max(0, conv.room.notes - 1);
        await refreshRoomPanels(conv);
    }

    // ---------- conversation actions ----------

    async function toggleVerified() {
        const conv = conversations.get(activeId);
        if (!conv) return;
        const next = !conv.verified;
        if (!(await Keystore.setVerified(conv.id, conv.peerPublicKey, next))) {
            Errors.report(Errors.CODES.W_VERIFICATION_NOT_SAVED);
            return;
        }
        conv.verified = next;
        setVerifiedState(next);
        if (next) showSuccess('marked as verified on this device');
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
    async function burn() {
        const id = activeId;
        const conv = conversations.get(id);
        const leaving = Boolean(conv && conv.room && !conv.room.owner);
        askBurn(false);
        if (!id) return;
        const result = await api('DELETE', `/conversations/${id}`);
        if (result.status === 204 || result.status === 404) {
            conversations.delete(id);
            if (conv) forgetMark(conv);
            backToList();
            showSuccess(leaving ? 'you left the room' : 'burned');
            scheduleRefresh();
        } else if (result.status !== 401) {
            Errors.report(leaving ? Errors.CODES.E_ROOM_NOT_LEFT : Errors.CODES.E_CONVERSATION_NOT_BURNED, null, result);
        }
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
        if (!me) return;
        events = new EventSource(`${API_BASE_URL}/events`);
        events.addEventListener('open', () => {
            reconnectAttempts = 0;
            resync();
        });
        events.addEventListener('msg', onMessageEvent);
        events.addEventListener('conv', scheduleRefresh);
        // Never rely on the browser's built-in retry (fixed interval, unlimited attempts):
        // every drop goes through our bounded exponential backoff (RULES.md §17.1)
        events.onerror = () => {
            scheduleReconnect();
        };
    }

    function scheduleReconnect() {
        closeEvents();
        if (!me) return;
        const delay = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** reconnectAttempts);
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            Errors.report(Errors.CODES.W_LIVE_UPDATES_PAUSED);
            return;
        }
        reconnectAttempts++;
        reconnectTimer = setTimeout(reconnect, delay);
    }

    // Only reconnect while the session is still valid (a 401 ends the session instead)
    async function reconnect() {
        if (!me) return;
        const check = await api('GET', '/me');
        if (!me || check.status === 401) return;
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
            return;
        }
        if (!data || Object.keys(data).length !== 1 || !validateConversationId(data.c)) return;
        const conv = conversations.get(data.c);
        if (!conv) {
            scheduleRefresh();
            return;
        }
        bump(conv.id);
        if (activeId === conv.id && document.visibilityState === 'visible') {
            sync(conv);
        } else {
            scheduleRefresh();
        }
    }

    function resync() {
        if (!me) return;
        scheduleRefresh();
        const conv = conversations.get(activeId);
        if (conv) sync(conv);
    }

    function onVisible() {
        if (!me || document.visibilityState !== 'visible') return;
        if (!events) {
            reconnectAttempts = 0;
            connectEvents();
        } else {
            resync();
        }
    }

    return Object.freeze({
        start, stop, open, backToList, send, createInvite, join, createRoom,
        toggleMembers, toggleRoomCode, copyRoomCode,
        showSafety, toggleVerified, askBurn, burn, onVisible,
        isActive: () => me !== null,
        publicKey: () => (me ? me.publicKey : null)
    });
})();
