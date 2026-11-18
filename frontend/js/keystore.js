// ========================================
// KEYSTORE (IndexedDB)
// ========================================
// Persists ONLY the non-extractable X25519 CryptoKey, its public key and the non-extractable
// rooms root (an HKDF key every room key derives from), so a reload does not require
// re-entering the account number. Raw key bytes cannot be read back out of a
// non-extractable CryptoKey, not even by script running on this page.
// The AccountNumber itself is never stored anywhere.
//
// Which form of the identity is kept is decided by what this browser proves it can read back,
// never by its name. Before an identity is derived, keepsKeys() stores a throwaway
// non-extractable X25519 key, reads it back in a new transaction and deletes it (once per page
// load). Only an engine that fails it (WebKit, Nov 2026: it stores the key and reads back null)
// is asked to make the sealed form at all (ElyrnCrypto.unsealIdentity: the PKCS#8 wrapped under
// a non-extractable AES device key, weaker at rest, docs/security/threat-model.md); everywhere
// else the wrapped form never exists. save() still proves what it stored by reading it back
// through load()'s own path. Both forms live under RECORD, so one form at a time exists and
// every wipe removes either. When nothing reads back, nothing is kept and the user is told once
// (W_IDENTITY_NOT_KEPT).
//
// It also keeps whether content-free alerts are on (alerts.js), remembers which conversations
// the user verified (safety number compared), bound to the peer key that was verified, and, per
// conversation, the counter record that
// exposes replays after a reload (counters.js: highest seq and counters, a use stamp that only
// counts, and a room's own expiry hour from its code; never text, ids or the time of any
// activity). Which records are kept and for how long: counters.js KEEPING RECORDS. None of this
// ever reaches the server.
//
// Two ways to forget. wipeIdentity() is for what the server decides (a 401, a refused /me): it
// removes the identity record (and the alerts preference) only, so the counter records and
// verification marks survive and a server cannot erase replay protection by ending a session
// once. wipeAll() is the user's own
// logout or identity deletion: the whole database goes.
// Those records are keyed by conversation id, and one conversation id is shared by both of its
// members, so the records left behind belong to the account that wrote them (OWNER, its public
// key). save() clears them before another account's identity is stored: a different account on
// this device never inherits, reads or links to the previous account's conversations.
//
// When storage fails (a private window that refuses it, a full quota, a database from a newer
// version), the user is told once per page load (W_STORAGE_UNAVAILABLE): nothing survives a
// reload, replay protection included. Each operation opens and closes its own connection, so
// another tab can upgrade or delete the database in between; one that does so while a
// connection is open closes it here, and this tab then stops using storage (W_STORAGE_CLOSED).
// An upgrade another tab holds back (W_STORAGE_BLOCKED) fails the operation instead of waiting.

const Keystore = (() => {
    'use strict';

    // Stored name, kept across the rename to elyrn: changing it would orphan every saved key.
    const DB_NAME = 'noaddx';
    // 3 adds COUNTERS_STORE; an upgrade only creates missing stores, so saved keys survive it
    const DB_VERSION = 3;
    const STORE = 'keys';
    const VERIFIED_STORE = 'verified';
    const COUNTERS_STORE = 'counters';
    const RECORD = 'identity';
    // The public key of the account the counter and verified records belong to (kept by wipeIdentity)
    const OWNER = 'owner';
    // The last use stamp given to a counter record (saveCounters): only ever grows
    const USE_STAMP = 'counterUse';
    // Web Locks name of one conversation's counter record, shared by every tab of this browser
    const COUNTER_LOCK_PREFIX = 'elyrn-counter-';
    // Where keepsKeys() puts its throwaway key for the moment of the test
    const PROBE = 'keyProbe';
    // The content-free alerts preference (alerts.js): present (true) only while alerts are on.
    // It belongs to the identity: every way the identity goes (wipeIdentity, wipeAll, another
    // account's save) takes it along.
    const ALERTS = 'alerts';

    // A storage that refuses once (private window) refuses every time: say it once, not per sync
    let storageWarned = false;
    // Another tab upgraded or deleted the database under this one: storage is not used again here
    let retired = false;
    // This tab is deleting the database itself (wipeAll): its own versionchange is no news
    let wiping = false;
    let lockWarned = false;
    // keepsKeys()'s answer, asked once per page load
    let keepsKeysAnswer = null;

    // A failed operation: logged under its own code and told to the user, both once per page load
    function unavailable(logCode, error) {
        if (storageWarned) return;
        storageWarned = true;
        Log.warn(logCode, error);
        Errors.report(Errors.CODES.W_STORAGE_UNAVAILABLE, null, error);
    }

    // Says why storage stopped (code) once; every later failure is then silent
    function stopped(code) {
        if (storageWarned) return;
        storageWarned = true;
        Errors.report(code);
    }

    function open() {
        return new Promise((resolve, reject) => {
            if (retired) {
                reject(new Error('storage closed by another tab'));
                return;
            }
            if (!window.indexedDB) {
                reject(new Error('indexeddb unavailable'));
                return;
            }
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            // Set once the caller has its answer: a connection arriving after a block is closed
            let settled = false;
            request.onupgradeneeded = () => {
                const db = request.result;
                for (const name of [STORE, VERIFIED_STORE, COUNTERS_STORE]) {
                    if (!db.objectStoreNames.contains(name)) {
                        db.createObjectStore(name);
                    }
                }
            };
            request.onsuccess = () => {
                const db = request.result;
                if (settled) {
                    db.close();
                    return;
                }
                settled = true;
                db.onversionchange = () => retire(db);
                resolve(db);
            };
            request.onerror = () => {
                settled = true;
                reject(request.error);
            };
            // Another tab holds an older connection open: fail now rather than wait on it
            request.onblocked = () => {
                settled = true;
                stopped(Errors.CODES.W_STORAGE_BLOCKED);
                reject(new Error('storage blocked by another tab'));
            };
        });
    }

    // Another tab wants to upgrade or delete the database: let it, and stop using storage here
    function retire(db) {
        db.close();
        if (wiping) return;
        retired = true;
        stopped(Errors.CODES.W_STORAGE_CLOSED);
    }

    // Runs action(tx) in one transaction over storeNames; resolves to the result of the request
    // action returns (if any) once the transaction has committed
    async function run(storeNames, mode, action) {
        const db = await open();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(storeNames, mode);
                const request = action(tx);
                tx.oncomplete = () => resolve(request ? request.result : undefined);
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
        } finally {
            db.close();
        }
    }

    function transact(mode, action, storeName = STORE) {
        return run(storeName, mode, tx => action(tx.objectStore(storeName)));
    }

    // Whether this engine gives a stored non-extractable X25519 key back (see the top of this
    // file). A storage failure counts as "cannot": the sealed form is then made, and save() finds
    // out for itself whether anything is kept.
    function keepsKeys() {
        if (!keepsKeysAnswer) keepsKeysAnswer = probeKeys();
        return keepsKeysAnswer;
    }

    async function probeKeys() {
        let kept = false;
        try {
            const key = await ElyrnCrypto.throwawayKey();
            await transact('readwrite', store => store.put(key, PROBE));
            kept = ElyrnCrypto.isThrowawayKey(await transact('readonly', store => store.get(PROBE)));
        } catch (e) {
            Log.warn(Errors.INTERNAL.W_KEY_PROBE_FAILED, e);
        }
        try {
            await transact('readwrite', store => store.delete(PROBE));
        } catch (e) {
            Log.warn(Errors.INTERNAL.W_KEY_PROBE_FAILED, e);
        }
        return kept;
    }

    // Stores the identity, and first clears the records of any other account (see OWNER above).
    // True only once a read through load()'s own path gave the identity back: the key itself,
    // or else its sealed form. Neither: the unusable record goes and the user is told once.
    async function save(identity) {
        try {
            for (const form of [directForm(identity), identity.sealed ? sealedForm(identity) : null]) {
                if (!form) continue;
                await run([STORE, VERIFIED_STORE, COUNTERS_STORE], 'readwrite', tx => claimRecords(tx, identity.publicKey, form));
                const kept = (await readIdentity()).identity;
                if (kept && kept.publicKey === identity.publicKey) return true;
            }
            await transact('readwrite', store => store.delete(RECORD));
            stopped(Errors.CODES.W_IDENTITY_NOT_KEPT);
            return false;
        } catch (e) {
            // Private windows may block IndexedDB: identity then lives in memory only
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    function directForm(identity) {
        return { privateKey: identity.privateKey, publicKey: identity.publicKey, roomsRoot: identity.roomsRoot };
    }

    function sealedForm(identity) {
        return { sealed: identity.sealed, publicKey: identity.publicKey, roomsRoot: identity.roomsRoot };
    }

    // A database from before OWNER existed was always wiped whole on logout, so its records
    // belong to the identity it holds: that identity's key stands in for the missing owner
    function claimRecords(tx, publicKey, form) {
        const keys = tx.objectStore(STORE);
        const owner = keys.get(OWNER);
        owner.onsuccess = () => {
            const previous = keys.get(RECORD);
            previous.onsuccess = () => {
                const holder = owner.result || (previous.result && previous.result.publicKey);
                if (holder && holder !== publicKey) {
                    tx.objectStore(VERIFIED_STORE).clear();
                    tx.objectStore(COUNTERS_STORE).clear();
                    keys.delete(ALERTS);
                }
                keys.put(publicKey, OWNER);
                keys.put(form, RECORD);
            };
        };
    }

    // { present, identity }: whether a record is stored, and the identity it gives, or null. The
    // record is counted in a transaction of its own: a get this engine fails on (a key the
    // released build stored, read back in WebKit) aborts only its own transaction, so the record
    // still counts as present instead of the whole store as unavailable.
    async function readIdentity() {
        const present = (await run(STORE, 'readonly', tx => tx.objectStore(STORE).count(RECORD))) > 0;
        if (!present) return { present: false, identity: null };
        let record = null;
        try {
            record = await run(STORE, 'readonly', tx => tx.objectStore(STORE).get(RECORD));
        } catch (e) {
            // The cause is kept in the log; the page says W_IDENTITY_UNREADABLE (app.js)
            Log.warn(Errors.CODES.W_IDENTITY_UNREADABLE, e);
        }
        return { present: true, identity: await identityFrom(record) };
    }

    // The identity a stored record gives, or null. A record from before rooms has no rooms root:
    // logging in again derives it.
    async function identityFrom(record) {
        if (!record || typeof record !== 'object' || typeof record.publicKey !== 'string' ||
            !ElyrnRoomCrypto.isRoomsRoot(record.roomsRoot)) {
            return null;
        }
        let privateKey = record.privateKey;
        if (record.sealed !== undefined) {
            try {
                privateKey = await ElyrnCrypto.unsealIdentity(record.sealed, record.publicKey);
            } catch (e) {
                return null;
            }
        }
        if (!(privateKey instanceof CryptoKey) || privateKey.extractable) return null;
        return { privateKey: privateKey, publicKey: record.publicKey, roomsRoot: record.roomsRoot };
    }

    // { identity, unreadable }: the stored identity, or null; unreadable when a record is stored
    // but gives no identity (an engine that cannot read its key back, a damaged record, one the
    // released build wrote in a form WebKit cannot read). The main menu says so once
    // (app.js, W_IDENTITY_UNREADABLE); the next login replaces the record.
    async function load() {
        try {
            const read = await readIdentity();
            return { identity: read.identity, unreadable: read.present && !read.identity };
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return { identity: null, unreadable: false };
        }
    }

    // Whether alerts were turned on on this device for the identity kept here
    async function loadAlerts() {
        try {
            return (await transact('readonly', store => store.get(ALERTS))) === true;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    // Remembers alerts on, or forgets the preference; resolves to whether storage took it
    async function saveAlerts(on) {
        try {
            await transact('readwrite', store => (on === true ? store.put(true, ALERTS) : store.delete(ALERTS)));
            return true;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    // Verification is bound to the exact peer key that was compared
    async function setVerified(conversationId, peerPublicKey, verified) {
        try {
            await transact('readwrite', store => verified
                ? store.put(peerPublicKey, conversationId)
                : store.delete(conversationId), VERIFIED_STORE);
            return true;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    async function isVerified(conversationId, peerPublicKey) {
        try {
            return (await transact('readonly', store => store.get(conversationId), VERIFIED_STORE)) === peerPublicKey;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    // Without storage the record lives in memory only (counter-records.js), as before it was persisted.
    // Resolves to the stored value (undefined when none), or null when storage failed.
    async function countersRun(storeNames, mode, action) {
        try {
            const value = await run(storeNames, mode, action);
            return mode === 'readonly' ? value : true;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_COUNTERS_UNAVAILABLE, e);
            return null;
        }
    }

    function countersOp(mode, action) {
        return countersRun(COUNTERS_STORE, mode, tx => action(tx.objectStore(COUNTERS_STORE)));
    }

    // Runs action holding one conversation's counter lock, shared by every tab of this browser,
    // so two tabs never read, raise and write one counter record at once (counter-records.js). Without the
    // Web Locks API action runs unlocked, still reading fresh and writing ahead; logged once.
    function withCounterLock(conversationId, action) {
        if (navigator.locks && typeof navigator.locks.request === 'function') {
            return navigator.locks.request(COUNTER_LOCK_PREFIX + conversationId, () => action());
        }
        if (!lockWarned) {
            lockWarned = true;
            Log.warn(Errors.INTERNAL.W_COUNTER_LOCK_UNAVAILABLE);
        }
        return action();
    }

    function loadCounters(conversationId) {
        return countersOp('readonly', store => store.get(conversationId));
    }

    // Stores a raised record with its use stamp (the next USE_STAMP: an increasing number shared
    // by every tab, never a time) and its room's expiry (expiresMs; 0 for a pair), the two facts
    // pruneCounters keeps records by (counters.js KEEPING RECORDS)
    function saveCounters(conversationId, record, expiresMs) {
        return countersRun([STORE, COUNTERS_STORE], 'readwrite', tx => {
            const keys = tx.objectStore(STORE);
            const stamp = keys.get(USE_STAMP);
            stamp.onsuccess = () => {
                const used = (Number.isSafeInteger(stamp.result) && stamp.result > 0 ? stamp.result : 0) + 1;
                keys.put(used, USE_STAMP);
                tx.objectStore(COUNTERS_STORE).put({
                    seq: record.seq,
                    mine: record.mine,
                    senders: record.senders.map(entry => [entry[0], entry[1]]),
                    used: used,
                    expires: expiresMs
                }, conversationId);
            };
        });
    }

    // Only the user's own burn or leave the server confirmed: never a listing that omitted the
    // conversation or a 404 (counters.js KEEPING RECORDS)
    function forgetCounters(conversationId) {
        return countersOp('readwrite', store => store.delete(conversationId));
    }

    // Drops the records Counters.retention names (rooms expired long ago; past its bound the least
    // recently used, the conversations in `held` last), in one transaction. Resolves to whether
    // the bound evicted any (false when storage failed).
    async function pruneCounters(nowMs, held) {
        let evicted = false;
        const done = await countersOp('readwrite', store => {
            const entries = [];
            const cursor = store.openCursor();
            cursor.onsuccess = () => {
                const at = cursor.result;
                if (at) {
                    entries.push(Counters.retentionEntry(at.key, at.value));
                    at.continue();
                    return;
                }
                const verdict = Counters.retention(entries, nowMs, held);
                evicted = verdict.evicted;
                for (const id of verdict.drop) store.delete(id);
            };
        });
        return done === true && evicted;
    }

    // A session the server ended: the identity and its alerts preference go, the replay records
    // stay with their owner
    async function wipeIdentity() {
        try {
            await transact('readwrite', store => {
                store.delete(ALERTS);
                return store.delete(RECORD);
            });
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
        }
    }

    // The user's own logout or identity deletion: nothing stays. A connection of this tab still
    // open (a save queued behind a sync) is closed by its versionchange without retiring storage.
    function wipeAll() {
        return new Promise(resolve => {
            if (!window.indexedDB) {
                resolve();
                return;
            }
            wiping = true;
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = request.onerror = request.onblocked = () => {
                wiping = false;
                resolve();
            };
        });
    }

    return Object.freeze({
        keepsKeys, save, load, wipeIdentity, wipeAll, setVerified, isVerified, loadAlerts, saveAlerts,
        loadCounters, saveCounters, forgetCounters, pruneCounters, withCounterLock
    });
})();
