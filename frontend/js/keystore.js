// ========================================
// KEYSTORE (IndexedDB)
// ========================================
// Persists ONLY the non-extractable X25519 CryptoKey, its public key and the non-extractable
// rooms root (an HKDF key every room key derives from), so a reload does not require
// re-entering the account number. Raw key bytes cannot be read back out of a
// non-extractable CryptoKey, not even by script running on this page.
// The AccountNumber itself is never stored anywhere.
// It also remembers which conversations the user verified (safety number compared),
// bound to the peer key that was verified, and, per conversation, the counter record that
// exposes replays after a reload (counters.js: highest seq and counters, never text, ids or
// times). None of this ever reaches the server.
//
// Two ways to forget. wipeIdentity() is for what the server decides (a 401, a refused /me): it
// removes the identity record only, so the counter records and verification marks survive and a
// server cannot erase replay protection by ending a session once. wipeAll() is the user's own
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
    // Web Locks name of one conversation's counter record, shared by every tab of this browser
    const COUNTER_LOCK_PREFIX = 'elyrn-counter-';

    // A storage that refuses once (private window) refuses every time: say it once, not per sync
    let storageWarned = false;
    // Another tab upgraded or deleted the database under this one: storage is not used again here
    let retired = false;
    // This tab is deleting the database itself (wipeAll): its own versionchange is no news
    let wiping = false;
    let lockWarned = false;

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

    // Stores the identity, and first clears the records of any other account (see OWNER above)
    async function save(identity) {
        try {
            await run([STORE, VERIFIED_STORE, COUNTERS_STORE], 'readwrite', tx => claimRecords(tx, identity));
            return true;
        } catch (e) {
            // Private windows may block IndexedDB: identity then lives in memory only
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
    }

    // A database from before OWNER existed was always wiped whole on logout, so its records
    // belong to the identity it holds: that identity's key stands in for the missing owner
    function claimRecords(tx, identity) {
        const keys = tx.objectStore(STORE);
        const owner = keys.get(OWNER);
        owner.onsuccess = () => {
            const previous = keys.get(RECORD);
            previous.onsuccess = () => {
                const holder = owner.result || (previous.result && previous.result.publicKey);
                if (holder && holder !== identity.publicKey) {
                    tx.objectStore(VERIFIED_STORE).clear();
                    tx.objectStore(COUNTERS_STORE).clear();
                }
                keys.put(identity.publicKey, OWNER);
                keys.put({
                    privateKey: identity.privateKey,
                    publicKey: identity.publicKey,
                    roomsRoot: identity.roomsRoot
                }, RECORD);
            };
        };
    }

    async function load() {
        try {
            const record = await transact('readonly', store => store.get(RECORD));
            // A record from before rooms has no rooms root: logging in again derives it
            if (!record || !(record.privateKey instanceof CryptoKey) || record.privateKey.extractable ||
                typeof record.publicKey !== 'string' || !ElyrnRoomCrypto.isRoomsRoot(record.roomsRoot)) {
                return null;
            }
            return { privateKey: record.privateKey, publicKey: record.publicKey, roomsRoot: record.roomsRoot };
        } catch (e) {
            unavailable(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return null;
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

    // Without storage the record lives in memory only (chat.js), as before it was persisted.
    // Resolves to the stored value (undefined when none), or null when storage failed.
    async function countersOp(mode, action) {
        try {
            const value = await transact(mode, action, COUNTERS_STORE);
            return mode === 'readonly' ? value : true;
        } catch (e) {
            unavailable(Errors.INTERNAL.W_COUNTERS_UNAVAILABLE, e);
            return null;
        }
    }

    // Runs action holding one conversation's counter lock, shared by every tab of this browser,
    // so two tabs never read, raise and write one counter record at once (chat.js). Without the
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

    function saveCounters(conversationId, record) {
        return countersOp('readwrite', store => store.put({
            seq: record.seq,
            mine: record.mine,
            senders: record.senders.map(entry => [entry[0], entry[1]])
        }, conversationId));
    }

    // Burned, left or gone: nothing about the conversation stays behind
    function forgetCounters(conversationId) {
        return countersOp('readwrite', store => store.delete(conversationId));
    }

    // A session the server ended: the identity goes, the replay records stay with their owner
    async function wipeIdentity() {
        try {
            await transact('readwrite', store => store.delete(RECORD));
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
        save, load, wipeIdentity, wipeAll, setVerified, isVerified,
        loadCounters, saveCounters, forgetCounters, withCounterLock
    });
})();
