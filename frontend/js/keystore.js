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

    // A storage that refuses once (private window) refuses every time: log it once, not per sync
    let countersWarned = false;

    function open() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error('indexeddb unavailable'));
                return;
            }
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                for (const name of [STORE, VERIFIED_STORE, COUNTERS_STORE]) {
                    if (!db.objectStoreNames.contains(name)) {
                        db.createObjectStore(name);
                    }
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
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
            Log.warn(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
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
            return false;
        }
    }

    async function isVerified(conversationId, peerPublicKey) {
        try {
            return (await transact('readonly', store => store.get(conversationId), VERIFIED_STORE)) === peerPublicKey;
        } catch (e) {
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
            if (!countersWarned) {
                countersWarned = true;
                Log.warn(Errors.INTERNAL.W_COUNTERS_UNAVAILABLE, e);
            }
            return null;
        }
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
            Log.warn(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
        }
    }

    // The user's own logout or identity deletion: nothing stays
    function wipeAll() {
        return new Promise(resolve => {
            if (!window.indexedDB) {
                resolve();
                return;
            }
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = request.onerror = request.onblocked = () => resolve();
        });
    }

    return Object.freeze({ save, load, wipeIdentity, wipeAll, setVerified, isVerified, loadCounters, saveCounters, forgetCounters });
})();
