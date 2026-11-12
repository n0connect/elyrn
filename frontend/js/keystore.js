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

    async function transact(mode, action, storeName = STORE) {
        const db = await open();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(storeName, mode);
                const request = action(tx.objectStore(storeName));
                tx.oncomplete = () => resolve(request ? request.result : undefined);
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
        } finally {
            db.close();
        }
    }

    async function save(identity) {
        try {
            await transact('readwrite', store => store.put({
                privateKey: identity.privateKey,
                publicKey: identity.publicKey,
                roomsRoot: identity.roomsRoot
            }, RECORD));
            return true;
        } catch (e) {
            // Private windows may block IndexedDB: identity then lives in memory only
            Log.warn(Errors.INTERNAL.W_KEYSTORE_UNAVAILABLE, e);
            return false;
        }
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

    function wipe() {
        return new Promise(resolve => {
            if (!window.indexedDB) {
                resolve();
                return;
            }
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = request.onerror = request.onblocked = () => resolve();
        });
    }

    return Object.freeze({ save, load, wipe, setVerified, isVerified, loadCounters, saveCounters, forgetCounters });
})();
