package encryption

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/config"
	"elyrn/internal/utils"
)

var masterKeyLogger = utils.NewLogger("MASTER_KEY")

const masterKeyBytes = 32

// The variables that hold the master keys
const (
	envActiveKey   = "MASTER_KEY_ACTIVE"
	envActiveKeyID = "MASTER_KEY_ACTIVE_ID"
	envOldKeys     = "MASTER_KEY_OLD"
)

type masterKeySet struct {
	activeID string
	active   []byte
	old      map[string][]byte
}

var (
	masterKeys     masterKeySet
	masterKeyOnce  sync.Once
	masterKeyError error
)

// keyIDPattern whitelists master key ids: they are stored next to every record (size:32)
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// InitMasterKeys loads MASTER_KEY_ACTIVE(_ID) and MASTER_KEY_OLD ("id:key,id:key").
// Fails closed: any malformed entry stops startup, because a silently dropped old key would
// make every record it protects unreadable.
func InitMasterKeys() error {
	masterKeyOnce.Do(func() {
		masterKeys, masterKeyError = loadMasterKeys()
		if masterKeyError == nil {
			masterKeyLogger.Info("Master keys initialized: active_id=%s old_keys=%d", masterKeys.activeID, len(masterKeys.old))
		}
	})
	return masterKeyError
}

func loadMasterKeys() (masterKeySet, error) {
	activeID := strings.TrimSpace(config.GetEnv(envActiveKeyID, ""))
	activeKeyRaw := strings.TrimSpace(config.GetEnv(envActiveKey, ""))
	if activeKeyRaw == "" {
		return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envActiveKey, "is required")
	}
	if !keyIDPattern.MatchString(activeID) {
		return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envActiveKeyID, "must match "+keyIDPattern.String())
	}
	activeKey, err := decodeKeyMaterial(activeKeyRaw)
	if err != nil {
		return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envActiveKey, err.Error())
	}

	oldKeys := make(map[string][]byte)
	oldRaw := strings.TrimSpace(config.GetEnv(envOldKeys, ""))
	if oldRaw != "" {
		for _, entry := range strings.Split(oldRaw, ",") {
			parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
			if len(parts) != 2 {
				return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envOldKeys, "entries must be id:key")
			}
			kid := strings.TrimSpace(parts[0])
			if !keyIDPattern.MatchString(kid) || kid == activeID {
				return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envOldKeys, "has an invalid key id or the active one")
			}
			if _, dup := oldKeys[kid]; dup {
				return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envOldKeys, "repeats a key id")
			}
			key, err := decodeKeyMaterial(strings.TrimSpace(parts[1]))
			if err != nil {
				return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envOldKeys, "has invalid key material")
			}
			if subtle.ConstantTimeCompare(key, activeKey) == 1 {
				return masterKeySet{}, opcode.Fail(opcode.ConfigInvalid, envOldKeys, "repeats the active key")
			}
			oldKeys[kid] = key
		}
	}
	return masterKeySet{activeID: activeID, active: activeKey, old: oldKeys}, nil
}

// ErrClosing: the server is shutting down and its master keys are being zeroized; nothing is
// sealed or opened any more (apperr answers 503 E_SHUTTING_DOWN). A late request can therefore
// never seal a record under a zeroized key.
var ErrClosing = errors.New("master keys closed")

// keyUse guards the key material against Close: every use of a master key holds it for reading
// for the whole operation, Close takes it for writing, so it waits for every operation in flight
// and zeroizes nothing that is still being used. closed is read and written under it.
var (
	keyUse sync.RWMutex
	closed bool
)

// ActiveMasterKey returns the active master key, for inspection only (tests, its length):
// sealing goes through SealWithActiveKey, which holds the key for the whole operation.
func ActiveMasterKey() []byte {
	if err := InitMasterKeys(); err != nil {
		// Unreachable in a running server: the result is cached once and startup refuses to run
		// on it (ValidateStartupConfig); getting here means encrypting without a key, so abort
		panic(err)
	}
	return masterKeys.active
}

// withActiveKey runs fn with the active key and its id while holding the key, or answers
// ErrClosing once Close has begun.
func withActiveKey(fn func(id string, key []byte) error) error {
	if err := InitMasterKeys(); err != nil {
		// Unreachable in a running server (see ActiveMasterKey): a record must never be
		// labelled with an empty key id or sealed without a key, so abort
		panic(err)
	}
	keyUse.RLock()
	defer keyUse.RUnlock()
	if closed {
		return ErrClosing
	}
	return fn(masterKeys.activeID, masterKeys.active)
}

// withKeyByID runs fn with the master key named id while holding it; unknown ids and a closed
// key set answer ok=false (or ErrClosing).
func withKeyByID(id string, fn func(key []byte) error) (ok bool, err error) {
	if err := InitMasterKeys(); err != nil {
		return false, nil
	}
	keyUse.RLock()
	defer keyUse.RUnlock()
	if closed {
		return false, ErrClosing
	}
	key, ok := masterKeys.old[id]
	if id == masterKeys.activeID {
		key, ok = masterKeys.active, true
	}
	if !ok {
		return false, nil
	}
	return true, fn(key)
}

// SealWithActiveKey seals text under the active master key with aad (EncryptWithAAD), holding
// the key for the whole operation.
func SealWithActiveKey(text string, aad []byte) (string, error) {
	var sealed string
	err := withActiveKey(func(_ string, key []byte) error {
		var err error
		sealed, err = EncryptWithAAD(text, key, aad)
		return err
	})
	return sealed, err
}

// OpenWithKeyID opens text sealed under the master key named id with aad (DecryptWithAAD).
// ok is false when no such key is configured.
func OpenWithKeyID(id, text string, aad []byte) (plain string, ok bool, err error) {
	ok, err = withKeyByID(id, func(key []byte) error {
		var err error
		plain, err = DecryptWithAAD(text, key, aad)
		return err
	})
	return plain, ok, err
}

func ActiveMasterKeyID() string {
	if err := InitMasterKeys(); err != nil {
		// Unreachable in a running server (see ActiveMasterKey): a record must never be
		// labelled with an empty key id, so abort
		panic(err)
	}
	return masterKeys.activeID
}

// OldMasterKeyIDs lists the configured MASTER_KEY_OLD ids in sorted order.
func OldMasterKeyIDs() []string {
	if err := InitMasterKeys(); err != nil {
		return nil
	}
	ids := make([]string, 0, len(masterKeys.old))
	for id := range masterKeys.old {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// HasMasterKey reports whether a master key with this id is configured.
func HasMasterKey(id string) bool {
	if err := InitMasterKeys(); err != nil {
		return false
	}
	if id == masterKeys.activeID {
		return true
	}
	_, ok := masterKeys.old[id]
	return ok
}

// decodeKeyMaterial accepts exactly 32 bytes of key material encoded as hex or base64.
// Raw text is never a key: a 32-character passphrase has a fraction of 256 bits of entropy.
func decodeKeyMaterial(keyRaw string) ([]byte, error) {
	if decoded, err := hex.DecodeString(keyRaw); err == nil && len(decoded) == masterKeyBytes {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(keyRaw); err == nil && len(decoded) == masterKeyBytes {
		return decoded, nil
	}
	return nil, fmt.Errorf("must be 32 bytes as hex (64 chars) or base64")
}

// zeroizeKey securely zeros key material in memory (RULES.md §1.2)
func zeroizeKey(key []byte) {
	if len(key) == 0 {
		return
	}
	// Zero out the slice
	for i := range key {
		key[i] = 0
	}
	// Ensure compiler doesn't optimize away the zeroing
	if len(key) > 0 {
		ptr := unsafe.Pointer(&key[0])
		for i := 0; i < len(key); i++ {
			*(*byte)(unsafe.Add(ptr, i)) = 0
		}
	}
}

// Close ends every use of the master keys: it waits for each operation in flight, refuses
// every later one (ErrClosing) and zeroizes the key material (RULES.md §1.2). Call it last on
// shutdown, after the HTTP server and the background jobs have stopped.
func Close() {
	keyUse.Lock()
	defer keyUse.Unlock()
	closed = true
	zeroizeKey(masterKeys.active)
	for _, key := range masterKeys.old {
		zeroizeKey(key)
	}
}
