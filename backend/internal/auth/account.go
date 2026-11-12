package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"
)

var accountLogger = utils.NewLogger("ACCOUNT")

// Argon2id runs only in registration phase 2 (login proves the key by the keyed lookup).
// It allocates ARGON2_MEMORY_KIB per call (64 MiB by default), so unbounded
// concurrency is a memory-exhaustion attack. At most ARGON2_MAX_CONCURRENT calls run at
// once; a caller waits up to Argon2WaitTimeout for a slot and otherwise gets ErrBusy.
const Argon2WaitTimeout = 3 * time.Second

// ErrBusy: every Argon2id slot was taken for the whole wait; the client retries later.
var ErrBusy = errors.New("argon2: server busy")

var (
	slotsOnce sync.Once
	slots     *utils.Slots
)

func argon2Slots() *utils.Slots {
	slotsOnce.Do(func() { slots = utils.NewSlots(config.GetArgon2MaxConcurrent()) })
	return slots
}

// withArgon2Slot runs fn inside one of the bounded Argon2id slots.
func withArgon2Slot(fn func() ([]byte, error)) ([]byte, error) {
	if err := argon2Slots().Acquire(Argon2WaitTimeout); err != nil {
		return nil, ErrBusy
	}
	defer argon2Slots().Release()
	return fn()
}

type argon2Params struct {
	memoryKiB  uint32
	time       uint32
	parallel   uint32
	saltLength uint32
	hashLength uint32
}

func getArgon2Params() (argon2Params, error) {
	memory := config.GetArgon2MemoryKiB()
	timeCost := config.GetArgon2Time()
	parallel := config.GetArgon2Parallelism()
	saltLen := config.GetArgon2SaltLength()
	hashLen := config.GetArgon2HashLength()

	if memory <= 0 || timeCost <= 0 || parallel <= 0 || saltLen <= 0 || hashLen <= 0 {
		return argon2Params{}, fmt.Errorf("argon2 parameters not configured")
	}

	return argon2Params{
		memoryKiB:  uint32(memory),
		time:       uint32(timeCost),
		parallel:   uint32(parallel),
		saltLength: uint32(saltLen),
		hashLength: uint32(hashLen),
	}, nil
}

// accountLookupHexLen is the length of every lookup ComputeAccountLookup returns: the hex of
// one HMAC-SHA256 output.
const accountLookupHexLen = 2 * 32

// absentAccountLookup stands in for the stored lookup when no account matched, so a login for
// an unknown key runs the same comparison on the same length as one for a known key. It is
// not hex, so no computed lookup can ever equal it.
var absentAccountLookup = strings.Repeat("x", accountLookupHexLen)

// AccountLookupMatches proves knowledge of the auth key: the lookup computed from the
// presented key equals the account's stored one, compared in constant time. A nil-account
// caller passes "" and is compared against absentAccountLookup instead (always false).
func AccountLookupMatches(computed, stored string) bool {
	if stored == "" {
		stored = absentAccountLookup
	}
	return cryptoengine.ConstantTimeEqual([]byte(computed), []byte(stored))
}

// ComputeAccountLookup computes HMAC-SHA256(pepper, accountNumber) for fast database lookup
// Returns hex-encoded string
func ComputeAccountLookup(accountNumber string) (string, error) {
	pepper := config.GetAccountLookupPepper()
	if len(pepper) == 0 {
		return "", errors.New("ACCOUNT_LOOKUP_PEPPER not configured")
	}
	if len(pepper) < 32 {
		return "", errors.New("ACCOUNT_LOOKUP_PEPPER too short")
	}
	mac, err := cryptoengine.HMACSHA256(pepper, []byte(accountNumber))
	if err != nil {
		return "", err
	}
	lookup := hex.EncodeToString(mac)

	accountLogger.Debug("ComputeAccountLookup: computed lookup for account number (masked)")
	return lookup, nil
}

// HashAccountNumber hashes account number using Argon2id
// Returns encoded hash string with parameters
func HashAccountNumber(accountNumber string) (string, error) {
	params, err := getArgon2Params()
	if err != nil {
		return "", err
	}

	// Generate random salt
	salt, err := cryptoengine.RandomBytes(int(params.saltLength))
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash with Argon2id
	hash, err := withArgon2Slot(func() ([]byte, error) {
		return cryptoengine.Argon2idKey([]byte(accountNumber), salt, params.time, params.memoryKiB, params.parallel, params.hashLength)
	})
	if errors.Is(err, ErrBusy) {
		return "", err
	}
	if err != nil {
		return "", fmt.Errorf("argon2id failed: %w", err)
	}

	// Encode: format = "argon2id$m=memory$t=time$p=parallelism$salt$hash"
	// Using hex encoding for both salt and hash
	encoded := fmt.Sprintf("argon2id$m=%d$t=%d$p=%d$%s$%s",
		params.memoryKiB,
		params.time,
		params.parallel,
		hex.EncodeToString(salt),
		hex.EncodeToString(hash))

	accountLogger.Debug("HashAccountNumber: hashed account number (masked)")
	return encoded, nil
}
