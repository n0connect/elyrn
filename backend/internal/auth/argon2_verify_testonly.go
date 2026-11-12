//go:build test
// +build test

package auth

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
)

// parseParam reads one "<name>=<canonical decimal>" field within [min, max].
func parseParam(field, name string, min, max uint64) (uint32, error) {
	digits := strings.TrimPrefix(field, name+"=")
	if digits == field || digits == "" {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	value, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || strconv.FormatUint(value, 10) != digits || value < min || value > max {
		return 0, fmt.Errorf("invalid %s parameter", name)
	}
	return uint32(value), nil
}

// VerifyAccountNumberHash verifies an auth key against a stored Argon2id hash
// ("argon2id$m=<KiB>$t=<n>$p=<n>$<salt hex>$<hash hex>"). Every parameter is range-checked
// before Argon2 runs, so a corrupted record can neither crash nor exhaust the server.
// Test builds only: login proves the key by the keyed lookup and reads no hash (S-02), but
// the hash registration stores must stay verifiable while it is kept (S-07).
func VerifyAccountNumberHash(encodedHash, accountNumber string) error {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "argon2id" {
		return fmt.Errorf("invalid hash format: expected 6 parts starting with 'argon2id'")
	}
	memory, err := parseParam(parts[1], "m", config.MinArgon2MemoryKiB, config.MaxArgon2MemoryKiB)
	if err != nil {
		return err
	}
	timeCost, err := parseParam(parts[2], "t", config.MinArgon2Time, config.MaxArgon2Time)
	if err != nil {
		return err
	}
	parallelism, err := parseParam(parts[3], "p", config.MinArgon2Parallelism, config.MaxArgon2Parallelism)
	if err != nil {
		return err
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil || len(salt) < config.MinArgon2SaltBytes || len(salt) > config.MaxArgon2SaltBytes {
		return fmt.Errorf("invalid salt")
	}
	expectedHash, err := hex.DecodeString(parts[5])
	if err != nil || len(expectedHash) < config.MinArgon2HashBytes || len(expectedHash) > config.MaxArgon2HashBytes {
		return fmt.Errorf("invalid hash")
	}

	computedHash, err := withArgon2Slot(func() ([]byte, error) {
		return cryptoengine.Argon2idKey([]byte(accountNumber), salt, timeCost, memory, parallelism, uint32(len(expectedHash)))
	})
	if errors.Is(err, ErrBusy) {
		return err
	}
	if err != nil {
		return fmt.Errorf("argon2id failed: %w", err)
	}

	// Constant-time comparison
	if !cryptoengine.ConstantTimeEqual(computedHash, expectedHash) {
		return errors.New("account number hash mismatch")
	}
	return nil
}
