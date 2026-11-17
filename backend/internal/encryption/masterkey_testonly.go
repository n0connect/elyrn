//go:build test
// +build test

package encryption

import "sync"

// ResetMasterKeysForTesting clears cached master key state for tests.
func ResetMasterKeysForTesting() {
	masterKeyOnce = sync.Once{}
	masterKeyError = nil
	masterKeys = masterKeySet{}
	keyUse.Lock()
	closed = false
	keyUse.Unlock()
}

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
