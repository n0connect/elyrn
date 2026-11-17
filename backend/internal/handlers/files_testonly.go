//go:build test
// +build test

package handlers

// FileRequestSlotsFreeForTesting reports how many file request slots are free.
// SECURITY: compiled only with -tags test.
func FileRequestSlotsFreeForTesting() int {
	return fileRequestSlots.FreeForTesting()
}

// MaxConcurrentFileRequestsForTesting is the bound itself.
func MaxConcurrentFileRequestsForTesting() int {
	return maxConcurrentFileRequests
}

// HoldFileRequestSlotsForTesting takes every free file request slot, as that many authenticated
// requests in flight would, and returns how to give them back.
func HoldFileRequestSlotsForTesting() (release func()) {
	held := 0
	for fileRequestSlots.Acquire(noWait) == nil {
		held++
	}
	return func() {
		for ; held > 0; held-- {
			fileRequestSlots.Release()
		}
	}
}
