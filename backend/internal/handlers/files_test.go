package handlers

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/tests/testutil"
)

// A file request slot is given back on every path: when the work answers an error, when it
// panics, and when many run at once; with every slot held the next request is refused at once
// with 503 E_FILE_REQUESTS_BUSY and its work never runs.
func TestWithFileSlot_ReleasedOnEveryPath(t *testing.T) {
	free := fileRequestSlots.FreeForTesting()

	rec := httptest.NewRecorder()
	withFileSlot(rec, "test", func() { apperr.Write(rec, "test", apperr.NotFound) })
	if fileRequestSlots.FreeForTesting() != free || !testutil.IsAnswer(rec, apperr.NotFound) {
		t.Fatal("an answered error kept its slot")
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not reach the caller (middleware.Recover answers it there)")
			}
		}()
		withFileSlot(httptest.NewRecorder(), "test", func() { panic("work failed") })
	}()
	if fileRequestSlots.FreeForTesting() != free {
		t.Fatal("a panic kept its slot")
	}

	var wg sync.WaitGroup
	for i := 0; i < 4*maxConcurrentFileRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			withFileSlot(httptest.NewRecorder(), "test", func() {})
		}()
	}
	wg.Wait()
	if fileRequestSlots.FreeForTesting() != free {
		t.Fatal("concurrent requests leaked slots")
	}

	release := HoldFileRequestSlotsForTesting()
	ran := false
	busy := httptest.NewRecorder()
	withFileSlot(busy, "test", func() { ran = true })
	release()
	if ran || busy.Code != http.StatusServiceUnavailable || !testutil.IsAnswer(busy, apperr.FileRequestsBusy) {
		t.Fatalf("a request over the bound ran=%v and answered %d %q", ran, busy.Code, busy.Body.String())
	}
	if fileRequestSlots.FreeForTesting() != free {
		t.Fatal("the held slots did not come back")
	}
}
