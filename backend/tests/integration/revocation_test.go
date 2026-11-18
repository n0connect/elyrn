package integration

// Session revocation and the live event stream (C3, logout partial revocation): a logout or an
// account deletion whose streams could not be closed answers the registered 503 after the
// sessions were revoked, a stream that missed its kick ends at its next heartbeat, and a kick
// that lands between the stream's generation read and its subscription refuses the stream.
// The hub lock is held with the real lock (realtime.Hub.HoldLockForTesting), the stream tag's
// pepper is really removed, the database is really stalled (testutil.StallingProxy).

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/tests/testutil"
)

const (
	// streamEndBound is how long a stream whose session was revoked may stay open: one heartbeat
	// (handlers.sseKeepAlive, 10 s) until the session re-check, a second one of slack
	streamEndBound = 20 * time.Second
	// markToStallPause lets a stream request pass its generation read (no database) and reach
	// the session check's statement, which the stalled database holds
	markToStallPause = 500 * time.Millisecond
)

// holdHub takes the real hub's lock for the caller until release; a kick, generation read or
// subscription meanwhile fails after utils.DefaultLockTimeout.
func holdHub(t *testing.T) func() {
	t.Helper()
	unlock, err := realtime.Default.HoldLockForTesting()
	if err != nil {
		t.Fatalf("hold the hub lock: %v", err)
	}
	released := false
	t.Cleanup(func() {
		if !released {
			unlock()
		}
	})
	return func() {
		released = true
		unlock()
	}
}

// streamTagOf derives u's stream tag the way the server does, from its session token's account.
func streamTagOf(t *testing.T, u *user) string {
	t.Helper()
	session, err := auth.VerifyToken(u.cookie.Value)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	tag, err := identity.StreamTag(session.UserUUID)
	if err != nil {
		t.Fatalf("StreamTag: %v", err)
	}
	return tag
}

// expectRevoked insists the session behind cookie is refused now (401).
func expectRevoked(t *testing.T, mux http.Handler, cookie http.Cookie, what string) {
	t.Helper()
	stale := newClient(t, mux)
	stale.cookie = &cookie
	expectStatus(t, stale.do(http.MethodGet, models.PathMe, nil), http.StatusUnauthorized, what)
}

// A logout whose kick cannot take the hub lock used to answer 200 while the account's streams
// stayed open; now it answers 503 E_STORE_UNAVAILABLE, after the sessions were revoked.
func TestLogout_KickTimeoutAnswersUnavailable(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	session := *alice.cookie
	release := holdHub(t)
	rr := alice.do(http.MethodPost, models.PathLogout, nil)
	release()
	expectAnswer(t, rr, apperr.StoreUnavailable, "logout with the hub lock held")
	if rr.Header().Get("Clear-Site-Data") != "" {
		t.Fatal("a partial revocation answered Clear-Site-Data, as a completed logout does")
	}
	expectRevoked(t, mux, session, "the session after a partial revocation")
}

// A logout that cannot derive the stream tag (no pepper) used to skip the kick silently and
// answer 200; now it reports the partial revocation.
func TestLogout_StreamTagUnavailableAnswersUnavailable(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	session := *alice.cookie
	pepper := os.Getenv("ACCOUNT_LOOKUP_PEPPER")
	t.Setenv("ACCOUNT_LOOKUP_PEPPER", "")
	expectAnswer(t, alice.do(http.MethodPost, models.PathLogout, nil), apperr.StoreUnavailable,
		"logout without the stream tag's key")
	t.Setenv("ACCOUNT_LOOKUP_PEPPER", pepper)
	expectRevoked(t, mux, session, "the session after a partial revocation")
}

// An account deletion whose kick cannot take the hub lock answers 503 too: the account is gone,
// its other devices' streams may not be.
func TestAccountDeletion_KickTimeoutAnswersUnavailable(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	session := *alice.cookie
	release := holdHub(t)
	rr := alice.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: alice.authKey})
	release()
	expectAnswer(t, rr, apperr.StoreUnavailable, "account deletion with the hub lock held")
	expectRevoked(t, mux, session, "the session of a deleted account")
}

// A stream the kick did not reach (the hub lock was held) used to stay open until its 10-minute
// lifetime; now it ends at its next heartbeat, whose session check finds the epoch bumped.
func TestEvents_StreamEndsAtHeartbeatAfterMissedKick(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	srv := eventServer(t, mux)
	resp, lines := openEvents(t, srv, alice.cookie)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	release := holdHub(t)
	rr := alice.do(http.MethodPost, models.PathLogout, nil)
	release()
	expectAnswer(t, rr, apperr.StoreUnavailable, "logout with the hub lock held")

	deadline := time.After(streamEndBound)
	for {
		select {
		case _, open := <-lines:
			if !open {
				return
			}
		case <-deadline:
			t.Fatalf("the stream of a revoked session was still open %v after the logout", streamEndBound)
		}
	}
}

// A kick that lands after the stream read its tag's generation (before the session check) but
// before it subscribed refuses the stream. The database is stalled while the stream's session
// check waits on it, the account's streams are kicked, then the database resumes: the session
// check still sees the old epoch (the kick is the race this closes; the epoch bump is covered
// above), and the stream is refused with the stream's "retry later" instead of being admitted.
func TestEvents_KickBetweenGenerationAndSubscribeRefusesTheStream(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	tag := streamTagOf(t, alice)
	srv := eventServer(t, mux)
	proxy := stallDatabase(t)
	proxy.Stall()

	// The stream's answer: the response (its body read unless admitted) or the request's error
	type answer struct {
		resp *http.Response
		body []byte
		err  error
	}
	answers := make(chan answer, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, srv.URL+models.PathEvents, nil)
		if err != nil {
			answers <- answer{err: err}
			return
		}
		req.AddCookie(alice.cookie)
		resp, err := srv.Client().Do(req)
		if err != nil {
			answers <- answer{err: err}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			answers <- answer{resp: resp}
			return
		}
		body, err := io.ReadAll(resp.Body)
		answers <- answer{resp: resp, body: body, err: err}
	}()

	time.Sleep(markToStallPause)
	if err := realtime.Default.Kick(tag); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	proxy.Resume()

	got := <-answers
	if got.err != nil {
		t.Fatalf("events: %v", got.err)
	}
	if got.resp.StatusCode == http.StatusOK {
		t.Fatal("a stream subscribed after a kick that followed its generation read")
	}
	if !testutil.IsWireAnswer(got.resp, got.body, apperr.SubscriberLimit) {
		t.Fatalf("the refused stream answered %d %q, want E_SUBSCRIBER_LIMIT", got.resp.StatusCode, got.body)
	}
}
