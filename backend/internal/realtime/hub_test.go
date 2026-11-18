package realtime

import (
	"errors"
	"strconv"
	"testing"
)

// clientA and clientB stand for two networks (middleware.ClientKey values).
const (
	clientA = "client-a"
	clientB = "client-b"
)

// subscribeNow subscribes with the tag's current generation, as a stream whose session check
// saw no kick does.
func subscribeNow(h *Hub, tag, client string) (<-chan Event, func(), error) {
	generation, err := h.Generation(tag)
	if err != nil {
		return nil, nil, err
	}
	return h.Subscribe(tag, client, generation)
}

// C3 (events.go:EventsHandler:stream-outlives-session-revocation): a kick between the generation
// read (before the session check) and Subscribe is not missed. The old hub registered the late
// subscriber and kept it open.
func TestHub_KickBeforeSubscribeRefusesTheStaleGeneration(t *testing.T) {
	h := NewHub()
	stale, err := h.Generation("a")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Kick("a"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	if _, _, err := h.Subscribe("a", clientA, stale); !errors.Is(err, ErrRevokedSinceMark) {
		t.Fatalf("Subscribe with a generation read before the kick = %v, want ErrRevokedSinceMark", err)
	}
	if h.total != 0 || len(h.subs) != 0 || len(h.clients) != 0 {
		t.Fatalf("a refused subscribe took a slot: total=%d subs=%d clients=%d", h.total, len(h.subs), len(h.clients))
	}
	// A stream that reads the generation after the kick (a fresh session) subscribes
	_, cancel, err := subscribeNow(h, "a", clientA)
	if err != nil {
		t.Fatalf("Subscribe after the kick with a fresh generation: %v", err)
	}
	cancel()
	// Another tag's kick does not touch this tag's generation
	fresh, _ := h.Generation("a")
	if err := h.Kick("b"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	_, cancel, err = h.Subscribe("a", clientA, fresh)
	if err != nil {
		t.Fatalf("another tag's kick refused this one: %v", err)
	}
	cancel()
}

// The generation map stays within maxRevokedTags however many distinct tags are kicked, and its
// reset keeps every revocation: a generation read before a kick is refused even once the kicked
// tag's entry was dropped by the reset.
func TestHub_RevocationsBoundedAndKeptAcrossReset(t *testing.T) {
	h := NewHub()
	stale, err := h.Generation("victim")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Kick("victim"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	for i := 0; i < 2*maxRevokedTags; i++ {
		if err := h.Kick("tag-" + strconv.Itoa(i)); err != nil {
			t.Fatalf("Kick %d: %v", i, err)
		}
		if len(h.kicked) > maxRevokedTags {
			t.Fatalf("after %d kicks the hub keeps %d generations, bound %d", i+1, len(h.kicked), maxRevokedTags)
		}
	}
	if _, ok := h.kicked["victim"]; ok {
		t.Fatal("the reset under test never dropped the victim's entry")
	}
	if _, _, err := h.Subscribe("victim", clientA, stale); !errors.Is(err, ErrRevokedSinceMark) {
		t.Fatalf("a pre-kick generation after the reset = %v, want ErrRevokedSinceMark", err)
	}
	if _, cancel, err := subscribeNow(h, "victim", clientA); err != nil {
		t.Fatalf("a fresh generation after the reset: %v", err)
	} else {
		cancel()
	}
}

// A Kick that cannot take the hub lock reports it (the old Kick only logged), so logout and
// account deletion can answer 503 instead of success.
func TestHub_KickReportsALockTimeout(t *testing.T) {
	h := NewHub()
	if err := h.mu.Lock(); err != nil {
		t.Fatal(err)
	}
	err := h.Kick("a")
	h.mu.Unlock()
	if err == nil {
		t.Fatal("Kick with the hub lock held elsewhere reported success")
	}
}

func TestHub_PublishReachesOnlyTargetTags(t *testing.T) {
	h := NewHub()
	a, cancelA, err := subscribeNow(h, "a", clientA)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelA()
	b, cancelB, _ := subscribeNow(h, "b", clientA)
	defer cancelB()

	h.Publish([]string{"a"}, Event{Kind: KindMessage, ConversationID: "c1"})
	select {
	case ev := <-a:
		if ev.ConversationID != "c1" {
			t.Fatalf("unexpected event %+v", ev)
		}
	default:
		t.Fatal("subscriber a did not receive event")
	}
	select {
	case ev := <-b:
		t.Fatalf("subscriber b received foreign event %+v", ev)
	default:
	}
}

func TestHub_LimitsAndKick(t *testing.T) {
	h := NewHub()
	cancels := []func(){}
	for i := 0; i < MaxSubscribersPerMember; i++ {
		_, cancel, err := subscribeNow(h, "a", clientA)
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, err := subscribeNow(h, "a", clientA); err != ErrTooManySubscribers {
		t.Fatalf("expected per-member limit, got %v", err)
	}

	if err := h.Kick("a"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	if h.total != 0 || len(h.subs) != 0 {
		t.Fatalf("kick left state behind: total=%d subs=%d", h.total, len(h.subs))
	}
	// Cancels after kick must be harmless (idempotent, no double close)
	for _, cancel := range cancels {
		cancel()
	}
	// Publishing to a kicked tag must not panic
	h.Publish([]string{"a"}, Event{Kind: KindConversation})
}

func TestHub_FullBufferDropsInsteadOfBlocking(t *testing.T) {
	h := NewHub()
	_, cancel, _ := subscribeNow(h, "a", clientA)
	defer cancel()
	for i := 0; i < subscriberBuffer*3; i++ {
		h.Publish([]string{"a"}, Event{Kind: KindConversation})
	}
}

// fillClient opens one stream per account from client until its share is spent.
func fillClient(t *testing.T, h *Hub, client string) []func() {
	t.Helper()
	cancels := make([]func(), 0, MaxSubscribersPerClient)
	for i := 0; i < MaxSubscribersPerClient; i++ {
		_, cancel, err := subscribeNow(h, client+"-account-"+strconv.Itoa(i), client)
		if err != nil {
			t.Fatalf("subscribe %d within the share: %v", i, err)
		}
		cancels = append(cancels, cancel)
	}
	return cancels
}

func TestHub_ClientShareSpansAccounts(t *testing.T) {
	h := NewHub()
	cancels := fillClient(t, h, clientA)
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()
	// A fresh account on the same network is still the same network
	if _, _, err := subscribeNow(h, "one-more-account", clientA); err != ErrTooManySubscribers {
		t.Fatalf("expected the client share to refuse, got %v", err)
	}
	if h.total != MaxSubscribersPerClient || h.clients[clientA] != MaxSubscribersPerClient {
		t.Fatalf("a refused subscribe changed the counts: total=%d client=%d", h.total, h.clients[clientA])
	}
}

func TestHub_OtherClientStillSubscribes(t *testing.T) {
	h := NewHub()
	cancels := fillClient(t, h, clientA)
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()
	ch, cancel, err := subscribeNow(h, "someone-else", clientB)
	if err != nil {
		t.Fatalf("another network was refused while the first is at its share: %v", err)
	}
	defer cancel()
	h.Publish([]string{"someone-else"}, Event{Kind: KindConversation})
	select {
	case <-ch:
	default:
		t.Fatal("the other network's stream did not receive its event")
	}
}

func TestHub_ShareReleasedOnCancelAndKick(t *testing.T) {
	h := NewHub()
	cancels := fillClient(t, h, clientA)
	cancels[0]()
	cancels[0]() // idempotent: the share is returned once
	if h.clients[clientA] != MaxSubscribersPerClient-1 {
		t.Fatalf("cancel returned %d streams, want 1", MaxSubscribersPerClient-h.clients[clientA])
	}
	_, again, err := subscribeNow(h, "returning-account", clientA)
	if err != nil {
		t.Fatalf("a cancelled stream's share was not released: %v", err)
	}
	again()
	if err := h.Kick(clientA + "-account-1"); err != nil {
		t.Fatalf("Kick: %v", err)
	}
	for _, cancel := range cancels[2:] {
		cancel()
	}
	if h.total != 0 || len(h.subs) != 0 || len(h.clients) != 0 {
		t.Fatalf("state left behind: total=%d subs=%d clients=%d", h.total, len(h.subs), len(h.clients))
	}
	if _, _, err := subscribeNow(h, "a", ""); err != ErrNoClientKey {
		t.Fatalf("a stream without a client key was accepted: %v", err)
	}
}
