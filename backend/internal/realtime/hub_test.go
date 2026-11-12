package realtime

import (
	"strconv"
	"testing"
)

// clientA and clientB stand for two networks (middleware.ClientKey values).
const (
	clientA = "client-a"
	clientB = "client-b"
)

func TestHub_PublishReachesOnlyTargetTags(t *testing.T) {
	h := NewHub()
	a, cancelA, err := h.Subscribe("a", clientA)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelA()
	b, cancelB, _ := h.Subscribe("b", clientA)
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
		_, cancel, err := h.Subscribe("a", clientA)
		if err != nil {
			t.Fatalf("subscribe %d: %v", i, err)
		}
		cancels = append(cancels, cancel)
	}
	if _, _, err := h.Subscribe("a", clientA); err != ErrTooManySubscribers {
		t.Fatalf("expected per-member limit, got %v", err)
	}

	h.Kick("a")
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
	_, cancel, _ := h.Subscribe("a", clientA)
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
		_, cancel, err := h.Subscribe(client+"-account-"+strconv.Itoa(i), client)
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
	if _, _, err := h.Subscribe("one-more-account", clientA); err != ErrTooManySubscribers {
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
	ch, cancel, err := h.Subscribe("someone-else", clientB)
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
	_, again, err := h.Subscribe("returning-account", clientA)
	if err != nil {
		t.Fatalf("a cancelled stream's share was not released: %v", err)
	}
	again()
	h.Kick(clientA + "-account-1")
	for _, cancel := range cancels[2:] {
		cancel()
	}
	if h.total != 0 || len(h.subs) != 0 || len(h.clients) != 0 {
		t.Fatalf("state left behind: total=%d subs=%d clients=%d", h.total, len(h.subs), len(h.clients))
	}
	if _, _, err := h.Subscribe("a", ""); err != ErrNoClientKey {
		t.Fatalf("a stream without a client key was accepted: %v", err)
	}
}
