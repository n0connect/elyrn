// Package realtime fans out content-free "pokes" to connected clients over SSE.
// Events never carry ciphertext: clients refetch through the authorized REST path,
// so there is exactly one code path that decides who may read what.
package realtime

import (
	"errors"

	"elyrn/internal/utils"
)

const (
	// MaxSubscribersPerMember bounds open tabs/devices per identity.
	MaxSubscribersPerMember = 4
	// MaxSubscribersPerClient is one network's share of the hub (middleware.ClientKey: an IPv4
	// address, an IPv6 /64 or a Tor circuit), however many accounts it holds. 16 is four
	// accounts at their full per-account cap: a household or small office behind one NAT, each
	// person with a phone, a laptop and a spare tab. Accounts cost only a proof of work, so
	// without this share one network could hold every stream; now it takes 256 networks.
	MaxSubscribersPerClient = 16
	// MaxSubscribersTotal bounds goroutines and sockets held by event streams.
	MaxSubscribersTotal = 4096
	// subscriberBuffer absorbs bursts; a full buffer drops pokes (clients resync on reconnect).
	subscriberBuffer = 32
	// maxRevokedTags bounds the revocation generations kept per stream tag (one entry per tag
	// kicked since the last reset, ~100 bytes each). At the bound the map is reset under a raised
	// floor (Kick), which keeps every revocation in force; see Generation for the proof.
	maxRevokedTags = 4096
)

// Event kinds (whitelist): the SSE handler only ever writes these names.
const (
	KindMessage      = "msg"  // new message in conversation ConversationID
	KindConversation = "conv" // conversation list changed (created / burned)
)

var (
	ErrTooManySubscribers = errors.New("too many subscribers")
	ErrNoClientKey        = errors.New("subscriber without a client key")
	// ErrRevokedSinceMark: the stream tag was kicked after its generation was read (Generation),
	// so the session the subscriber proved may already be revoked
	ErrRevokedSinceMark = errors.New("stream tag revoked since its generation was read")
	hubLogger           = utils.NewLogger("REALTIME")
)

// Event is a content-free notification.
type Event struct {
	Kind           string
	ConversationID string
}

// Hub maps stream tags to live subscriber channels, each remembering the client (network) that
// opened it so its share is released with it, and keeps a revocation generation per kicked tag.
// Lock order: Hub.mu is a leaf lock (Priority Level 1); nothing is acquired while holding it,
// and every acquisition is bounded by utils.DefaultLockTimeout. It guards the generations too.
type Hub struct {
	mu      *utils.SafeMutex
	subs    map[string]map[chan Event]string // stream tag -> channel -> client key
	clients map[string]int                   // client key -> open streams
	total   int
	// kicked maps a stream tag to the sequence number of its latest Kick; a tag absent from it
	// has generation floor. kickSeq is the last sequence number Kick handed out.
	kicked  map[string]uint64
	kickSeq uint64
	floor   uint64
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{mu: utils.NewSafeMutex(), subs: make(map[string]map[chan Event]string),
		clients: make(map[string]int), kicked: make(map[string]uint64)}
}

// Default is the process-wide hub used by handlers.
var Default = NewHub()

// Generation returns memberTag's revocation generation. A stream reads it before its session is
// checked and hands it to Subscribe, which refuses when the tag was kicked in between.
//
// Why no revocation is lost, although the map is bounded: a value read here is at most kickSeq
// at that moment. A later Kick of the tag stores a strictly larger kickSeq. From then on the
// tag's generation is either its entry (which only grows) or, once a reset dropped the entry,
// floor, which the reset raised to at least every value handed out before it. Either way it is
// above the value read, so Subscribe refuses. A reset can also refuse a stream of a tag that
// was never kicked (its read floor is raised): that costs one retried stream, never a missed
// revocation, and happens once per maxRevokedTags distinct kicked tags.
func (h *Hub) Generation(memberTag string) (uint64, error) {
	if err := h.mu.Lock(); err != nil {
		return 0, err
	}
	defer h.mu.Unlock()
	return h.generationLocked(memberTag), nil
}

// generationLocked is memberTag's generation. Caller holds h.mu.
func (h *Hub) generationLocked(memberTag string) uint64 {
	if gen, ok := h.kicked[memberTag]; ok {
		return gen
	}
	return h.floor
}

// Subscribe registers a channel for a stream tag opened from clientKey's network, within the
// account's, the network's and the hub's caps, provided the tag was not kicked since generation
// was read (Generation). The returned cancel func is idempotent.
func (h *Hub) Subscribe(memberTag, clientKey string, generation uint64) (<-chan Event, func(), error) {
	if clientKey == "" {
		return nil, nil, ErrNoClientKey
	}
	if err := h.mu.Lock(); err != nil {
		return nil, nil, err
	}
	defer h.mu.Unlock()

	if h.generationLocked(memberTag) != generation {
		return nil, nil, ErrRevokedSinceMark
	}
	if h.total >= MaxSubscribersTotal || len(h.subs[memberTag]) >= MaxSubscribersPerMember ||
		h.clients[clientKey] >= MaxSubscribersPerClient {
		return nil, nil, ErrTooManySubscribers
	}
	ch := make(chan Event, subscriberBuffer)
	if h.subs[memberTag] == nil {
		h.subs[memberTag] = make(map[chan Event]string)
	}
	h.subs[memberTag][ch] = clientKey
	h.clients[clientKey]++
	h.total++

	cancel := func() {
		if err := h.mu.Lock(); err != nil {
			hubLogger.Error("Subscribe cancel: %v", err)
			return
		}
		defer h.mu.Unlock()
		h.removeLocked(memberTag, ch)
	}
	return ch, cancel, nil
}

// removeLocked closes and forgets ch if still registered, returning its client's share.
// Caller holds h.mu.
func (h *Hub) removeLocked(memberTag string, ch chan Event) {
	set, ok := h.subs[memberTag]
	if !ok {
		return
	}
	clientKey, ok := set[ch]
	if !ok {
		return
	}
	delete(set, ch)
	close(ch)
	h.total--
	if len(set) == 0 {
		delete(h.subs, memberTag)
	}
	if h.clients[clientKey] <= 1 {
		delete(h.clients, clientKey)
	} else {
		h.clients[clientKey]--
	}
}

// Publish delivers ev to every subscriber of each tag without blocking.
// Sends happen under h.mu, so a channel can never be closed mid-send.
func (h *Hub) Publish(memberTags []string, ev Event) {
	if err := h.mu.Lock(); err != nil {
		hubLogger.Error("Publish: %v", err)
		return
	}
	defer h.mu.Unlock()

	dropped := 0
	for _, tag := range memberTags {
		for ch := range h.subs[tag] {
			select {
			case ch <- ev:
			default:
				dropped++
			}
		}
	}
	if dropped > 0 {
		hubLogger.Warn("Publish: dropped %d pokes on full subscriber buffers", dropped)
	}
}

// Kick closes every stream of memberTag and bumps its generation, so a stream that read the
// generation before the kick is refused by Subscribe (used when sessions are revoked). An error
// (the hub lock was not taken in time) means nothing was closed or bumped: the caller reports
// the revocation as incomplete.
func (h *Hub) Kick(memberTag string) error {
	if err := h.mu.Lock(); err != nil {
		hubLogger.Error("Kick: %v", err)
		return err
	}
	defer h.mu.Unlock()

	if _, ok := h.kicked[memberTag]; !ok && len(h.kicked) >= maxRevokedTags {
		// Reset under a floor at least every generation handed out so far (Generation)
		h.floor = h.kickSeq
		h.kicked = make(map[string]uint64)
	}
	h.kickSeq++
	h.kicked[memberTag] = h.kickSeq
	for ch := range h.subs[memberTag] {
		h.removeLocked(memberTag, ch)
	}
	return nil
}
