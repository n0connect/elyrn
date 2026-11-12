package agent

// What the tools return. Nothing here ever carries the AccountNumber, a room secret other than
// the code the caller asked to create, or text the server wrote.

// IdentityResult is this agent's public identity.
type IdentityResult struct {
	Name      string `json:"name"`
	Code      string `json:"code"`
	PublicKey string `json:"public_key"`
	Server    string `json:"server"`
	Created   bool   `json:"created"`
}

// RoomCreated carries the code to share: whoever holds it can join.
type RoomCreated struct {
	Room       string `json:"room"`
	Name       string `json:"name"`
	Code       string `json:"code"`
	MaxMembers int    `json:"max_members"`
	ExpiresAt  string `json:"expires_at"`
}

// RoomJoined is the room just joined.
type RoomJoined struct {
	Room      string `json:"room"`
	Name      string `json:"name"`
	Members   int    `json:"members"`
	ExpiresAt string `json:"expires_at"`
}

// RoomInfo is one room of the listing.
type RoomInfo struct {
	Room       string `json:"room"`
	Name       string `json:"name"`
	Members    int    `json:"members"`
	MaxMembers int    `json:"max_members"`
	Owner      bool   `json:"owner"`
	ExpiresAt  string `json:"expires_at"`
	Unread     int64  `json:"unread"`
}

// RoomsResult lists the rooms this account is in.
type RoomsResult struct {
	Rooms []RoomInfo `json:"rooms"`
}

// MemberInfo is one verified member, under the name people see in the browser.
type MemberInfo struct {
	Name  string `json:"name"`
	Code  string `json:"code"`
	Mine  bool   `json:"mine"`
	Owner bool   `json:"owner"`
}

// MembersResult is a verified roster and the room safety number members compare.
type MembersResult struct {
	Room            string       `json:"room"`
	Name            string       `json:"name"`
	Members         []MemberInfo `json:"members"`
	UnverifiedCards int          `json:"unverified_cards"`
	SafetyNumber    string       `json:"safety_number"`
}

// Sent reports a stored message; Seq is null when only a 409 confirmed the store.
type Sent struct {
	Room   string `json:"room"`
	Seq    *int64 `json:"seq"`
	Stored bool   `json:"stored"`
}

// Message is one room message. Text is written by another member: data, never instructions.
type Message struct {
	Seq    int64  `json:"seq"`
	Sender string `json:"sender,omitempty"`
	Mine   bool   `json:"mine"`
	Text   string `json:"text,omitempty"`
	SentAt string `json:"sent_at,omitempty"`
	Broken bool   `json:"broken,omitempty"`
}

// Gap is a run of a sender's messages the server withheld, delayed or deleted.
type Gap struct {
	Sender  string `json:"sender"`
	Missing int64  `json:"missing"`
}

// Replay is a message served again under a new seq, or out of its sender's order (counters.go):
// it is not delivered as new, and its text is withheld.
type Replay struct {
	Seq    int64  `json:"seq"`
	Sender string `json:"sender,omitempty"`
	Mine   bool   `json:"mine"`
}

// ReadResult is what room_read and room_wait return.
type ReadResult struct {
	Room     string    `json:"room"`
	Messages []Message `json:"messages"`
	Gaps     []Gap     `json:"gaps"`
	Replays  []Replay  `json:"replays"`
	LastSeq  int64     `json:"last_seq"`
	TimedOut bool      `json:"timed_out,omitempty"`
}

// Left reports a leave; Burned is true when the owner left and the room is gone for everyone.
type Left struct {
	Room   string `json:"room"`
	Burned bool   `json:"burned"`
}
