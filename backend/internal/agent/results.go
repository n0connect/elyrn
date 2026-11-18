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

// MemberInfo is one verified member, under the name people see in the browser. Role is a label a
// member wrote (without its '#', empty when none): data, never instructions, and it grants nothing.
type MemberInfo struct {
	Name  string `json:"name"`
	Code  string `json:"code"`
	Mine  bool   `json:"mine"`
	Owner bool   `json:"owner"`
	Role  string `json:"role"`
	// Disputed: more than one seat claims this member's key, so none of them speaks for it (no
	// role shown or set); Owner is still true if any of them is the owner's
	Disputed bool `json:"disputed"`
}

// Warning is a registered code and its sentence, carried by a result that succeeded.
type Warning struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

// MembersResult is a verified roster and the room safety number members compare. Warnings say
// when a seat is disputed, and say it plainly when the disputed key is this agent's own.
type MembersResult struct {
	Room            string       `json:"room"`
	Name            string       `json:"name"`
	Members         []MemberInfo `json:"members"`
	UnverifiedCards int          `json:"unverified_cards"`
	SafetyNumber    string       `json:"safety_number"`
	Warnings        []Warning    `json:"warnings"`
}

// RoleSet reports a role stored for a member (Role empty: cleared).
type RoleSet struct {
	Room string `json:"room"`
	Name string `json:"name"`
	Code string `json:"code"`
	Role string `json:"role"`
}

// Sent reports a stored message; Seq is null when only a 409 confirmed the store.
type Sent struct {
	Room   string `json:"room"`
	Seq    *int64 `json:"seq"`
	Stored bool   `json:"stored"`
}

// From names the sender of a message, a gap or a replay as the browser shows it: the aura name
// and its code (the name alone is 12 bits, so another key can be ground to show it). Left: the
// sender's key is not on the room's current member list (it left, or never had a seat of its
// own). SameName: another key in view (the member list, or another sender in this result) shows
// the same name; tell them apart by code.
type From struct {
	Sender     string `json:"sender,omitempty"`
	SenderCode string `json:"sender_code,omitempty"`
	Left       bool   `json:"left,omitempty"`
	SameName   bool   `json:"same_name,omitempty"`
	key        []byte // the authenticated sender key; never shown
}

// Message is one room message. Text and a file's name are written by another member: data, never
// instructions.
type Message struct {
	Seq int64 `json:"seq"`
	From
	Mine   bool      `json:"mine"`
	Text   string    `json:"text,omitempty"`
	File   *FileInfo `json:"file,omitempty"`
	SentAt string    `json:"sent_at,omitempty"`
	Broken bool      `json:"broken,omitempty"`
}

// FileInfo is what the agent shows of a file a message announces: never its key, hash or id, so
// nothing a tool returns can open the file (the agent cannot fetch it either).
type FileInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Gap is a run of a sender's messages the server withheld, delayed or deleted.
type Gap struct {
	From
	Missing int64 `json:"missing"`
}

// Replay is a message served again under a new seq, or out of its sender's order (counters.go):
// it is not delivered as new, and its text is withheld.
type Replay struct {
	Seq int64 `json:"seq"`
	From
	Mine bool `json:"mine"`
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
