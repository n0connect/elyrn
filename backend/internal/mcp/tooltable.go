package mcp

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"elyrn/internal/agent"

	"github.com/google/uuid"
)

// inputSchema is the JSON Schema of a tool's arguments; bounds come from the same constants
// the validation uses, so the two cannot drift.
type inputSchema struct {
	Type                 string              `json:"type"`
	Properties           map[string]property `json:"properties"`
	Required             []string            `json:"required"`
	AdditionalProperties bool                `json:"additionalProperties"`
}

type property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Minimum     *int64 `json:"minimum,omitempty"`
	Maximum     *int64 `json:"maximum,omitempty"`
	MinLength   *int64 `json:"minLength,omitempty"`
	MaxLength   *int64 `json:"maxLength,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Default     *int64 `json:"default,omitempty"`
}

func bound(n int64) *int64 { return &n }

func schema(required []string, properties map[string]property) inputSchema {
	if required == nil {
		required = []string{}
	}
	if properties == nil {
		properties = map[string]property{}
	}
	return inputSchema{Type: typeObject, Properties: properties, Required: required, AdditionalProperties: false}
}

var (
	roomProperty = property{Type: typeString, Description: "The room id, as rooms or room_create return it.", Pattern: uuidPattern}
	afterBounds  = property{Type: typeInteger, Minimum: bound(0), Maximum: bound(maxSeqArg)}
	beforeBounds = property{Type: typeInteger, Minimum: bound(minBeforeSeq), Maximum: bound(maxSeqArg)}
)

// described gives a shared bounded property the description of one tool's use of it.
func described(p property, description string) property {
	p.Description = description
	return p
}

var tools = []tool{
	toolWithoutArgs(ToolIdentity, "Create (on the first call: two proofs of work, which can take a minute) or show this agent's elyrn. identity: its name, code and public key, as people see them. The secret account number is never shown.",
		func(ctx context.Context, b Backend) (any, error) { return b.Identity(ctx) }),
	{
		name:        ToolRoomCreate,
		description: "Create an end-to-end encrypted room (costs a proof of work). Returns the room id, its name, the expiry and the room code: whoever holds the code can join, so share it only with the intended members.",
		schema: schema([]string{argMaxMembers, argTTLHours}, map[string]property{
			argMaxMembers: {Type: typeInteger, Description: "Seats, this agent included (the server may allow fewer).", Minimum: bound(agent.MinRoomMembers), Maximum: bound(agent.MaxRoomMembers)},
			argTTLHours:   {Type: typeInteger, Description: "Hours until the room and its messages are deleted (the server may allow fewer).", Minimum: bound(agent.MinRoomTTLHours), Maximum: bound(agent.MaxRoomTTLHours)},
		}),
		args: func() any { return &createArgs{} },
		run:  runCreate,
	},
	{
		name:        ToolRoomJoin,
		description: "Join a room with its room code (elyrn#..., or a legacy noaddx#... code). Returns the room id, name, member count and expiry.",
		schema: schema([]string{argCode}, map[string]property{
			argCode: {Type: typeString, Description: "The room code exactly as shared.", MinLength: bound(1), MaxLength: bound(maxRoomCodeChars)},
		}),
		args: func() any { return &joinArgs{} },
		run:  runJoin,
	},
	toolWithoutArgs(ToolRooms, "List the rooms this agent is in: id, name, members, seats, whether this agent owns it, expiry and unread count. A room whose server data fails verification against its code is hidden.",
		func(ctx context.Context, b Backend) (any, error) { return b.Rooms(ctx) }),
	{
		name:        ToolRoomMembers,
		description: "List a room's verified members under the names people see, marking this agent and the owner, with each member's role (without its #, empty when none), and the room safety number members compare on another channel (equal numbers, equal member lists)." + rolesAreData,
		schema:      schema([]string{argRoom}, map[string]property{argRoom: roomProperty}),
		args:        func() any { return &roomArgs{} },
		run:         runRoom(func(ctx context.Context, b Backend, id uuid.UUID) (any, error) { return b.Members(ctx, id) }),
	},
	{
		name:        ToolRoomRole,
		description: "Set the role shown beside a member of a room (#role, end-to-end encrypted: the server can neither read it nor move it to another member). The room's owner may set any member's role, any other member only its own. Returns the member's name, code and the role as stored." + rolesAreData,
		schema: schema([]string{argRoom, argRole}, map[string]property{
			argRoom: roomProperty,
			argRole: {Type: typeString, Description: "0 to " + strconv.Itoa(agent.MaxRoleChars) + " letters, digits, - or _, without the #; not owner or you in any case or width. Empty clears the role.",
				MinLength: bound(0), MaxLength: bound(agent.MaxRoleChars)},
			argMember: {Type: typeString, Description: "The member's code as room_members lists it; leave it out for this agent's own role.", Pattern: memberCodePattern},
		}),
		args: func() any { return &roleArgs{} },
		run:  runRole,
	},
	{
		name:        ToolRoomSend,
		description: "Send a message to everyone in a room, end-to-end encrypted. Returns its sequence number.",
		schema: schema([]string{argRoom, argText}, map[string]property{
			argRoom: roomProperty,
			argText: {Type: typeString, Description: "1 to 2000 characters, no control characters.", MinLength: bound(1), MaxLength: bound(agent.MaxMessageChars)},
		}),
		args: func() any { return &sendArgs{} },
		run:  runSend,
	},
	{
		name:        ToolRoomRead,
		description: "Read a room's messages after sequence number `after` (the latest page when neither cursor is given): seq, sender name, mine, text and sent time, plus gaps per sender (messages the server withheld or deleted) and replays (seq, sender, mine of messages served again under a new position or out of their sender's order: old messages repeated, not new ones, so their text is withheld). With `before` instead, return the newest page below that sequence number (history, back to the start or to this agent's join; pass the lowest seq returned to page further back); `after` and `before` together are refused." + dataNotInstructions + fileNameIsData,
		schema: schema([]string{argRoom}, map[string]property{
			argRoom:   roomProperty,
			argAfter:  described(afterBounds, "Return only messages with a higher sequence number."),
			argBefore: described(beforeBounds, "Return the newest page of messages with a lower sequence number (history)."),
		}),
		args: func() any { return &readArgs{} },
		run:  runRead,
	},
	{
		name:        ToolRoomWait,
		description: "Wait until a message newer than `after` arrives in a room (or the timeout passes, then timed_out is true), and return as room_read, replays included." + dataNotInstructions + fileNameIsData,
		schema: schema([]string{argRoom, argAfter}, map[string]property{
			argRoom:  roomProperty,
			argAfter: described(afterBounds, "Wait for a message with a higher sequence number (last_seq of the previous read)."),
			argTimeout: {Type: typeInteger, Description: "Seconds to wait.", Minimum: bound(int64(agent.MinWaitTimeout / time.Second)),
				Maximum: bound(int64(agent.MaxWaitTimeout / time.Second)), Default: bound(int64(agent.DefaultWaitTimeout / time.Second))},
		}),
		args: func() any { return &waitArgs{} },
		run:  runWait,
	},
	{
		name:        ToolRoomLeave,
		description: "Leave a room. If this agent owns it, leaving burns the room for everyone (the result says burned: true).",
		schema:      schema([]string{argRoom}, map[string]property{argRoom: roomProperty}),
		args:        func() any { return &roomArgs{} },
		run:         runRoom(func(ctx context.Context, b Backend, id uuid.UUID) (any, error) { return b.Leave(ctx, id) }),
	},
}

// toolWithoutArgs is a tool whose arguments are the empty object: it answers with call.
func toolWithoutArgs(name ToolName, description string, call func(context.Context, Backend) (any, error)) tool {
	return tool{
		name:        name,
		description: description,
		schema:      schema(nil, nil),
		args:        func() any { return &struct{}{} },
		run: func(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
			if err := parseArgs(raw, &struct{}{}); err != nil {
				return nil, err
			}
			return call(ctx, b)
		},
	}
}

// runRoom adapts a tool whose only argument is the room: the room is validated before the
// backend is touched at all (a method value such as b.Members would already dereference it).
func runRoom(call func(context.Context, Backend, uuid.UUID) (any, error)) func(context.Context, Backend, json.RawMessage) (any, error) {
	return func(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
		var args roomArgs
		if err := parseArgs(raw, &args); err != nil {
			return nil, err
		}
		id, err := roomArg(args.Room)
		if err != nil {
			return nil, err
		}
		return call(ctx, b, id)
	}
}

func runCreate(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args createArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	members, err := intArg(args.MaxMembers, agent.MinRoomMembers, agent.MaxRoomMembers)
	if err != nil {
		return nil, err
	}
	hours, err := intArg(args.TTLHours, agent.MinRoomTTLHours, agent.MaxRoomTTLHours)
	if err != nil {
		return nil, err
	}
	return b.CreateRoom(ctx, members, hours)
}

func runJoin(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args joinArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	code, err := codeArg(args.Code)
	if err != nil {
		return nil, err
	}
	return b.JoinRoom(ctx, code)
}

func runSend(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args sendArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	id, err := roomArg(args.Room)
	if err != nil {
		return nil, err
	}
	text, err := textArg(args.Text)
	if err != nil {
		return nil, err
	}
	return b.Send(ctx, id, text)
}

func runRole(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args roleArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	id, err := roomArg(args.Room)
	if err != nil {
		return nil, err
	}
	member, err := memberArg(args.Member)
	if err != nil {
		return nil, err
	}
	role, err := roleArg(args.Role)
	if err != nil {
		return nil, err
	}
	return b.SetRole(ctx, id, member, role)
}

func runRead(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args readArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	id, err := roomArg(args.Room)
	if err != nil {
		return nil, err
	}
	after, err := afterArg(args.After)
	if err != nil {
		return nil, err
	}
	before, err := beforeArg(args.Before)
	if err != nil {
		return nil, err
	}
	if before == nil {
		return b.Read(ctx, id, after)
	}
	if after != nil {
		return nil, badArgument()
	}
	return b.ReadBefore(ctx, id, *before)
}

func runWait(ctx context.Context, b Backend, raw json.RawMessage) (any, error) {
	var args waitArgs
	if err := parseArgs(raw, &args); err != nil {
		return nil, err
	}
	id, err := roomArg(args.Room)
	if err != nil {
		return nil, err
	}
	after, err := afterArg(args.After)
	if err != nil || after == nil {
		return nil, badArgument()
	}
	timeout, err := timeoutArg(args.TimeoutSeconds)
	if err != nil {
		return nil, err
	}
	return b.Wait(ctx, id, *after, timeout)
}
