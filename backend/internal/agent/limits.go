// Package agent is the HTTP client of one elyrn. account (the robot entrance,
// docs/architecture/agents.md). It speaks the browser's protocol through internal/e2e and
// treats every server answer as untrusted, exactly as the browser does.
package agent

import (
	"time"

	"elyrn/internal/config"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

// logger is the one log home of elyrn-agent: utils writes to stderr, stdout carries MCP only.
var logger = utils.NewLogger("AGENT")

// Paths of the server API this client uses (docs/api/rest-api.md); models holds the contract.
const (
	pathChallenge     = models.PathPoWChallenge
	pathRegister      = models.PathRegister
	pathLogin         = models.PathLogin
	pathMe            = models.PathMe
	pathRooms         = models.PathRooms
	pathRoomsJoin     = models.PathRoomsJoin
	pathConversations = models.PathConversations
	pathEvents        = models.PathEvents
	pathMessages      = "/" + models.SubMessages
	pathMembers       = "/" + models.SubMembers
	pathRead          = "/" + models.SubRead
	queryAfter        = models.QueryAfter
	queryBefore       = models.QueryBefore
)

// Timeouts: every exchange is bounded (RULES.md §17.1).
const (
	requestTimeout     = 30 * time.Second
	powTimeout         = 5 * time.Minute
	dialTimeout        = 10 * time.Second
	tlsTimeout         = 10 * time.Second
	headerTimeout      = 20 * time.Second
	idleConnTimeout    = 90 * time.Second
	backoffBase        = 500 * time.Millisecond
	callLockTimeout    = MaxWaitTimeout + 2*requestTimeout
	DefaultWaitTimeout = 60 * time.Second
	MinWaitTimeout     = time.Second
	MaxWaitTimeout     = 300 * time.Second
)

// Sizes and counts: every loop and every server-supplied collection is bounded (RULES.md §8.1).
const (
	maxResponseBytes       = 4 << 20
	maxErrorBodyBytes      = 4 << 10
	maxSSELineBytes        = 1024
	maxSSELines            = 100000
	maxStreamOpens         = 4
	maxListedConversations = 1024
	maxPageMessages        = 1000
	maxSyncPages           = 64
	maxCiphertextChars     = 11000 // as chat.js MAX_CIPHERTEXT_CHARS
	maxCardChars           = 80
	maxPendingTokenChars   = 2048
	maxCookieValueChars    = 4096
	maxTrackedSenders      = 256
	maxPendingGaps         = 64
	maxCreateAttempts      = 3 // a fresh secret per attempt, as rooms.js MAX_CREATE_ATTEMPTS
	maxRosterRetries       = 2 // a 412 re-encrypts under the same id at most twice
	maxLostAnswerRetries   = 2 // a lost answer resends the same id and ciphertext
	maxConfirmAttempts     = 3 // registration phase 2 after a passing failure
	maxPoWDifficulty       = 28
	maxPoWNonces           = uint64(1) << 36
	powContextCheckEvery   = 1 << 14
	maxSafeSeq             = int64(1)<<53 - 1 // JavaScript's safe integers, as the browser checks
	hourSeconds            = 3600
)

// Message text, as frontend/validation.js validateMessageText.
const (
	MaxMessageChars = 2000
)

// Room limits the tools accept before asking the server (the server's own limits apply after).
const (
	MinRoomMembers  = config.MinRoomMembers
	MaxRoomMembers  = config.MaxRoomMembersBound
	MinRoomTTLHours = config.MinRoomTTLHours
	MaxRoomTTLHours = config.MaxRoomTTLHoursBound
)
