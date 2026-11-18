package store

import (
	"context"
	"errors"
	"time"

	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var chatRepoLogger = utils.NewLogger("CHAT_REPOSITORY")

// ChatRepository defines data access for invites, conversations and messages.
// Conversation-scoped reads are always keyed by (conversation, per-conversation tag).
type ChatRepository interface {
	// Transaction runs fn on a repository bound to one database transaction.
	Transaction(fn func(tx ChatRepository) error) error

	CountActiveInvites(creatorTag string, now time.Time) (int64, error)
	DeleteExpiredInvites(creatorTag string, now time.Time) error
	DeleteInvites(creatorTag string) error
	CreateInvite(invite *models.Invite) error
	TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error)

	LockUsers(userUUIDs []string) (map[string]*models.User, error)
	SaveConvIndex(userUUID, enc string) error
	DeleteUser(userUUID string) error

	CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error
	FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error)
	FindMembershipsByTags(memberTags []string) (map[uuid.UUID]models.ConversationMember, error)
	ListMembers(conversationID uuid.UUID) ([]models.ConversationMember, error)
	LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error)
	// DeleteConversation ends a conversation for every member; its messages and file parts stay
	// as an orphan until retention deletes them (see the function)
	DeleteConversation(conversationID uuid.UUID, now time.Time) error

	NextSeq(conversationID uuid.UUID) (int64, error)
	CreateMessage(message *models.Message) error
	// FindMessage is the message stored under a client-generated id, live or not (ErrNotFound
	// when none): the id is unique server-wide, so it also names a message of another conversation
	FindMessage(messageID uuid.UUID) (*models.Message, error)
	ListMessages(conversationID uuid.UUID, window MessageWindow, today time.Time) ([]models.Message, error)
	AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error

	CreateRoom(room *models.Room, creator *models.ConversationMember) error
	FindRoom(roomID uuid.UUID) (*models.Room, error)
	FindRooms(roomIDs []uuid.UUID) (map[uuid.UUID]models.Room, error)
	LockRoom(roomID uuid.UUID) (*models.Room, error)
	LockConversation(conversationID uuid.UUID) (int64, error)
	AddMember(member *models.ConversationMember) error
	UpdateVault(conversationID uuid.UUID, memberTag, vault string) error
	UpdateRole(conversationID uuid.UUID, memberTag, role string) error
	DeleteMember(conversationID uuid.UUID, memberTag string) error
	CountMembers(conversationIDs []uuid.UUID) (map[uuid.UUID]int, error)

	CreateNote(note *models.RoomNote) error
	// FindNote is the note stored under a client-generated id, live or not (ErrNotFound when none)
	FindNote(noteID uuid.UUID) (*models.RoomNote, error)
	CountNotesFor(recipientTags []string, now time.Time) (map[uuid.UUID]int, error)
	ListNotes(conversationID uuid.UUID, recipientTag string, now time.Time) ([]models.RoomNote, error)
	DeleteNote(conversationID, noteID uuid.UUID, recipientTag string) error

	FileRepository

	PurgeExpired(today, latest, now time.Time) (PurgeCounts, error)

	// WithContext is this repository bound to a request's context (its deadline); an open
	// transaction is rebound with it
	WithContext(ctx context.Context) ChatRepository
}

// PurgeCounts reports what one retention pass removed.
type PurgeCounts struct {
	Messages, Invites, Rooms, Notes, FileParts int64
}

// MessageWindow selects one page of a conversation: seq above Floor and, when Ceiling is
// positive, below it. Newest takes the newest Limit of them (the latest page, or the page just
// before a cursor) instead of the oldest; either way the page comes back in ascending seq.
type MessageWindow struct {
	Floor   int64
	Ceiling int64 // 0: no upper bound
	Newest  bool
	Limit   int
}

// roomPurgeBatch bounds how many expired rooms one retention pass deletes; the rest go next pass
const roomPurgeBatch = 1000

// SQL fragments more than one query shares, spelled exactly as the schema names its columns
const (
	colID                      = "id"
	colConversationID          = "conversation_id"
	colMasterKeyID             = "master_key_id"
	whereID                    = "id = ?"
	whereIDIn                  = "id IN ?"
	whereUUID                  = "uuid = ?"
	whereAccountLookup         = "account_lookup = ?"
	whereConversation          = "conversation_id = ?"
	whereMember                = "conversation_id = ? AND member_tag = ?"
	whereExpired               = "expires_at <= ?"
	whereMessageLive           = "expires_on >= ?"
	whereMessageExpired        = "expires_on < ?"
	whereKeyAfterID            = "master_key_id = ? AND id > ?"
	selectCountPerConversation = "conversation_id, count(*) AS count"
)

type chatRepository struct {
	handle
	tx *gorm.DB // nil outside a transaction
}

// NewChatRepository creates a ChatRepository for request paths (database.DB)
func NewChatRepository() ChatRepository {
	return &chatRepository{handle: requestHandle}
}

// NewBackgroundChatRepository creates a ChatRepository for background work (database.BackgroundDB)
func NewBackgroundChatRepository() ChatRepository {
	return &chatRepository{handle: backgroundHandle}
}

// db is the open transaction, or the repository's handle (resolved at each call)
func (r *chatRepository) db() *gorm.DB {
	if r.tx != nil {
		return r.tx
	}
	return r.handle.db()
}

// WithContext binds the repository to ctx (see handle)
func (r *chatRepository) WithContext(ctx context.Context) ChatRepository {
	bound := &chatRepository{handle: r.handle.bound(ctx)}
	if r.tx != nil {
		bound.tx = r.tx.WithContext(ctx)
	}
	return bound
}

func (r *chatRepository) Transaction(fn func(tx ChatRepository) error) error {
	return r.db().Transaction(func(tx *gorm.DB) error {
		return fn(&chatRepository{handle: r.handle, tx: tx})
	})
}

// first is the one row matching query, ErrNotFound when there is none; any other failure is
// logged under op.
func first[T any](db *gorm.DB, op, query string, args ...any) (*T, error) {
	var row T
	if err := db.Where(query, args...).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		chatRepoLogger.LogError(op, err)
		return nil, err
	}
	return &row, nil
}
