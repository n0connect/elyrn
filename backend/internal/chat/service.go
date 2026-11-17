// Package chat implements pairing and the message relay. The server only ever handles
// opaque E2E ciphertext, and storage alone does not reveal who talks to whom:
//   - a member appears under a different HMAC pseudonym in every conversation,
//   - who that member is lives only in master-key-encrypted references,
//   - a user's conversation list is a padded blob encrypted with their own server key,
//   - sequence numbers are per conversation, and ciphertext is deleted after MESSAGE_TTL_DAYS.
//
// Rooms (rooms.go) reuse all of this: a room is a conversation with more members, a code the
// server never sees, and a lifetime.
package chat

import (
	"context"
	"errors"
	"time"

	"elyrn/internal/encryption"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

const (
	// The conversation index is padded to this block so its size only reveals a coarse bucket
	indexPadBlock = 1024
	day           = 24 * time.Hour
	// FirstSeq is the seq of a conversation's first message (the counter starts at 0 and the
	// store increments it before each insert)
	FirstSeq int64 = 1
)

var (
	ErrNotFound      = errors.New("not found")
	ErrInvalidInput  = errors.New("invalid input")
	ErrLimitReached  = errors.New("limit reached")
	ErrConflict      = errors.New("conflict")
	ErrIdentityUnset = errors.New("identity not initialised")
	ErrForbidden     = errors.New("forbidden")
	errCorrupt       = errors.New("stored record failed authentication")
)

// Member is the authenticated caller, resolved once per request.
type Member struct {
	UserUUID  string
	PublicKey string
	StreamTag string // in-memory address for live events; never stored
	inviteTag string
	key       []byte // per-user server key (wraps peer keys and the conversation index)
}

// Service holds chat business logic.
type Service struct {
	users  store.UserRepository
	chats  store.ChatRepository
	keys   store.KeyRepository
	logger *utils.Logger
}

// NewService creates a new chat Service instance
func NewService() *Service {
	return newService(store.NewUserRepository(), store.NewChatRepository(), store.NewKeyRepository())
}

// NewBackgroundService is the service of the server's background work (the startup key check,
// re-wrapping, retention): its repositories go through database.BackgroundDB, whose deadlines do
// not follow the HTTP write timeout (retention's bulk statements run under LongTransaction, with
// their own longer deadline either way).
func NewBackgroundService() *Service {
	return newService(store.NewBackgroundUserRepository(), store.NewBackgroundChatRepository(), store.NewBackgroundKeyRepository())
}

// WithContext is the service bound to a request's context: every statement of the request
// runs under its one deadline (database.RequestBudget, set by middleware.RequestDeadline).
func (s *Service) WithContext(ctx context.Context) *Service {
	bound := *s
	bound.users, bound.chats, bound.keys = s.users.WithContext(ctx), s.chats.WithContext(ctx), s.keys.WithContext(ctx)
	return &bound
}

func newService(users store.UserRepository, chats store.ChatRepository, keys store.KeyRepository) *Service {
	return &Service{users: users, chats: chats, keys: keys, logger: utils.NewLogger("CHAT_SERVICE")}
}

func memberFromUser(user *models.User) (*Member, error) {
	if !identity.ValidateEncodedKey(user.PublicKey) {
		return nil, ErrIdentityUnset
	}
	streamTag, err := identity.StreamTag(user.UUID)
	if err != nil {
		return nil, err
	}
	inviteTag, err := identity.InviteCreatorTag(user.UUID)
	if err != nil {
		return nil, err
	}
	key, err := encryption.DecryptUserKey(user.EncryptedKey, user.MasterKeyID)
	if err != nil {
		return nil, err
	}
	return &Member{UserUUID: user.UUID, PublicKey: user.PublicKey, StreamTag: streamTag, inviteTag: inviteTag, key: key}, nil
}

// ResolveMember loads the caller's identity and unwrapped server key.
func (s *Service) ResolveMember(userUUID string) (*Member, error) {
	user, err := s.users.FindByUUID(userUUID)
	if err != nil {
		return nil, err
	}
	return memberFromUser(user)
}

func (m *Member) tag(conversationID uuid.UUID) (string, error) {
	return identity.ConversationTag(m.UserUUID, conversationID)
}
