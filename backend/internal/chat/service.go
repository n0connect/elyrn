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
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/auth"
	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
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

// ---------- encrypted conversation index ----------

func indexAAD(m *Member) []byte {
	return encryption.BuildAAD(m.UserUUID, uuid.Nil, encryption.FieldConversationIndex, encryption.PurposeStoredRecord)
}

// openIndex returns the caller's conversation ids, newest first.
func openIndex(m *Member, enc string) ([]uuid.UUID, error) {
	if enc == "" {
		return nil, nil
	}
	plain, err := encryption.DecryptWithAAD(enc, m.key, indexAAD(m))
	if err != nil {
		return nil, errCorrupt
	}
	var raw []string
	if err := json.Unmarshal([]byte(plain), &raw); err != nil || len(raw) > config.MaxConversationsPerUserBound {
		return nil, errCorrupt
	}
	ids := make([]uuid.UUID, 0, len(raw))
	seen := make(map[uuid.UUID]struct{}, len(raw))
	for _, r := range raw {
		id, ok := utils.ParseCanonicalUUIDv4(r)
		if !ok {
			return nil, errCorrupt
		}
		if _, dup := seen[id]; !dup {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func sealIndex(m *Member, ids []uuid.UUID) (string, error) {
	if len(ids) == 0 {
		return "", nil
	}
	raw := make([]string, len(ids))
	for i, id := range ids {
		raw[i] = id.String()
	}
	plain, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	// Trailing spaces are valid JSON whitespace; they hide the exact conversation count
	padded := len(plain) + (indexPadBlock-len(plain)%indexPadBlock)%indexPadBlock
	return encryption.EncryptWithAAD(string(plain)+strings.Repeat(" ", padded-len(plain)), m.key, indexAAD(m))
}

func withoutID(ids []uuid.UUID, drop map[uuid.UUID]struct{}) []uuid.UUID {
	kept := ids[:0:0]
	for _, id := range ids {
		if _, gone := drop[id]; !gone {
			kept = append(kept, id)
		}
	}
	return kept
}

// ---------- membership records ----------

// The AAD binding each master-key encrypted reference to its row (shared with re-wrapping)
func memberRefAAD(memberTag string, conversationID uuid.UUID) []byte {
	return encryption.BuildAAD(memberTag, conversationID, encryption.FieldMemberRef, encryption.PurposeStoredRecord)
}

func inviteCreatorAAD(lookup string, inviteID uuid.UUID) []byte {
	return encryption.BuildAAD(lookup, inviteID, encryption.FieldInviteCreator, encryption.PurposeStoredRecord)
}

func sealMembership(owner *Member, conversationID uuid.UUID, peerPublicKey string) (models.ConversationMember, error) {
	tag, err := owner.tag(conversationID)
	if err != nil {
		return models.ConversationMember{}, err
	}
	refEnc, err := encryption.SealWithActiveKey(owner.UserUUID, memberRefAAD(tag, conversationID))
	if err != nil {
		return models.ConversationMember{}, err
	}
	peerAAD := encryption.BuildAAD(tag, conversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	peerEnc, err := encryption.EncryptWithAAD(peerPublicKey, owner.key, peerAAD)
	if err != nil {
		return models.ConversationMember{}, err
	}
	return models.ConversationMember{
		ConversationID: conversationID,
		MemberTag:      tag,
		MemberRefEnc:   refEnc,
		MasterKeyID:    encryption.ActiveMasterKeyID(),
		PeerKeyEnc:     peerEnc,
	}, nil
}

// openUnderMasterKey opens a user UUID sealed under the master key named keyID. A record that
// does not open (unknown key, failed tag, not a UUID) is errCorrupt; a server that is closing its
// keys answers encryption.ErrClosing, so the request gets 503 and nothing looks corrupt.
func openUnderMasterKey(keyID, sealed string, aad []byte) (string, error) {
	userUUID, ok, err := encryption.OpenWithKeyID(keyID, sealed, aad)
	if errors.Is(err, encryption.ErrClosing) {
		return "", err
	}
	if !ok || err != nil || !utils.ValidateUUID(userUUID) {
		return "", errCorrupt
	}
	return userUUID, nil
}

// memberRefUUID decrypts who a membership row belongs to (master key only, tag unchecked).
func memberRefUUID(member *models.ConversationMember) (string, error) {
	return openUnderMasterKey(member.MasterKeyID, member.MemberRefEnc, memberRefAAD(member.MemberTag, member.ConversationID))
}

// openMemberRef recovers who a membership row belongs to, and cross-checks the tag.
func openMemberRef(member *models.ConversationMember) (string, error) {
	userUUID, err := memberRefUUID(member)
	if err != nil {
		return "", err
	}
	expected, err := identity.ConversationTag(userUUID, member.ConversationID)
	if err != nil || expected != member.MemberTag {
		return "", errCorrupt
	}
	return userUUID, nil
}

func (s *Service) openPeerKey(me *Member, member *models.ConversationMember) (string, error) {
	aad := encryption.BuildAAD(member.MemberTag, member.ConversationID, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord)
	peerKey, err := encryption.DecryptWithAAD(member.PeerKeyEnc, me.key, aad)
	if err != nil || !identity.ValidateEncodedKey(peerKey) {
		return "", errCorrupt
	}
	return peerKey, nil
}

// requireMembership is the single authorization gate for conversation-scoped calls.
func (s *Service) requireMembership(repo store.ChatRepository, me *Member, conversationID uuid.UUID) (*models.ConversationMember, error) {
	tag, err := me.tag(conversationID)
	if err != nil {
		return nil, err
	}
	member, err := repo.FindMembership(conversationID, tag)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return member, nil
}

// peerStreams returns live-event addresses of the other members (for notifications).
func (s *Service) peerStreams(repo store.ChatRepository, me *Member, conversationID uuid.UUID) ([]string, []string, error) {
	members, err := repo.ListMembers(conversationID)
	if err != nil {
		return nil, nil, err
	}
	var uuids, streams []string
	for i := range members {
		userUUID, err := openMemberRef(&members[i])
		if err != nil {
			return nil, nil, err
		}
		uuids = append(uuids, userUUID)
		if userUUID == me.UserUUID {
			continue
		}
		stream, err := identity.StreamTag(userUUID)
		if err != nil {
			return nil, nil, err
		}
		streams = append(streams, stream)
	}
	return uuids, streams, nil
}

// ---------- invites ----------

// CreateInvite issues a single-use token. Only its HMAC is stored.
func (s *Service) CreateInvite(me *Member) (string, time.Time, error) {
	now := time.Now().UTC()
	if err := s.chats.DeleteExpiredInvites(me.inviteTag, now); err != nil {
		return "", time.Time{}, err
	}
	active, err := s.chats.CountActiveInvites(me.inviteTag, now)
	if err != nil {
		return "", time.Time{}, err
	}
	if active >= int64(config.GetMaxActiveInvites()) {
		return "", time.Time{}, ErrLimitReached
	}

	rawToken, err := cryptoengine.RandomBytes(utils.InviteTokenBytes)
	if err != nil {
		return "", time.Time{}, err
	}
	lookup, err := identity.InviteLookup(rawToken)
	if err != nil {
		return "", time.Time{}, err
	}
	inviteID, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
	if err != nil {
		return "", time.Time{}, err
	}

	creatorEnc, err := encryption.SealWithActiveKey(me.UserUUID, inviteCreatorAAD(lookup, inviteID))
	if err != nil {
		return "", time.Time{}, err
	}

	expiresAt := expiryAfter(now, config.GetInviteTTL())
	invite := models.Invite{
		ID:            inviteID,
		Lookup:        lookup,
		CreatorTag:    me.inviteTag,
		CreatorRefEnc: creatorEnc,
		MasterKeyID:   encryption.ActiveMasterKeyID(),
		ExpiresAt:     expiresAt,
	}
	if err := s.chats.CreateInvite(&invite); err != nil {
		return "", time.Time{}, err
	}
	return base64.RawURLEncoding.EncodeToString(rawToken), expiresAt, nil
}

func openInviteCreator(invite *models.Invite) (string, error) {
	return openUnderMasterKey(invite.MasterKeyID, invite.CreatorRefEnc, inviteCreatorAAD(invite.Lookup, invite.ID))
}

// RedeemInvite consumes a token and opens a conversation between creator and caller.
// Everything happens in one transaction: on any failure the invite is restored.
// Returns the caller's view plus the creator's stream address (to notify).
func (s *Service) RedeemInvite(me *Member, token string) (*models.ConversationDTO, string, error) {
	rawToken, ok := utils.ValidateInviteToken(token)
	if !ok {
		return nil, "", ErrInvalidInput
	}
	lookup, err := identity.InviteLookup(rawToken)
	if err != nil {
		return nil, "", err
	}

	var (
		dto           *models.ConversationDTO
		creatorStream string
	)
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		invite, err := tx.TakeInvite(lookup, me.inviteTag, time.Now().UTC())
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		creatorUUID, err := openInviteCreator(invite)
		if err != nil {
			return err
		}

		rows, err := tx.LockUsers([]string{me.UserUUID, creatorUUID})
		if err != nil {
			return err
		}
		if rows[me.UserUUID] == nil || rows[creatorUUID] == nil {
			return ErrNotFound
		}
		self, err := memberFromUser(rows[me.UserUUID])
		if err != nil {
			return err
		}
		creator, err := memberFromUser(rows[creatorUUID])
		if err != nil {
			return err
		}
		if creator.inviteTag != invite.CreatorTag {
			return errCorrupt
		}

		myIndex, err := openIndex(self, rows[self.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		theirIndex, err := openIndex(creator, rows[creator.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		limit := config.GetMaxConversationsPerUser()
		if len(myIndex) >= limit || len(theirIndex) >= limit {
			return ErrLimitReached
		}

		conversationID, err := uuid.NewRandomFromReader(cryptoengine.RandReader)
		if err != nil {
			return err
		}
		mine, err := sealMembership(self, conversationID, creator.PublicKey)
		if err != nil {
			return err
		}
		theirs, err := sealMembership(creator, conversationID, self.PublicKey)
		if err != nil {
			return err
		}
		if err := tx.CreateConversation(conversationID, []models.ConversationMember{mine, theirs}); err != nil {
			return err
		}
		if err := s.saveIndex(tx, self, append([]uuid.UUID{conversationID}, myIndex...)); err != nil {
			return err
		}
		if err := s.saveIndex(tx, creator, append([]uuid.UUID{conversationID}, theirIndex...)); err != nil {
			return err
		}

		dto = &models.ConversationDTO{ID: conversationID.String(), PeerPublicKey: creator.PublicKey}
		creatorStream = creator.StreamTag
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	s.logger.Debug("RedeemInvite: conversation opened")
	return dto, creatorStream, nil
}

func (s *Service) saveIndex(repo store.ChatRepository, m *Member, ids []uuid.UUID) error {
	enc, err := sealIndex(m, ids)
	if err != nil {
		return err
	}
	return repo.SaveConvIndex(m.UserUUID, enc)
}

// ---------- conversations ----------

// ListConversations returns the caller's conversations in index order (newest first).
// Recency across conversations is deliberately not tracked server-side.
func (s *Service) ListConversations(me *Member) ([]models.ConversationDTO, error) {
	user, err := s.users.FindByUUID(me.UserUUID)
	if err != nil {
		return nil, err
	}
	ids, err := openIndex(me, user.ConvIndexEnc)
	if err != nil {
		return nil, err
	}

	tags := make([]string, len(ids))
	for i, id := range ids {
		if tags[i], err = me.tag(id); err != nil {
			return nil, err
		}
	}
	memberships, err := s.chats.FindMembershipsByTags(tags)
	if err != nil {
		return nil, err
	}
	lastSeqs, err := s.chats.LastSeqs(ids)
	if err != nil {
		return nil, err
	}
	rooms, counts, notes, err := s.roomDetails(ids, tags)
	if err != nil {
		return nil, err
	}

	result := make([]models.ConversationDTO, 0, len(ids))
	stale := make(map[uuid.UUID]struct{})
	now := time.Now()
	for i, id := range ids {
		member, ok := memberships[id]
		if !ok || member.MemberTag != tags[i] {
			stale[id] = struct{}{}
			continue
		}
		if room, isRoom := rooms[id]; isRoom {
			if !roomAlive(&room, now) {
				stale[id] = struct{}{}
				continue
			}
			result = append(result, roomDTO(&room, &member, counts[id], notes[id], lastSeqs[id]))
			continue
		}
		peerKey, err := s.openPeerKey(me, &member)
		if err != nil {
			s.logger.Error("SECURITY: a stored peer key failed authentication")
			continue
		}
		result = append(result, models.ConversationDTO{
			ID:            id.String(),
			PeerPublicKey: peerKey,
			LastSeq:       lastSeqs[id],
			ReadSeq:       member.ReadSeq,
		})
	}
	if len(stale) > 0 {
		s.pruneIndex(me, stale)
	}
	return result, nil
}

// roomDetails loads, for the rooms among ids, the room rows, member counts and the caller's
// waiting notes (tags are the caller's per-conversation tags, in the order of ids).
func (s *Service) roomDetails(ids []uuid.UUID, tags []string) (map[uuid.UUID]models.Room, map[uuid.UUID]int, map[uuid.UUID]int, error) {
	rooms, err := s.chats.FindRooms(ids)
	if err != nil || len(rooms) == 0 {
		return rooms, nil, nil, err
	}
	roomIDs := make([]uuid.UUID, 0, len(rooms))
	roomTags := make([]string, 0, len(rooms))
	for i, id := range ids {
		if _, isRoom := rooms[id]; isRoom {
			roomIDs = append(roomIDs, id)
			roomTags = append(roomTags, tags[i])
		}
	}
	counts, err := s.chats.CountMembers(roomIDs)
	if err != nil {
		return nil, nil, nil, err
	}
	notes, err := s.chats.CountNotesFor(roomTags, time.Now().UTC())
	if err != nil {
		return nil, nil, nil, err
	}
	return rooms, counts, notes, nil
}

// pruneIndex drops ids whose conversation no longer exists (burned by the peer elsewhere).
func (s *Service) pruneIndex(me *Member, stale map[uuid.UUID]struct{}) {
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil || rows[me.UserUUID] == nil {
			return err
		}
		ids, err := openIndex(me, rows[me.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		return s.saveIndex(tx, me, withoutID(ids, stale))
	})
	if err != nil {
		s.logger.LogError("pruneIndex", err)
	}
}

// BurnConversation deletes a conversation and all its ciphertext for every member,
// and removes it from every member's encrypted index. In a room only the owner burns;
// any other member leaves instead.
func (s *Service) BurnConversation(me *Member, conversationID uuid.UUID) ([]string, error) {
	room, err := s.liveRoom(s.chats, conversationID)
	if err != nil {
		return nil, err
	}
	if room != nil {
		tag, err := me.tag(conversationID)
		if err != nil {
			return nil, err
		}
		if tag != room.OwnerTag {
			return s.leaveRoom(me, conversationID)
		}
	}
	var streams []string
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := s.requireMembership(tx, me, conversationID); err != nil {
			return err
		}
		uuids, peerStreams, err := s.peerStreams(tx, me, conversationID)
		if err != nil {
			return err
		}
		rows, err := tx.LockUsers(uuids)
		if err != nil {
			return err
		}
		if err := tx.DeleteConversation(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		drop := map[uuid.UUID]struct{}{conversationID: {}}
		for _, row := range rows {
			member, err := memberFromUser(row)
			if err != nil {
				return err
			}
			ids, err := openIndex(member, row.ConvIndexEnc)
			if err != nil {
				return err
			}
			if err := s.saveIndex(tx, member, withoutID(ids, drop)); err != nil {
				return err
			}
		}
		streams = peerStreams
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("BurnConversation: conversation burned")
	return streams, nil
}

// DeleteAccount erases the caller once authKey proves the account: its invites, every
// conversation it is in (all ciphertext, for both sides; rooms it owns likewise, rooms it
// joined it only leaves) and the account row. Returns the
// peers' live-event addresses. The key is checked against the locked row that is deleted; the
// lookup is HMAC(pepper, auth key), so a match proves the key without an Argon2 run.
// Lock order is RedeemInvite's (invites, then users), so the invites go first; a wrong key
// rolls the whole transaction back. Peers' rows are left unlocked: their encrypted indexes
// drop the vanished conversations at their next listing (pruneIndex).
func (s *Service) DeleteAccount(me *Member, authKey string) ([]string, error) {
	lookup, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		return nil, err
	}
	var streams []string
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if err := tx.DeleteInvites(me.inviteTag); err != nil {
			return err
		}
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil {
			return err
		}
		row := rows[me.UserUUID]
		if row == nil {
			return ErrNotFound
		}
		if !auth.AccountLookupMatches(lookup, row.AccountLookup) {
			return ErrForbidden
		}
		ids, err := openIndex(me, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		for _, id := range ids {
			member, err := s.requireMembership(tx, me, id)
			if errors.Is(err, ErrNotFound) {
				continue // the peer burned it already
			} else if err != nil {
				return err
			}
			_, peers, err := s.peerStreams(tx, me, id)
			if err != nil {
				return err
			}
			if err := s.forget(tx, id, member); err != nil {
				return err
			}
			streams = append(streams, peers...)
		}
		if err := tx.DeleteUser(me.UserUUID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.logger.Debug("DeleteAccount: account erased")
	return streams, nil
}

// forget removes one of a deleted account's conversations: a room it joined loses only its
// membership (taken under the conversation lock, as leaving does), anything else is burned.
func (s *Service) forget(tx store.ChatRepository, id uuid.UUID, member *models.ConversationMember) error {
	room, err := tx.FindRoom(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if room != nil && room.OwnerTag != member.MemberTag {
		if _, err := tx.LockConversation(id); err != nil {
			return err
		}
		return tx.DeleteMember(id, member.MemberTag)
	}
	if err := tx.DeleteConversation(id); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// ---------- messages ----------

// PageCursor names which page of messages a read asks for.
type PageCursor struct {
	Kind CursorKind
	Seq  int64 // the cursor's seq; unused for CursorLatest
}

// CursorKind is the page a read asks for (the whitelisted query parameters of the messages route).
type CursorKind int

const (
	CursorLatest CursorKind = iota // the newest page
	CursorAfter                    // the oldest page above Seq: catching up
	CursorBefore                   // the newest page below Seq: paging back through history
)

// messageWindow turns a cursor into the stored range it reads. A room member never gets what was
// sent before they joined (it was not encrypted for them), so every window stops at joined_seq.
func messageWindow(cursor PageCursor, joinedSeq int64, limit int) store.MessageWindow {
	switch cursor.Kind {
	case CursorAfter:
		return store.MessageWindow{Floor: max(cursor.Seq, joinedSeq), Limit: limit}
	case CursorBefore:
		// A ceiling of FirstSeq is an empty page; 0 would mean "no ceiling"
		return store.MessageWindow{Floor: joinedSeq, Ceiling: max(cursor.Seq, FirstSeq), Newest: true, Limit: limit}
	default:
		return store.MessageWindow{Floor: joinedSeq, Newest: true, Limit: limit}
	}
}

// ListMessages returns the page of messages the cursor names, in ascending seq.
func (s *Service) ListMessages(me *Member, conversationID uuid.UUID, cursor PageCursor) ([]models.MessageDTO, error) {
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return nil, err
	}
	if _, err := s.liveRoom(s.chats, conversationID); err != nil {
		return nil, err
	}
	window := messageWindow(cursor, member.JoinedSeq, config.GetMessagePageLimit())
	messages, err := s.chats.ListMessages(conversationID, window, deletionCutoff(time.Now()))
	if err != nil {
		return nil, err
	}
	result := make([]models.MessageDTO, 0, len(messages))
	for _, m := range messages {
		result = append(result, models.MessageDTO{
			ID:         m.ID.String(),
			Seq:        m.Seq,
			Mine:       m.SenderTag == member.MemberTag,
			Ciphertext: m.Ciphertext,
		})
	}
	return result, nil
}

// expiryGranularity: invites and room notes expire on a whole hour, rounded up (rooms expire on
// whole hours, messages on whole days), so a stored expiry never tells the second a row was
// created. Rows stored before this keep their exact expiry and expire as stored.
const expiryGranularity = time.Hour

// expiryAfter is now + ttl rounded up to the next whole expiryGranularity (UTC): never before
// now + ttl, so an invite or a note lives at least its TTL, and at most one granule longer.
func expiryAfter(now time.Time, ttl time.Duration) time.Time {
	at := now.UTC().Add(ttl)
	rounded := at.Truncate(expiryGranularity)
	if rounded.Before(at) {
		rounded = rounded.Add(expiryGranularity)
	}
	return rounded
}

// expiryDay returns the day-granular deletion date for ciphertext stored now.
func expiryDay(now time.Time) time.Time {
	return deletionCutoff(now).Add(time.Duration(config.GetMessageTTLDays()) * day)
}

// deletionCutoff is the first deletion day still alive at now: a message whose deletion day is
// before it is expired, deleted by retention and never served before that (one rule for both).
func deletionCutoff(now time.Time) time.Time {
	return now.UTC().Truncate(day)
}

// SendMessage stores one opaque ciphertext under the conversation's next sequence number.
// A room message must have the room format and be encrypted for the current roster.
func (s *Service) SendMessage(me *Member, conversationID uuid.UUID, rawID, ciphertext string) (int64, []string, error) {
	messageID, ok := utils.ParseCanonicalUUIDv4(rawID)
	if !ok {
		return 0, nil, ErrInvalidInput
	}
	room, err := s.liveRoom(s.chats, conversationID)
	if err != nil {
		return 0, nil, err
	}
	var seq int64
	var senderTag string
	raced := false
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		// Membership first: the format a conversation expects (pair or room, and a room's size)
		// is told only to its members, so "not yours" answers exactly like "does not exist"; a
		// duplicate id is judged only after it too (duplicates.go: no existence oracle)
		member, err := s.requireMembership(tx, me, conversationID)
		if err != nil {
			return err
		}
		senderTag = member.MemberTag
		blob, err := messageBlob(room, ciphertext)
		if err != nil {
			return err
		}
		// A held id is judged before the roster: a resend after a lost answer whose first attempt
		// is stored answers "stored" (409) even when someone joined or left meanwhile, instead of
		// 412, which would make the client re-encrypt and resend different bytes under that id
		if err := messageDuplicate(tx, messageID, conversationID, senderTag, ciphertext); err != nil {
			return err
		}
		if seq, err = tx.NextSeq(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		if blob != nil {
			if err := checkRoomMessage(tx, conversationID, blob); err != nil {
				return err
			}
		}
		err = tx.CreateMessage(&models.Message{
			ConversationID: conversationID,
			Seq:            seq,
			ID:             messageID,
			SenderTag:      member.MemberTag,
			Ciphertext:     ciphertext,
			ExpiresOn:      expiryDay(time.Now()),
		})
		raced = errors.Is(err, store.ErrConflict)
		return err
	})
	if raced {
		// The refused insert aborted the transaction: the holder is read outside it
		return 0, nil, racedMessage(s.chats, messageID, conversationID, senderTag, ciphertext)
	}
	if err != nil {
		return 0, nil, err
	}
	_, streams, err := s.peerStreams(s.chats, me, conversationID)
	if err != nil {
		// The message is stored; the peer sees it on its next sync
		s.logger.LogError("peerStreams", err)
		return seq, nil, nil
	}
	return seq, streams, nil
}

// messageBlob checks a ciphertext against the format of its conversation: the room format with
// at most one wrap per seat in a room (returned parsed, for checkRoomMessage), the one-to-one
// format elsewhere (nil).
func messageBlob(room *models.Room, ciphertext string) (*utils.RoomBlob, error) {
	if room == nil {
		if !utils.ValidateCiphertext(ciphertext) {
			return nil, ErrInvalidInput
		}
		return nil, nil
	}
	blob, ok := utils.ParseRoomBlob(ciphertext, utils.RoomMessageMagic, room.MaxMembers)
	if !ok {
		return nil, ErrInvalidInput
	}
	return blob, nil
}

// MarkRead advances the caller's read marker (never backwards, never past the end). seq is at
// least FirstSeq: the input contract refuses anything lower before a handler runs.
func (s *Service) MarkRead(me *Member, conversationID uuid.UUID, seq int64) error {
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return err
	}
	lastSeqs, err := s.chats.LastSeqs([]uuid.UUID{conversationID})
	if err != nil {
		return err
	}
	if seq > lastSeqs[conversationID] {
		return ErrInvalidInput
	}
	return s.chats.AdvanceReadSeq(conversationID, member.MemberTag, seq)
}

// ---------- retention ----------

// Retention deletes by the wall clock, so a clock that jumps would destroy data: forward, it
// expires everything at once; backward, the cap step rewrites expiry dates earlier and messages
// die early once the clock is put right. Each cycle therefore purges only when the clock can be
// trusted (clockTrusted), and remembers when it last purged (the retention mark, in key_checks):
//  1. while running, the wall clock must have moved with the monotonic clock since the previous
//     cycle (utils.ClockSteady, within utils.ClockJumpTolerance); a jump pauses that cycle;
//  2. now must not be before the last purge: a clock behind it went back, and purging (the cap
//     above all) would be wrong until it catches up again;
//  3. at boot there is no previous cycle to compare with, so a time far past the last purge
//     (more than maxRetentionGap) waits one cycle: a boot clock that is wrong (no RTC, NTP not
//     yet synced) usually gets corrected meanwhile, which rule 1 then sees; a gap that is still
//     there after a steady cycle is real downtime, and purging proceeds.
//
// A paused cycle deletes nothing and logs E_CLOCK_JUMP; expired data stays unreadable meanwhile
// (reads filter by expiry themselves).
const (
	// maxRetentionGapTTLs: a boot more than this many maximum retention periods after the last
	// purge waits for a steady cycle (rule 3)
	maxRetentionGapTTLs = 2
)

// maxRetentionGap is rule 3's bound: twice the longest retention MESSAGE_TTL_DAYS allows.
func maxRetentionGap() time.Duration {
	return maxRetentionGapTTLs * time.Duration(config.MaxMessageTTLDays()) * day
}

// clockTrusted applies the rules above. prev is the previous cycle's reading in this process
// (zero at boot), mark the last purge (zero if retention never ran on this database).
func clockTrusted(now, prev, mark time.Time) bool {
	if !utils.ClockSteady(now, prev) {
		return false
	}
	if mark.IsZero() {
		return true
	}
	if now.Before(mark) {
		return false
	}
	return !prev.IsZero() || !now.After(mark.Add(maxRetentionGap()))
}

// PurgeExpired runs one retention pass at now as the first cycle after boot does (no previous
// reading in this process; see retentionCycle).
func (s *Service) PurgeExpired(now time.Time) error {
	return s.retentionCycle(now, time.Time{})
}

// retentionCycle purges what is expired at now, unless the clock cannot be trusted (then it
// deletes nothing and logs E_CLOCK_JUMP): ciphertext past its deletion day, expired invites and
// notes, and expired rooms with everything in them, and keeps no ciphertext past the deletion
// day of a message sent now (MESSAGE_TTL_DAYS may have shrunk). The mark moves to now once
// the pass has run, also when a step failed: the clock was trusted either way.
func (s *Service) retentionCycle(now, prev time.Time) error {
	mark, _, err := s.keys.RetentionMark()
	if err != nil {
		return err
	}
	trusted := clockTrusted(now, prev, mark)
	utils.FlagClockJump(!trusted)
	if !trusted {
		s.logger.Error("RunRetention: %s", opcode.ClockJump)
		return nil
	}
	counts, purgeErr := s.chats.PurgeExpired(deletionCutoff(now), expiryDay(now), now.UTC())
	s.logger.Debug("PurgeExpired: removed %d messages, %d invites, %d notes, %d rooms",
		counts.Messages, counts.Invites, counts.Notes, counts.Rooms)
	return errors.Join(purgeErr, s.keys.SaveRetentionMark(now))
}

const (
	// Rooms expire on the hour and stop answering at once; this bounds how long their rows
	// stay on disk afterwards
	retentionInterval = 5 * time.Minute
	// maxRetentionCycles bounds the loop (RULES.md §8.1); every five minutes it outlives any deployment
	maxRetentionCycles = 1 << 22
)

// Retention liveness, for the healthcheck: each cycle records when it began, on the monotonic
// clock (time since processStart), so a clock jump never makes retention look dead or alive.
var (
	processStart  = time.Now()
	retentionBeat atomic.Int64
)

// retentionSilence: no cycle began for this long means retention is stuck (three missed cycles)
const retentionSilence = 3 * retentionInterval

// RetentionAlive reports whether a retention cycle began within retentionSilence (or the process
// is younger than that).
func RetentionAlive() bool {
	return time.Since(processStart)-time.Duration(retentionBeat.Load()) <= retentionSilence
}

// RunRetention runs a retention cycle now and then every five minutes until ctx ends, each
// compared with the one before it (clockTrusted).
func (s *Service) RunRetention(ctx context.Context) {
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	var prev time.Time
	for cycle := 0; cycle < maxRetentionCycles; cycle++ {
		retentionBeat.Store(int64(time.Since(processStart)))
		now := time.Now()
		if err := s.retentionCycle(now, prev); err != nil {
			s.logger.LogError("RunRetention", err)
		}
		prev = now
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
