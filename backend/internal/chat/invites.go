package chat

import (
	"encoding/base64"
	"errors"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/encryption"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

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

func inviteCreatorAAD(lookup string, inviteID uuid.UUID) []byte {
	return encryption.BuildAAD(lookup, inviteID, encryption.FieldInviteCreator, encryption.PurposeStoredRecord)
}
