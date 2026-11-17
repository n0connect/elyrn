package chat

import (
	"errors"

	"elyrn/internal/encryption"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// ---------- membership records ----------

// The AAD binding each master-key encrypted reference to its row (shared with re-wrapping)
func memberRefAAD(memberTag string, conversationID uuid.UUID) []byte {
	return encryption.BuildAAD(memberTag, conversationID, encryption.FieldMemberRef, encryption.PurposeStoredRecord)
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
