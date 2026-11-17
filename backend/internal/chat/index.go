package chat

import (
	"encoding/json"
	"strings"

	"elyrn/internal/config"
	"elyrn/internal/encryption"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

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

func (s *Service) saveIndex(repo store.ChatRepository, m *Member, ids []uuid.UUID) error {
	enc, err := sealIndex(m, ids)
	if err != nil {
		return err
	}
	return repo.SaveConvIndex(m.UserUUID, enc)
}
