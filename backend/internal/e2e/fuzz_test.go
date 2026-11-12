package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Decrypt never panics, and whatever it accepts for this key and AAD is a genuine sealing of
// the vector message: a fuzzer cannot forge GCM, and non-canonical encodings are refused.
func FuzzDecrypt(f *testing.F) {
	a, b := load(f, accountA), load(f, accountB)
	key, err := ConversationKey(a.private, b.public, vectorConversation)
	if err != nil {
		f.Fatalf("ConversationKey: %v", err)
	}
	genuine, err := Encrypt(key, vectorConversation, vectorMessage, a.public, vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	f.Add(genuine)
	f.Add(browserCiphertext)
	f.Add("")
	f.Add(genuine[:len(genuine)-1])
	f.Add(genuine + "A")

	f.Fuzz(func(t *testing.T, ciphertext string) {
		msg, err := Decrypt(key, vectorConversation, vectorMessage, a.public, ciphertext)
		if err != nil {
			return
		}
		if *msg != (Message{Text: vectorText, SentAt: vectorSentAt, Counter: vectorCounter}) {
			t.Fatalf("ciphertext %q decrypted to %+v", ciphertext, msg)
		}
		if !utils.IsBase64URL(ciphertext) {
			t.Fatalf("non-canonical ciphertext %q accepted", ciphertext)
		}
	})
}

// Mutating the message id or sender must fail authentication (they are bound by the AAD).
func FuzzDecryptBindings(f *testing.F) {
	a, b := load(f, accountA), load(f, accountB)
	key, err := ConversationKey(a.private, b.public, vectorConversation)
	if err != nil {
		f.Fatalf("ConversationKey: %v", err)
	}
	genuine, err := Encrypt(key, vectorConversation, vectorMessage, a.public, vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	f.Add(vectorMessage.String(), a.public)
	f.Add(vectorMessage.String(), b.public)
	f.Add(uuid.New().String(), a.public)

	f.Fuzz(func(t *testing.T, messageID, sender string) {
		id, err := uuid.Parse(messageID)
		if err != nil {
			return
		}
		_, err = Decrypt(key, vectorConversation, id, sender, genuine)
		if err == nil && (id != vectorMessage || sender != a.public) {
			// the same bytes in a non-canonical spelling (e.g. an embedded CR) must not pass either
			t.Fatalf("ciphertext accepted under message %s sender %q", id, sender)
		}
	})
}

// ---------- rooms ----------
//
// The room targets open the browser's interop vectors (room_test.go): fixed inputs, so every
// fuzz worker checks against the same genuine blob, note, cards and vault.

const (
	// vectorRoomCounter and vectorNoteText are what the browser sealed into the vector blob and note
	vectorRoomCounter = int64(4)
	vectorNoteText    = "noaddx:invite-vector"
	// maxFuzzKeys bounds the keys one safety-number input is cut into
	maxFuzzKeys = MaxRoomMembers + 1
)

// vectorRoom is the browser vector's room with its two members and an outsider (accountC).
type vectorRoom struct {
	code      *RoomCode
	room      *Room
	a, b, c   roomParty
	bBrowser  *RoomMember // B holding its browser card, the note's addressee
	messageID uuid.UUID
	noteID    uuid.UUID
}

func loadVectorRoom(t testing.TB) vectorRoom {
	t.Helper()
	code, err := ParseRoomCode(roomVectorCode)
	if err != nil {
		t.Fatalf("ParseRoomCode: %v", err)
	}
	room, err := DeriveRoom(code.Secret)
	if err != nil {
		t.Fatalf("DeriveRoom: %v", err)
	}
	v := vectorRoom{code: code, room: room, a: joinAs(t, room, accountA), b: joinAs(t, room, accountB),
		c: joinAs(t, room, accountC), messageID: uuid.MustParse(roomVectorMessage), noteID: uuid.MustParse(roomVectorNote)}
	v.bBrowser = &RoomMember{private: v.b.member.private, Public: v.b.member.Public, Card: browserCardB}
	return v
}

// mustDecode decodes a vector known to be canonical base64url.
func mustDecode(t testing.TB, encoded string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return raw
}

// sameSealedParts reports whether blob carries exactly genuine's header and body: the only
// bytes a recipient may see changed in a blob that still opens are other recipients' wraps.
func sameSealedParts(blob string, genuine []byte) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(blob)
	if err != nil || len(raw) != len(genuine) {
		return false
	}
	bodyStart := roomHeaderSize + int(genuine[roomHeaderSize-1])*roomWrapSize
	return bytes.Equal(raw[:roomHeaderSize], genuine[:roomHeaderSize]) && bytes.Equal(raw[bodyStart:], genuine[bodyStart:])
}

// expectGenuineRoomMessage fails unless msg is exactly what the vector's sender sealed.
func expectGenuineRoomMessage(t *testing.T, v vectorRoom, msg *RoomMessage, text string, counter int64, blob string, genuine []byte) {
	t.Helper()
	if msg.Text != text || msg.SentAt != vectorSentAt || msg.Counter != counter || !bytes.Equal(msg.Sender, v.a.member.Public) {
		t.Fatalf("blob %q opened to %+v", blob, msg)
	}
	if !sameSealedParts(blob, genuine) || !bytes.Equal(msg.Digest, genuine[offsetDigest:roomHeaderSize-1]) {
		t.Fatalf("a blob with a changed header or body opened: %q", blob)
	}
}

// FuzzParseRoomCode: an accepted code is valid and canonical: rendering it gives the input back
// (under the current prefix), and the rendering parses to the same code.
func FuzzParseRoomCode(f *testing.F) {
	v := loadVectorRoom(f)
	for _, seed := range []string{roomVectorCode, v.code.String(), v.code.String() + "A", v.code.String()[:len(v.code.String())-1],
		strings.ToUpper(v.code.String()), "elyrn#", "noaddx#", "", "elyrn#\n" + v.code.String()[len(RoomCodePrefix):],
		RoomCodePrefix + LegacyRoomCodePrefix, "\u202e" + v.code.String()} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		code, err := ParseRoomCode(s)
		if err != nil {
			return
		}
		body, ok := strings.CutPrefix(s, RoomCodePrefix)
		if !ok {
			body, ok = strings.CutPrefix(s, LegacyRoomCodePrefix)
		}
		if !ok || !code.valid() || code.String() != RoomCodePrefix+body {
			t.Fatalf("accepted the non-canonical code %q", s)
		}
		again, err := ParseRoomCode(code.String())
		if err != nil || !bytes.Equal(again.Secret, code.Secret) || again.MaxMembers != code.MaxMembers || again.ExpiresHour != code.ExpiresHour {
			t.Fatalf("%q does not round-trip: %v", s, err)
		}
	})
}

// FuzzRoomCodeBuild: any code built from arbitrary fields parses back to itself exactly when it
// is valid (32-byte secret, 2..32 members, a non-zero expiry hour), and is refused otherwise.
func FuzzRoomCodeBuild(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x40}, RoomSecretSize), uint8(MinRoomMembers), uint32(480000))
	f.Add(bytes.Repeat([]byte{0x40}, RoomSecretSize), uint8(MaxRoomMembers+1), uint32(1))
	f.Add(bytes.Repeat([]byte{0x40}, RoomSecretSize-1), uint8(5), uint32(1))
	f.Add([]byte{}, uint8(0), uint32(0))
	f.Fuzz(func(t *testing.T, secret []byte, maxMembers uint8, hour uint32) {
		built := &RoomCode{Secret: secret, MaxMembers: int(maxMembers), ExpiresHour: hour}
		parsed, err := ParseRoomCode(built.String())
		if !built.valid() {
			if err == nil {
				t.Fatalf("an invalid code parsed: %+v", built)
			}
			return
		}
		if err != nil || !bytes.Equal(parsed.Secret, secret) || parsed.MaxMembers != built.MaxMembers || parsed.ExpiresHour != hour {
			t.Fatalf("a valid code did not round-trip: %v", err)
		}
	})
}

// FuzzOpenRoomMessage: a blob opens only for a member it was sealed for, and only when its
// header and body are the sender's (a fuzzer cannot forge AES-GCM, the commitment or a card);
// what opens is then exactly what the sender sealed. The outsider never opens anything.
func FuzzOpenRoomMessage(f *testing.F) {
	v := loadVectorRoom(f)
	genuine := mustDecode(f, browserRoomBlob)
	for _, seed := range []string{browserRoomBlob, flip(f, browserRoomBlob, offsetCommit), flip(f, browserRoomBlob, len(genuine)-1),
		flip(f, browserRoomBlob, roomHeaderSize), browserRoomNote, browserRoomBlob + "A", browserRoomBlob[:len(browserRoomBlob)-1], ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, blob string) {
		for _, reader := range []roomParty{v.a, v.b} {
			if msg, err := v.room.OpenMessage(reader.member, v.messageID, blob); err == nil {
				expectGenuineRoomMessage(t, v, msg, roomInteropText, vectorRoomCounter, blob, genuine)
			}
		}
		if _, err := v.room.OpenMessage(v.c.member, v.messageID, blob); err == nil {
			t.Fatalf("a member outside the roster opened %q", blob)
		}
	})
}

// FuzzMutateRoomMessage flips bits at one position of the genuine blob: a change in the header
// or the body never opens for anyone; a change inside a wrap may only cost that wrap's reader.
func FuzzMutateRoomMessage(f *testing.F) {
	v := loadVectorRoom(f)
	genuine := mustDecode(f, browserRoomBlob)
	for _, index := range []int{0, 4, offsetCard, offsetEph, offsetCommit, offsetDigest, roomHeaderSize - 1, roomHeaderSize, len(genuine) - 1} {
		f.Add(uint16(index), uint8(1))
	}
	f.Fuzz(func(t *testing.T, index uint16, mask uint8) {
		if mask == 0 {
			return
		}
		mutated := append([]byte(nil), genuine...)
		mutated[int(index)%len(mutated)] ^= mask
		blob := encode(mutated)
		for _, reader := range []roomParty{v.a, v.b} {
			if msg, err := v.room.OpenMessage(reader.member, v.messageID, blob); err == nil {
				expectGenuineRoomMessage(t, v, msg, roomInteropText, vectorRoomCounter, blob, genuine)
			}
		}
		if _, err := v.room.OpenMessage(v.c.member, v.messageID, blob); err == nil {
			t.Fatal("a member outside the roster opened a mutated blob")
		}
	})
}

// FuzzOpenRoomNote: a note opens only for its addressee and only with the sender's header and
// body; neither the sender nor a bystander ever opens it.
func FuzzOpenRoomNote(f *testing.F) {
	v := loadVectorRoom(f)
	genuine := mustDecode(f, browserRoomNote)
	for _, seed := range []string{browserRoomNote, browserRoomBlob, flip(f, browserRoomNote, offsetDigest), flip(f, browserRoomNote, roomHeaderSize-1), ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, blob string) {
		if msg, err := v.room.OpenNote(v.bBrowser, v.noteID, blob); err == nil {
			expectGenuineRoomMessage(t, v, msg, vectorNoteText, 1, blob, genuine)
		}
		for _, other := range []*RoomMember{v.a.member, v.c.member} {
			if _, err := v.room.OpenNote(other, v.noteID, blob); err == nil {
				t.Fatalf("a note opened for a member it was not addressed to: %q", blob)
			}
		}
	})
}

// FuzzOpenRoomCard: a card opens only to one of the room's member keys (deterministic from the
// accounts, so every fuzz process judges alike), a browser vector card opens to its own key,
// and a card that keeps a vector card's nonce but changes anything else never opens. Cards
// sealed in this process (random nonces) are seeds only: any process opens them to their key.
func FuzzOpenRoomCard(f *testing.F) {
	v := loadVectorRoom(f)
	members := [][]byte{v.a.member.Public, v.b.member.Public, v.c.member.Public}
	vectors := map[string][]byte{browserCardA: v.a.member.Public, browserCardB: v.b.member.Public}
	for _, card := range []string{browserCardA, browserCardB, v.a.member.Card, v.b.member.Card, v.c.member.Card} {
		f.Add(card)
		f.Add(flip(f, card, 0))
		f.Add(flip(f, card, roomCardSize-1))
	}
	f.Add("")
	f.Add(browserCardA + "A")
	f.Fuzz(func(t *testing.T, card string) {
		public, err := v.room.OpenCard(card)
		if err != nil {
			return
		}
		raw, decodeErr := decodeExact(card, roomCardSize)
		member := false
		for _, key := range members {
			member = member || bytes.Equal(public, key)
		}
		if decodeErr != nil || !member {
			t.Fatalf("card %q opened to a key no member holds", card)
		}
		for vector, key := range vectors {
			vectorRaw := mustDecode(t, vector)
			if card == vector && !bytes.Equal(public, key) {
				t.Fatalf("vector card %q opened to another key", card)
			}
			if card != vector && bytes.Equal(raw[:cryptoengine.GCMNonceSize], vectorRaw[:cryptoengine.GCMNonceSize]) {
				t.Fatalf("a changed vector card opened: %q", card)
			}
		}
	})
}

// FuzzOpenRoomVault: only the vault the account sealed opens, to the code it sealed.
func FuzzOpenRoomVault(f *testing.F) {
	v := loadVectorRoom(f)
	f.Add(browserVaultA)
	f.Add(flip(f, browserVaultA, 0))
	f.Add(flip(f, browserVaultA, len(mustDecode(f, browserVaultA))-1))
	f.Add("")
	f.Fuzz(func(t *testing.T, vault string) {
		code, err := OpenVault(v.a.root, v.room.ID, vault)
		if err != nil {
			return
		}
		if vault != browserVaultA || !bytes.Equal(code.Secret, v.code.Secret) || code.MaxMembers != v.code.MaxMembers || code.ExpiresHour != v.code.ExpiresHour {
			t.Fatalf("an unknown vault opened: %q", vault)
		}
		if _, err := OpenVault(v.b.root, v.room.ID, vault); err == nil {
			t.Fatal("another account opened the vault")
		}
	})
}

// cardListSeparator splits one fuzzed string into a roster
const cardListSeparator = ","

// FuzzRosterDigest: a digest exists only for 1..32 canonical cards; it ignores their order and
// changes when any card is dropped.
func FuzzRosterDigest(f *testing.F) {
	f.Add(browserCardA + cardListSeparator + browserCardB)
	f.Add(browserCardA + cardListSeparator + browserCardA)
	f.Add(browserCardA)
	f.Add(browserCardA + cardListSeparator)
	f.Add(strings.Repeat(browserCardA+cardListSeparator, MaxRoomMembers) + browserCardA)
	f.Add("")
	f.Fuzz(func(t *testing.T, list string) {
		cards := strings.Split(list, cardListSeparator)
		digest, err := RosterDigest(cards)
		if err != nil {
			return
		}
		if len(cards) < 1 || len(cards) > MaxRoomMembers {
			t.Fatalf("a roster of %d cards was digested", len(cards))
		}
		for _, card := range cards {
			if _, err := decodeExact(card, roomCardSize); err != nil {
				t.Fatalf("a malformed card was digested: %q", card)
			}
		}
		reversed := make([]string, len(cards))
		for i, card := range cards {
			reversed[len(cards)-1-i] = card
		}
		if again, err := RosterDigest(reversed); err != nil || !bytes.Equal(again, digest) {
			t.Fatal("the digest depends on the roster's order")
		}
		if len(cards) > 1 {
			if fewer, err := RosterDigest(cards[1:]); err != nil || bytes.Equal(fewer, digest) {
				t.Fatal("dropping a card left the digest unchanged")
			}
		}
	})
}

// expectAura fails unless a is a well-formed aura: two listed words and four lowercase hex digits.
func expectAura(t *testing.T, a Aura) {
	t.Helper()
	adjective, noun, ok := strings.Cut(a.Name, "-")
	inList := func(words [auraWords]string, w string) bool {
		for _, candidate := range words {
			if candidate == w {
				return true
			}
		}
		return false
	}
	raw, err := hex.DecodeString(a.Code)
	if !ok || !inList(auraAdjectives, adjective) || !inList(auraNouns, noun) || err != nil ||
		len(raw) != auraCodeEnd-auraCodeStart || hex.EncodeToString(raw) != a.Code {
		t.Fatalf("malformed aura %+v", a)
	}
}

// FuzzAura: a key of exactly 32 bytes and a non-nil room id each have one well-formed,
// deterministic aura; anything else is refused.
func FuzzAura(f *testing.F) {
	f.Add(make([]byte, keySize))
	f.Add(bytes.Repeat([]byte{0xff}, keySize))
	f.Add(make([]byte, keySize-1))
	f.Add(make([]byte, 16))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, key []byte) {
		aura, err := AuraOf(key)
		if (err == nil) != (len(key) == keySize) {
			t.Fatalf("AuraOf(%d bytes): %v", len(key), err)
		}
		if err == nil {
			expectAura(t, aura)
			if again, _ := AuraOf(key); again != aura {
				t.Fatal("AuraOf is not deterministic")
			}
		}
		var id uuid.UUID
		copy(id[:], key)
		roomAura, err := RoomAura(id)
		if (err == nil) != (id != uuid.Nil) {
			t.Fatalf("RoomAura(%s): %v", id, err)
		}
		if err == nil {
			expectAura(t, roomAura)
		}
	})
}

// FuzzRoomSafetyNumber: 1..32 keys of 32 bytes give six groups of five digits, the same in any
// order; a key of another size or a roster out of bounds is refused.
func FuzzRoomSafetyNumber(f *testing.F) {
	f.Add(mustDecode(f, roomVectorPublicA), 0)
	f.Add(append(mustDecode(f, roomVectorPublicA), mustDecode(f, roomVectorPublicB)...), 0)
	f.Add(make([]byte, keySize*(MaxRoomMembers+1)), 0)
	f.Add(make([]byte, keySize+1), 1)
	f.Add([]byte{}, 0)
	f.Fuzz(func(t *testing.T, material []byte, cut int) {
		var keys [][]byte
		for len(material) > 0 && len(keys) < maxFuzzKeys {
			size := min(len(material), keySize)
			if cut != 0 && len(keys) == 0 {
				size = min(len(material), keySize+cut%keySize) // a first key of another size
			}
			keys = append(keys, material[:size])
			material = material[size:]
		}
		groups, err := RoomSafetyNumber(keys)
		valid := len(keys) >= 1 && len(keys) <= MaxRoomMembers
		for _, key := range keys {
			valid = valid && len(key) == keySize
		}
		if (err == nil) != valid {
			t.Fatalf("RoomSafetyNumber(%d keys): %v", len(keys), err)
		}
		if err != nil {
			return
		}
		if len(groups) != safetyGroups {
			t.Fatalf("%d groups", len(groups))
		}
		for _, g := range groups {
			if n, convErr := strconv.Atoi(g); len(g) != safetyGroupBytes || convErr != nil || n < 0 || n >= safetyGroupMod {
				t.Fatalf("malformed group %q", g)
			}
		}
		reversed := make([][]byte, len(keys))
		for i, key := range keys {
			reversed[len(keys)-1-i] = key
		}
		if again, err := RoomSafetyNumber(reversed); err != nil || strings.Join(again, " ") != strings.Join(groups, " ") {
			t.Fatal("the safety number depends on the order of the keys")
		}
	})
}
