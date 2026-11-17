package integration

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/database"
	"elyrn/internal/handlers"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// The server never opens a part: it stores whatever sealed part of the one size a member sends.
// These tests use random bytes of that size, which is exactly what the server can check of a
// genuine one.
func newFilePart(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, utils.FilePartSealedBytes))
}

// filesSetup is setup plus a fresh count of the stored parts: the server takes one at start, and
// every test starts on an emptied database.
func filesSetup(t *testing.T) http.Handler {
	t.Helper()
	mux := setup(t)
	recountParts(t)
	return mux
}

func recountParts(t *testing.T) {
	t.Helper()
	if err := chat.NewService().RecountFileParts(); err != nil {
		t.Fatalf("RecountFileParts: %v", err)
	}
}

func filesPath(conv string) string {
	return models.PathConversations + "/" + conv + "/" + models.SubFiles
}

func (c *client) uploadPart(conv, file string, part int, data string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(http.MethodPost, filesPath(conv), models.UploadFilePartRequest{ID: file, Part: part, Data: data})
}

func (c *client) readPart(conv, file string, part int) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(http.MethodGet, filesPath(conv)+"/"+file+"?"+models.QueryPart+"="+strconv.Itoa(part), nil)
}

// expectPart insists c reads exactly data as that part.
func expectPart(t *testing.T, c *client, conv, file string, part int, data, what string) {
	t.Helper()
	rr := c.readPart(conv, file, part)
	expectStatus(t, rr, http.StatusOK, what)
	var got models.FilePartResponse
	decode(t, rr, &got)
	if got.Data != data {
		t.Fatalf("%s: the part read back is not the part stored", what)
	}
}

// storedParts counts the parts stored in conv.
func storedParts(t *testing.T, conv uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := database.DB.Model(&models.FilePart{}).Where("conversation_id = ?", conv).Count(&n).Error; err != nil {
		t.Fatalf("count parts: %v", err)
	}
	return n
}

// missingAnswer is the answer to a file read in a conversation that does not exist: what every
// refused read must answer byte for byte.
func missingAnswer(t *testing.T, c *client) *httptest.ResponseRecorder {
	t.Helper()
	rr := c.readPart(uuid.NewString(), uuid.NewString(), 0)
	expectAnswer(t, rr, apperr.NotFound, "a file of a conversation that does not exist")
	return rr
}

func TestFiles_MembersStoreAndReadParts(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file := uuid.NewString()
	parts := []string{newFilePart(t), newFilePart(t), newFilePart(t)}
	for i, data := range parts {
		expectStatus(t, alice.uploadPart(conv, file, i, data), http.StatusCreated, "upload part "+strconv.Itoa(i))
	}
	for i, data := range parts {
		expectPart(t, bob.client, conv, file, i, data, "bob reads part "+strconv.Itoa(i))
		expectPart(t, alice.client, conv, file, i, data, "alice reads her own part "+strconv.Itoa(i))
	}

	// A room works alike, for every member
	a := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, a.code)
	c := joinRoom(t, carol, a.code)
	roomFile, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, carol.uploadPart(c.room.ID.String(), roomFile, 0, data), http.StatusCreated, "carol uploads in the room")
	expectPart(t, bob.client, b.room.ID.String(), roomFile, 0, data, "bob reads carol's part")
	expectPart(t, alice.client, a.room.ID.String(), roomFile, 0, data, "the owner reads carol's part")

	// Stored raw, one size, nothing but the declared columns
	var stored models.FilePart
	if err := database.DB.Where("conversation_id = ? AND file_id = ? AND part = 0", c.room.ID, roomFile).First(&stored).Error; err != nil {
		t.Fatalf("read the stored part: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(data)
	if !bytes.Equal(stored.Data, raw) || len(stored.Data) != utils.FilePartSealedBytes {
		t.Fatal("the stored part is not the raw sealed part")
	}
	if day := stored.ExpiresOn.UTC(); !day.Truncate(24 * time.Hour).Equal(day) {
		t.Fatalf("a part's expiry %v is finer than a day", day)
	}

	// /me tells clients the largest file
	rr := alice.do(http.MethodGet, models.PathMe, nil)
	var me models.MeResponse
	decode(t, rr, &me)
	if me.FileMaxBytes != config.GetMaxFileBytes() {
		t.Fatalf("/me file_max_bytes = %d, want %d", me.FileMaxBytes, config.GetMaxFileBytes())
	}
}

// Nothing tells a non-member whether a conversation or a file exists: a stranger's read and
// upload, an unknown file, a part never stored, an expired room and a room left answer exactly
// like a conversation that does not exist.
func TestFiles_RefusedReadsAnswerLikeNothing(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, mallory := register(t, mux), register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, alice.uploadPart(conv, file, 0, data), http.StatusCreated, "upload")
	room := createRoom(t, alice, 4, 24)
	gone := joinRoom(t, mallory, room.code)
	roomFile := uuid.NewString()
	expectStatus(t, alice.uploadPart(room.room.ID.String(), roomFile, 0, newFilePart(t)), http.StatusCreated, "upload in the room")
	expectStatus(t, mallory.do(http.MethodDelete, gone.path(""), nil), http.StatusNoContent, "mallory leaves")

	for name, c := range map[string]*client{"mallory": mallory.client, "bob": bob.client} {
		reference := missingAnswer(t, c)
		if c == mallory.client {
			expectIdentical(t, c.readPart(conv, file, 0), reference, name+" reads a part of a conversation she is not in")
			expectIdentical(t, c.readPart(room.room.ID.String(), roomFile, 0), reference, name+" reads a part of a room she left")
			expectIdentical(t, c.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), uploadReference(t, c), name+" uploads to a conversation she is not in")
		}
		expectIdentical(t, c.readPart(conv, uuid.NewString(), 0), reference, name+": an unknown file")
		expectIdentical(t, c.readPart(conv, file, 1), reference, name+": a part never stored")
	}
	if storedParts(t, uuid.MustParse(conv)) != 1 {
		t.Fatal("a refused upload stored a part")
	}

	database.DB.Model(&models.Room{}).Where("id = ?", room.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	expectIdentical(t, alice.readPart(room.room.ID.String(), roomFile, 0), missingAnswer(t, alice.client), "the owner reads a part of an expired room")
	expectIdentical(t, alice.uploadPart(room.room.ID.String(), uuid.NewString(), 0, newFilePart(t)), uploadReference(t, alice.client),
		"the owner uploads to an expired room")
}

// uploadReference is the answer to an upload to a conversation that does not exist.
func uploadReference(t *testing.T, c *client) *httptest.ResponseRecorder {
	t.Helper()
	rr := c.uploadPart(uuid.NewString(), uuid.NewString(), 0, newFilePart(t))
	expectAnswer(t, rr, apperr.NotFound, "an upload to a conversation that does not exist")
	return rr
}

// A file belongs to whoever stored its part 0: nobody continues a file before that, nor anyone
// else's file, and nobody takes a stored part's place.
func TestFiles_PartZeroOpensTheFileForItsUploader(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file := uuid.NewString()

	expectAnswer(t, alice.uploadPart(conv, file, 1, newFilePart(t)), apperr.FilePartOutOfOrder, "part 1 before part 0")
	if storedParts(t, uuid.MustParse(conv)) != 0 {
		t.Fatal("an out-of-order part was stored")
	}
	first := newFilePart(t)
	expectStatus(t, alice.uploadPart(conv, file, 0, first), http.StatusCreated, "part 0")

	// bob squats neither alice's part 0 nor the rest of her file
	expectAnswer(t, bob.uploadPart(conv, file, 0, newFilePart(t)), apperr.IDTaken, "bob sends part 0 of alice's file")
	expectAnswer(t, bob.uploadPart(conv, file, 1, newFilePart(t)), apperr.FilePartOutOfOrder, "bob continues alice's file")
	expectAnswer(t, bob.uploadPart(conv, file, 0, first), apperr.IDTaken, "bob sends alice's very bytes as part 0")
	expectPart(t, alice.client, conv, file, 0, first, "part 0 after bob's attempts")
	if storedParts(t, uuid.MustParse(conv)) != 1 {
		t.Fatal("bob's refused parts were stored")
	}

	// alice's later parts take part 0's deletion day, so a file expires as one
	expectStatus(t, alice.uploadPart(conv, file, 2, newFilePart(t)), http.StatusCreated, "part 2 (parts need not come in order after part 0)")
	var days []time.Time
	database.DB.Model(&models.FilePart{}).Where("file_id = ?", file).Pluck("expires_on", &days)
	if len(days) != 2 || !days[0].Equal(days[1]) {
		t.Fatalf("the parts of one file expire on %v", days)
	}

	// Beyond the largest file MAX_FILE_BYTES allows, a part number is refused before anything else
	last := int(utils.FilePartCount(config.GetMaxFileBytes()))
	expectStatus(t, alice.uploadPart(conv, file, last, newFilePart(t)), http.StatusBadRequest, "a part past MAX_FILE_BYTES")
}

// A resend after a lost answer is told apart from a clash, as for messages: the same uploader's
// identical part answers 409 Conflict ("stored"), anything else 409 Id taken, and nothing moves.
func TestFiles_IdenticalResendIsStoredAlteredIsTaken(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, alice.uploadPart(conv, file, 0, data), http.StatusCreated, "part 0")
	expectAnswer(t, alice.uploadPart(conv, file, 0, data), apperr.Conflict, "the identical part again")
	raw, _ := base64.RawURLEncoding.DecodeString(data)
	raw[len(raw)-1] ^= 1
	expectAnswer(t, alice.uploadPart(conv, file, 0, base64.RawURLEncoding.EncodeToString(raw)), apperr.IDTaken, "an altered part")
	expectPart(t, bob.client, conv, file, 0, data, "the stored part after the resends")

	// The identical resend still answers "stored" once the quota is full
	t.Setenv(config.EnvFileConversationQuotaBytes, strconv.Itoa(utils.FilePartBytes))
	expectAnswer(t, alice.uploadPart(conv, file, 0, data), apperr.Conflict, "the identical part with the quota full")
}

// One file id in two conversations names two files: the key spans the conversation.
func TestFiles_TheSameIDInTwoConversationsDoesNotCollide(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	withBob, withCarol := pair(t, alice, bob), pair(t, alice, carol)
	file, forBob, forCarol := uuid.NewString(), newFilePart(t), newFilePart(t)
	expectStatus(t, alice.uploadPart(withBob, file, 0, forBob), http.StatusCreated, "the file for bob")
	expectStatus(t, carol.uploadPart(withCarol, file, 0, forCarol), http.StatusCreated, "carol's file under the same id")
	expectPart(t, bob.client, withBob, file, 0, forBob, "bob's file")
	expectPart(t, carol.client, withCarol, file, 0, forCarol, "carol's file")
	expectAnswer(t, carol.readPart(withBob, file, 0), apperr.NotFound, "carol reads bob's file by its id")
}

// FILE_CONVERSATION_QUOTA_BYTES caps one conversation, FILE_STORE_MAX_BYTES the server; the store
// is counted in process, fails closed before its first count, follows burns and is set again by
// every retention cycle.
func TestFiles_QuotaStoreAndTheCounter(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, carol, dave := register(t, mux), register(t, mux), register(t, mux), register(t, mux)
	first, second, third := pair(t, alice, bob), pair(t, alice, carol), pair(t, alice, dave)
	twoParts, threeParts := strconv.Itoa(2*utils.FilePartBytes), strconv.Itoa(3*utils.FilePartBytes)
	t.Setenv(config.EnvFileConversationQuotaBytes, twoParts)
	t.Setenv(config.EnvFileStoreMaxBytes, threeParts)

	file := uuid.NewString()
	expectStatus(t, alice.uploadPart(first, file, 0, newFilePart(t)), http.StatusCreated, "part 0")
	expectStatus(t, alice.uploadPart(first, file, 1, newFilePart(t)), http.StatusCreated, "part 1")
	expectAnswer(t, alice.uploadPart(first, file, 2, newFilePart(t)), apperr.FileQuotaReached, "part 2 past the quota")
	expectAnswer(t, bob.uploadPart(first, uuid.NewString(), 0, newFilePart(t)), apperr.FileQuotaReached, "bob's file past the same quota")

	expectStatus(t, alice.uploadPart(second, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "the third part on the server")
	expectAnswer(t, alice.uploadPart(third, uuid.NewString(), 0, newFilePart(t)), apperr.FileStoreFull, "a fourth part on the server")
	if storedParts(t, uuid.MustParse(third)) != 0 {
		t.Fatal("a part was stored past the store's bound")
	}

	// A burn gives its parts back at once
	expectStatus(t, alice.do(http.MethodDelete, models.PathConversations+"/"+first, nil), http.StatusNoContent, "burn the first conversation")
	expectStatus(t, alice.uploadPart(third, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "an upload after the burn")

	// Expired parts are purged by retention, which counts the store again
	expectStatus(t, alice.uploadPart(third, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "the store full again")
	expectAnswer(t, carol.uploadPart(second, uuid.NewString(), 0, newFilePart(t)), apperr.FileStoreFull, "full")
	database.DB.Model(&models.FilePart{}).Where("conversation_id = ?", uuid.MustParse(third)).
		UpdateColumn("expires_on", time.Now().UTC().Add(-2*24*time.Hour))
	if err := chat.NewService().PurgeExpired(time.Now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if storedParts(t, uuid.MustParse(third)) != 0 {
		t.Fatal("expired parts survived retention")
	}
	expectStatus(t, carol.uploadPart(second, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "an upload after the purge")

	// Before the server has counted its parts, every upload is refused (fail closed)
	if err := chat.ForgetFilePartCountForTesting(); err != nil {
		t.Fatalf("forget the count: %v", err)
	}
	t.Setenv(config.EnvFileStoreMaxBytes, strconv.FormatInt(config.MaxFileStoreBytesBound, 10))
	expectAnswer(t, alice.uploadPart(third, uuid.NewString(), 0, newFilePart(t)), apperr.FileStoreFull, "an upload before the first count")
	recountParts(t)
	expectStatus(t, alice.uploadPart(third, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "an upload after the count")
}

// Reads filter on expiry themselves: a part past its deletion day is never served, and a file
// whose part 0 expired cannot be continued, whether or not retention ran.
func TestFiles_ExpiredPartsAreNotServed(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file := uuid.NewString()
	expectStatus(t, alice.uploadPart(conv, file, 0, newFilePart(t)), http.StatusCreated, "part 0")
	database.DB.Model(&models.FilePart{}).Where("file_id = ?", file).UpdateColumn("expires_on", time.Now().UTC().Add(-2*24*time.Hour))
	expectIdentical(t, bob.readPart(conv, file, 0), missingAnswer(t, bob.client), "an expired part")
	expectAnswer(t, alice.uploadPart(conv, file, 1, newFilePart(t)), apperr.FilePartOutOfOrder, "continuing a file whose part 0 expired")
}

// Parts go with their conversation: a burn, a room's expiry and an account deletion remove them;
// leaving a room keeps the leaver's parts, readable like their messages.
func TestFiles_PartsGoWithTheirConversation(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)

	burned := pair(t, alice, bob)
	expectStatus(t, alice.uploadPart(burned, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "a part to burn")
	expectStatus(t, bob.do(http.MethodDelete, models.PathConversations+"/"+burned, nil), http.StatusNoContent, "bob burns")
	if storedParts(t, uuid.MustParse(burned)) != 0 {
		t.Fatal("parts survived the burn")
	}

	room := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, room.code)
	roomID := room.room.ID.String()
	kept, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, bob.uploadPart(roomID, kept, 0, data), http.StatusCreated, "bob's part in the room")
	expectStatus(t, bob.do(http.MethodDelete, b.path(""), nil), http.StatusNoContent, "bob leaves")
	expectPart(t, alice.client, roomID, kept, 0, data, "bob's part after he left")
	database.DB.Model(&models.Room{}).Where("id = ?", room.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	if err := chat.NewService().PurgeExpired(time.Now()); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if storedParts(t, room.room.ID) != 0 {
		t.Fatal("parts survived their room's expiry")
	}

	deleted := pair(t, carol, alice)
	expectStatus(t, carol.uploadPart(deleted, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "carol's part")
	expectStatus(t, carol.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: carol.authKey}), http.StatusOK, "carol deletes her account")
	if storedParts(t, uuid.MustParse(deleted)) != 0 {
		t.Fatal("parts survived the account deletion")
	}
}

// Only the part that opens a file takes a token from the caller's file bucket: a long file
// uploads in one go, many new files do not.
func TestFiles_OnlyPartZeroIsRateLimited(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	// No token comes back while the test runs (a bucket takes the interval when it is created)
	t.Setenv("RATE_LIMIT_REFILL_INTERVAL_SEC", "3600")
	file := uuid.NewString()
	parts := int(utils.FilePartCount(config.GetMaxFileBytes()))
	tokens := config.GetRateLimitMaxTokens()
	if parts <= tokens {
		t.Fatalf("a file of %d parts proves nothing against %d tokens", parts, tokens)
	}
	for i := 0; i < parts; i++ {
		expectStatus(t, alice.uploadPart(conv, file, i, newFilePart(t)), http.StatusCreated, "part "+strconv.Itoa(i))
	}
	for i := 1; i < tokens; i++ {
		expectStatus(t, alice.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "new file "+strconv.Itoa(i))
	}
	expectAnswer(t, alice.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), apperr.RateLimited, "one new file too many")
}

// A file budget is created only for an authenticated account: requests without a session never
// reach the handler that takes one (the session gate refuses them first), so a flood of them
// cannot fill the bounded budget map.
func TestFiles_BudgetsOnlyForAuthenticatedAccounts(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	before := middleware.FileBudgetCountForTesting()
	for i := 0; i < 5; i++ {
		anonymous := newClient(t, mux)
		expectAnswer(t, anonymous.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), apperr.NoSession, "an upload without a session")
		forged := withCookie(t, mux, "not-a-session")
		expectAnswer(t, forged.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), apperr.NoSession, "an upload with a forged cookie")
	}
	if after := middleware.FileBudgetCountForTesting(); after != before {
		t.Fatalf("requests without a session created %d budgets", after-before)
	}
	expectStatus(t, alice.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "alice uploads")
	if after := middleware.FileBudgetCountForTesting(); after != before+1 {
		t.Fatalf("an authenticated upload created %d budgets, want 1", after-before)
	}
}

// A file request slot is taken only by an authenticated caller: with every slot held, a request
// without a session still gets its 401 (it never waits for or takes a slot), a member's request
// gets 503 E_FILE_REQUESTS_BUSY at once, and a flood without a session leaves the pool as it was.
func TestFiles_OnlyAuthenticatedRequestsTakeASlot(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	file, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, alice.uploadPart(conv, file, 0, data), http.StatusCreated, "part 0")
	free := handlers.FileRequestSlotsFreeForTesting()
	if free != handlers.MaxConcurrentFileRequestsForTesting() {
		t.Fatalf("%d of %d slots free before the test", free, handlers.MaxConcurrentFileRequestsForTesting())
	}

	release := handlers.HoldFileRequestSlotsForTesting()
	anonymous := newClient(t, mux)
	expectAnswer(t, anonymous.uploadPart(conv, uuid.NewString(), 0, newFilePart(t)), apperr.NoSession, "an upload without a session, pool full")
	expectAnswer(t, anonymous.readPart(conv, file, 0), apperr.NoSession, "a read without a session, pool full")
	expectAnswer(t, alice.readPart(conv, file, 0), apperr.FileRequestsBusy, "a member's read, pool full")
	expectAnswer(t, alice.uploadPart(conv, file, 1, newFilePart(t)), apperr.FileRequestsBusy, "a member's upload, pool full")
	release()

	for i := 0; i < 3*handlers.MaxConcurrentFileRequestsForTesting(); i++ {
		expectAnswer(t, newClient(t, mux).readPart(conv, file, 0), apperr.NoSession, "a read in a flood without a session")
	}
	if got := handlers.FileRequestSlotsFreeForTesting(); got != free {
		t.Fatalf("requests without a session left %d of %d slots free", got, free)
	}
	// A refused read gives its slot back, and the pool serves members again
	expectAnswer(t, bob.readPart(conv, uuid.NewString(), 0), apperr.NotFound, "a refused read")
	expectPart(t, bob.client, conv, file, 0, data, "a read once the pool is free")
	if got := handlers.FileRequestSlotsFreeForTesting(); got != free {
		t.Fatalf("answered member requests left %d of %d slots free", got, free)
	}
}

// FILE_ACCOUNT_DAILY_BYTES is one budget per account across all its conversations: every stored
// part spends from it, a resend or a refused part spends nothing, an empty budget answers 429
// E_FILE_BUDGET_SPENT before the quota or the store is looked at, and another account keeps its own.
func TestFiles_DailyBudgetIsPerAccount(t *testing.T) {
	mux := filesSetup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	withBob, withCarol := pair(t, alice, bob), pair(t, alice, carol)
	t.Setenv(config.EnvFileAccountDailyBytes, strconv.Itoa(3*utils.FilePartBytes)) // before the budgets exist

	file, first := uuid.NewString(), newFilePart(t)
	expectStatus(t, alice.uploadPart(withBob, file, 0, first), http.StatusCreated, "part 0 (1 of 3)")
	expectAnswer(t, alice.uploadPart(withBob, file, 0, first), apperr.Conflict, "the identical resend")
	expectAnswer(t, alice.uploadPart(withBob, uuid.NewString(), 1, newFilePart(t)), apperr.FilePartOutOfOrder, "a refused part")
	expectStatus(t, alice.uploadPart(withBob, file, 1, newFilePart(t)), http.StatusCreated, "part 1 (2 of 3)")
	expectStatus(t, alice.uploadPart(withCarol, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "another conversation (3 of 3)")
	expectAnswer(t, alice.uploadPart(withCarol, uuid.NewString(), 0, newFilePart(t)), apperr.FileBudgetSpent, "a fourth part anywhere")

	// Checked before the quota: even with no quota left the answer is the budget's
	t.Setenv(config.EnvFileConversationQuotaBytes, strconv.Itoa(utils.FilePartBytes))
	expectAnswer(t, alice.uploadPart(withBob, file, 2, newFilePart(t)), apperr.FileBudgetSpent, "spent budget and full quota")
	t.Setenv(config.EnvFileConversationQuotaBytes, "")

	// bob's budget is his own
	expectStatus(t, bob.uploadPart(withBob, uuid.NewString(), 0, newFilePart(t)), http.StatusCreated, "bob uploads")
	if n := storedParts(t, uuid.MustParse(withBob)) + storedParts(t, uuid.MustParse(withCarol)); n != 4 {
		t.Fatalf("%d parts stored, want 4", n)
	}
}
