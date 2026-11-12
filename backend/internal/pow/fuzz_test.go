package pow

import (
	"crypto/sha256"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"elyrn/internal/models"
)

// A solution is accepted only when every echoed field is exactly as issued (the salt
// authenticates them), unexpired, unused, and its hash meets the issued difficulty; nothing a
// client sends may panic the validator.
func FuzzValidateSolution(f *testing.F) {
	f.Setenv("POW_DIFFICULTY", "18")
	f.Setenv("POW_CHALLENGE_TTL_SEC", "300")
	ch := issue(f)
	f.Add(ch.Challenge, ch.Salt, "0", ch.Timestamp, ch.TTL, ch.Difficulty)
	f.Add(ch.Challenge, ch.Salt, search(f, ch, false), ch.Timestamp, ch.TTL, ch.Difficulty)
	f.Add(ch.Challenge, ch.Salt, search(f, ch, true), ch.Timestamp+1, ch.TTL, ch.Difficulty)
	f.Add(ch.Challenge, ch.Salt, search(f, ch, true), ch.Timestamp, ch.TTL, 0)
	f.Add("", "", "", int64(0), int64(0), 0)
	f.Add(ch.Challenge+"00", ch.Salt, "1", ch.Timestamp, ch.TTL, ch.Difficulty)

	f.Fuzz(func(t *testing.T, challenge, salt, solution string, timestamp, ttl int64, difficulty int) {
		err := ValidateSolution(&models.PoWSolution{Challenge: challenge, Salt: salt, Solution: solution,
			Timestamp: timestamp, TTL: ttl, Difficulty: difficulty})
		if err != nil {
			return
		}
		if challenge != ch.Challenge || salt != ch.Salt || timestamp != ch.Timestamp || ttl != ch.TTL || difficulty != ch.Difficulty {
			t.Fatalf("fields not as issued accepted: %q/%q ts=%d ttl=%d d=%d", challenge, salt, timestamp, ttl, difficulty)
		}
		sum := sha256.Sum256([]byte(challenge + solution + salt))
		if !HasLeadingZeroBits(sum[:], ch.Difficulty) {
			t.Fatalf("solution %q accepted below difficulty %d", solution, ch.Difficulty)
		}
	})
}

// Field indexes FuzzTagMutation changes, one per run
const (
	mutateChallenge = iota
	mutateSalt
	mutateTimestamp
	mutateTTL
	mutateDifficulty
	mutatedFields
)

const (
	// fuzzNow is the fixed clock FuzzCheckSolutionWindow judges expiry against
	fuzzNow = int64(1767225600)
	// maxFuzzDifficulty keeps a fuzzed difficulty low enough for the fuzzer to meet it
	maxFuzzDifficulty = 12
	// spentOpBytes: kind, challenge index, signed time step
	spentOpBytes = 3
	// spentChallengeSpace is how many distinct challenges a spent-set program uses
	spentChallengeSpace = 16
	// spentOpKinds: spend, or a cleanup pass
	spentOpKinds = 2
	spentOpSpend = 0
)

// FuzzTagMutation: the salt authenticates every echoed field, so changing any single one of
// them (challenge, salt, timestamp, ttl, difficulty), to anything, is refused by the MAC.
func FuzzTagMutation(f *testing.F) {
	f.Setenv("POW_DIFFICULTY", "18")
	ch := issue(f)
	// Seeds are fixed text: the issued challenge and the MAC secret differ in every fuzz process
	f.Add(uint8(mutateChallenge), strings.Repeat("AB", ChallengeBytes), int64(0))
	f.Add(uint8(mutateSalt), strings.Repeat("0", 2*SaltBytes), int64(0))
	f.Add(uint8(mutateTimestamp), "", int64(1))
	f.Add(uint8(mutateTTL), "", int64(-1))
	f.Add(uint8(mutateDifficulty), "", int64(1)<<32)
	f.Fuzz(func(t *testing.T, field uint8, text string, delta int64) {
		challenge, salt, timestamp, ttl, difficulty := ch.Challenge, ch.Salt, ch.Timestamp, ch.TTL, ch.Difficulty
		switch field % mutatedFields {
		case mutateChallenge:
			challenge = text
		case mutateSalt:
			salt = text
		case mutateTimestamp:
			timestamp += delta
		case mutateTTL:
			ttl += delta
		case mutateDifficulty:
			difficulty += int(delta)
		}
		if challenge == ch.Challenge && salt == ch.Salt && timestamp == ch.Timestamp && ttl == ch.TTL && difficulty == ch.Difficulty {
			return // nothing changed
		}
		ok, err := tagMatches(challenge, salt, timestamp, ttl, difficulty)
		if err != nil || ok {
			t.Fatalf("field %d changed and the tag still matched (err %v)", field%mutatedFields, err)
		}
	})
}

// meetsDifficulty is the validator's oracle, counted bit by bit: the first n bits are zero.
func meetsDifficulty(sum []byte, n int) bool {
	for bit := 0; bit < n; bit++ {
		if bit/8 >= len(sum) || sum[bit/8]&(0x80>>(bit%8)) != 0 {
			return false
		}
	}
	return true
}

// FuzzCheckSolutionWindow: for genuinely issued fields of any timestamp and ttl, a solution is
// accepted only when ttl is positive, the clock has not passed timestamp+ttl (exact arithmetic,
// no wrap-around), and its hash meets the difficulty.
func FuzzCheckSolutionWindow(f *testing.F) {
	f.Add(fuzzNow, int64(300), int32(0), uint8(0), "0")
	f.Add(fuzzNow-300, int64(300), int32(0), uint8(4), "17")
	f.Add(fuzzNow-301, int64(300), int32(0), uint8(0), "1")
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), int32(0), uint8(0), "0")
	f.Add(int64(math.MaxInt64-1), int64(1), int32(-1), uint8(0), "0")
	f.Add(fuzzNow, int64(0), int32(0), uint8(0), "0")
	f.Add(fuzzNow, int64(-1), int32(0), uint8(0), "0")
	key, err := challengeSecret()
	if err != nil {
		f.Fatalf("challengeSecret: %v", err)
	}
	challenge := strings.Repeat("ab", ChallengeBytes)
	f.Fuzz(func(t *testing.T, timestamp, ttl int64, nowOffset int32, difficultyByte uint8, solution string) {
		difficulty := int(difficultyByte % maxFuzzDifficulty)
		salt, err := challengeTag(key, challenge, timestamp, ttl, difficulty)
		if err != nil {
			t.Fatalf("challengeTag: %v", err)
		}
		now := time.Unix(fuzzNow+int64(nowOffset), 0)
		expiresAt, err := checkSolution(&models.PoWSolution{Challenge: challenge, Salt: salt, Solution: solution,
			Timestamp: timestamp, TTL: ttl, Difficulty: difficulty}, now)
		if err != nil {
			return
		}
		deadline := new(big.Int).Add(big.NewInt(timestamp), big.NewInt(ttl))
		sum := sha256.Sum256([]byte(challenge + solution + salt))
		if ttl <= 0 || deadline.Cmp(big.NewInt(now.Unix())) < 0 || !deadline.IsInt64() || expiresAt != deadline.Int64() ||
			!meetsDifficulty(sum[:], difficulty) {
			t.Fatalf("accepted ts=%d ttl=%d at %d (difficulty %d, solution %q)", timestamp, ttl, now.Unix(), difficulty, solution)
		}
	})
}

// FuzzSpentSet drives the spent set with arbitrary spends and cleanup passes: a challenge is
// never spent twice while it is remembered, a cleanup forgets exactly the expired entries, and
// the set never outgrows its bound.
func FuzzSpentSet(f *testing.F) {
	f.Add([]byte{spentOpSpend, 1, 0, spentOpSpend, 1, 0})
	f.Add([]byte{spentOpSpend, 1, 0, 1, 0, 0x7f, spentOpSpend, 1, 0})
	f.Add([]byte{spentOpSpend, 2, 0x80, 1, 0, 0x80, spentOpSpend, 2, 0x81})
	f.Fuzz(func(t *testing.T, program []byte) {
		resetSpent(t)
		model := make(map[string]int64)
		for op := 0; op+spentOpBytes <= len(program); op += spentOpBytes {
			at := fuzzNow + int64(int8(program[op+2]))
			if program[op]%spentOpKinds == spentOpSpend {
				challenge := strconv.Itoa(int(program[op+1]) % spentChallengeSpace)
				_, remembered := model[challenge]
				err := spend(challenge, at)
				if remembered != (err != nil) {
					t.Fatalf("op %d: spend of %s (remembered %v) answered %v", op/spentOpBytes, challenge, remembered, err)
				}
				if err == nil {
					model[challenge] = at
				}
				continue
			}
			cleanupSpentChallenges(time.Unix(at, 0))
			for challenge, expiresAt := range model {
				if at > expiresAt { // whole seconds: past the expiry second
					delete(model, challenge)
				}
			}
		}
		spentMutex.Lock()
		defer spentMutex.Unlock()
		if len(spentChallenges) != len(model) || len(spentChallenges) > maxSpentChallenges {
			t.Fatalf("spent set holds %d entries, model %d", len(spentChallenges), len(model))
		}
		for challenge, expiresAt := range model {
			if got, ok := spentChallenges[challenge]; !ok || got != expiresAt {
				t.Fatalf("challenge %s: stored %d (%v), model %d", challenge, got, ok, expiresAt)
			}
		}
	})
}
