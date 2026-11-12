package pow

import (
	"crypto/sha256"
	"testing"

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
