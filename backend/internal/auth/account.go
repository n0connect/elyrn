package auth

import (
	"encoding/hex"
	"strings"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/identity"
	"elyrn/internal/utils"
)

var accountLogger = utils.NewLogger("ACCOUNT")

// accountLookupHexLen is the length of every lookup ComputeAccountLookup returns: the hex of
// one HMAC-SHA256 output (hex spells each byte with two characters).
const accountLookupHexLen = 2 * cryptoengine.SHA256Size

// absentAccountLookup stands in for the stored lookup when no account matched, so a login for
// an unknown key runs the same comparison on the same length as one for a known key. It is
// not hex, so no computed lookup can ever equal it.
var absentAccountLookup = strings.Repeat("x", accountLookupHexLen)

// AccountLookupMatches proves knowledge of the auth key: the lookup computed from the
// presented key equals the account's stored one, compared in constant time. A nil-account
// caller passes "" and is compared against absentAccountLookup instead (always false).
func AccountLookupMatches(computed, stored string) bool {
	if stored == "" {
		stored = absentAccountLookup
	}
	return cryptoengine.ConstantTimeEqual([]byte(computed), []byte(stored))
}

// ComputeAccountLookup computes HMAC-SHA256(pepper, accountNumber) for fast database lookup
// Returns hex-encoded string
func ComputeAccountLookup(accountNumber string) (string, error) {
	pepper := config.GetAccountLookupPepper()
	// GetAccountLookupPepper answers nil for a short pepper too: either way it is not configured
	if len(pepper) < config.MinPepperBytes() {
		return "", identity.ErrPepperNotConfigured
	}
	mac, err := cryptoengine.HMACSHA256(pepper, []byte(accountNumber))
	if err != nil {
		return "", err
	}
	lookup := hex.EncodeToString(mac)

	accountLogger.Debug("ComputeAccountLookup: computed lookup for account number (masked)")
	return lookup, nil
}
