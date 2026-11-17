package encryption

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"
)

var cryptoLogger = utils.NewLogger("CRYPTO")

// The failures of this file, each one class: a handler that meets one answers 500 E_INTERNAL
// (apperr.WriteError) and logs the class, never a value. ErrClosing (masterkey.go) is the one
// failure with its own answer.
var (
	// ErrKeyLength: a key is not AES-256 sized (a programming error, never client input)
	ErrKeyLength = errors.New("encryption: key is not 32 bytes")
	// ErrAADLength: the AAD is not the length its record format fixes
	ErrAADLength = errors.New("encryption: AAD has the wrong length")
	// ErrUnknownKeyID: a record names a master key id that is not configured
	ErrUnknownKeyID = errors.New("encryption: no master key has this id")
	// ErrUserKey: a stored per-user key is empty, does not open, or does not hold 32 bytes
	ErrUserKey = errors.New("encryption: the stored user key is unusable")
	// ErrOpen: a record does not open under this key and AAD (tampered, moved or corrupt)
	ErrOpen = errors.New("encryption: the record does not open")
	// ErrKeyGeneration: the CSPRNG could not produce a new user key
	ErrKeyGeneration = errors.New("encryption: no new user key")
)

// EncryptWithKey encrypts data with AES-256-GCM
// Flow: raw data -> AES encrypt -> base64 encode (for storage)
func EncryptWithKey(text string, key []byte) (string, error) {
	cryptoLogger.Debug("EncryptWithKey: starting encryption, input length: %d", len(text))

	if len(key) != cryptoengine.AES256KeySize {
		return "", ErrKeyLength
	}

	// AES encrypt the raw text
	ciphertext, err := cryptoengine.EncryptAES256GCM(key, []byte(text), nil)
	if err != nil {
		cryptoLogger.LogError("EncryptAES256GCM", err)
		return "", err
	}
	cryptoLogger.Debug("EncryptWithKey: AES encryption completed, ciphertext length: %d", len(ciphertext))

	// Base64 encode the encrypted data for storage
	result := base64.StdEncoding.EncodeToString(ciphertext)
	cryptoLogger.Debug("EncryptWithKey: base64 encoding completed, result length: %d", len(result))
	return result, nil
}

// DecryptWithKey decrypts data with AES-256-GCM
// Flow: encrypted data -> base64 decode -> AES decrypt -> raw data
func DecryptWithKey(encryptedText string, key []byte) (string, error) {
	cryptoLogger.Debug("DecryptWithKey: starting decryption, input length: %d", len(encryptedText))

	if len(key) != cryptoengine.AES256KeySize {
		return "", ErrKeyLength
	}

	// Base64 decode the stored encrypted data
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		cryptoLogger.LogError("Base64 decode", err)
		return "", err
	}
	cryptoLogger.Debug("DecryptWithKey: base64 decoded, data length: %d", len(data))

	// AES decrypt
	plaintext, err := cryptoengine.DecryptAES256GCM(key, data, nil)
	if err != nil {
		cryptoLogger.LogError("DecryptAES256GCM", err)
		return "", err
	}
	cryptoLogger.Debug("DecryptWithKey: AES decryption completed, plaintext length: %d", len(plaintext))

	return string(plaintext), nil
}

func EncryptWithMasterKey(text string) (string, error) {
	cryptoLogger.Debug("EncryptWithMasterKey: starting encryption with master key, input length: %d", len(text))
	var result string
	err := withActiveKey(func(_ string, key []byte) error {
		var err error
		result, err = EncryptWithKey(text, key)
		return err
	})
	if err != nil {
		cryptoLogger.LogError("EncryptWithMasterKey", err)
		return "", err
	}
	cryptoLogger.Debug("EncryptWithMasterKey: successfully encrypted with master key, result length: %d", len(result))
	return result, nil
}

// DecryptWithMasterKey opens a record with the master key named by its stored key id.
// There is no fallback: a record is never trial-decrypted under every key.
func DecryptWithMasterKey(encryptedText string, keyID string) (string, error) {
	var result string
	ok, err := withKeyByID(keyID, func(key []byte) error {
		var err error
		result, err = DecryptWithKey(encryptedText, key)
		return err
	})
	if err == nil && !ok {
		return "", ErrUnknownKeyID
	}
	if err != nil {
		cryptoLogger.LogError("DecryptWithMasterKey", err)
		return "", err
	}
	return result, nil
}

func GenerateUserAESKey() ([]byte, error) {
	cryptoLogger.Debug("GenerateUserAESKey: generating new 32-byte AES key")
	key, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
	if err != nil {
		cryptoLogger.LogError("GenerateUserAESKey", err)
		return nil, ErrKeyGeneration
	}
	cryptoLogger.Debug("GenerateUserAESKey: successfully generated 32-byte AES key")
	return key, nil
}

// DecryptUserKey decrypts an encrypted user key and returns the raw AES key
// This function is separated from database access for better modularity
func DecryptUserKey(encryptedKey string, keyID string) ([]byte, error) {
	cryptoLogger.Debug("DecryptUserKey: starting decryption, encryptedKey length: %d", len(encryptedKey))

	if encryptedKey == "" {
		cryptoLogger.Error("DecryptUserKey: encrypted key is empty")
		return nil, ErrUserKey
	}

	cryptoLogger.Debug("DecryptUserKey: decrypting user key with master key")
	decryptedKeyHex, err := DecryptWithMasterKey(encryptedKey, keyID)
	if err != nil {
		cryptoLogger.LogError("DecryptUserKey", err)
		return nil, errors.Join(ErrUserKey, err)
	}
	cryptoLogger.Debug("DecryptUserKey: successfully decrypted user key, hex length: %d", len(decryptedKeyHex))

	userKey, err := hex.DecodeString(decryptedKeyHex)
	if err != nil {
		// The decoder's error quotes the offending byte of the key: only the class is kept
		cryptoLogger.LogError("DecryptUserKey (hex decode)", ErrUserKey)
		return nil, ErrUserKey
	}

	if len(userKey) != cryptoengine.AES256KeySize {
		cryptoLogger.Error("DecryptUserKey: invalid user key length: %d (expected %d)", len(userKey), cryptoengine.AES256KeySize)
		return nil, ErrUserKey
	}
	cryptoLogger.Debug("DecryptUserKey: successfully decoded user key, length: %d", len(userKey))

	return userKey, nil
}

// EncryptWithAAD encrypts data with Additional Authenticated Data (AAD)
// AAD is used to prevent cross-user data swapping attacks
// Flow: raw data -> base64 encode -> AES-GCM encrypt (with AAD) -> base64 encode
func EncryptWithAAD(text string, key []byte, aad []byte) (string, error) {
	cryptoLogger.Debug("EncryptWithAAD: starting encryption, input length: %d, AAD length: %d", len(text), len(aad))
	if err := validateKeyAndAAD(key, aad, AADLength); err != nil {
		return "", err
	}

	ciphertext, err := cryptoengine.EncryptAES256GCM(key, []byte(text), aad)
	if err != nil {
		cryptoLogger.LogError("EncryptAES256GCM", err)
		return "", err
	}
	result := base64.StdEncoding.EncodeToString(ciphertext)
	cryptoLogger.Debug("EncryptWithAAD: encryption completed, result length: %d", len(result))
	return result, nil
}

// DecryptWithAAD decrypts data with Additional Authenticated Data (AAD)
// AAD must match the AAD used during encryption, otherwise decryption fails
// Flow: encrypted data -> base64 decode -> AES-GCM decrypt (with AAD) -> raw data
func DecryptWithAAD(encryptedText string, key []byte, aad []byte) (string, error) {
	cryptoLogger.Debug("DecryptWithAAD: starting decryption, input length: %d, AAD length: %d", len(encryptedText), len(aad))
	if err := validateKeyAndAAD(key, aad, AADLength); err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		cryptoLogger.LogError("Base64 decode (step 1)", err)
		return "", err
	}

	plaintext, err := cryptoengine.DecryptAES256GCM(key, data, aad)
	if err != nil {
		cryptoLogger.LogError("DecryptAES256GCM", err)
		return "", ErrOpen
	}

	cryptoLogger.Debug("DecryptWithAAD: decryption completed, plaintext length: %d", len(plaintext))
	return string(plaintext), nil
}

func validateKeyAndAAD(key []byte, aad []byte, expectedAADLen int) error {
	if len(key) != cryptoengine.AES256KeySize {
		cryptoLogger.Error("Invalid key length: %d", len(key))
		return ErrKeyLength
	}
	if len(aad) != expectedAADLen {
		cryptoLogger.Error("Invalid AAD length: %d (expected %d)", len(aad), expectedAADLen)
		return ErrAADLength
	}
	return nil
}
