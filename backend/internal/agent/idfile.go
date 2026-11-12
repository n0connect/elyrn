package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"elyrn/internal/utils"
)

// The identity lives in one file (design D4): the server origin and the AccountNumber. Whoever
// reads it is this agent, so it is created 0600 in a 0700 directory; how a wider one is refused
// differs per operating system and lives in permissions_unix.go / permissions_windows.go only.
// Beside it live the process lock (agent.json.lock) and the message-counter file (state.go);
// every file the agent writes goes through writePrivate.
const (
	identityDirName      = "elyrn"
	identityFileName     = "agent.json"
	privateTempPattern   = ".agent-*.json"
	identityDirMode      = fs.FileMode(0o700)
	identityFileMode     = fs.FileMode(0o600)
	lockFileSuffix       = ".lock"
	stateFileSuffix      = ".counters.json"
	identityFieldsBytes  = 1024
	maxIdentityFileBytes = identityFieldsBytes + maxPendingTokenChars
)

// errUnreadable marks an I/O failure (as opposed to a refused shape or permission): the caller
// decides whether that is fatal.
var errUnreadable = errors.New("agent: file unreadable")

// identityFile is the stored identity. It may only grow, and only by optional fields: a file
// written by an older release must keep loading. PendingToken is present only between the two
// registration phases (the account is not confirmed yet); it is a secret like the AccountNumber
// and is dropped from the file once the account exists, so a confirmed file has the original
// two fields only and older releases still read it.
type identityFile struct {
	Server        string `json:"server"`
	AccountNumber string `json:"account_number"`
	PendingToken  string `json:"pending_token,omitempty"`
}

// DefaultIdentityPath is <os.UserConfigDir>/elyrn/agent.json: ~/.config on Linux (or
// $XDG_CONFIG_HOME), ~/Library/Application Support on macOS, %AppData% on Windows.
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "", fail(CodeConfigDir, err)
	}
	return filepath.Join(dir, identityDirName, identityFileName), nil
}

func lockPath(identityPath string) string { return identityPath + lockFileSuffix }

func statePath(identityPath string) string {
	return strings.TrimSuffix(identityPath, filepath.Ext(identityPath)) + stateFileSuffix
}

// checkPrivate refuses anything but a private directory or regular file (no symlinks).
func checkPrivate(info fs.FileInfo, wantDir bool, code Code) error {
	if info.IsDir() != wantDir || (!wantDir && !info.Mode().IsRegular()) {
		return fail(code, nil)
	}
	return checkPrivateMode(info)
}

func checkPrivateDir(dir string, code Code) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fail(code, err)
	}
	return checkPrivate(info, true, code)
}

// ensurePrivateDir creates the identity directory (0700) if needed and checks it is private.
func ensurePrivateDir(dir string, code Code) error {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return fail(code, err)
	}
	return checkPrivateDir(dir, code)
}

// readPrivate returns the content of a private regular file of at most limit bytes, or nil, nil
// when it does not exist. A refused shape, size or permission is a registered error under code;
// an I/O failure wraps errUnreadable, for the caller to classify.
func readPrivate(path string, limit int, code Code) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Join(errUnreadable, err)
	}
	if err := checkPrivateDir(filepath.Dir(path), code); err != nil {
		return nil, err
	}
	if err := checkPrivate(info, false, code); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.Join(errUnreadable, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fail(code, err) // swapped between the check and the open
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		zeroBytes(raw)
		return nil, errors.Join(errUnreadable, err)
	}
	if len(raw) > limit {
		zeroBytes(raw)
		return nil, fail(code, nil)
	}
	return raw, nil
}

// writePrivate publishes raw at path atomically: a private temporary file in the same directory
// is written and synced, then linked into place (replace false: never over an existing file) or
// renamed over it (replace true), and the directory entry is synced. A temporary file a killed
// process leaves behind is swept at the next start (sweepTemps).
func writePrivate(path string, raw []byte, replace bool, code Code) error {
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir, code); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, privateTempPattern) // created 0600
	if err != nil {
		return fail(code, err)
	}
	name := tmp.Name()
	_, writeErr := tmp.Write(raw)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(name)
		return fail(code, err)
	}
	if replace {
		err = os.Rename(name, path)
	} else {
		err = os.Link(name, path)
	}
	_ = os.Remove(name) // after a rename it is already gone
	if err != nil {
		return fail(code, err)
	}
	return syncDir(dir, code)
}

// sweepTemps removes temporary files an interrupted write left in dir. It runs only under the
// identity lock, so no other agent is writing one.
func sweepTemps(dir string) {
	leftovers, err := filepath.Glob(filepath.Join(dir, privateTempPattern))
	if err != nil {
		return
	}
	for _, name := range leftovers {
		if err := os.Remove(name); err != nil {
			logger.Warn("a leftover temporary file could not be removed")
		}
	}
}

// loadIdentity returns nil, nil when no identity file exists yet.
func loadIdentity(path string) (*identityFile, error) {
	raw, err := readPrivate(path, maxIdentityFileBytes, CodeIdentityFile)
	if errors.Is(err, errUnreadable) {
		return nil, fail(CodeIdentityFile, err)
	}
	if err != nil || raw == nil {
		return nil, err
	}
	defer zeroBytes(raw)
	return parseIdentity(raw)
}

func parseIdentity(raw []byte) (*identityFile, error) {
	var id identityFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&id); err != nil || decoder.More() {
		return nil, fail(CodeIdentityFile, err)
	}
	if _, kind := ClassifyServerURL(id.Server); kind == URLRefused || !utils.ValidateAccountNumber(id.AccountNumber) ||
		(id.PendingToken != "" && !validPendingToken(id.PendingToken)) {
		return nil, fail(CodeIdentityFile, nil)
	}
	return &id, nil
}

// saveIdentity writes the identity file; only replace may overwrite an existing one.
func saveIdentity(path string, id *identityFile, replace bool) error {
	raw, err := json.Marshal(id)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	defer zeroBytes(raw)
	return writePrivate(path, raw, replace, CodeIdentityFile)
}

// confirmIdentityFile drops the pending token from the stored identity once the account exists.
// It reads the AccountNumber back from the file rather than keeping it in memory.
func confirmIdentityFile(path string) error {
	id, err := loadIdentity(path)
	if err != nil {
		return err
	}
	if id == nil {
		return fail(CodeIdentityFile, nil)
	}
	id.PendingToken = ""
	return saveIdentity(path, id, true)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
