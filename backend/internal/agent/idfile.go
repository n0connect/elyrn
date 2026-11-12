package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"elyrn/internal/utils"
)

// The identity lives in one file (design D4): the server origin and the AccountNumber. Whoever
// reads it is this agent, so it is created 0600 in a 0700 directory and refused when wider.
const (
	identityDirName      = "elyrn"
	identityFileName     = "agent.json"
	identityTempPattern  = ".agent-*.json"
	identityDirMode      = fs.FileMode(0o700)
	permissionsOpenMask  = fs.FileMode(0o077)
	maxIdentityFileBytes = 1024
)

type identityFile struct {
	Server        string `json:"server"`
	AccountNumber string `json:"account_number"`
}

// DefaultIdentityPath is <user config dir>/elyrn/agent.json (~/.config on Linux).
func DefaultIdentityPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "", fail(CodeConfigDir, err)
	}
	return filepath.Join(dir, identityDirName, identityFileName), nil
}

// checkPrivate refuses anything but a private directory or regular file (no symlinks).
func checkPrivate(info fs.FileInfo, wantDir bool) error {
	if info.IsDir() != wantDir || (!wantDir && !info.Mode().IsRegular()) {
		return fail(CodeIdentityFile, nil)
	}
	if info.Mode().Perm()&permissionsOpenMask != 0 {
		return fail(CodeIdentityPermissions, nil)
	}
	return nil
}

// loadIdentity returns nil, nil when no identity file exists yet.
func loadIdentity(path string) (*identityFile, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fail(CodeIdentityFile, err)
	}
	if err := checkPrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := checkPrivate(info, false); err != nil {
		return nil, err
	}
	raw, err := readPrivateFile(path, info)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	return parseIdentity(raw)
}

func checkPrivateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	return checkPrivate(info, true)
}

// readPrivateFile reads the file checked by Lstat, refusing one swapped in between.
func readPrivateFile(path string, checked fs.FileInfo) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fail(CodeIdentityFile, err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(checked, opened) {
		return nil, fail(CodeIdentityFile, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxIdentityFileBytes+1))
	if err != nil || len(raw) > maxIdentityFileBytes {
		zeroBytes(raw)
		return nil, fail(CodeIdentityFile, err)
	}
	return raw, nil
}

func parseIdentity(raw []byte) (*identityFile, error) {
	var id identityFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&id); err != nil || decoder.More() {
		return nil, fail(CodeIdentityFile, err)
	}
	if _, kind := ClassifyServerURL(id.Server); kind == URLRefused || !utils.ValidateAccountNumber(id.AccountNumber) {
		return nil, fail(CodeIdentityFile, nil)
	}
	return &id, nil
}

// saveIdentity publishes the file atomically and never replaces an existing identity: the
// content is written to a private temporary file, synced, then hard-linked into place.
func saveIdentity(path string, id *identityFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return fail(CodeIdentityFile, err)
	}
	if err := checkPrivateDir(dir); err != nil {
		return err
	}
	raw, err := json.Marshal(id)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	defer zeroBytes(raw)
	tmp, err := os.CreateTemp(dir, identityTempPattern) // created 0600
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(raw)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fail(CodeIdentityFile, err)
	}
	if err := os.Link(tmp.Name(), path); err != nil {
		return fail(CodeIdentityFile, err)
	}
	return syncDir(dir)
}

// syncDir makes the new directory entry durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fail(CodeIdentityFile, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fail(CodeIdentityFile, err)
	}
	return nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
