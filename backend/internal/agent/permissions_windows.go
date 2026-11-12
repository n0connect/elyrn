//go:build windows

package agent

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// errorSharingViolation is ERROR_SHARING_VIOLATION: another handle holds the file without
// sharing it.
const errorSharingViolation = syscall.Errno(32)

// lockShareMode shares the lock file with nobody: a second open fails until this handle closes.
const lockShareMode = 0

// A replace (rename over the file) fails while another process holds the file open without
// sharing delete, as a whoami beside the running agent briefly does while it reads the identity:
// Windows answers a sharing violation or access denied. The replace is retried replaceRetries
// times after replaceBackoff, doubled each time (10 ms … 160 ms, about 0.3 s in all).
const (
	replaceRetries = 5
	replaceBackoff = 10 * time.Millisecond
)

// replaceFile renames from over to, retrying while another handle briefly holds to.
func replaceFile(from, to string) error {
	for attempt := 0; ; attempt++ {
		err := os.Rename(from, to)
		if err == nil || attempt == replaceRetries ||
			!(errors.Is(err, errorSharingViolation) || errors.Is(err, syscall.ERROR_ACCESS_DENIED)) {
			return err
		}
		time.Sleep(replaceBackoff << attempt)
	}
}

// checkPrivateMode accepts any mode on Windows. Go synthesises Windows modes from the read-only
// attribute alone (0666 or 0444 for files, 0777 for directories), so they say nothing about who
// may read the file; access is governed by ACLs instead. The identity lives under
// os.UserConfigDir, which is %AppData% inside the user's own profile directory, and that profile
// is readable only by the user, SYSTEM and administrators by default. Comparing modes here would
// refuse every identity on every Windows machine without protecting anything.
func checkPrivateMode(fs.FileInfo) error {
	return nil
}

// syncDir does nothing on Windows: a directory cannot be opened for writing through os.Open, so
// FlushFileBuffers on it fails, and NTFS journals metadata changes such as the new entry. The file's
// own content was synced before it was linked into place.
func syncDir(string, Code) error {
	return nil
}

// lockFile opens path with no sharing at all, which Windows enforces across processes, and
// holds it until the returned file is closed or the process ends.
func lockFile(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fail(CodeIdentityFile, err)
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ|syscall.GENERIC_WRITE, lockShareMode, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) {
			return nil, fail(CodeIdentityInUse, nil)
		}
		return nil, fail(CodeIdentityFile, err)
	}
	return os.NewFile(uintptr(handle), path), nil
}
