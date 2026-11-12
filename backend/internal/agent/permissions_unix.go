//go:build !windows

package agent

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// permissionsOpenMask: any bit for the group or for others makes the identity readable by
// someone who is not this user.
const permissionsOpenMask = fs.FileMode(0o077)

// checkPrivateMode refuses an identity file or directory open to the group or to others: on
// Unix the mode bits are the access control.
func checkPrivateMode(info fs.FileInfo) error {
	if info.Mode().Perm()&permissionsOpenMask != 0 {
		return fail(CodeIdentityPermissions, nil)
	}
	return nil
}

// syncDir makes the new directory entry durable.
func syncDir(dir string, code Code) error {
	d, err := os.Open(dir)
	if err != nil {
		return fail(code, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fail(code, err)
	}
	return nil
}

// lockFile takes an exclusive, non-blocking flock on path (created 0600, never through a
// symlink) and holds it until the returned file is closed or the process ends.
func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, identityFileMode)
	if err != nil {
		return nil, fail(CodeIdentityFile, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fail(CodeIdentityInUse, nil)
		}
		return nil, fail(CodeIdentityFile, err)
	}
	return f, nil
}
