//go:build !windows

package agent

import (
	"io/fs"
	"os"
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
