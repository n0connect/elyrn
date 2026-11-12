//go:build windows

package agent

import "io/fs"

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
func syncDir(string) error {
	return nil
}
