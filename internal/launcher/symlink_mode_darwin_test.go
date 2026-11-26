//go:build darwin

package launcher

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSymlinkMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "link")

	err := os.Symlink("target", path)
	if err != nil {
		t.Fatal(err)
	}

	err = setSymlinkMode(path)
	if err != nil {
		t.Fatal(err)
	}

	checkSymlinkMode(t, path, 0o755)
}

func TestFixLinkModes(t *testing.T) {
	lay := Layout{Dir: t.TempDir()}

	for _, name := range []string{linkCurrent, linkKnownGood, linkPreviousGood} {
		path := filepath.Join(lay.Dir, name)

		err := os.Symlink("target", path)
		if err != nil {
			t.Fatal(err)
		}

		err = unix.Fchmodat(unix.AT_FDCWD, path, 0o700, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := lay.FixLinkModes()
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{linkCurrent, linkKnownGood, linkPreviousGood} {
		checkSymlinkMode(t, filepath.Join(lay.Dir, name), 0o755)
	}
}

func checkSymlinkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}
