//go:build darwin

package launcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const symlinkMode = 0o755

func setSymlinkMode(path string) error {
	//nolint:wrapcheck // callers add context to the syscall error
	return unix.Fchmodat(unix.AT_FDCWD, path, symlinkMode, unix.AT_SYMLINK_NOFOLLOW)
}

// FixLinkModes makes existing owned install links accessible to local users.
func (lay Layout) FixLinkModes() error {
	var errs []error

	for _, name := range []string{linkCurrent, linkKnownGood, linkPreviousGood} {
		path := filepath.Join(lay.Dir, name)

		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("launcher: stat link %s: %w", name, err))

			continue
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSymlink == 0 || !ok || int(stat.Uid) != os.Geteuid() {
			continue
		}

		err = setSymlinkMode(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("launcher: chmod link %s: %w", name, err))
		}
	}

	return errors.Join(errs...)
}
