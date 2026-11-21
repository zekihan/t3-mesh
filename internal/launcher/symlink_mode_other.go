//go:build !darwin

package launcher

func setSymlinkMode(string) error { return nil }

// FixLinkModes is a no-op where symlink modes are not enforced.
func (lay Layout) FixLinkModes() error { return nil }
