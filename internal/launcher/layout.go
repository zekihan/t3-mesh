// Package launcher implements the small supervisor mode of the agent binary:
// the install layout with its symlinks, the health pipe between launcher and
// child, probation and rollback, and the fallback used when a new launcher
// itself fails.
package launcher

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	dirMode    = 0o755
	binaryMode = 0o755
	fileMode   = 0o644
)

var (
	errInvalid          = errors.New("invalid")
	errUnexpectedTarget = errors.New("unexpected target")
)

// BinaryName is the file name of the agent binary inside a version directory.
const BinaryName = "t3-mesh-agent"

const (
	linkCurrent      = "current"
	linkKnownGood    = "known-good"
	linkPreviousGood = "previous-good"
	versionsDir      = "versions"
)

// ErrNoLink is returned when a symlink does not exist.
var ErrNoLink = errors.New("launcher: link does not exist")

// Layout is an install directory.
type Layout struct{ Dir string }

func validVersion(v string) error {
	if v == "" || v == "." || v == ".." || strings.ContainsAny(v, "/\\\x00") ||
		strings.HasPrefix(v, ".") {
		return fmt.Errorf("launcher: %w version %q", errInvalid, v)
	}

	return nil
}

// Current returns the version the current link points at.
func (lay Layout) Current() (string, error) { return lay.link(linkCurrent) }

// KnownGood returns the version the known-good link points at.
func (lay Layout) KnownGood() (string, error) { return lay.link(linkKnownGood) }

// PreviousGood returns the version the previous-good link points at.
func (lay Layout) PreviousGood() (string, error) { return lay.link(linkPreviousGood) }

// Binary returns the path of the agent binary of a version.
func (lay Layout) Binary(version string) string {
	return filepath.Join(lay.Dir, versionsDir, version, BinaryName)
}

// Stage moves a downloaded binary into versions/<version>/ with mode 0755.
func (lay Layout) Stage(version, binaryPath string) error {
	err := validVersion(version)
	if err != nil {
		return err
	}

	dir := filepath.Join(lay.Dir, versionsDir, version)

	err = os.MkdirAll(dir, dirMode)
	if err != nil {
		return fmt.Errorf("launcher: create version dir: %w", err)
	}

	dst := lay.Binary(version)
	tmp := dst + ".tmp"

	err = os.Chmod(binaryPath, binaryMode)
	if err != nil {
		return fmt.Errorf("launcher: chmod staged binary: %w", err)
	}

	err = os.Rename(binaryPath, tmp)
	if err != nil {
		err = copyFile(binaryPath, tmp)
		if err != nil {
			_ = os.Remove(tmp)

			return err
		}

		_ = os.Remove(binaryPath)
	}

	err = os.Chmod(tmp, binaryMode)
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("launcher: chmod staged binary: %w", err)
	}

	err = os.Rename(tmp, dst)
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("launcher: install staged binary: %w", err)
	}

	return nil
}

func copyFile(src, dst string) (err error) {
	in, err := os.Open(src) //nolint:gosec // src is a caller-chosen staged binary
	if err != nil {
		return fmt.Errorf("launcher: open %s: %w", src, err)
	}

	defer in.Close()

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC

	out, err := os.OpenFile(dst, flags, binaryMode)
	if err != nil {
		return fmt.Errorf("launcher: create %s: %w", dst, err)
	}

	defer func() {
		cerr := out.Close()
		if err == nil && cerr != nil {
			err = fmt.Errorf("launcher: close %s: %w", dst, cerr)
		}
	}()

	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("launcher: copy to %s: %w", dst, err)
	}

	return nil
}

// SetCurrent atomically points current at a staged version.
func (lay Layout) SetCurrent(version string) error { return lay.setLink(linkCurrent, version) }

// Promote makes current the known-good version and keeps the old known-good as
// previous-good.
func (lay Layout) Promote() error {
	cur, err := lay.Current()
	if err != nil {
		return err
	}

	kg, err := lay.KnownGood()
	if err != nil && !errors.Is(err, ErrNoLink) {
		return err
	}

	if kg == cur {
		return nil
	}

	if kg != "" {
		err := lay.setLink(linkPreviousGood, kg)
		if err != nil {
			return err
		}
	}

	return lay.setLink(linkKnownGood, cur)
}

// Rollback points current back at known-good.
func (lay Layout) Rollback() error {
	kg, err := lay.KnownGood()
	if err != nil {
		return err
	}

	return lay.SetCurrent(kg)
}

// FallbackToPrevious points known-good and current at previous-good.
func (lay Layout) FallbackToPrevious() error {
	pg, err := lay.PreviousGood()
	if err != nil {
		return err
	}

	err = lay.setLink(linkKnownGood, pg)
	if err != nil {
		return err
	}

	return lay.setLink(linkCurrent, pg)
}

// Prune deletes version directories that no symlink references, except the
// keep newest (by modification time) of them.
func (lay Layout) Prune(keep int) error {
	entries, err := os.ReadDir(filepath.Join(lay.Dir, versionsDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("launcher: list versions: %w", err)
	}

	ref := map[string]bool{}

	for _, name := range []string{linkCurrent, linkKnownGood, linkPreviousGood} {
		target, linkErr := lay.link(name)
		if linkErr == nil {
			ref[target] = true
		}
	}

	type cand struct {
		name string
		mod  int64
	}

	var cands []cand

	for _, entry := range entries {
		if !entry.IsDir() || ref[entry.Name()] {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		cands = append(cands, cand{entry.Name(), info.ModTime().UnixNano()})
	}

	sort.Slice(cands, func(i, j int) bool {
		if cands[i].mod != cands[j].mod {
			return cands[i].mod > cands[j].mod
		}

		return cands[i].name > cands[j].name
	})

	if keep < 0 {
		keep = 0
	}

	var errs []error

	for i := keep; i < len(cands); i++ {
		err := os.RemoveAll(filepath.Join(lay.Dir, versionsDir, cands[i].name))
		if err != nil {
			errs = append(errs, fmt.Errorf("launcher: prune %s: %w", cands[i].name, err))
		}
	}

	return errors.Join(errs...)
}

func (lay Layout) link(name string) (string, error) {
	target, err := os.Readlink(filepath.Join(lay.Dir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrNoLink, name)
		}

		return "", fmt.Errorf("launcher: read link %s: %w", name, err)
	}

	clean := filepath.Clean(target)
	if filepath.Dir(clean) != versionsDir {
		return "", fmt.Errorf("launcher: link %s has %w %q", name, errUnexpectedTarget, target)
	}

	return filepath.Base(clean), nil
}

func (lay Layout) setLink(name, version string) error {
	err := validVersion(version)
	if err != nil {
		return err
	}

	_, err = os.Stat(lay.Binary(version))
	if err != nil {
		return fmt.Errorf("launcher: version %s is not staged: %w", version, err)
	}

	tmp := filepath.Join(lay.Dir, "."+name+".tmp")

	_ = os.Remove(tmp)

	err = os.Symlink(filepath.Join(versionsDir, version), tmp)
	if err != nil {
		return fmt.Errorf("launcher: create temp link: %w", err)
	}

	err = os.Rename(tmp, filepath.Join(lay.Dir, name))
	if err != nil {
		_ = os.Remove(tmp)

		return fmt.Errorf("launcher: swap link %s: %w", name, err)
	}

	return nil
}
