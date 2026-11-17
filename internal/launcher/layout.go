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
	if v == "" || v == "." || v == ".." || strings.ContainsAny(v, "/\\\x00") || strings.HasPrefix(v, ".") {
		return fmt.Errorf("launcher: invalid version %q", v)
	}
	return nil
}

func (l Layout) link(name string) (string, error) {
	target, err := os.Readlink(filepath.Join(l.Dir, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrNoLink, name)
		}
		return "", fmt.Errorf("launcher: read link %s: %w", name, err)
	}
	clean := filepath.Clean(target)
	if filepath.Dir(clean) != versionsDir {
		return "", fmt.Errorf("launcher: link %s has unexpected target %q", name, target)
	}
	return filepath.Base(clean), nil
}

// Current returns the version the current link points at.
func (l Layout) Current() (string, error) { return l.link(linkCurrent) }

// KnownGood returns the version the known-good link points at.
func (l Layout) KnownGood() (string, error) { return l.link(linkKnownGood) }

// PreviousGood returns the version the previous-good link points at.
func (l Layout) PreviousGood() (string, error) { return l.link(linkPreviousGood) }

// Binary returns the path of the agent binary of a version.
func (l Layout) Binary(version string) string {
	return filepath.Join(l.Dir, versionsDir, version, BinaryName)
}

// Stage moves a downloaded binary into versions/<version>/ with mode 0755.
func (l Layout) Stage(version, binaryPath string) error {
	if err := validVersion(version); err != nil {
		return err
	}
	dir := filepath.Join(l.Dir, versionsDir, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("launcher: create version dir: %w", err)
	}
	dst := l.Binary(version)
	tmp := dst + ".tmp"
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return fmt.Errorf("launcher: chmod staged binary: %w", err)
	}
	if err := os.Rename(binaryPath, tmp); err != nil {
		if err := copyFile(binaryPath, tmp); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		_ = os.Remove(binaryPath)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("launcher: chmod staged binary: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("launcher: install staged binary: %w", err)
	}
	return nil
}

func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("launcher: open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("launcher: create %s: %w", dst, err)
	}
	defer func() {
		if cerr := out.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("launcher: close %s: %w", dst, cerr)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("launcher: copy to %s: %w", dst, err)
	}
	return nil
}

func (l Layout) setLink(name, version string) error {
	if err := validVersion(version); err != nil {
		return err
	}
	if _, err := os.Stat(l.Binary(version)); err != nil {
		return fmt.Errorf("launcher: version %s is not staged: %w", version, err)
	}
	tmp := filepath.Join(l.Dir, "."+name+".tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(filepath.Join(versionsDir, version), tmp); err != nil {
		return fmt.Errorf("launcher: create temp link: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(l.Dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("launcher: swap link %s: %w", name, err)
	}
	return nil
}

// SetCurrent atomically points current at a staged version.
func (l Layout) SetCurrent(version string) error { return l.setLink(linkCurrent, version) }

// Promote makes current the known-good version and keeps the old known-good as
// previous-good.
func (l Layout) Promote() error {
	cur, err := l.Current()
	if err != nil {
		return err
	}
	kg, err := l.KnownGood()
	if err != nil && !errors.Is(err, ErrNoLink) {
		return err
	}
	if kg == cur {
		return nil
	}
	if kg != "" {
		if err := l.setLink(linkPreviousGood, kg); err != nil {
			return err
		}
	}
	return l.setLink(linkKnownGood, cur)
}

// Rollback points current back at known-good.
func (l Layout) Rollback() error {
	kg, err := l.KnownGood()
	if err != nil {
		return err
	}
	return l.SetCurrent(kg)
}

// FallbackToPrevious points known-good and current at previous-good.
func (l Layout) FallbackToPrevious() error {
	pg, err := l.PreviousGood()
	if err != nil {
		return err
	}
	if err := l.setLink(linkKnownGood, pg); err != nil {
		return err
	}
	return l.setLink(linkCurrent, pg)
}

// Prune deletes version directories that no symlink references, except the
// keep newest (by modification time) of them.
func (l Layout) Prune(keep int) error {
	entries, err := os.ReadDir(filepath.Join(l.Dir, versionsDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("launcher: list versions: %w", err)
	}
	ref := map[string]bool{}
	for _, name := range []string{linkCurrent, linkKnownGood, linkPreviousGood} {
		if v, err := l.link(name); err == nil {
			ref[v] = true
		}
	}
	type cand struct {
		name string
		mod  int64
	}
	var cands []cand
	for _, e := range entries {
		if !e.IsDir() || ref[e.Name()] {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{e.Name(), info.ModTime().UnixNano()})
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
		if err := os.RemoveAll(filepath.Join(l.Dir, versionsDir, cands[i].name)); err != nil {
			errs = append(errs, fmt.Errorf("launcher: prune %s: %w", cands[i].name, err))
		}
	}
	return errors.Join(errs...)
}
