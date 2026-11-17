// Package release decides which agent version to install and verifies it.
// It does not supervise processes; that is the launcher's job.
package release

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	versionParts = 3
)

var (
	errMissingV       = errors.New("missing leading v")
	errEmptyPre       = errors.New("empty pre-release")
	errEmptyPreID     = errors.New("empty pre-release identifier")
	errInvalidPreChar = errors.New("invalid pre-release character")
	errWantSemver     = errors.New("want MAJOR.MINOR.PATCH")
	errEmptyNumber    = errors.New("empty number")
	errInvalidNumber  = errors.New("invalid number")
	errLeadingZero    = errors.New("leading zero in")
)

// Version is a parsed vMAJOR.MINOR.PATCH[-pre] version.
type Version struct {
	Pre   string
	Major uint64
	Minor uint64
	Patch uint64
}

// ParseVersion parses "v1.2.3" or "v1.2.3-rc.1". The leading "v" is required.
func ParseVersion(str string) (Version, error) {
	var ver Version

	rest, ok := strings.CutPrefix(str, "v")
	if !ok {
		return ver, fmt.Errorf("version %q: %w", str, errMissingV)
	}

	core, pre, hasPre := strings.Cut(rest, "-")
	if hasPre {
		if pre == "" {
			return ver, fmt.Errorf("version %q: %w", str, errEmptyPre)
		}

		err := checkPre(pre)
		if err != nil {
			return ver, fmt.Errorf("version %q: %w", str, err)
		}

		ver.Pre = pre
	}

	parts := strings.Split(core, ".")
	if len(parts) != versionParts {
		return ver, fmt.Errorf("version %q: %w", str, errWantSemver)
	}

	nums := [3]*uint64{&ver.Major, &ver.Minor, &ver.Patch}

	for i, p := range parts {
		n, err := parseNum(p)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: %w", str, err)
		}

		*nums[i] = n
	}

	return ver, nil
}

// checkPre validates the dot-separated pre-release identifiers.
func checkPre(pre string) error {
	for id := range strings.SplitSeq(pre, ".") {
		if id == "" {
			return errEmptyPreID
		}

		for _, r := range id {
			if !isAlnum(r) && r != '-' {
				return fmt.Errorf("%w %q", errInvalidPreChar, r)
			}
		}
	}

	return nil
}

func parseNum(part string) (uint64, error) {
	if part == "" {
		return 0, errEmptyNumber
	}

	for _, r := range part {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%w %q", errInvalidNumber, part)
		}
	}

	if len(part) > 1 && part[0] == '0' {
		return 0, fmt.Errorf("%w %q", errLeadingZero, part)
	}

	n, err := strconv.ParseUint(part, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", part, err)
	}

	return n, nil
}

// String returns the canonical form.
func (ver Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", ver.Major, ver.Minor, ver.Patch)
	if ver.Pre != "" {
		s += "-" + ver.Pre
	}

	return s
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release.
func (ver Version) Compare(other Version) int {
	if c := cmpUint(ver.Major, other.Major); c != 0 {
		return c
	}

	if c := cmpUint(ver.Minor, other.Minor); c != 0 {
		return c
	}

	if c := cmpUint(ver.Patch, other.Patch); c != 0 {
		return c
	}

	switch {
	case ver.Pre == other.Pre:
		return 0
	case ver.Pre == "":
		return 1
	case other.Pre == "":
		return -1
	}

	return comparePre(ver.Pre, other.Pre)
}

// Compare parses and compares two version strings.
func Compare(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}

	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}

	return va.Compare(vb), nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}

	return 0
}

// comparePre follows semver: numeric identifiers sort numerically and before
// alphanumeric ones; a shorter list sorts first when all else is equal.
func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aerr := strconv.ParseUint(as[i], 10, 64)

		bn, berr := strconv.ParseUint(bs[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if c := cmpUint(an, bn); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		case berr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}

	return cmpUint(uint64(len(as)), uint64(len(bs)))
}
