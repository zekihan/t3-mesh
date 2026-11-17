// Package release decides which agent version to install and verifies it.
// It does not supervise processes; that is the launcher's job.
package release

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is a parsed vMAJOR.MINOR.PATCH[-pre] version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 string
}

// ParseVersion parses "v1.2.3" or "v1.2.3-rc.1". The leading "v" is required.
func ParseVersion(s string) (Version, error) {
	var v Version
	rest, ok := strings.CutPrefix(s, "v")
	if !ok {
		return v, fmt.Errorf("version %q: missing leading v", s)
	}
	core, pre, hasPre := strings.Cut(rest, "-")
	if hasPre {
		if pre == "" {
			return v, fmt.Errorf("version %q: empty pre-release", s)
		}
		for _, id := range strings.Split(pre, ".") {
			if id == "" {
				return v, fmt.Errorf("version %q: empty pre-release identifier", s)
			}
			for _, r := range id {
				if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
					return v, fmt.Errorf("version %q: invalid pre-release character %q", s, r)
				}
			}
		}
		v.Pre = pre
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q: want MAJOR.MINOR.PATCH", s)
	}
	nums := [3]*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, err := parseNum(p)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: %w", s, err)
		}
		*nums[i] = n
	}
	return v, nil
}

func parseNum(p string) (uint64, error) {
	if p == "" {
		return 0, errors.New("empty number")
	}
	for _, r := range p {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid number %q", p)
		}
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, fmt.Errorf("leading zero in %q", p)
	}
	n, err := strconv.ParseUint(p, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", p, err)
	}
	return n, nil
}

// String returns the canonical form.
func (v Version) String() string {
	s := fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release.
func (v Version) Compare(o Version) int {
	if c := cmpUint(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmpUint(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmpUint(v.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return comparePre(v.Pre, o.Pre)
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
