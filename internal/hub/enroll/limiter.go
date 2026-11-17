package enroll

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter limits enrollment attempts per source address with a sliding window.
type Limiter struct {
	Now        func() time.Time
	entries    map[netip.Addr][]time.Time
	Max        int
	Window     time.Duration
	MaxEntries int
	mu         sync.Mutex
}

const (
	defaultMaxAttempts = 5
	defaultWindow      = 10 * time.Minute
	defaultMaxEntries  = 4096
)

// NewLimiter returns a limiter allowing 5 attempts per 10 minutes per address.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}

	return &Limiter{
		Max:        defaultMaxAttempts,
		Window:     defaultWindow,
		MaxEntries: defaultMaxEntries,
		Now:        now,
	}
}

// Allow records an attempt from addr and reports whether it is within the
// limit. When the table is full of live entries, new addresses are refused.
func (limiter *Limiter) Allow(addr netip.Addr) bool {
	addr = addr.Unmap()
	now := limiter.Now()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if limiter.entries == nil {
		limiter.entries = map[netip.Addr][]time.Time{}
	}

	hits := limiter.live(limiter.entries[addr], now)

	if _, known := limiter.entries[addr]; !known && len(limiter.entries) >= limiter.MaxEntries {
		limiter.cleanup(now)

		if len(limiter.entries) >= limiter.MaxEntries {
			return false
		}
	}

	if len(hits) >= limiter.Max {
		limiter.entries[addr] = hits

		return false
	}

	limiter.entries[addr] = append(hits, now)

	return true
}

func (limiter *Limiter) live(hits []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-limiter.Window)
	i := 0

	for i < len(hits) && !hits[i].After(cutoff) {
		i++
	}

	return hits[i:]
}

func (limiter *Limiter) cleanup(now time.Time) {
	for addr, hits := range limiter.entries {
		if len(limiter.live(hits, now)) == 0 {
			delete(limiter.entries, addr)
		}
	}
}
