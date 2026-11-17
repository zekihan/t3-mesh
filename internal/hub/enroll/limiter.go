package enroll

import (
	"net/netip"
	"sync"
	"time"
)

// Limiter limits enrollment attempts per source address with a sliding window.
type Limiter struct {
	// Max attempts per Window per address; Window is the sliding window;
	// MaxEntries bounds the number of tracked addresses.
	Max        int
	Window     time.Duration
	MaxEntries int
	Now        func() time.Time

	mu      sync.Mutex
	entries map[netip.Addr][]time.Time
}

// NewLimiter returns a limiter allowing 5 attempts per 10 minutes per address.
func NewLimiter(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}

	return &Limiter{Max: 5, Window: 10 * time.Minute, MaxEntries: 4096, Now: now}
}

// Allow records an attempt from addr and reports whether it is within the
// limit. When the table is full of live entries, new addresses are refused.
func (l *Limiter) Allow(addr netip.Addr) bool {
	addr = addr.Unmap()
	now := l.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.entries == nil {
		l.entries = map[netip.Addr][]time.Time{}
	}

	hits := l.live(l.entries[addr], now)

	if _, known := l.entries[addr]; !known && len(l.entries) >= l.MaxEntries {
		l.cleanup(now)

		if len(l.entries) >= l.MaxEntries {
			return false
		}
	}

	if len(hits) >= l.Max {
		l.entries[addr] = hits

		return false
	}

	l.entries[addr] = append(hits, now)

	return true
}

func (l *Limiter) live(hits []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-l.Window)
	i := 0

	for i < len(hits) && !hits[i].After(cutoff) {
		i++
	}

	return hits[i:]
}

func (l *Limiter) cleanup(now time.Time) {
	for addr, hits := range l.entries {
		if len(l.live(hits, now)) == 0 {
			delete(l.entries, addr)
		}
	}
}
