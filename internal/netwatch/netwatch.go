// Package netwatch reports local network changes and sleep/wake transitions and
// answers a few questions about the local network (addresses, default gateway).
package netwatch

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// EventKind says why an Event was emitted.
type EventKind int

const (
	// EventNetwork means an address, route or link changed.
	EventNetwork EventKind = iota + 1
	// EventWake means the machine appears to have slept and woken.
	EventWake
	// EventTick is a periodic backup event. Watch does not currently emit it.
	EventTick
)

func (k EventKind) String() string {
	switch k {
	case EventNetwork:
		return "network"
	case EventWake:
		return "wake"
	case EventTick:
		return "tick"
	default:
		return "unknown"
	}
}

// Event is a coalesced notification.
type Event struct {
	Kind EventKind
	At   time.Time
}

const (
	debounceInterval = 250 * time.Millisecond
	wakeInterval     = 5 * time.Second
	wakeSlack        = 5 * time.Second
)

// Watch emits coalesced events until ctx ends, then closes the channel. If the
// OS notification socket cannot be opened the error is logged and only wake
// detection runs.
func Watch(ctx context.Context, log *slog.Logger) <-chan Event {
	return watch(ctx, log, config{
		open:     openSource,
		debounce: debounceInterval,
		interval: wakeInterval,
		slack:    wakeSlack,
		clock:    newRealClock(),
	})
}

// reading is a pair of wall-clock time (monotonic part stripped) and a
// monotonic offset. The monotonic offset does not advance while the machine is
// suspended, which is what makes sleep detectable.
type reading struct {
	Wall time.Time
	Mono time.Duration
}

type clock interface {
	Read() reading
}

type realClock struct{ start time.Time }

func newRealClock() realClock { return realClock{start: time.Now()} }

func (c realClock) Read() reading {
	now := time.Now()
	return reading{Wall: now.Round(0), Mono: now.Sub(c.start)}
}

// config holds the injectable parts of Watch.
type config struct {
	// open starts delivering OS change notifications. The returned channel
	// carries one value per raw notification and is closed on fatal error or
	// when ctx ends.
	open     func(ctx context.Context) (<-chan struct{}, error)
	debounce time.Duration
	interval time.Duration // wake check period, used when tick is nil
	slack    time.Duration
	clock    clock
	tick     <-chan time.Time // overrides the wake ticker in tests
}

func watch(ctx context.Context, log *slog.Logger, cfg config) <-chan Event {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	out := make(chan Event, 16)
	go func() {
		defer close(out)
		run(ctx, log, cfg, out)
	}()
	return out
}

func send(out chan<- Event, kind EventKind, at time.Time) {
	select {
	case out <- Event{Kind: kind, At: at}:
	default: // consumer is behind; it will see the newer queued events
	}
}

func run(ctx context.Context, log *slog.Logger, cfg config, out chan<- Event) {
	var raw <-chan struct{}
	if cfg.open != nil {
		ch, err := cfg.open(ctx)
		if err != nil {
			log.Warn("netwatch: cannot open network change socket, wake detection only", "err", err)
		} else {
			raw = ch
		}
	}

	tick := cfg.tick
	if tick == nil {
		t := time.NewTicker(cfg.interval)
		defer t.Stop()
		tick = t.C
	}

	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	defer debounce.Stop()
	pending := false

	last := cfg.clock.Read()
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-raw:
			if !ok {
				if ctx.Err() == nil {
					log.Warn("netwatch: network change socket closed, wake detection only")
				}
				raw = nil
				continue
			}
			if !pending {
				pending = true
				debounce.Reset(cfg.debounce)
			}
		case <-debounce.C:
			pending = false
			send(out, EventNetwork, cfg.clock.Read().Wall)
		case <-tick:
			now := cfg.clock.Read()
			if slept(last, now, cfg.slack) {
				send(out, EventWake, now.Wall)
			}
			last = now
		}
	}
}

// slept reports whether wall time advanced by more than slack beyond the
// monotonic time between two readings.
func slept(prev, cur reading, slack time.Duration) bool {
	wall := cur.Wall.Sub(prev.Wall)
	mono := cur.Mono - prev.Mono
	return wall-mono > slack
}

// ErrNoGateway is returned when no IPv4 default gateway is known.
var ErrNoGateway = errors.New("netwatch: no default gateway")

// ErrNoMAC is returned when the default gateway is known but has no complete
// neighbor table entry.
var ErrNoMAC = errors.New("netwatch: no link-layer address for default gateway")
