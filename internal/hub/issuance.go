package hub

import (
	"context"
	"fmt"
	"sync"
)

// issuanceLocks serializes certificate issuance for each identity.
type issuanceLocks struct {
	active map[string]chan struct{}
	mu     sync.Mutex
}

// begin either takes the lock or returns a channel closed when the holder exits.
func (locks *issuanceLocks) begin(identity string) (func(), <-chan struct{}) {
	locks.mu.Lock()
	defer locks.mu.Unlock()

	if done := locks.active[identity]; done != nil {
		return nil, done
	}

	if locks.active == nil {
		locks.active = map[string]chan struct{}{}
	}

	done := make(chan struct{})
	locks.active[identity] = done

	return func() {
		locks.mu.Lock()
		delete(locks.active, identity)
		close(done)
		locks.mu.Unlock()
	}, nil
}

func (locks *issuanceLocks) wait(ctx context.Context, identity string) (func(), error) {
	for ctx.Err() == nil {
		end, done := locks.begin(identity)
		if end != nil {
			return end, nil
		}

		select {
		case <-ctx.Done():
		case <-done:
		}
	}

	return nil, fmt.Errorf("wait for issuance lock: %w", ctx.Err())
}
