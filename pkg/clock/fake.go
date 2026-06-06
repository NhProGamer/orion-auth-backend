package clock

import (
	"sync"
	"time"
)

// Fake is a Clock whose value is controlled by tests. It is safe for
// concurrent reads and writes — services use Now() from goroutines while
// the test mutates via Set / Advance from the main thread.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a Fake initialised at t.
func NewFake(t time.Time) *Fake {
	return &Fake{now: t}
}

// Now returns the current fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set jumps the fake clock to t.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Advance moves the fake clock forward by d. Negative d is permitted
// (rare, but useful when a test wants to assert "not-yet" behavior).
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
