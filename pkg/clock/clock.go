// Package clock provides a minimal time source for services that compute
// TTLs, lockout windows, or token expirations. Injecting a Clock instead
// of calling time.Now() directly lets tests pin or advance the clock
// deterministically — flaky "wait 200ms then assert" loops disappear.
//
// The interface deliberately exposes only Now(). Anything more (Sleep,
// AfterFunc, NewTicker) belongs in a richer abstraction; we don't need
// that here, and adding it would invite scope creep.
package clock

import "time"

// Clock is the read-only time source consumed by services.
type Clock interface {
	Now() time.Time
}

// Real returns a Clock backed by the wall clock (time.Now).
// Use this in production wiring; tests should use NewFake().
func Real() Clock {
	return realClock{}
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
