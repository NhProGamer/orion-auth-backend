package clock

import (
	"sync"
	"testing"
	"time"
)

func TestFakeNowAdvance(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := NewFake(start)
	if !f.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", f.Now(), start)
	}
	f.Advance(2 * time.Hour)
	if !f.Now().Equal(start.Add(2 * time.Hour)) {
		t.Errorf("after Advance: %v", f.Now())
	}
	f.Set(start)
	if !f.Now().Equal(start) {
		t.Errorf("after Set: %v", f.Now())
	}
}

func TestFakeRaceFree(t *testing.T) {
	f := NewFake(time.Now())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.Advance(time.Millisecond)
			_ = f.Now()
		}()
	}
	wg.Wait()
}

func TestRealReturnsCurrent(t *testing.T) {
	c := Real()
	got := c.Now()
	if time.Since(got) > time.Second {
		t.Errorf("Real().Now() drifted: %v", got)
	}
}
