package middleware

import (
	"testing"
	"time"
)

func TestTokenBucketAllow(t *testing.T) {
	b := &tokenBucket{
		tokens:     3,
		maxTokens:  3,
		refillRate: 1,
		lastRefill: time.Now(),
	}

	// Should allow up to burst size
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// Next request should be denied (bucket empty)
	if b.allow() {
		t.Error("request after burst should be denied")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	b := &tokenBucket{
		tokens:     0,
		maxTokens:  5,
		refillRate: 100, // 100 tokens/s for fast test
		lastRefill: time.Now().Add(-100 * time.Millisecond),
	}

	// After 100ms at 100/s, should have ~10 tokens (capped at 5)
	if !b.allow() {
		t.Error("should allow after refill")
	}
}

func TestTokenBucketMaxCap(t *testing.T) {
	b := &tokenBucket{
		tokens:     0,
		maxTokens:  2,
		refillRate: 1000,
		lastRefill: time.Now().Add(-10 * time.Second),
	}

	// Refill would give 10000 tokens, but capped at maxTokens=2
	b.allow()
	b.allow()
	if b.allow() {
		t.Error("should be denied after maxTokens consumed")
	}
}
