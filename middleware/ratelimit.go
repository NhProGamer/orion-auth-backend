package middleware

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/pkg"
)

type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func (b *tokenBucket) allow() bool {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RateLimiter stores per-IP buckets.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	max     float64
	rate    float64
}

// NewRateLimiter creates a rate limiter.
// maxRequests is the burst size, perSecond is the sustained rate.
func NewRateLimiter(maxRequests float64, perSecond float64) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		max:     maxRequests,
		rate:    perSecond,
	}

	// Cleanup stale buckets every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, bucket := range rl.buckets {
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

func (rl *RateLimiter) getBucket(ip string) *tokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[ip]
	if !exists {
		bucket = &tokenBucket{
			tokens:     rl.max,
			maxTokens:  rl.max,
			refillRate: rl.rate,
			lastRefill: time.Now(),
		}
		rl.buckets[ip] = bucket
	}
	return bucket
}

// Middleware returns a Gin middleware that rate limits by client IP.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		bucket := rl.getBucket(ip)

		rl.mu.Lock()
		allowed := bucket.allow()
		rl.mu.Unlock()

		if !allowed {
			pkg.HandleError(c, pkg.ErrTooManyRequests("rate limit exceeded, try again later"))
			c.Abort()
			return
		}

		c.Next()
	}
}
