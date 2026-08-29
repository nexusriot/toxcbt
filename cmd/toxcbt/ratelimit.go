package main

import "time"

// rateLimiter is a per-peer token bucket keyed on public key. Friend numbers
// are reused when a friend is removed, so the key has to be the cryptographic
// identity for the limit to mean anything.
//
// A nil *rateLimiter allows everything, which is how the limiter is disabled.
type rateLimiter struct {
	burst    float64
	perSec   float64
	notify   time.Duration
	buckets  map[string]*bucket
	lastSeen map[string]time.Time
}

type bucket struct {
	tokens     float64
	last       time.Time
	notifiedAt time.Time
}

// newRateLimiter returns nil (i.e. unlimited) when perMinute is not positive.
func newRateLimiter(burst, perMinute int) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	return &rateLimiter{
		burst:    float64(burst),
		perSec:   float64(perMinute) / 60,
		notify:   time.Minute,
		buckets:  map[string]*bucket{},
		lastSeen: map[string]time.Time{},
	}
}

// allow charges one message against key's bucket. It reports whether the
// message may proceed and, when it may not, whether the caller should tell the
// peer — that second flag is rate limited too, so a flood produces one notice
// per minute instead of one per message.
func (r *rateLimiter) allow(key string, now time.Time) (ok bool, notify bool) {
	if r == nil {
		return true, false
	}
	b := r.buckets[key]
	if b == nil {
		b = &bucket{tokens: r.burst, last: now}
		r.buckets[key] = b
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * r.perSec
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.last = now
	}
	r.lastSeen[key] = now

	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	if b.notifiedAt.IsZero() || now.Sub(b.notifiedAt) >= r.notify {
		b.notifiedAt = now
		return false, true
	}
	return false, false
}

// prune forgets peers that have been quiet long enough to have a full bucket
// anyway, so the map does not grow with every stranger that ever messaged.
func (r *rateLimiter) prune(now time.Time, idle time.Duration) {
	if r == nil {
		return
	}
	for key, seen := range r.lastSeen {
		if now.Sub(seen) > idle {
			delete(r.lastSeen, key)
			delete(r.buckets, key)
		}
	}
}

func (r *rateLimiter) tracked() int {
	if r == nil {
		return 0
	}
	return len(r.buckets)
}
