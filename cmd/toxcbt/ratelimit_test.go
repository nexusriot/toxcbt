package main

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsBurstThenRefills(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newRateLimiter(3, 60) // 3 at once, one more per second

	for i := 0; i < 3; i++ {
		if ok, _ := r.allow(keyA, now); !ok {
			t.Fatalf("message %d of the burst was rejected", i+1)
		}
	}
	if ok, notify := r.allow(keyA, now); ok || !notify {
		t.Errorf("fourth message: ok=%v notify=%v, want false/true", ok, notify)
	}
	if ok, _ := r.allow(keyA, now.Add(time.Second)); !ok {
		t.Error("a token should have refilled after a second")
	}
}

// A peer that keeps hammering gets told once a minute, not once a message:
// the notice must not become the amplification it exists to prevent.
func TestRateLimiterNotifiesAtMostOncePerMinute(t *testing.T) {
	start := time.Unix(1700000000, 0)
	r := newRateLimiter(1, 1) // one message, then one per minute

	notices, rejected := 0, 0
	for i := 0; i <= 90; i++ {
		ok, notify := r.allow(keyA, start.Add(time.Duration(i)*time.Second))
		if !ok {
			rejected++
		}
		if notify {
			notices++
		}
	}

	if rejected < 80 {
		t.Fatalf("only %d of 91 messages were rejected; the fixture is not flooding", rejected)
	}
	if notices < 1 || notices > 2 {
		t.Errorf("sent %d notices over 90s of flooding, want about one per minute", notices)
	}
}

func TestRateLimiterIsPerPeer(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newRateLimiter(1, 60)
	r.allow(keyA, now)

	if ok, _ := r.allow(keyA, now); ok {
		t.Error("keyA should be out of tokens")
	}
	if ok, _ := r.allow(keyB, now); !ok {
		t.Error("keyB has its own bucket and should be allowed")
	}
}

func TestRateLimiterPruneForgetsIdlePeers(t *testing.T) {
	now := time.Unix(1700000000, 0)
	r := newRateLimiter(1, 60)
	r.allow(keyA, now)
	r.allow(keyB, now.Add(time.Hour))

	r.prune(now.Add(time.Hour), 10*time.Minute)

	if r.tracked() != 1 {
		t.Errorf("tracked %d peers, want only the recent one", r.tracked())
	}
	if _, ok := r.buckets[keyB]; !ok {
		t.Error("the recently seen peer was pruned")
	}
}

func TestNilRateLimiterAllowsEverything(t *testing.T) {
	var r *rateLimiter
	if r != newRateLimiter(10, 0) {
		t.Error("a non-positive rate must disable the limiter")
	}
	for i := 0; i < 100; i++ {
		if ok, notify := r.allow(keyA, time.Now()); !ok || notify {
			t.Fatal("a nil limiter must allow everything, silently")
		}
	}
	r.prune(time.Now(), time.Minute) // must not panic
}
