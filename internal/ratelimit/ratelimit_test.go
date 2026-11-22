package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(3, time.Minute).WithClock(func() time.Time { return now })

	for i := range 3 {
		if !l.Allow("a") {
			t.Fatalf("event %d refused", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("4th event allowed")
	}
	if !l.Exceeded("a") {
		t.Fatal("Exceeded = false at limit")
	}
	if !l.Allow("b") {
		t.Fatal("other key refused")
	}

	now = now.Add(59 * time.Second)
	if l.Allow("a") {
		t.Fatal("allowed before window passed")
	}
	now = now.Add(time.Second)
	if !l.Allow("a") {
		t.Fatal("refused after window passed")
	}
}

func TestRecordCountsTowardsLimit(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(2, time.Hour).WithClock(func() time.Time { return now })
	l.Record("ip")
	if l.Exceeded("ip") {
		t.Fatal("exceeded after one")
	}
	l.Record("ip")
	if !l.Exceeded("ip") {
		t.Fatal("not exceeded after two")
	}
}

func TestIdleKeysAreDropped(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := New(1, time.Second).WithClock(func() time.Time { return now })
	for i := range 2000 {
		l.Allow(string(rune(i)))
		now = now.Add(time.Second)
	}
	if len(l.events) > 1100 {
		t.Fatalf("%d keys retained", len(l.events))
	}
}
