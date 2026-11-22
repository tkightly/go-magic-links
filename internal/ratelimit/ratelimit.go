// Package ratelimit is an in-memory sliding-window rate limiter. It suits a
// single API instance; limits reset when the process restarts, which is
// acceptable because Cloudflare's WAF rules are the outer layer.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows at most Max events per key in any Window.
type Limiter struct {
	Max    int
	Window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	events map[string][]time.Time
	calls  int
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{Max: max, Window: window, now: time.Now, events: map[string][]time.Time{}}
}

// WithClock replaces the clock, for tests.
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Allow records an event for key and reports whether it's within the limit.
// Refused events aren't recorded, so a client that backs off recovers.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	recent := l.prune(key, now)
	if len(recent) >= l.Max {
		return false
	}
	l.events[key] = append(recent, now)
	l.sweep(now)
	return true
}

// Exceeded reports whether key is already at its limit, without recording
// anything. Used to refuse early before doing work.
func (l *Limiter) Exceeded(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, l.now())) >= l.Max
}

// Record notes an event for key without checking the limit, e.g. a failed
// guess that should count towards a lockout.
func (l *Limiter) Record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.events[key] = append(l.prune(key, now), now)
	l.sweep(now)
}

func (l *Limiter) prune(key string, now time.Time) []time.Time {
	ev := l.events[key]
	cut := 0
	for cut < len(ev) && now.Sub(ev[cut]) >= l.Window {
		cut++
	}
	ev = ev[cut:]
	if len(ev) == 0 {
		delete(l.events, key)
		return nil
	}
	l.events[key] = ev
	return ev
}

// sweep drops idle keys every so often so memory stays bounded.
func (l *Limiter) sweep(now time.Time) {
	l.calls++
	if l.calls%1024 != 0 {
		return
	}
	for k := range l.events {
		l.prune(k, now)
	}
}
