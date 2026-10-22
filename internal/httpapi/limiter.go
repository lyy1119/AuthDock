package httpapi

import (
	"sync"
	"time"
)

// AttemptLimiter throttles repeated failed logins per username so the admin
// account cannot be brute-forced over the network. It is intentionally small:
// a fixed window, a failure budget and a cool-down.
type AttemptLimiter struct {
	mu          sync.Mutex
	entries     map[string]*attemptEntry
	maxFailures int
	lockFor     time.Duration
	window      time.Duration
}

type attemptEntry struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

// NewAttemptLimiter returns a limiter that locks a key for lockFor once it has
// collected maxFailures failures inside window.
func NewAttemptLimiter(maxFailures int, lockFor, window time.Duration) *AttemptLimiter {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if lockFor <= 0 {
		lockFor = time.Minute
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &AttemptLimiter{
		entries:     make(map[string]*attemptEntry),
		maxFailures: maxFailures,
		lockFor:     lockFor,
		window:      window,
	}
}

// Allow reports whether key may attempt a login at now. When it may not, the
// second result is how long the caller should wait.
func (l *AttemptLimiter) Allow(key string, now time.Time) (bool, time.Duration) {
	if key == "" {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		return true, 0
	}
	if now.Before(entry.lockedUntil) {
		return false, entry.lockedUntil.Sub(now)
	}
	if now.Sub(entry.lastFailure) >= l.window {
		delete(l.entries, key)
	}
	return true, 0
}

// Fail records one failed attempt for key.
func (l *AttemptLimiter) Fail(key string, now time.Time) {
	if key == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		entry = &attemptEntry{}
		l.entries[key] = entry
	}
	// A quiet period longer than the window starts a fresh budget.
	if now.Sub(entry.lastFailure) >= l.window {
		entry.failures = 0
		entry.lastFailure = time.Time{}
	}
	entry.failures++
	entry.lastFailure = now
	if entry.failures >= l.maxFailures {
		entry.lockedUntil = now.Add(l.lockFor)
		entry.failures = 0
	}
	if len(l.entries) > 10000 {
		l.pruneLocked(now)
	}
}

// Reset forgets the failures recorded for key, e.g. after a successful login.
func (l *AttemptLimiter) Reset(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *AttemptLimiter) pruneLocked(now time.Time) {
	for key, entry := range l.entries {
		if now.Sub(entry.lastFailure) >= l.window && !now.Before(entry.lockedUntil) {
			delete(l.entries, key)
		}
	}
}
