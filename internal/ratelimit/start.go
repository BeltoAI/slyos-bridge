package ratelimit

import (
	"errors"
	"time"
)

// ── BRAND-NEW CHATS: THE BAN-RISK GUARD ────────────────────────────────────
//
// The owner, 2026-10-23: the Brain and the Inbox may message people FIRST on
// his own WhatsApp, Telegram and Signal, not only answer. Writing to strangers
// is exactly the behaviour WhatsApp's enforcement looks for, and the ban falls
// on the customer's own number. So, per connection (one linked account):
//
//   - at most StartsPerDay brand-new chats in any rolling 24 hours, and
//   - at least StartSpacing between two of them.
//
// A start the provider refused (a number not on WhatsApp, a send that failed)
// takes nothing: the undo AllowStart hands back puts it back. A refusal names
// how long until the next start frees up (StartError.RetryAfter), so the
// person reads "in 3 hours 12 minutes", not "try later".
//
// The brain holds the same two numbers (`packages/shared/src/new-chat-limits.ts`)
// and counts them from its own durable record, so a deploy that resets this
// in-memory count does not reset the limit. This is the second wall, in the
// process that talks to WhatsApp, so a brain defect cannot become a burst.
const (
	StartsPerDay = 10
	StartSpacing = 60 * time.Second
)

var (
	ErrStartDaily   = errors.New("ratelimit: as many new chats as allowed in a day")
	ErrStartSpacing = errors.New("ratelimit: a new chat was started less than a minute ago")
)

// StartError is a start refused by the guard, with how long until one frees
// up. It unwraps to ErrStartDaily or ErrStartSpacing.
type StartError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *StartError) Error() string { return e.Err.Error() }
func (e *StartError) Unwrap() error { return e.Err }

// startRefusal is the guard's verdict on s at now, or nil. Under l.mu.
func startRefusal(s *state, now time.Time) error {
	s.starts = trim(s.starts, now.Add(-24*time.Hour))
	if len(s.starts) >= StartsPerDay {
		return &StartError{Err: ErrStartDaily, RetryAfter: s.starts[len(s.starts)-StartsPerDay].Add(24 * time.Hour).Sub(now)}
	}
	if n := len(s.starts); n > 0 {
		if next := s.starts[n-1].Add(StartSpacing); next.After(now) {
			return &StartError{Err: ErrStartSpacing, RetryAfter: next.Sub(now)}
		}
	}
	return nil
}

// CanStart says whether this connection may start a brand-new chat now, and
// takes nothing. Asked before the provider is (a number is looked up on
// WhatsApp only when a start could follow).
func (l *Limiter) CanStart(conn, kind string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return startRefusal(l.get(conn, kind), l.now())
}

// AllowStart takes one brand-new chat AND one send, if the start guard and the
// send pace (PerMinute, PerDay) all have room, and nothing otherwise. The send
// is not counted as a first contact: starting a chat is exactly that, and
// this guard is the one that limits it. undo gives both back, for a start the
// provider then refused.
func (l *Limiter) AllowStart(conn, kind string) (undo func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.get(conn, kind)
	now := l.now()
	if err := startRefusal(s, now); err != nil {
		return nil, err
	}
	s.sends = trim(s.sends, now.Add(-24*time.Hour))
	if count(s.sends, now.Add(-time.Minute)) >= s.limits.PerMinute {
		return nil, ErrPerMinute
	}
	if len(s.sends) >= s.limits.PerDay {
		return nil, ErrPerDay
	}
	s.sends = append(s.sends, now)
	s.starts = append(s.starts, now)
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if s, ok := l.conns[conn]; ok {
			s.sends = without(s.sends, now)
			s.starts = without(s.starts, now)
		}
	}, nil
}

// without removes the last occurrence of t.
func without(ts []time.Time, t time.Time) []time.Time {
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(t) {
			return append(ts[:i:i], ts[i+1:]...)
		}
	}
	return ts
}
