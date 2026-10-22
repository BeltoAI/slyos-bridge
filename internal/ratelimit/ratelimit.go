// Package ratelimit holds every connection to a human pace. ADR 0093.
//
// WHY THE BRIDGE ENFORCES THIS AND NOT ONLY THE BRAIN: the person whose number
// is suspended is the customer. WhatsApp's enforcement is behavioural, and the
// behaviour that gets numbers banned is volume — many sends in a burst, and
// many messages to people who never wrote first. The brain already refuses an
// unpressed send; this is the second wall, in the one process that actually
// talks to WhatsApp, so a brain bug cannot turn into a burst.
//
// Three limits per connection, all in memory and all deliberately below what a
// fast human typist does:
//
//   - PerMinute sends in any rolling minute;
//   - PerDay sends in any rolling 24 hours;
//   - FirstContactsPerDay sends to a chat that has never written to this
//     account through the bridge — the "messaging non-contacts in bulk"
//     pattern, refused after a handful.
//
// In memory means a deploy resets the counters. That is acceptable for a pace
// limit (a deploy takes longer than a minute) and is stated in the ADR rather
// than discovered.
package ratelimit

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrPerMinute    = errors.New("ratelimit: too many sends this minute")
	ErrPerDay       = errors.New("ratelimit: too many sends today")
	ErrFirstContact = errors.New("ratelimit: too many first messages to new people today")
)

type Limits struct {
	PerMinute           int
	PerDay              int
	FirstContactsPerDay int
}

// Defaults by channel. WhatsApp is the strictest because it is the one whose
// terms forbid the client and whose enforcement falls on the customer.
var Defaults = map[string]Limits{
	"whatsapp":          {PerMinute: 6, PerDay: 200, FirstContactsPerDay: 5},
	"telegram_personal": {PerMinute: 10, PerDay: 300, FirstContactsPerDay: 10},
	"sms_gmessages":     {PerMinute: 6, PerDay: 200, FirstContactsPerDay: 5},
	// Signal flags bursts from new linked devices as spam and answers with a
	// captcha the bridge cannot solve, so it gets WhatsApp's pace.
	"signal_personal": {PerMinute: 6, PerDay: 200, FirstContactsPerDay: 5},
}

type Limiter struct {
	now func() time.Time

	mu    sync.Mutex
	conns map[string]*state
}

type state struct {
	limits Limits
	sends  []time.Time
	firsts []time.Time
	known  map[string]bool // chat ids that have written to this account
}

func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{now: now, conns: map[string]*state{}}
}

func (l *Limiter) get(conn, kind string) *state {
	s, ok := l.conns[conn]
	if !ok {
		lim, ok := Defaults[kind]
		if !ok {
			// An unknown kind gets the strictest limits rather than none.
			lim = Defaults["whatsapp"]
		}
		s = &state{limits: lim, known: map[string]bool{}}
		l.conns[conn] = s
	}
	return s
}

// NoteInbound records that a chat wrote to the account, which makes a reply
// to it an ordinary reply rather than a first contact.
func (l *Limiter) NoteInbound(conn, kind, chat string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.get(conn, kind).known[chat] = true
}

// Allow takes one send if every limit has room, and takes nothing if any is
// full: a refused send must not use up the allowance it was refused for.
func (l *Limiter) Allow(conn, kind, chat string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.get(conn, kind)
	now := l.now()
	s.sends = trim(s.sends, now.Add(-24*time.Hour))
	s.firsts = trim(s.firsts, now.Add(-24*time.Hour))
	if count(s.sends, now.Add(-time.Minute)) >= s.limits.PerMinute {
		return ErrPerMinute
	}
	if len(s.sends) >= s.limits.PerDay {
		return ErrPerDay
	}
	first := !s.known[chat]
	if first && len(s.firsts) >= s.limits.FirstContactsPerDay {
		return ErrFirstContact
	}
	s.sends = append(s.sends, now)
	if first {
		s.firsts = append(s.firsts, now)
	}
	return nil
}

// Forget drops a connection's counters on revoke.
func (l *Limiter) Forget(conn string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, conn)
}

func trim(ts []time.Time, after time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(after) {
		i++
	}
	return ts[i:]
}

func count(ts []time.Time, after time.Time) int {
	n := 0
	for _, t := range ts {
		if t.After(after) {
			n++
		}
	}
	return n
}
