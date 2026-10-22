package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ── HOW OFTEN ONE PHONE NUMBER CAN BE SENT A CODE ─────────────────────────
//
// A phone-number link is the one request in the bridge that reaches somebody
// ELSE'S device: typing a number makes WhatsApp put a "link a device"
// notification on that phone, and makes Telegram send that account a login
// code. Without a limit, anybody with a SlyOS account could turn the bridge on
// a stranger's phone. ADR 0093, addendum "Phone-only linking".
//
// So, per NUMBER (whichever SlyOS account typed it), at most PerHour code
// requests in any rolling hour. The brain holds its own limit per SlyOS
// account; this one is in the process that actually asks WhatsApp and
// Telegram, and it is the one that covers many accounts typing one number.
//
// THE NUMBER IS NOT A MAP KEY. Each is reduced to an HMAC under a key made
// fresh when the process starts and never written anywhere, so a heap dump of
// the bridge shows counters, not phone numbers. In memory: a deploy resets
// the counts, which is acceptable for an hourly limit and stated in the ADR.
type PairLimiter struct {
	PerHour int

	now  func() time.Time
	key  []byte
	mu   sync.Mutex
	hits map[string][]time.Time
}

// DefaultPairsPerHour: enough for a person who mistypes their number twice
// and lets a code run out once; few enough that a phone is not pestered.
const DefaultPairsPerHour = 5

func NewPairLimiter(now func() time.Time) *PairLimiter {
	if now == nil {
		now = time.Now
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("ratelimit: no randomness for the pair limiter's key")
	}
	return &PairLimiter{PerHour: DefaultPairsPerHour, now: now, key: key, hits: map[string][]time.Time{}}
}

// Allow takes one code request for phone if the hour has room, and says how
// long until it would when it has not. A refused request takes nothing.
func (p *PairLimiter) Allow(phone string) (retryAfter time.Duration, ok bool) {
	id := p.id(phone)
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	hits := trim(p.hits[id], now.Add(-time.Hour))
	if len(hits) >= p.PerHour {
		p.hits[id] = hits
		return hits[0].Add(time.Hour).Sub(now), false
	}
	p.hits[id] = append(hits, now)
	// Forget numbers whose hour is over, so the map does not grow for ever.
	for k, v := range p.hits {
		if len(trim(v, now.Add(-time.Hour))) == 0 {
			delete(p.hits, k)
		}
	}
	return 0, true
}

func (p *PairLimiter) id(phone string) string {
	digits := make([]byte, 0, len(phone))
	for i := 0; i < len(phone); i++ {
		if c := phone[i]; c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}
	m := hmac.New(sha256.New, p.key)
	m.Write(digits)
	return hex.EncodeToString(m.Sum(nil))
}
