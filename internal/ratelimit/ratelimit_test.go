package ratelimit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestPerMinute(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	l.NoteInbound("c", "whatsapp", "chat")
	for i := 0; i < 6; i++ {
		if err := l.Allow("c", "whatsapp", "chat"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := l.Allow("c", "whatsapp", "chat"); !errors.Is(err, ErrPerMinute) {
		t.Fatalf("7th send in a minute: %v", err)
	}
	c.t = c.t.Add(61 * time.Second)
	if err := l.Allow("c", "whatsapp", "chat"); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

func TestFirstContactsAreCapped(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	for i := 0; i < 5; i++ {
		c.t = c.t.Add(time.Minute)
		if err := l.Allow("c", "whatsapp", string(rune('a'+i))); err != nil {
			t.Fatalf("first contact %d: %v", i, err)
		}
	}
	c.t = c.t.Add(time.Minute)
	if err := l.Allow("c", "whatsapp", "zzz"); !errors.Is(err, ErrFirstContact) {
		t.Fatalf("6th stranger in a day must be refused, got %v", err)
	}
	// A reply to somebody who wrote first is still fine.
	l.NoteInbound("c", "whatsapp", "friend")
	if err := l.Allow("c", "whatsapp", "friend"); err != nil {
		t.Fatalf("reply to a known chat: %v", err)
	}
}

func TestRefusalTakesNothing(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	for i := 0; i < 5; i++ {
		_ = l.Allow("c", "whatsapp", string(rune('a'+i)))
		c.t = c.t.Add(time.Minute)
	}
	for i := 0; i < 50; i++ {
		_ = l.Allow("c", "whatsapp", "stranger")
	}
	l.NoteInbound("c", "whatsapp", "friend")
	if err := l.Allow("c", "whatsapp", "friend"); err != nil {
		t.Fatalf("refused sends consumed the allowance: %v", err)
	}
}

func TestConnectionsAreSeparate(t *testing.T) {
	l := New(nil)
	for i := 0; i < 6; i++ {
		l.NoteInbound("a", "whatsapp", "x")
		_ = l.Allow("a", "whatsapp", "x")
	}
	l.NoteInbound("b", "whatsapp", "x")
	if err := l.Allow("b", "whatsapp", "x"); err != nil {
		t.Fatalf("one connection's pace limited another: %v", err)
	}
}

// One number, many requests: the sixth in an hour is refused with the wait
// until the first falls out, another number is unaffected, and the hour
// passing frees it again. Spaces and a + do not make it a different number.
func TestAPhoneNumberIsSentAtMostFiveCodesAnHour(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := NewPairLimiter(func() time.Time { return now })
	for i := 0; i < DefaultPairsPerHour; i++ {
		if _, ok := p.Allow("+1 555 765 4321"); !ok {
			t.Fatalf("request %d refused", i+1)
		}
		now = now.Add(time.Minute)
	}
	wait, ok := p.Allow("15557654321")
	if ok {
		t.Fatal("a sixth code in an hour for one number was allowed")
	}
	if wait != 55*time.Minute {
		t.Fatalf("the wait should run to when the first request is an hour old, got %v", wait)
	}
	if _, ok := p.Allow("+44 20 7946 0000"); !ok {
		t.Fatal("another number was refused because of the first")
	}
	now = now.Add(wait)
	if _, ok := p.Allow("15557654321"); !ok {
		t.Fatal("still refused after the hour")
	}
}

// The limiter never holds the number itself.
func TestThePairLimiterDoesNotKeepTheNumber(t *testing.T) {
	p := NewPairLimiter(nil)
	p.Allow("+15557654321")
	for k := range p.hits {
		if strings.Contains(k, "5557654321") {
			t.Fatalf("the number is a map key: %q", k)
		}
	}
	if len(p.hits) != 1 {
		t.Fatalf("expected one counter, got %d", len(p.hits))
	}
}
