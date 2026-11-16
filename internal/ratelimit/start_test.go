package ratelimit

import (
	"errors"
	"testing"
	"time"
)

// The owner's numbers, 2026-10-23. The brain holds the same two
// (packages/shared/src/new-chat-limits.ts) and a brain test reads this file
// to keep them equal.
func TestTheOwnersNumbers(t *testing.T) {
	if StartsPerDay != 10 || StartSpacing != 60*time.Second {
		t.Fatalf("StartsPerDay=%d StartSpacing=%s, want 10 and 1m0s", StartsPerDay, StartSpacing)
	}
}

func startErr(t *testing.T, err error, want error) *StartError {
	t.Helper()
	var se *StartError
	if !errors.As(err, &se) || !errors.Is(err, want) {
		t.Fatalf("err = %v, want a StartError wrapping %v", err, want)
	}
	return se
}

// Ten brand-new chats in a day, and the eleventh is refused with when the
// first of the ten drops out of the 24 hours.
func TestTenNewChatsADay(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	first := c.t
	l := New(c.now)
	for i := 0; i < StartsPerDay; i++ {
		if err := l.CanStart("c", "whatsapp_linked"); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		c.t = c.t.Add(2 * time.Minute)
	}
	se := startErr(t, l.CanStart("c", "whatsapp_linked"), ErrStartDaily)
	if want := first.Add(24 * time.Hour).Sub(c.t); se.RetryAfter != want {
		t.Fatalf("frees up in %s, want %s", se.RetryAfter, want)
	}
	if _, err := l.AllowStart("c", "whatsapp_linked"); !errors.Is(err, ErrStartDaily) {
		t.Fatalf("the 11th start was taken: %v", err)
	}
	// Telegram has the same limits.
	for i := 0; i < StartsPerDay; i++ {
		c.t = c.t.Add(time.Minute)
		if _, err := l.AllowStart("t", "telegram_personal"); err != nil {
			t.Fatalf("telegram start %d: %v", i+1, err)
		}
	}
	c.t = c.t.Add(time.Minute)
	startErr(t, l.CanStart("t", "telegram_personal"), ErrStartDaily)
	// The day rolls: the first start drops out and one more is allowed.
	c.t = first.Add(24*time.Hour + time.Second)
	if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
		t.Fatalf("after 24 hours: %v", err)
	}
}

// At least a minute between two starts, and the refusal says how long is left.
func TestAMinuteBetweenStarts(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(20 * time.Second)
	se := startErr(t, l.CanStart("c", "whatsapp_linked"), ErrStartSpacing)
	if se.RetryAfter != 40*time.Second {
		t.Fatalf("frees up in %s, want 40s", se.RetryAfter)
	}
	if _, err := l.AllowStart("c", "whatsapp_linked"); !errors.Is(err, ErrStartSpacing) {
		t.Fatalf("a second start 20 s later was taken: %v", err)
	}
	c.t = c.t.Add(40 * time.Second)
	if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
		t.Fatalf("a minute later: %v", err)
	}
}

// Asking takes nothing; a start the provider refused is given back; and a
// start is not also a "first contact" (the start guard is the one that
// limits it — five firsts a day would otherwise cap ten starts at five).
func TestOnlyAStartThatWentCounts(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	for i := 0; i < 3; i++ {
		if err := l.CanStart("c", "whatsapp_linked"); err != nil {
			t.Fatal(err)
		}
	}
	undo, err := l.AllowStart("c", "whatsapp_linked")
	if err != nil {
		t.Fatal(err)
	}
	undo()
	if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
		t.Fatalf("a refused start still counted: %v", err)
	}
	for i := 1; i < StartsPerDay; i++ {
		c.t = c.t.Add(time.Minute)
		if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
			t.Fatalf("start %d was counted as a first contact: %v", i+1, err)
		}
	}
}

// The send pace still holds for a start.
func TestAStartIsStillASend(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	l.NoteInbound("c", "whatsapp_linked", "chat")
	for i := 0; i < 6; i++ {
		if err := l.Allow("c", "whatsapp_linked", "chat"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.AllowStart("c", "whatsapp_linked"); !errors.Is(err, ErrPerMinute) {
		t.Fatalf("a start past the per-minute pace: %v", err)
	}
	if err := l.CanStart("c", "whatsapp_linked"); err != nil {
		t.Fatalf("the refused start was counted: %v", err)
	}
}

// Disconnecting and linking again is not a way round the daily limit.
func TestForgetKeepsTheDaysStarts(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(c.now)
	for i := 0; i < StartsPerDay; i++ {
		c.t = c.t.Add(time.Minute)
		if _, err := l.AllowStart("c", "whatsapp_linked"); err != nil {
			t.Fatal(err)
		}
	}
	l.Forget("c")
	c.t = c.t.Add(time.Minute)
	startErr(t, l.CanStart("c", "whatsapp_linked"), ErrStartDaily)
	c.t = c.t.Add(25 * time.Hour)
	l.Forget("c")
	if _, ok := l.conns["c"]; ok {
		t.Fatal("a connection with nothing left in its day was kept")
	}
}
