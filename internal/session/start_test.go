package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

// starterSession is a linked session that can start chats: a directory of who
// is on the provider, and a record of every call in order.
type starterSession struct {
	mu        sync.Mutex
	directory map[string]string // to -> chat id
	known     map[string]bool
	sendErr   error
	calls     []string
}

func (s *starterSession) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (s *starterSession) Status() Status {
	return Status{State: StateLinked, ExternalAccountID: number}
}
func (s *starterSession) SubmitCode(context.Context, string, string) error { return ErrWrongState }
func (s *starterSession) Send(context.Context, string, string) (string, error) {
	return "m", nil
}
func (s *starterSession) Logout(context.Context) error { return nil }

func (s *starterSession) note(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *starterSession) Resolve(_ context.Context, to string) (Target, error) {
	s.note("resolve")
	s.mu.Lock()
	chat, ok := s.directory[to]
	known := s.known[chat]
	s.mu.Unlock()
	if !ok {
		return Target{}, &RecipientError{Reason: RecipientNotOnWhatsApp}
	}
	return Target{ChatID: chat, RecipientID: strings.TrimSuffix(chat, "@lid"), Known: known,
		Release: func(context.Context) { s.note("release") }}, nil
}

func (s *starterSession) SendTo(_ context.Context, t Target, text string) (string, error) {
	s.note("send " + t.ChatID + " " + text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return "", s.sendErr
	}
	return "msg-" + t.ChatID, nil
}

func (s *starterSession) callCount(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func startHarness(t *testing.T) (*Manager, *starterSession, *clock, *bytes.Buffer) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	ss := &starterSession{directory: map[string]string{}, known: map[string]bool{}}
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	logs := &bytes.Buffer{}
	mgr := NewManager(sealed.NewKeyring(root, sealed.NewMemoryBackend()), map[string]Factory{
		"whatsapp_linked": func(string, *sealed.Vault, Reporter, StartOptions) (Session, error) { return ss, nil },
	}, &recSink{}, ratelimit.New(c.now), logsafe.New(logs))
	t.Cleanup(mgr.Shutdown)
	if _, err := mgr.Connect(context.Background(), "c1", "whatsapp_linked", StartOptions{Method: "qr"}); err != nil {
		t.Fatal(err)
	}
	return mgr, ss, c, logs
}

// A start nobody pressed reaches nothing — not even the lookup.
func TestAStartNeedsAPress(t *testing.T) {
	mgr, ss, _, _ := startHarness(t)
	ss.directory["+15557654321"] = "8800@lid"
	if _, err := mgr.Start(context.Background(), "c1", "+15557654321", "hi", false); !errors.Is(err, ErrNotPressed) {
		t.Fatalf("err = %v, want ErrNotPressed", err)
	}
	if len(ss.calls) != 0 {
		t.Fatalf("an unpressed start reached the provider: %v", ss.calls)
	}
}

// Ten brand-new chats a day. The eleventh is refused with when it frees up,
// and BEFORE the provider is asked anything: a refused start looks nobody up.
func TestTheDailyCapIsAskedBeforeTheProvider(t *testing.T) {
	ctx := context.Background()
	mgr, ss, c, _ := startHarness(t)
	for i := 0; i < ratelimit.StartsPerDay; i++ {
		to := "+155576543" + string(rune('1'+i/10)) + string(rune('0'+i%10))
		ss.directory[to] = to[1:] + "@lid"
		got, err := mgr.Start(ctx, "c1", to, "hello", true)
		if err != nil {
			t.Fatalf("start %d: %v", i+1, err)
		}
		if !got.New || got.ChatID != to[1:]+"@lid" || got.MessageID != "msg-"+to[1:]+"@lid" {
			t.Fatalf("start %d answered %+v", i+1, got)
		}
		c.add(2 * time.Minute)
	}
	resolves := ss.callCount("resolve")
	ss.directory["+15550000099"] = "99@lid"
	_, err := mgr.Start(ctx, "c1", "+15550000099", "one too many", true)
	var limited *ratelimit.StartError
	if !errors.As(err, &limited) || !errors.Is(err, ratelimit.ErrStartDaily) {
		t.Fatalf("the 11th start: err = %v, want the daily cap", err)
	}
	if want := 24*time.Hour - 20*time.Minute; limited.RetryAfter != want {
		t.Fatalf("frees up in %s, want %s", limited.RetryAfter, want)
	}
	if ss.callCount("resolve") != resolves || ss.callCount("send 99@lid") != 0 {
		t.Fatal("the provider was asked about a start the cap refused")
	}
}

// A minute between two starts; the second is refused with how long is left.
func TestStartsAreAMinuteApart(t *testing.T) {
	ctx := context.Background()
	mgr, ss, c, _ := startHarness(t)
	ss.directory["+15557654321"] = "1@lid"
	ss.directory["+15557654322"] = "2@lid"
	if _, err := mgr.Start(ctx, "c1", "+15557654321", "hi", true); err != nil {
		t.Fatal(err)
	}
	c.add(15 * time.Second)
	_, err := mgr.Start(ctx, "c1", "+15557654322", "hi", true)
	var limited *ratelimit.StartError
	if !errors.As(err, &limited) || !errors.Is(err, ratelimit.ErrStartSpacing) || limited.RetryAfter != 45*time.Second {
		t.Fatalf("err = %v (%+v), want spacing with 45s left", err, limited)
	}
	if ss.callCount("send 2@lid") != 0 {
		t.Fatal("sent inside the minute")
	}
	c.add(45 * time.Second)
	if _, err := mgr.Start(ctx, "c1", "+15557654322", "hi", true); err != nil {
		t.Fatalf("a minute later: %v", err)
	}
}

// Not on WhatsApp: refused in its own reason, nothing sent, and nothing used
// up — the next start needs no minute's wait.
func TestARecipientNotThereTakesNothing(t *testing.T) {
	ctx := context.Background()
	mgr, ss, _, logs := startHarness(t)
	_, err := mgr.Start(ctx, "c1", "+15550001111", "hi", true)
	var refused *RecipientError
	if !errors.As(err, &refused) || refused.Reason != RecipientNotOnWhatsApp {
		t.Fatalf("err = %v, want not_on_whatsapp", err)
	}
	if ss.callCount("send") != 0 {
		t.Fatal("sent to a number that is not on WhatsApp")
	}
	ss.directory["+15557654321"] = "1@lid"
	if _, err := mgr.Start(ctx, "c1", "+15557654321", "hi", true); err != nil {
		t.Fatalf("the refused start used up the spacing: %v", err)
	}
	if strings.Contains(logs.String(), "15550001111") || strings.Contains(logs.String(), "15557654321") {
		t.Fatalf("a number reached the log: %s", logs.String())
	}
}

// A message the provider refused started nothing: given back, and whatever
// resolving did is undone either way — after the send, never before it.
func TestAFailedFirstMessageIsGivenBack(t *testing.T) {
	ctx := context.Background()
	mgr, ss, _, _ := startHarness(t)
	ss.directory["+15557654321"] = "1@lid"
	ss.sendErr = errors.New("provider said no")
	if _, err := mgr.Start(ctx, "c1", "+15557654321", "hi", true); err == nil {
		t.Fatal("a refused message reported as started")
	}
	ss.mu.Lock()
	ss.sendErr = nil
	order := strings.Join(ss.calls, ",")
	ss.mu.Unlock()
	if order != "resolve,send 1@lid hi,release" {
		t.Fatalf("calls = %s", order)
	}
	if _, err := mgr.Start(ctx, "c1", "+15557654321", "hi", true); err != nil {
		t.Fatalf("the failed start was counted: %v", err)
	}
	if ss.callCount("release") != 2 {
		t.Fatal("resolving was not undone after the start")
	}
}

// Somebody this account already has a chat with is not a brand-new chat: an
// ordinary send, not counted, and the next start needs no minute's wait.
func TestAKnownChatIsNotANewOne(t *testing.T) {
	ctx := context.Background()
	mgr, ss, _, _ := startHarness(t)
	ss.directory["+15557654321"] = "1@lid"
	ss.known["1@lid"] = true
	got, err := mgr.Start(ctx, "c1", "+15557654321", "hi", true)
	if err != nil || got.New {
		t.Fatalf("got %+v, %v; want an ordinary send", got, err)
	}
	ss.directory["+15557654322"] = "2@lid"
	if got, err := mgr.Start(ctx, "c1", "+15557654322", "hi", true); err != nil || !got.New {
		t.Fatalf("got %+v, %v; the known chat was counted as a start", got, err)
	}
}

// A kind whose session cannot start chats says so.
func TestAKindThatCannotStartSaysSo(t *testing.T) {
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	ctx := context.Background()
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	h.session("c1").scan(ctx)
	if _, err := h.mgr.Start(ctx, "c1", "+15557654321", "hi", true); !errors.Is(err, ErrCannotStart) {
		t.Fatalf("err = %v, want ErrCannotStart", err)
	}
}
