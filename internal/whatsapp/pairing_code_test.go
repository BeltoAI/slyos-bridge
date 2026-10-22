package whatsapp

// ── LINKING WITH A CODE, FOR SOMEBODY WHOSE ONLY SCREEN IS THE PHONE ──────
//
// The owner, 2026-10-21: "how would someone who only uses the phone do that?
// theyd need to scan the qr code with their phone that also has whats app".
// They cannot: the camera is on the phone the QR is on. WhatsApp's answer is
// "Link with phone number instead" — the companion asks for an eight-character
// code and the person types it into WhatsApp.
//
// No test may ask WhatsApp's servers for a code: the request names a real
// number and puts a notification on that phone. So the flow is driven through
// `pairer`, the three calls of *whatsmeow.Client it uses, by a fake that
// behaves as whatsmeow documents: a QR channel that offers codes, a socket
// that connects, and PairPhone answering with a code or a refusal.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow"

	"github.com/BeltoAI/slyos-bridge/internal/session"
)

const thePhone = "15557654321"

type fakePairer struct {
	items      chan whatsmeow.QRChannelItem
	connectErr error
	pairErr    error

	mu        sync.Mutex
	pushed    int // QR items the test has put on the channel
	consumed  int // how many of them had been read when PairPhone was asked
	pairCalls int
	phone     string
	notify    bool
	display   string
}

func newFakePairer() *fakePairer {
	return &fakePairer{items: make(chan whatsmeow.QRChannelItem, 8)}
}

func (f *fakePairer) push(item whatsmeow.QRChannelItem) {
	f.mu.Lock()
	f.pushed++
	f.mu.Unlock()
	f.items <- item
}

func (f *fakePairer) GetQRChannel(context.Context) (<-chan whatsmeow.QRChannelItem, error) {
	return f.items, nil
}

func (f *fakePairer) Connect() error { return f.connectErr }

func (f *fakePairer) PairPhone(_ context.Context, phone string, notify bool, _ whatsmeow.PairClientType, display string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pairCalls++
	f.consumed = f.pushed - len(f.items)
	f.phone, f.notify, f.display = phone, notify, display
	if f.pairErr != nil {
		return "", f.pairErr
	}
	return "ABCD-EFGH", nil
}

// statusLog is a Reporter that keeps every status it was given.
type statusLog struct {
	mu  sync.Mutex
	all []session.Status
}

func (l *statusLog) Status(s session.Status) {
	l.mu.Lock()
	l.all = append(l.all, s)
	l.mu.Unlock()
}
func (l *statusLog) Message(session.Inbound) {}
func (l *statusLog) last() session.Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.all) == 0 {
		return session.Status{}
	}
	return l.all[len(l.all)-1]
}

func codeSession(t *testing.T, method string) (*Session, *statusLog) {
	t.Helper()
	_, v, _, _ := setup(t)
	rep := &statusLog{}
	s, err := Factory()("conn-wa", v, rep, session.StartOptions{Method: method, Phone: thePhone})
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Session), rep
}

func firstQR() whatsmeow.QRChannelItem {
	return whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: "2@qr-payload", Timeout: 60 * time.Second}
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The code is asked for once the socket has offered its first QR — not before
// (whatsmeow: "wait for the first item in the channel") — and it is what the
// person sees: the QR is never shown in code mode. It lives 160 seconds from
// that first QR, and the person's phone is told to expect it.
func TestAPairingCodeIsAskedForAfterTheFirstQRAndShownInsteadOfIt(t *testing.T) {
	s, rep := codeSession(t, "code")
	f := newFakePairer()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- s.pair(context.Background(), f) }()

	f.push(firstQR())
	waitUntil(t, "the pairing code", func() bool {
		ch := rep.last().Challenge
		return ch != nil && ch.Kind == "pairing_code"
	})
	st := rep.last()
	if st.State != session.StatePairing || st.Challenge.Data != "ABCD-EFGH" {
		t.Fatalf("the code is not what the person sees: %+v", st)
	}
	life := st.Challenge.ExpiresAt.Sub(start)
	if life < PairingCodeLifetime-2*time.Second || life > PairingCodeLifetime+2*time.Second {
		t.Fatalf("the code should live %v from the first QR, got %v", PairingCodeLifetime, life)
	}
	f.mu.Lock()
	if f.pairCalls != 1 || f.consumed < 1 {
		t.Fatalf("PairPhone must be asked once, after the first QR was read: calls=%d consumed=%d", f.pairCalls, f.consumed)
	}
	if f.phone != thePhone || !f.notify || f.display != "Chrome (Linux)" {
		t.Fatalf("PairPhone was asked with %q notify=%v display=%q", f.phone, f.notify, f.display)
	}
	f.mu.Unlock()

	// WhatsApp goes on offering QRs while the code is up. None reaches the screen.
	f.push(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: "2@second-qr", Timeout: 20 * time.Second})
	f.push(whatsmeow.QRChannelSuccess)
	if err := <-done; err != nil {
		t.Fatalf("a typed code that linked must end pairing cleanly, got %v", err)
	}
	rep.mu.Lock()
	defer rep.mu.Unlock()
	for _, st := range rep.all {
		if st.Challenge != nil && st.Challenge.Kind == "qr" {
			t.Fatalf("a QR was shown to somebody who asked for a code: %+v", st)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pairCalls != 1 {
		t.Fatalf("a second QR asked for a second code (%d calls): the one on screen would stop working", f.pairCalls)
	}
}

// Nobody typed it in time: WhatsApp runs out of QRs and closes the socket.
func TestAPairingCodeNobodyTypedEndsAsExpired(t *testing.T) {
	s, _ := codeSession(t, "code")
	f := newFakePairer()
	f.push(firstQR())
	f.push(whatsmeow.QRChannelTimeout)
	if err := s.pair(context.Background(), f); !errors.Is(err, session.ErrPairingExpired) {
		t.Fatalf("expected ErrPairingExpired, got %v", err)
	}
}

// What WhatsApp refuses becomes the one reason the person reads — and the
// number they typed is in none of them.
func TestWhatsAppsRefusalsOfACodeBecomeReasons(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"too short", whatsmeow.ErrPhoneNumberTooShort, session.ReasonBadPhone},
		{"not international", whatsmeow.ErrPhoneNumberIsNotInternational, session.ReasonBadPhone},
		{"bad request", &whatsmeow.IQError{Code: 400, Text: "bad-request"}, session.ReasonBadPhone},
		{"not acceptable", &whatsmeow.IQError{Code: 406, Text: "not-acceptable"}, session.ReasonBadPhone},
		{"rate overlimit", &whatsmeow.IQError{Code: 429, Text: "rate-overlimit"}, session.ReasonRateLimited},
		{"anything else", errors.New("stream error for " + thePhone), session.ReasonPairingFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := codeSession(t, "code")
			f := newFakePairer()
			f.pairErr = c.err
			f.push(firstQR())
			err := s.pair(context.Background(), f)
			var pe *session.PairingError
			if !errors.As(err, &pe) || pe.Reason != c.want {
				t.Fatalf("want reason %q, got %v", c.want, err)
			}
			if pe.RetryAfter != 0 {
				t.Fatalf("WhatsApp names no wait; none may be invented, got %v", pe.RetryAfter)
			}
			if strings.Contains(err.Error(), thePhone) {
				t.Fatalf("the number reached the error: %v", err)
			}
		})
	}
}

// A socket that will not open: for a QR, the watchdog's retry is right (a new
// QR, nothing sent anywhere). For a code it is not — a retry is another code
// pushed to the person's phone — so it ends as a reason.
func TestACodeLinkThatCannotConnectEndsInsteadOfRetrying(t *testing.T) {
	s, _ := codeSession(t, "code")
	f := newFakePairer()
	f.connectErr = errors.New("dial tcp: i/o timeout")
	var pe *session.PairingError
	if err := s.pair(context.Background(), f); !errors.As(err, &pe) || pe.Reason != session.ReasonPairingFailed {
		t.Fatalf("a code link that cannot connect must end with a reason, got %v", err)
	}

	q, _ := codeSession(t, "qr")
	if err := q.pair(context.Background(), f); err == nil || errors.As(err, &pe) {
		t.Fatalf("a QR link that cannot connect is the watchdog's to retry, got %v", err)
	}
}

// The QR flow is untouched: QRs are shown, refreshed, and no code is asked for.
func TestAQRLinkStillShowsQRsAndNeverAsksForACode(t *testing.T) {
	s, rep := codeSession(t, "qr")
	f := newFakePairer()
	f.push(firstQR())
	f.push(whatsmeow.QRChannelItem{Event: whatsmeow.QRChannelEventCode, Code: "2@second-qr", Timeout: 20 * time.Second})
	f.push(whatsmeow.QRChannelSuccess)
	if err := s.pair(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if f.pairCalls != 0 {
		t.Fatal("a QR link asked WhatsApp for a pairing code")
	}
	if ch := rep.last().Challenge; ch == nil || ch.Kind != "qr" || ch.Data != "2@second-qr" {
		t.Fatalf("the refreshed QR is not on screen: %+v", rep.last())
	}
}
