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

const (
	body   = "the clinic moved my appointment to thursday"
	number = "15557654321"
)

var deviceSecret = []byte("identity-key-material-0123456789")

// fakeSession behaves like a provider session: pairs, stores a key in its
// vault, links, receives a message, sends.
type fakeSession struct {
	vault *sealed.Vault
	rep   Reporter

	mu       sync.Mutex
	st       Status
	runErr   chan error
	sent     []string
	loggedIn bool
	panicky  bool
}

func (f *fakeSession) Run(ctx context.Context) error {
	if f.panicky {
		f.panicky = false
		panic("library exploded with " + body)
	}
	if _, err := f.vault.Get(ctx, "device", "self"); errors.Is(err, sealed.ErrNotFound) {
		f.set(Status{State: StatePairing, Challenge: &Challenge{Kind: "qr", Data: "2@qrpayload"}})
	} else {
		f.set(Status{State: StateLinked, ExternalAccountID: number})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-f.runErr:
		return err
	}
}

func (f *fakeSession) set(s Status) {
	f.mu.Lock()
	f.st = s
	f.mu.Unlock()
	f.rep.Status(s)
}

func (f *fakeSession) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st
}

// scan is the phone scanning the QR.
func (f *fakeSession) scan(ctx context.Context) {
	_ = f.vault.Put(ctx, "device", "self", deviceSecret)
	f.set(Status{State: StateLinked, ExternalAccountID: number, DisplayName: "Emil"})
}

func (f *fakeSession) SubmitCode(context.Context, string, string) error { return ErrWrongState }
func (f *fakeSession) Send(_ context.Context, chat, text string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, chat+":"+text)
	return "msg-1", nil
}
func (f *fakeSession) Logout(context.Context) error { f.loggedIn = false; return nil }

type recSink struct {
	mu       sync.Mutex
	msgs     []Inbound
	statuses []Status
}

func (s *recSink) Message(_ context.Context, _, _ string, m Inbound) error {
	s.mu.Lock()
	s.msgs = append(s.msgs, m)
	s.mu.Unlock()
	return nil
}
func (s *recSink) Status(_ context.Context, _, _ string, st Status) error {
	s.mu.Lock()
	s.statuses = append(s.statuses, st)
	s.mu.Unlock()
	return nil
}
func (s *recSink) last() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.statuses) == 0 {
		return Status{}
	}
	return s.statuses[len(s.statuses)-1]
}

type harness struct {
	root    sealed.RootKey
	backend *sealed.MemoryBackend
	logs    *bytes.Buffer
	sink    *recSink
	mgr     *Manager
	mu      sync.Mutex
	made    map[string]*fakeSession
	panicky bool
}

func newHarness(t *testing.T, backend *sealed.MemoryBackend, root *sealed.RootKey) *harness {
	t.Helper()
	h := &harness{backend: backend, logs: &bytes.Buffer{}, sink: &recSink{}, made: map[string]*fakeSession{}}
	if root == nil {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		k, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
		h.root = k
	} else {
		h.root = *root
	}
	factory := func(connID string, v *sealed.Vault, rep Reporter, _ StartOptions) (Session, error) {
		s := &fakeSession{vault: v, rep: rep, runErr: make(chan error, 1), panicky: h.panicky}
		h.mu.Lock()
		h.made[connID] = s
		h.mu.Unlock()
		return s, nil
	}
	h.mgr = NewManager(sealed.NewKeyring(h.root, backend), map[string]Factory{"whatsapp": factory},
		h.sink, ratelimit.New(nil), logsafe.New(h.logs))
	h.mgr.BackoffMin = 5 * time.Millisecond
	h.mgr.BackoffMax = 20 * time.Millisecond
	t.Cleanup(h.mgr.Shutdown)
	return h
}

func (h *harness) session(id string) *fakeSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.made[id]
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestConnectShowsTheChallengeThenLinks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	st, err := h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "qr"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Challenge == nil || st.Challenge.Data != "2@qrpayload" {
		t.Fatalf("expected the QR in the connect answer, got %+v", st)
	}
	h.session("c1").scan(ctx)
	c, _ := h.backend.GetConnection(ctx, "c1")
	if c.State != StateLinked {
		t.Fatalf("linked state not persisted: %q", c.State)
	}
}

func TestSendNeedsAPressAndAHumanPace(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	s := h.session("c1")
	s.scan(ctx)
	if _, err := h.mgr.Send(ctx, "c1", "chat", "hi", false); !errors.Is(err, ErrNotPressed) {
		t.Fatalf("an unpressed send must be refused, got %v", err)
	}
	if len(s.sent) != 0 {
		t.Fatal("an unpressed send reached the provider")
	}
	s.rep.Message(Inbound{ChatID: "chat", Direction: "inbound", Body: body})
	for i := 0; i < 6; i++ {
		if _, err := h.mgr.Send(ctx, "c1", "chat", "hi", true); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, err := h.mgr.Send(ctx, "c1", "chat", "hi", true); !errors.Is(err, ratelimit.ErrPerMinute) {
		t.Fatalf("a seventh send in a minute must be refused, got %v", err)
	}
}

func TestRevokeDestroysKeysAndSession(t *testing.T) {
	ctx := context.Background()
	b := sealed.NewMemoryBackend()
	h := newHarness(t, b, nil)
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	h.session("c1").scan(ctx)
	if err := h.mgr.Revoke(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if len(b.Dump()) != 0 {
		t.Fatal("revoke left sealed bytes behind")
	}
	if _, err := h.mgr.Status("c1"); !errors.Is(err, ErrUnknownConnection) {
		t.Fatalf("a revoked connection is still live: %v", err)
	}
	if _, err := h.session("c1").vault.Get(ctx, "device", "self"); !errors.Is(err, sealed.ErrDestroyed) {
		t.Fatalf("the session's vault still opens after revoke: %v", err)
	}
}

func TestUnlinkedOnThePhoneDestroysKeys(t *testing.T) {
	ctx := context.Background()
	b := sealed.NewMemoryBackend()
	h := newHarness(t, b, nil)
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	h.session("c1").scan(ctx)
	h.session("c1").runErr <- ErrLoggedOut
	eventually(t, "the logged-out status", func() bool { return h.sink.last().State == StateLoggedOut })
	eventually(t, "the keys to go", func() bool { return len(b.Dump()) == 0 })
}

func TestAPanicIsRestartedNotFatal(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	h.panicky = true
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	eventually(t, "the restart after a panic", func() bool {
		st, err := h.mgr.Status("c1")
		return err == nil && st.Challenge != nil
	})
	if h.mgr.Health()["events.panic"] != 1 {
		t.Fatalf("panic not counted: %v", h.mgr.Health())
	}
}

// A deploy: the old process stops without logging out, a new process with
// the same root key and database resumes the linked session; a connection
// that was still pairing is destroyed rather than resumed.
func TestDeploySurvival(t *testing.T) {
	ctx := context.Background()
	b := sealed.NewMemoryBackend()
	h := newHarness(t, b, nil)
	_, _ = h.mgr.Connect(ctx, "linked", "whatsapp", StartOptions{})
	h.session("linked").scan(ctx)
	_, _ = h.mgr.Connect(ctx, "half", "whatsapp", StartOptions{})
	h.mgr.Shutdown()

	root := h.root
	h2 := newHarness(t, b, &root)
	if err := h2.mgr.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the resumed session to be linked", func() bool {
		st, err := h2.mgr.Status("linked")
		return err == nil && st.State == StateLinked
	})
	if _, err := b.GetConnection(ctx, "half"); !errors.Is(err, sealed.ErrNotFound) {
		t.Fatalf("a half-paired connection was kept across a deploy: %v", err)
	}
}

func TestPhoneOfflineWarnsOnceAtTwelveDays(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	s := h.session("c1")
	eventually(t, "pairing", func() bool { return s.Status().Challenge != nil })
	now := time.Unix(1_800_000_000, 0)
	h.mgr.now = func() time.Time { return now }
	s.set(Status{State: StateLinked, PhoneLastSeen: now.Add(-11 * 24 * time.Hour)})
	h.mgr.CheckPhones(ctx)
	if h.sink.last().Warning != "" {
		t.Fatal("warned at 11 days")
	}
	s.set(Status{State: StateLinked, PhoneLastSeen: now.Add(-12*24*time.Hour - time.Minute)})
	h.mgr.CheckPhones(ctx)
	if h.sink.last().Warning != "phone_offline" {
		t.Fatalf("no warning at 12 days: %+v", h.sink.last())
	}
	n := len(h.sink.statuses)
	h.mgr.CheckPhones(ctx)
	if len(h.sink.statuses) != n {
		t.Fatal("warned twice")
	}
}

// Every path above, through the real logger: the key, the message body and
// the phone number never reach a log line.
func TestNothingSecretReachesTheLog(t *testing.T) {
	ctx := context.Background()
	b := sealed.NewMemoryBackend()
	h := newHarness(t, b, nil)
	h.panicky = true
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{Phone: number})
	eventually(t, "restart", func() bool { st, _ := h.mgr.Status("c1"); return st.Challenge != nil })
	s := h.session("c1")
	s.scan(ctx)
	s.rep.Message(Inbound{ChatID: number + "@s.whatsapp.net", Direction: "inbound", Body: body, SenderName: "Dr Smith"})
	_, _ = h.mgr.Send(ctx, "c1", number+"@s.whatsapp.net", body, false)
	_, _ = h.mgr.Send(ctx, "c1", number+"@s.whatsapp.net", body, true)
	s.runErr <- errors.New("socket closed while sending " + body + " to " + number)
	eventually(t, "the restart log", func() bool { return strings.Contains(h.logs.String(), "restarting") })
	h.mgr.Shutdown()
	_ = h.mgr.Resume(ctx)
	_ = h.mgr.Revoke(ctx, "c1")

	out := h.logs.String()
	if out == "" {
		t.Fatal("nothing was logged, so this test proved nothing")
	}
	for _, needle := range []string{
		body, number, "Dr Smith", string(deviceSecret),
		base64.StdEncoding.EncodeToString(deviceSecret), "2@qrpayload",
	} {
		if strings.Contains(out, needle) {
			t.Fatalf("%q reached the log:\n%s", needle, out)
		}
	}
}

// The QR is a pairing secret: it is fetched by the person's own request and
// never pushed to the brain in a status event.
func TestTheQRIsNeverPushed(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	st, _ := h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{})
	if st.Challenge == nil || st.Challenge.Data == "" {
		t.Fatal("the connect answer must carry the QR")
	}
	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()
	if len(h.sink.statuses) == 0 {
		t.Fatal("no status was pushed, so this proved nothing")
	}
	for _, s := range h.sink.statuses {
		if s.Challenge != nil && s.Challenge.Data != "" {
			t.Fatalf("a status event carried the QR: %+v", s.Challenge)
		}
	}
}
