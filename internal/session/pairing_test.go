package session

// ── A LINK BY PHONE NUMBER, AS THE MANAGER RUNS IT ────────────────────────
//
// Phone-only linking (ADR 0093 addendum): a WhatsApp pairing code, or a
// Telegram login code. Three things the manager has to get right that the QR
// flow never needed:
//
//   1. A refusal ENDS the attempt, with its reason readable by the next poll
//      — "WhatsApp did not accept that number", not a 404 called "expired".
//   2. A code link is NEVER RETRIED BY ITSELF. Every retry is another code
//      sent to the person's phone and the one on their screen made worthless.
//   3. A typed code is answered on the press that sent it: SubmitCode waits
//      for Telegram's answer, including "that code was wrong" — which is the
//      same state as before, so it is told apart by the status's sequence.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

// scripted is a session whose Run does what the test says: set a status,
// then end with the given error (or wait for codes).
type scripted struct {
	rep   Reporter
	vault *sealed.Vault
	runs  *atomic.Int64

	first  *Status // set at the start of Run, if any
	end    error   // Run's return, after `first`
	onCode func(string) (Status, error)
	codes  chan string
	mu     sync.Mutex
	st     Status
}

func (s *scripted) set(st Status) {
	s.mu.Lock()
	st.Seq = s.st.Seq + 1
	s.st = st
	s.mu.Unlock()
	s.rep.Status(st)
}

func (s *scripted) Run(ctx context.Context) error {
	s.runs.Add(1)
	_ = s.vault.Put(ctx, "device", "half", []byte("half-made link key"))
	if s.first != nil {
		s.set(*s.first)
	}
	if s.end != nil {
		return s.end
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case c := <-s.codes:
			// The provider takes a moment to answer.
			time.Sleep(60 * time.Millisecond)
			st, err := s.onCode(c)
			if err != nil {
				return err
			}
			s.set(st)
		}
	}
}

func (s *scripted) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *scripted) SubmitCode(_ context.Context, code, _ string) error {
	if s.Status().State != StateAwaitingCode {
		return ErrWrongState
	}
	s.codes <- code
	return nil
}
func (s *scripted) Send(context.Context, string, string) (string, error) { return "", ErrNotLinked }
func (s *scripted) Logout(context.Context) error                         { return nil }

type pairHarness struct {
	mgr     *Manager
	backend *sealed.MemoryBackend
	sink    *recSink
	runs    *atomic.Int64
	last    *scripted
}

func newPairHarness(t *testing.T, build func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted) *pairHarness {
	t.Helper()
	raw := make32()
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	h := &pairHarness{backend: sealed.NewMemoryBackend(), sink: &recSink{}, runs: &atomic.Int64{}}
	var mu sync.Mutex
	factory := func(_ string, v *sealed.Vault, rep Reporter, _ StartOptions) (Session, error) {
		s := build(rep, v, h.runs)
		mu.Lock()
		h.last = s
		mu.Unlock()
		return s, nil
	}
	h.mgr = NewManager(sealed.NewKeyring(root, h.backend), map[string]Factory{"whatsapp": factory},
		h.sink, ratelimit.New(nil), logsafe.New(&discard{}))
	h.mgr.BackoffMin = 5 * time.Millisecond
	h.mgr.BackoffMax = 10 * time.Millisecond
	t.Cleanup(h.mgr.Shutdown)
	return h
}

func make32() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// 1. WhatsApp refused the number. Connect answers with that, at once, the
// keys of the half-made link are gone, and the next poll still says it.
func TestARefusedNumberIsTheAnswerNotAWaitAndA404(t *testing.T) {
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs, end: &PairingError{Reason: ReasonBadPhone}}
	})
	start := time.Now()
	st, err := h.mgr.Connect(context.Background(), "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Connect waited %v for a refusal that was immediate", took)
	}
	if st.State != StateFailed || st.Reason != ReasonBadPhone {
		t.Fatalf("the answer should be the refusal: %+v", st)
	}
	again, err := h.mgr.Status("c1")
	if err != nil || again.State != StateFailed || again.Reason != ReasonBadPhone {
		t.Fatalf("the next poll lost the reason: %+v %v", again, err)
	}
	if h.sink.last().Reason != ReasonBadPhone {
		t.Fatalf("the brain was not told why: %+v", h.sink.last())
	}
	if len(h.backend.Dump()) != 0 {
		t.Fatal("a refused link kept its keys")
	}
	time.Sleep(50 * time.Millisecond) // several backoffs
	if n := h.runs.Load(); n != 1 {
		t.Fatalf("a refusal was retried: %d runs", n)
	}
}

// Telegram's flood wait travels to the brain in whole seconds.
func TestAFloodWaitSaysHowLong(t *testing.T) {
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs,
			end: &PairingError{Reason: ReasonRateLimited, RetryAfter: 299500 * time.Millisecond}}
	})
	st, _ := h.mgr.Connect(context.Background(), "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	if st.Reason != ReasonRateLimited || st.RetryAfterSeconds != 300 {
		t.Fatalf("want rate_limited, 300 s; got %+v", st)
	}
}

// 2. Anything else going wrong before a code link is made ends it too — once
// — where the same failure on a QR link is retried by the watchdog.
func TestACodeLinkIsNeverRetriedByItself(t *testing.T) {
	boom := errors.New("socket reset")
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs,
			first: &Status{State: StatePairing, Challenge: &Challenge{Kind: "pairing_code", Data: "ABCD-EFGH"}},
			end:   boom}
	})
	_, _ = h.mgr.Connect(context.Background(), "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	eventually(t, "the attempt to end", func() bool {
		st, err := h.mgr.Status("c1")
		return err == nil && st.State == StateFailed
	})
	time.Sleep(60 * time.Millisecond)
	if n := h.runs.Load(); n != 1 {
		t.Fatalf("a code link was retried %d times: each retry is a new code on somebody's phone", n-1)
	}
	if st, _ := h.mgr.Status("c1"); st.Reason != ReasonPairingFailed {
		t.Fatalf("reason: %+v", st)
	}

	q := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs,
			first: &Status{State: StatePairing, Challenge: &Challenge{Kind: "qr", Data: "2@qr"}},
			end:   boom}
	})
	_, _ = q.mgr.Connect(context.Background(), "c2", "whatsapp", StartOptions{Method: "qr"})
	eventually(t, "the QR link to be retried", func() bool { return q.runs.Load() >= 3 })
}

// 3. A typed code is answered on the press that sent it — the wrong-code
// answer included, which is the same state as before.
func TestATypedCodeIsAnsweredOnThePressThatSentIt(t *testing.T) {
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs, codes: make(chan string, 1),
			first: &Status{State: StateAwaitingCode, Challenge: &Challenge{Kind: "phone_code", Via: "app"}},
			onCode: func(c string) (Status, error) {
				if c == "22222" {
					return Status{State: StateLinked, ExternalAccountID: "200"}, nil
				}
				return Status{State: StateAwaitingCode, Reason: ReasonWrongCode,
					Challenge: &Challenge{Kind: "phone_code", Via: "app"}}, nil
			}}
	})
	ctx := context.Background()
	st, _ := h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	if st.State != StateAwaitingCode {
		t.Fatalf("connect: %+v", st)
	}
	st, err := h.mgr.SubmitCode(ctx, "c1", "11111", "")
	if err != nil || st.State != StateAwaitingCode || st.Reason != ReasonWrongCode {
		t.Fatalf("a wrong code must come back as wrong on the same press: %+v %v", st, err)
	}
	st, err = h.mgr.SubmitCode(ctx, "c1", "22222", "")
	if err != nil || st.State != StateLinked {
		t.Fatalf("the right code must come back linked on the same press: %+v %v", st, err)
	}
}

// A code typed into an attempt that has ended is the end, not a hang.
func TestACodeForAnAttemptThatEndsGetsTheEnding(t *testing.T) {
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs, codes: make(chan string, 1),
			first: &Status{State: StateAwaitingCode, Challenge: &Challenge{Kind: "phone_code"}},
			onCode: func(string) (Status, error) {
				return Status{}, &PairingError{Reason: ReasonCodeExpired}
			}}
	})
	ctx := context.Background()
	_, _ = h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	st, _ := h.mgr.SubmitCode(ctx, "c1", "22222", "")
	if st.State != StateFailed || st.Reason != ReasonCodeExpired {
		t.Fatalf("want the ending, got %+v", st)
	}
}

// How it ended is kept for EndedFor, then forgotten; a new attempt clears it.
func TestAnEndingIsReadableForAWhileThenGone(t *testing.T) {
	h := newPairHarness(t, func(rep Reporter, v *sealed.Vault, runs *atomic.Int64) *scripted {
		return &scripted{rep: rep, vault: v, runs: runs, end: &PairingError{Reason: ReasonBadPhone}}
	})
	now := time.Unix(1_800_000_000, 0)
	h.mgr.now = func() time.Time { return now }
	_, _ = h.mgr.Connect(context.Background(), "c1", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	now = now.Add(EndedFor - time.Second)
	if _, err := h.mgr.Status("c1"); err != nil {
		t.Fatalf("forgotten too soon: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := h.mgr.Status("c1"); !errors.Is(err, ErrUnknownConnection) {
		t.Fatalf("kept past EndedFor: %v", err)
	}

	_, _ = h.mgr.Connect(context.Background(), "c2", "whatsapp", StartOptions{Method: "code", Phone: "15557654321"})
	if err := h.mgr.Revoke(context.Background(), "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mgr.Status("c2"); !errors.Is(err, ErrUnknownConnection) {
		t.Fatalf("a revoked connection still reads as its old ending: %v", err)
	}
}
