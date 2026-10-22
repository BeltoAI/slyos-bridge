package telegram

// ── TELEGRAM BY PHONE NUMBER, EVERY WAY IT CAN GO ─────────────────────────
//
// For somebody whose only device is the phone: they type their number,
// Telegram puts a login code inside the Telegram app on that phone, and they
// type it into SlyOS. telegram_e2e_test.go walks the happy path over real
// MTProto; this file drives phoneLogin through `authAPI` with a fake, so that
// each refusal Telegram documents is pinned to the sentence it becomes:
//
//   a wrong code        → asked again, same code still good, up to MaxAttempts
//   FLOOD_WAIT_n        → ends, saying how long Telegram asked us to wait
//   no such account     → ends: SlyOS never signs anybody up
//   an expired code     → ends: the person asks for a new one
//   two-step password   → asked once, again only if wrong, and never kept

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	bsession "github.com/BeltoAI/slyos-bridge/internal/session"
)

const (
	flowPhone    = "+15550001111"
	flowCode     = "12345"
	flowPassword = "correct horse battery staple"
)

type fakeAuth struct {
	mu sync.Mutex

	sendErr  error
	sent     tg.AuthSentCodeClass
	signIn   func(code string) error
	password func(attempt int) error

	sendCalls     int
	signInCodes   []string
	passwordCalls int
}

func (f *fakeAuth) SendCode(_ context.Context, phone string, _ auth.SendCodeOptions) (tg.AuthSentCodeClass, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendCalls++
	if phone != flowPhone {
		return nil, errors.New("the flow sent Telegram a different number")
	}
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	if f.sent != nil {
		return f.sent, nil
	}
	return &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeApp{Length: 5}, PhoneCodeHash: "hash"}, nil
}

func (f *fakeAuth) SignIn(_ context.Context, phone, code, hash string) (*tg.AuthAuthorization, error) {
	f.mu.Lock()
	f.signInCodes = append(f.signInCodes, code)
	fn := f.signIn
	f.mu.Unlock()
	if phone != flowPhone || hash != "hash" {
		return nil, errors.New("sign-in without the number and hash SendCode gave")
	}
	if fn != nil {
		if err := fn(code); err != nil {
			return nil, err
		}
	} else if code != flowCode {
		return nil, tgerr.New(400, "PHONE_CODE_INVALID")
	}
	return &tg.AuthAuthorization{}, nil
}

func (f *fakeAuth) PasswordWith(ctx context.Context, hash auth.PasswordHashFunc) (*tg.AuthAuthorization, error) {
	f.mu.Lock()
	f.passwordCalls++
	n := f.passwordCalls
	fn := f.password
	f.mu.Unlock()
	if _, err := hash(ctx, &tg.AccountPassword{}); err != nil && !errors.Is(err, errHashCaptured) {
		return nil, err
	}
	if fn != nil {
		if err := fn(n); err != nil {
			return nil, err
		}
	}
	return &tg.AuthAuthorization{}, nil
}

// passwordHashFor is swapped for one that records the bytes it was given, so
// the test can see both what was used and that it was zeroed afterwards.
var errHashCaptured = errors.New("captured")

type capture struct {
	mu     sync.Mutex
	used   []string // the password as it was when the proof was made
	slices [][]byte // the very slices, read again after the login
}

func capturePasswords(t *testing.T) *capture {
	t.Helper()
	c := &capture{}
	orig := passwordHashFor
	passwordHashFor = func(password []byte) auth.PasswordHashFunc {
		c.mu.Lock()
		c.used = append(c.used, string(password))
		c.slices = append(c.slices, password)
		c.mu.Unlock()
		return func(context.Context, *tg.AccountPassword) (*tg.InputCheckPasswordSRP, error) {
			return nil, errHashCaptured
		}
	}
	t.Cleanup(func() { passwordHashFor = orig })
	return c
}

type flowRec struct {
	mu  sync.Mutex
	all []bsession.Status
	ch  chan bsession.Status
}

func (r *flowRec) Status(s bsession.Status) {
	r.mu.Lock()
	r.all = append(r.all, s)
	r.mu.Unlock()
	select {
	case r.ch <- s:
	default:
	}
}
func (r *flowRec) Message(bsession.Inbound) {}

func newFlow(t *testing.T) (*Session, *flowRec) {
	t.Helper()
	_, vault, _ := newVault(t)
	rec := &flowRec{ch: make(chan bsession.Status, 32)}
	cfg := Config{AppID: 1, AppHash: "x"}
	s, err := Factory(cfg)("conn-tg", vault, rec, bsession.StartOptions{Method: "code", Phone: flowPhone})
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Session), rec
}

// next waits for the next status the session sets.
func (r *flowRec) next(t *testing.T) bsession.Status {
	t.Helper()
	select {
	case s := <-r.ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the session set no status")
		return bsession.Status{}
	}
}

func run(t *testing.T, s *Session, f *fakeAuth) chan error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	out := make(chan error, 1)
	go func() { out <- s.phoneLogin(ctx, f) }()
	return out
}

func reasonOf(t *testing.T, err error) *bsession.PairingError {
	t.Helper()
	var pe *bsession.PairingError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a PairingError, got %v", err)
	}
	return pe
}

// A mistyped code is asked for again — with the code Telegram already sent
// still good, so no second code is sent — and the right one signs in.
func TestAWrongTelegramCodeIsAskedForAgain(t *testing.T) {
	s, rec := newFlow(t)
	f := &fakeAuth{}
	done := run(t, s, f)

	st := rec.next(t)
	if st.State != bsession.StateAwaitingCode || st.Reason != "" || st.Challenge == nil ||
		st.Challenge.Kind != "phone_code" || st.Challenge.Via != "app" || st.Challenge.Length != 5 {
		t.Fatalf("first ask: %+v %+v", st, st.Challenge)
	}
	if st.Challenge.ExpiresAt.IsZero() {
		t.Fatal("the code's deadline is not on the challenge")
	}
	_ = s.SubmitCode(context.Background(), "12354", "")
	st = rec.next(t)
	if st.State != bsession.StateAwaitingCode || st.Reason != bsession.ReasonWrongCode {
		t.Fatalf("a wrong code must ask again saying so: %+v", st)
	}
	_ = s.SubmitCode(context.Background(), flowCode, "")
	if err := <-done; err != nil {
		t.Fatalf("the right code must sign in: %v", err)
	}
	if f.sendCalls != 1 {
		t.Fatalf("Telegram was asked for %d codes; a wrong one must not send another", f.sendCalls)
	}
	if strings.Join(f.signInCodes, ",") != "12354,"+flowCode {
		t.Fatalf("codes tried: %v", f.signInCodes)
	}
}

// Guessing ends: after MaxAttempts wrong codes the login stops.
func TestFiveWrongCodesEndTheLogin(t *testing.T) {
	s, rec := newFlow(t)
	f := &fakeAuth{}
	done := run(t, s, f)
	for i := 0; i < MaxAttempts; i++ {
		if st := rec.next(t); st.State != bsession.StateAwaitingCode {
			t.Fatalf("attempt %d: %+v", i+1, st)
		}
		_ = s.SubmitCode(context.Background(), "00000", "")
	}
	if pe := reasonOf(t, <-done); pe.Reason != bsession.ReasonTooManyAttempts {
		t.Fatalf("got %q", pe.Reason)
	}
	if len(f.signInCodes) != MaxAttempts {
		t.Fatalf("%d codes reached Telegram, want %d", len(f.signInCodes), MaxAttempts)
	}
}

// What Telegram refuses, by type, and the wait it names.
func TestTelegramsRefusalsBecomeReasons(t *testing.T) {
	for _, c := range []struct {
		name      string
		sendErr   error
		signInErr error
		want      string
		wait      time.Duration
	}{
		{"flood wait on the code", tgerr.New(420, "FLOOD_WAIT_300"), nil, bsession.ReasonRateLimited, 300 * time.Second},
		{"number flood", tgerr.New(400, "PHONE_NUMBER_FLOOD"), nil, bsession.ReasonRateLimited, 0},
		{"bad number", tgerr.New(400, "PHONE_NUMBER_INVALID"), nil, bsession.ReasonBadPhone, 0},
		{"banned number", tgerr.New(400, "PHONE_NUMBER_BANNED"), nil, bsession.ReasonPhoneBanned, 0},
		{"no account", tgerr.New(400, "PHONE_NUMBER_UNOCCUPIED"), nil, bsession.ReasonNoAccount, 0},
		{"sign-up required", nil, &auth.SignUpRequired{}, bsession.ReasonNoAccount, 0},
		{"expired code", nil, tgerr.New(400, "PHONE_CODE_EXPIRED"), bsession.ReasonCodeExpired, 0},
		{"flood wait on sign-in", nil, tgerr.New(420, "FLOOD_WAIT_61"), bsession.ReasonRateLimited, 61 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, rec := newFlow(t)
			f := &fakeAuth{sendErr: c.sendErr}
			if c.signInErr != nil {
				f.signIn = func(string) error { return c.signInErr }
			}
			done := run(t, s, f)
			if c.sendErr == nil {
				rec.next(t)
				_ = s.SubmitCode(context.Background(), flowCode, "")
			}
			pe := reasonOf(t, <-done)
			if pe.Reason != c.want || pe.RetryAfter != c.wait {
				t.Fatalf("want %q after %v, got %q after %v", c.want, c.wait, pe.Reason, pe.RetryAfter)
			}
			if strings.Contains(pe.Error(), flowPhone) {
				t.Fatal("the number reached the error text")
			}
		})
	}
}

// Two-step verification: asked once; a wrong password asks again saying so;
// the right one signs in. The bytes the proof was made from are zeroed
// before the login returns, and the password is never written to the vault.
func TestATelegramPasswordIsAskedOnceAndNeverKept(t *testing.T) {
	seen := capturePasswords(t)
	s, rec := newFlow(t)
	f := &fakeAuth{
		signIn: func(string) error { return auth.ErrPasswordAuthNeeded },
		password: func(n int) error {
			if n == 1 {
				return auth.ErrPasswordInvalid
			}
			return nil
		},
	}
	done := run(t, s, f)
	rec.next(t)
	_ = s.SubmitCode(context.Background(), flowCode, "")
	st := rec.next(t)
	if st.State != bsession.StateAwaitingPassword || st.Reason != "" || st.Challenge.Kind != "password" {
		t.Fatalf("the password must be asked for: %+v", st)
	}
	_ = s.SubmitCode(context.Background(), "", "wrong password")
	st = rec.next(t)
	if st.State != bsession.StateAwaitingPassword || st.Reason != bsession.ReasonWrongPassword {
		t.Fatalf("a wrong password must ask again saying so: %+v", st)
	}
	_ = s.SubmitCode(context.Background(), "", flowPassword)
	if err := <-done; err != nil {
		t.Fatalf("the right password must sign in: %v", err)
	}

	seen.mu.Lock()
	defer seen.mu.Unlock()
	if strings.Join(seen.used, "|") != "wrong password|"+flowPassword {
		t.Fatalf("the proofs were made from %q", seen.used)
	}
	for i, b := range seen.slices {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("password bytes %d were not zeroed after the proof: %q", i, b)
			}
		}
	}
	// Nothing about the login is in the vault.
	if _, err := s.vault.Get(context.Background(), "mtproto", "password"); err == nil {
		t.Fatal("a password record exists")
	}
}

// Five wrong passwords end the login too.
func TestFiveWrongPasswordsEndTheLogin(t *testing.T) {
	capturePasswords(t)
	s, rec := newFlow(t)
	f := &fakeAuth{
		signIn:   func(string) error { return auth.ErrPasswordAuthNeeded },
		password: func(int) error { return auth.ErrPasswordInvalid },
	}
	done := run(t, s, f)
	rec.next(t)
	_ = s.SubmitCode(context.Background(), flowCode, "")
	for i := 0; i < MaxAttempts; i++ {
		if st := rec.next(t); st.State != bsession.StateAwaitingPassword {
			t.Fatalf("attempt %d: %+v", i+1, st)
		}
		_ = s.SubmitCode(context.Background(), "", "nope")
	}
	if pe := reasonOf(t, <-done); pe.Reason != bsession.ReasonTooManyAttempts {
		t.Fatalf("got %q", pe.Reason)
	}
}

// Where the code went decides what the person is told to open.
func TestWhereTheCodeWentIsSaid(t *testing.T) {
	for _, c := range []struct {
		typ  tg.AuthSentCodeTypeClass
		want string
	}{
		{&tg.AuthSentCodeTypeApp{Length: 5}, "app"},
		{&tg.AuthSentCodeTypeSMS{Length: 6}, "sms"},
		{&tg.AuthSentCodeTypeCall{Length: 5}, "call"},
		{&tg.AuthSentCodeTypeEmailCode{Length: 6}, "email"},
	} {
		if via, _ := codeVia(c.typ); via != c.want {
			t.Fatalf("%T: got %q want %q", c.typ, via, c.want)
		}
	}
}

// Nothing a login was handed outlives it. A second press of Continue while
// Telegram is still checking the first, or a password sent along with a code
// that needed none, used to wait in a channel buffer for as long as the
// session lived — months, for a linked account — in a process whose whole
// promise is that the two-step password is never kept. So is the number.
func TestNothingALoginWasHandedIsLeftWaiting(t *testing.T) {
	ctx := context.Background()

	t.Run("a password sent with a code that needed none", func(t *testing.T) {
		capturePasswords(t)
		s, rec := newFlow(t)
		done := run(t, s, &fakeAuth{})
		rec.next(t)
		if err := s.SubmitCode(ctx, flowCode, flowPassword); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("the right code must sign in: %v", err)
		}
		if n := len(s.passwords) + len(s.codes); n != 0 {
			t.Fatalf("%d secret(s) still waiting in the session after its login ended", n)
		}
		if s.opts.Phone != "" {
			t.Fatal("the number outlived the login")
		}
		// And a login that is over takes nothing more — even while the last
		// status it set (the code question) is still the session's state.
		if st := s.Status(); st.State != bsession.StateAwaitingCode {
			t.Fatalf("the state this check relies on moved: %+v", st)
		}
		if err := s.SubmitCode(ctx, flowCode, flowPassword); !errors.Is(err, bsession.ErrWrongState) {
			t.Fatalf("a finished login took a code and a password: %v", err)
		}
		if n := len(s.passwords) + len(s.codes); n != 0 {
			t.Fatalf("%d secret(s) sent after the login are waiting in the session", n)
		}
	})

	t.Run("Continue pressed twice while Telegram checks the password", func(t *testing.T) {
		capturePasswords(t)
		s, rec := newFlow(t)
		gate := make(chan struct{})
		checking := make(chan struct{}, 1)
		f := &fakeAuth{
			signIn: func(string) error { return auth.ErrPasswordAuthNeeded },
			password: func(int) error {
				checking <- struct{}{}
				<-gate
				return nil
			},
		}
		done := run(t, s, f)
		rec.next(t)
		_ = s.SubmitCode(ctx, flowCode, "")
		if st := rec.next(t); st.State != bsession.StateAwaitingPassword {
			t.Fatalf("the password must be asked for: %+v", st)
		}
		_ = s.SubmitCode(ctx, "", flowPassword)
		<-checking // Telegram has the first one
		if err := s.SubmitCode(ctx, "", flowPassword); err != nil {
			t.Fatalf("the second press: %v", err)
		}
		if len(s.passwords) != 1 {
			t.Fatal("the second press is not waiting, so this test would prove nothing")
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatalf("the password must sign in: %v", err)
		}
		if len(s.passwords) != 0 {
			t.Fatal("the second password is still in the session after the login")
		}
	})
}
