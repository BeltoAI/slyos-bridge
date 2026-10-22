package telegram

// End to end against gotd's in-process Telegram (tgtest): real MTProto, real
// key exchange, real encryption, a real second client — and no Telegram
// server, no api_id of ours and no phone number anywhere. That is as far as
// a test can go before the owner registers the app at my.telegram.org.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/gotd/td/tgtest"
	"github.com/gotd/td/tgtest/cluster"
	"github.com/gotd/td/tgtest/services"
	"github.com/gotd/td/tgtest/services/config"
	"github.com/gotd/td/tgtest/services/messages"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	bsession "github.com/BeltoAI/slyos-bridge/internal/session"
)

const (
	aliceID int64 = 100
	bobID   int64 = 200 // the SlyOS customer
	code          = "22222"

	floodedPhone = "+15550009999"
)

type recorder struct {
	mu       sync.Mutex
	statuses []bsession.Status
	msgs     []bsession.Inbound
	got      chan bsession.Inbound
}

func (r *recorder) Status(s bsession.Status) {
	r.mu.Lock()
	r.statuses = append(r.statuses, s)
	r.mu.Unlock()
}
func (r *recorder) Message(m bsession.Inbound) {
	r.mu.Lock()
	r.msgs = append(r.msgs, m)
	r.mu.Unlock()
	select {
	case r.got <- m:
	default:
	}
}
func (r *recorder) state() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.statuses) == 0 {
		return ""
	}
	return r.statuses[len(r.statuses)-1].State
}

// fakeTelegram is the auth half of Telegram that tgtest leaves to the test:
// a code is sent, the right code signs in, and the account exists after.
type fakeTelegram struct {
	mu        sync.Mutex
	signedIn  map[[8]byte]bool
	loggedOut int
}

func (f *fakeTelegram) register(d *tgtest.Dispatcher) {
	bob := &tg.User{ID: bobID, AccessHash: bobID, Self: true, FirstName: "Bob"}
	d.HandleFunc(tg.AuthSendCodeRequestTypeID, func(s *tgtest.Server, req *tgtest.Request) error {
		var r tg.AuthSendCodeRequest
		if err := r.Decode(req.Buf); err != nil {
			return err
		}
		if r.PhoneNumber == floodedPhone {
			// What Telegram answers a number asked for too many codes.
			return s.SendErr(req, tgerr.New(420, "FLOOD_WAIT_120"))
		}
		return s.SendResult(req, &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeApp{Length: 5}, PhoneCodeHash: "hash"})
	})
	d.HandleFunc(tg.AuthSignInRequestTypeID, func(s *tgtest.Server, req *tgtest.Request) error {
		var r tg.AuthSignInRequest
		if err := r.Decode(req.Buf); err != nil {
			return err
		}
		if r.PhoneCode != code {
			return s.SendErr(req, tgerr.New(400, "PHONE_CODE_INVALID"))
		}
		f.mu.Lock()
		f.signedIn[req.Session.AuthKey.ID] = true
		f.mu.Unlock()
		return s.SendResult(req, &tg.AuthAuthorization{User: bob})
	})
	d.HandleFunc(tg.UsersGetUsersRequestTypeID, func(s *tgtest.Server, req *tgtest.Request) error {
		f.mu.Lock()
		ok := f.signedIn[req.Session.AuthKey.ID]
		f.mu.Unlock()
		if !ok {
			return s.SendErr(req, tgerr.New(401, "AUTH_KEY_UNREGISTERED"))
		}
		return s.SendVector(req, bob)
	})
	d.HandleFunc(tg.AuthLogOutRequestTypeID, func(s *tgtest.Server, req *tgtest.Request) error {
		f.mu.Lock()
		f.loggedOut++
		delete(f.signedIn, req.Session.AuthKey.ID)
		f.mu.Unlock()
		return s.SendResult(req, &tg.AuthLoggedOut{})
	})
}

func newVault(t *testing.T) (*sealed.Keyring, *sealed.Vault, *sealed.MemoryBackend) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	b := sealed.NewMemoryBackend()
	kr := sealed.NewKeyring(root, b)
	v, err := kr.Create(context.Background(), "conn-tg", Kind)
	if err != nil {
		t.Fatal(err)
	}
	return kr, v, b
}

func TestTelegramPersonalEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	c := cluster.NewCluster(cluster.Options{})
	ft := &fakeTelegram{signedIn: map[[8]byte]bool{}}
	var resolveMu sync.Mutex
	bound := map[[8]byte]int64{}
	svc := messages.NewService(messages.WithSelfResolver(func(s tgtest.Session) *tg.User {
		resolveMu.Lock()
		defer resolveMu.Unlock()
		id, ok := bound[s.AuthKey.ID]
		if !ok {
			// The bridge binds first (its send below); Alice second.
			id = []int64{bobID, aliceID}[len(bound)]
			bound[s.AuthKey.ID] = id
		}
		return &tg.User{ID: id, AccessHash: id, Self: true}
	}))
	d := c.Dispatch(2, "server").Fallback(services.NotImplemented)
	config.NewService(&tg.Config{}, &tg.CDNConfig{}).Register(d)
	svc.Register(d)
	ft.register(d)
	go func() { _ = c.Up(ctx) }()
	<-c.Ready()

	cfg := Config{AppID: telegram.TestAppID, AppHash: telegram.TestAppHash,
		DC: 2, DCList: c.List(), Resolver: c.Resolver(), PublicKeys: c.Keys()}
	kr, vault, backend := newVault(t)
	rec := &recorder{got: make(chan bsession.Inbound, 4)}
	sess, err := Factory(cfg)("conn-tg", vault, rec, bsession.StartOptions{Method: "code", Phone: "+15550000000"})
	if err != nil {
		t.Fatal(err)
	}
	s := sess.(*Session)
	runCtx, stop := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(runCtx) }()

	// 1. Telegram asks for the code; a wrong one is refused and asked for
	// again — over real MTProto, Telegram's own PHONE_CODE_INVALID — and the
	// right one links.
	waitFor(t, "awaiting_code", func() bool { return rec.state() == bsession.StateAwaitingCode })
	if err := s.SubmitCode(ctx, "11111", ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the same question, saying the code was wrong", func() bool {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		last := rec.statuses[len(rec.statuses)-1]
		return last.State == bsession.StateAwaitingCode && last.Reason == bsession.ReasonWrongCode
	})
	if err := s.SubmitCode(ctx, code, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "linked", func() bool { return rec.state() == bsession.StateLinked })
	if st := s.Status(); st.ExternalAccountID != "200" || st.DisplayName != "Bob" {
		t.Fatalf("linked as the wrong account: %+v", st)
	}

	// 2. The MTProto auth key is in the vault, sealed — not in the clear.
	stored, err := vault.Get(ctx, "mtproto", "session")
	if err != nil || len(stored) == 0 {
		t.Fatalf("no sealed session after login: %v", err)
	}
	for _, blob := range backend.Dump() {
		if bytes.Contains(blob, stored) {
			t.Fatal("the MTProto session reached storage in the clear")
		}
	}

	// 3. A send to a chat that never wrote is refused.
	if _, err := s.Send(ctx, "u999", "hello stranger"); !errors.Is(err, ErrUnknownPeer) {
		t.Fatalf("a send to an unknown chat must be refused, got %v", err)
	}

	// 4. A reply to Alice goes out through MTProto (and binds Bob's session
	// on the fake server so it can receive).
	raw, _ := json.Marshal(peer{Type: "u", ID: aliceID, AccessHash: aliceID})
	_ = vault.Put(ctx, "peers", "u100", raw)
	id, err := s.Send(ctx, "u100", "on my way")
	if err != nil || id == "" {
		t.Fatalf("send: %q %v", id, err)
	}

	// 5. Alice writes; the bridge hands the brain a normalised message.
	alice := telegram.NewClient(telegram.TestAppID, telegram.TestAppHash, telegram.Options{
		PublicKeys: c.Keys(), DC: 2, DCList: c.List(), Resolver: c.Resolver(),
		SessionStorage: &session.StorageMemory{}, NoUpdates: true,
	})
	go func() {
		_ = alice.Run(ctx, func(ctx context.Context) error {
			_, err := alice.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
				Peer: &tg.InputPeerUser{UserID: bobID, AccessHash: bobID}, Message: "are you coming?", RandomID: 7,
			})
			if err != nil {
				return err
			}
			<-ctx.Done()
			return nil
		})
	}()
	select {
	case m := <-rec.got:
		if m.Body != "are you coming?" || m.Direction != "inbound" || m.ChatID != "u100" ||
			m.SenderID != "100" || m.ThreadKind != "direct" || m.ExternalAccountID != "200" {
			t.Fatalf("normalised wrongly: %+v", m)
		}
	case <-ctx.Done():
		t.Fatal("Alice's message never reached the bridge")
	}

	// 6. A deploy: stop, and a NEW session resumes from the sealed state with
	// no code asked for.
	stop()
	<-runErr
	vault2, err := kr.Open(ctx, "conn-tg")
	if err != nil {
		t.Fatal(err)
	}
	rec2 := &recorder{got: make(chan bsession.Inbound, 1)}
	sess2, _ := Factory(cfg)("conn-tg", vault2, rec2, bsession.StartOptions{Resume: true})
	runCtx2, stop2 := context.WithCancel(ctx)
	defer stop2()
	runErr2 := make(chan error, 1)
	go func() { runErr2 <- sess2.Run(runCtx2) }()
	waitFor(t, "resumed", func() bool { return rec2.state() == bsession.StateLinked })
	for _, st := range rec2.statuses {
		if st.State == bsession.StateAwaitingCode || st.State == bsession.StatePairing {
			t.Fatalf("a resumed session asked to pair again: %+v", st)
		}
	}

	// 7. Disconnect logs out at Telegram.
	if err := sess2.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	ft.mu.Lock()
	n := ft.loggedOut
	ft.mu.Unlock()
	if n != 1 {
		t.Fatalf("auth.logOut called %d times", n)
	}
}

// A session that Telegram no longer recognises on resume is reported as
// logged out, so the manager destroys its keys rather than retrying forever.
func TestResumeAfterTheSessionWasEndedInTelegram(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := cluster.NewCluster(cluster.Options{})
	ft := &fakeTelegram{signedIn: map[[8]byte]bool{}}
	d := c.Dispatch(2, "server").Fallback(services.NotImplemented)
	config.NewService(&tg.Config{}, &tg.CDNConfig{}).Register(d)
	ft.register(d)
	go func() { _ = c.Up(ctx) }()
	<-c.Ready()
	cfg := Config{AppID: telegram.TestAppID, AppHash: telegram.TestAppHash,
		DC: 2, DCList: c.List(), Resolver: c.Resolver(), PublicKeys: c.Keys()}
	_, vault, _ := newVault(t)
	sess, _ := Factory(cfg)("conn-tg", vault, &recorder{}, bsession.StartOptions{Resume: true})
	if err := sess.Run(ctx); !errors.Is(err, bsession.ErrLoggedOut) {
		t.Fatalf("expected ErrLoggedOut, got %v", err)
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// FLOOD_WAIT over real MTProto: the number Telegram is slowing down ends the
// login at once, with Telegram's own wait, and no code field is ever shown.
func TestATelegramFloodWaitEndsTheLoginWithItsWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := cluster.NewCluster(cluster.Options{})
	ft := &fakeTelegram{signedIn: map[[8]byte]bool{}}
	d := c.Dispatch(2, "server").Fallback(services.NotImplemented)
	config.NewService(&tg.Config{}, &tg.CDNConfig{}).Register(d)
	ft.register(d)
	go func() { _ = c.Up(ctx) }()
	<-c.Ready()
	cfg := Config{AppID: telegram.TestAppID, AppHash: telegram.TestAppHash,
		DC: 2, DCList: c.List(), Resolver: c.Resolver(), PublicKeys: c.Keys()}
	_, vault, _ := newVault(t)
	rec := &recorder{}
	sess, _ := Factory(cfg)("conn-tg", vault, rec, bsession.StartOptions{Method: "code", Phone: floodedPhone})
	err := sess.Run(ctx)
	var pe *bsession.PairingError
	if !errors.As(err, &pe) || pe.Reason != bsession.ReasonRateLimited || pe.RetryAfter != 120*time.Second {
		t.Fatalf("expected rate_limited after 120s, got %v", err)
	}
	if rec.state() == bsession.StateAwaitingCode {
		t.Fatal("a code field was shown for a code Telegram never sent")
	}
}
