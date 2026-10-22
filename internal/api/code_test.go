package api

// ── PHONE-ONLY LINKING OVER HTTP ──────────────────────────────────────────
//
// What the brain sends and gets back when a person links WhatsApp or
// Telegram by typing their number (ADR 0093 addendum): the number reaches the
// session and nowhere else, one number is sent at most five codes an hour
// whoever asks, a typed code is answered with Telegram's verdict, and none of
// the number, the pairing code, the login code or the password is in a log.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

const (
	typedPhone   = "+15557654321"
	pairingCode  = "QRST-VWXY"
	loginCode    = "48151"
	twoStepWords = "my telegram password"
)

// codeSession shows a pairing code for WhatsApp, or asks for Telegram's code
// and links on the right one.
type codeSession struct {
	kind string
	rep  session.Reporter
	mu   sync.Mutex
	st   session.Status
	in   chan string
}

func (c *codeSession) set(st session.Status) {
	c.mu.Lock()
	st.Seq = c.st.Seq + 1
	c.st = st
	c.mu.Unlock()
	c.rep.Status(st)
}

func (c *codeSession) Run(ctx context.Context) error {
	if c.kind == "whatsapp_linked" {
		c.set(session.Status{State: session.StatePairing, Challenge: &session.Challenge{
			Kind: "pairing_code", Data: pairingCode, ExpiresAt: time.Now().Add(160 * time.Second)}})
	} else {
		c.set(session.Status{State: session.StateAwaitingCode, Challenge: &session.Challenge{Kind: "phone_code", Via: "app"}})
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case code := <-c.in:
			if code == loginCode {
				c.set(session.Status{State: session.StateAwaitingPassword, Challenge: &session.Challenge{Kind: "password"}})
			} else if code == twoStepWords {
				c.set(session.Status{State: session.StateLinked, ExternalAccountID: "200"})
			} else {
				c.set(session.Status{State: session.StateAwaitingCode, Reason: session.ReasonWrongCode,
					Challenge: &session.Challenge{Kind: "phone_code", Via: "app"}})
			}
		}
	}
}
func (c *codeSession) Status() session.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}
func (c *codeSession) SubmitCode(_ context.Context, code, password string) error {
	if password != "" {
		c.in <- password
	} else {
		c.in <- code
	}
	return nil
}
func (c *codeSession) Send(context.Context, string, string) (string, error) {
	return "", session.ErrNotLinked
}
func (c *codeSession) Logout(context.Context) error { return nil }

type phoneServer struct {
	srv    *httptest.Server
	logs   *bytes.Buffer
	mu     sync.Mutex
	phones []string
	starts int
}

func newPhoneServer(t *testing.T) *phoneServer {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	ps := &phoneServer{logs: &bytes.Buffer{}}
	log := logsafe.New(ps.logs)
	factory := func(kind string) session.Factory {
		return func(_ string, _ *sealed.Vault, rep session.Reporter, opts session.StartOptions) (session.Session, error) {
			ps.mu.Lock()
			ps.starts++
			ps.phones = append(ps.phones, opts.Phone)
			ps.mu.Unlock()
			return &codeSession{kind: kind, rep: rep, in: make(chan string, 1)}, nil
		}
	}
	mgr := session.NewManager(sealed.NewKeyring(root, sealed.NewMemoryBackend()), map[string]session.Factory{
		"whatsapp_linked":   factory("whatsapp_linked"),
		"telegram_personal": factory("telegram_personal"),
	}, nopSink{}, ratelimit.New(nil), log)
	mgr.SubmitWait = 2 * time.Second
	t.Cleanup(mgr.Shutdown)
	s := &Server{Manager: mgr, Secret: []byte(secret), Log: log,
		Kinds: map[string]bool{"whatsapp_linked": true, "telegram_personal": true}}
	ps.srv = httptest.NewServer(s.Handler())
	t.Cleanup(ps.srv.Close)
	return ps
}

func connN(n int) string {
	return "6f1c2a0e-1111-4222-8333-94445555" + strings.Repeat("0", 4-len(itoa(n))) + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// WhatsApp by code: the typed number reaches the session, and the eight
// characters come back to show.
func TestAWhatsAppPairingCodeComesBackForTheTypedNumber(t *testing.T) {
	ps := newPhoneServer(t)
	res, st := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": connN(1), "kind": "whatsapp_linked", "method": "code", "phone": typedPhone})
	if res.StatusCode != 200 || st["state"] != "pairing" {
		t.Fatalf("connect: %d %v", res.StatusCode, st)
	}
	ch, _ := st["challenge"].(map[string]any)
	if ch["kind"] != "pairing_code" || ch["data"] != pairingCode || ch["expiresAt"] == nil {
		t.Fatalf("the code to show is not in the answer: %v", st)
	}
	if ps.phones[0] != typedPhone {
		t.Fatalf("the session was started for %q", ps.phones[0])
	}
	// A poll reads the same code.
	_, again := call(t, ps.srv, "GET", "/v1/connections/"+connN(1), secret, nil)
	if c2, _ := again["challenge"].(map[string]any); c2["data"] != pairingCode {
		t.Fatalf("poll: %v", again)
	}
}

// A number with no + is refused before a session starts. "9515550123" is a
// Riverside, California number to the person who typed it and +95, Myanmar, to
// WhatsApp; guessing would put a code on a stranger's phone.
func TestANumberWithoutItsCountryCodeReachesNobody(t *testing.T) {
	ps := newPhoneServer(t)
	for i, typed := range []string{"9515550123", "5551234", "15557654321"} {
		res, out := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
			"connectionId": connN(30 + i), "kind": "whatsapp_linked", "method": "code", "phone": typed})
		if res.StatusCode != 400 || out["error"] != "bad_phone" {
			t.Fatalf("%q: %d %v", typed, res.StatusCode, out)
		}
	}
	if ps.starts != 0 {
		t.Fatalf("a number with no country code started %d session(s)", ps.starts)
	}
	// The same digits with their +: a code, as before.
	if res, _ := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": connN(40), "kind": "whatsapp_linked", "method": "code", "phone": "+19515550123"}); res.StatusCode != 200 || ps.starts != 1 {
		t.Fatalf("the international form was refused: %d (%d starts)", res.StatusCode, ps.starts)
	}
}

// Five codes an hour for one number, however many connections ask; the sixth
// is refused BEFORE a session starts, so nothing reaches that phone.
func TestOneNumberIsSentAtMostFiveCodesAnHour(t *testing.T) {
	ps := newPhoneServer(t)
	for i := 1; i <= ratelimit.DefaultPairsPerHour; i++ {
		res, st := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
			"connectionId": connN(i), "kind": "whatsapp_linked", "method": "code", "phone": typedPhone})
		if res.StatusCode != 200 {
			t.Fatalf("request %d: %d %v", i, res.StatusCode, st)
		}
	}
	res, out := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": connN(9), "kind": "telegram_personal", "method": "code", "phone": typedPhone})
	if res.StatusCode != 429 || out["error"] != "too_many_codes" {
		t.Fatalf("the sixth code for one number: %d %v", res.StatusCode, out)
	}
	if secs, _ := out["retryAfterSeconds"].(float64); secs < 3500 || secs > 3600 {
		t.Fatalf("the wait should be about an hour, got %v", out["retryAfterSeconds"])
	}
	if ps.starts != ratelimit.DefaultPairsPerHour {
		t.Fatalf("a refused request still started a session (%d starts)", ps.starts)
	}
	// A QR is not a code to anybody's phone and is not counted.
	if res, _ := call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": connN(10), "kind": "whatsapp_linked", "method": "qr"}); res.StatusCode != 200 {
		t.Fatalf("a QR link was refused by the code limit: %d", res.StatusCode)
	}
}

// Telegram by code: a wrong code comes back wrong on the same request, the
// right one asks for the password, the password links.
func TestATelegramCodeIsAnsweredOnTheSameRequest(t *testing.T) {
	ps := newPhoneServer(t)
	id := connN(2)
	call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": id, "kind": "telegram_personal", "method": "code", "phone": typedPhone})
	res, st := call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"code": "00000"})
	if res.StatusCode != 200 || st["state"] != "awaiting_code" || st["reason"] != "wrong_code" {
		t.Fatalf("wrong code: %d %v", res.StatusCode, st)
	}
	_, st = call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"code": loginCode})
	if st["state"] != "awaiting_password" {
		t.Fatalf("right code: %v", st)
	}
	_, st = call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"password": twoStepWords})
	if st["state"] != "linked" {
		t.Fatalf("password: %v", st)
	}
	for _, body := range []map[string]string{{}, {"code": "12 34"}, {"code": strings.Repeat("1", 17)}} {
		if res, out := call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, body); res.StatusCode != 400 || out["error"] != "bad_code" {
			t.Fatalf("%v: %d %v", body, res.StatusCode, out)
		}
	}
}

// Every path above, through the real logger: none of the secrets is in it.
func TestNoNumberOrCodeIsLogged(t *testing.T) {
	ps := newPhoneServer(t)
	for i := 1; i <= 6; i++ {
		call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
			"connectionId": connN(i), "kind": "whatsapp_linked", "method": "code", "phone": typedPhone})
	}
	id := connN(20)
	call(t, ps.srv, "POST", "/v1/connections", secret, map[string]string{
		"connectionId": id, "kind": "telegram_personal", "method": "code", "phone": "+15550001234"})
	call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"code": "00000"})
	call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"code": loginCode})
	call(t, ps.srv, "POST", "/v1/connections/"+id+"/code", secret, map[string]string{"password": twoStepWords})
	call(t, ps.srv, "GET", "/v1/connections/"+connN(1), secret, nil)
	call(t, ps.srv, "DELETE", "/v1/connections/"+id, secret, nil)

	out := ps.logs.String()
	if !strings.Contains(out, `"route"`) {
		t.Fatal("nothing was logged, so this test proved nothing")
	}
	for _, needle := range []string{
		"5557654321", "5550001234", pairingCode, "QRSTVWXY", loginCode, twoStepWords, id,
	} {
		if strings.Contains(out, needle) {
			t.Fatalf("%q reached the log:\n%s", needle, out)
		}
	}
}
