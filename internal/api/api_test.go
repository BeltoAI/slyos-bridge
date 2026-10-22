package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

type linkedSession struct {
	mu   sync.Mutex
	sent int
}

func (l *linkedSession) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (l *linkedSession) Status() session.Status {
	return session.Status{State: session.StateLinked, Challenge: &session.Challenge{Kind: "qr", Data: "x"}}
}
func (l *linkedSession) SubmitCode(context.Context, string, string) error {
	return session.ErrWrongState
}
func (l *linkedSession) Send(context.Context, string, string) (string, error) {
	l.mu.Lock()
	l.sent++
	l.mu.Unlock()
	return "m1", nil
}
func (l *linkedSession) Logout(context.Context) error { return nil }

type nopSink struct{}

func (nopSink) Message(context.Context, string, string, session.Inbound) error { return nil }
func (nopSink) Status(context.Context, string, string, session.Status) error   { return nil }

const secret = "a-shared-secret-of-at-least-32-characters"
const connID = "6f1c2a0e-1111-4222-8333-944455556666"

func newServer(t *testing.T) (*httptest.Server, *linkedSession, *bytes.Buffer, *sealed.MemoryBackend) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	b := sealed.NewMemoryBackend()
	ls := &linkedSession{}
	logs := &bytes.Buffer{}
	log := logsafe.New(logs)
	mgr := session.NewManager(sealed.NewKeyring(root, b), map[string]session.Factory{
		"whatsapp": func(string, *sealed.Vault, session.Reporter, session.StartOptions) (session.Session, error) {
			return ls, nil
		},
	}, nopSink{}, ratelimit.New(nil), log)
	t.Cleanup(mgr.Shutdown)
	s := &Server{Manager: mgr, Secret: []byte(secret), Log: log, Kinds: map[string]bool{"whatsapp": true}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, ls, logs, b
}

func call(t *testing.T, srv *httptest.Server, method, path, auth string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rdr = bytes.NewReader(j)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rdr)
	if auth != "" {
		req.Header.Set(AuthHeader, auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestEveryRouteButHealthNeedsTheSecret(t *testing.T) {
	srv, _, _, _ := newServer(t)
	for _, auth := range []string{"", "wrong", secret + "x"} {
		res, _ := call(t, srv, "POST", "/v1/connections", auth, map[string]string{"connectionId": connID, "kind": "whatsapp", "method": "qr"})
		if res.StatusCode != 401 {
			t.Fatalf("auth %q: got %d", auth, res.StatusCode)
		}
		res, _ = call(t, srv, "DELETE", "/v1/connections/"+connID, auth, nil)
		if res.StatusCode != 401 {
			t.Fatalf("revoke with auth %q: got %d", auth, res.StatusCode)
		}
	}
	if res, _ := call(t, srv, "GET", "/health", "", nil); res.StatusCode != 200 {
		t.Fatalf("health: %d", res.StatusCode)
	}
}

func TestConnectSendRevoke(t *testing.T) {
	srv, ls, logs, b := newServer(t)
	res, st := call(t, srv, "POST", "/v1/connections", secret, map[string]string{"connectionId": connID, "kind": "whatsapp", "method": "qr"})
	if res.StatusCode != 200 || st["state"] != "linked" {
		t.Fatalf("connect: %d %v", res.StatusCode, st)
	}
	res, out := call(t, srv, "POST", "/v1/connections/"+connID+"/send", secret,
		map[string]any{"chatId": "c", "text": "private words", "pressedByPerson": false})
	if res.StatusCode != 403 || out["error"] != "not_pressed" || ls.sent != 0 {
		t.Fatalf("unpressed send: %d %v sent=%d", res.StatusCode, out, ls.sent)
	}
	res, out = call(t, srv, "POST", "/v1/connections/"+connID+"/send", secret,
		map[string]any{"chatId": "c", "text": "private words", "pressedByPerson": true})
	if res.StatusCode != 429 && (res.StatusCode != 200 || out["messageId"] != "m1") {
		t.Fatalf("pressed send: %d %v", res.StatusCode, out)
	}
	res, _ = call(t, srv, "DELETE", "/v1/connections/"+connID, secret, nil)
	if res.StatusCode != 204 {
		t.Fatalf("revoke: %d", res.StatusCode)
	}
	if len(b.Dump()) != 0 {
		t.Fatal("revoke over HTTP left sealed bytes")
	}
	if strings.Contains(logs.String(), "private words") || strings.Contains(logs.String(), connID) {
		t.Fatalf("the access log carried a body or an id:\n%s", logs.String())
	}
}

func TestAKindNotServedIsRefused(t *testing.T) {
	srv, _, _, _ := newServer(t)
	res, out := call(t, srv, "POST", "/v1/connections", secret, map[string]string{"connectionId": connID, "kind": "sms_gmessages", "method": "qr"})
	if res.StatusCode != 404 || out["error"] != "kind_not_served" {
		t.Fatalf("got %d %v", res.StatusCode, out)
	}
}
