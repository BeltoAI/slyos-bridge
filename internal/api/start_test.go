package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// startingSession is linked and can start chats with the one number it knows.
type startingSession struct{ linkedSession }

func (s *startingSession) Resolve(_ context.Context, to string) (session.Target, error) {
	if to != "+15557654321" {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientNotOnWhatsApp}
	}
	return session.Target{ChatID: "8800@lid", RecipientID: "8800"}, nil
}

func (s *startingSession) SendTo(context.Context, session.Target, string) (string, error) {
	return "3EB0FIRST", nil
}

func startServer(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	logs := &bytes.Buffer{}
	log := logsafe.New(logs)
	ss := &startingSession{}
	mgr := session.NewManager(sealed.NewKeyring(root, sealed.NewMemoryBackend()), map[string]session.Factory{
		"whatsapp_linked": func(string, *sealed.Vault, session.Reporter, session.StartOptions) (session.Session, error) {
			return ss, nil
		},
	}, nopSink{}, ratelimit.New(nil), log)
	t.Cleanup(mgr.Shutdown)
	s := &Server{Manager: mgr, Secret: []byte(secret), Log: log, Kinds: map[string]bool{"whatsapp_linked": true}}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	if res, _ := call(t, srv, "POST", "/v1/connections", secret,
		map[string]any{"connectionId": connID, "kind": "whatsapp_linked", "method": "qr"}); res.StatusCode != 200 {
		t.Fatalf("connect: %d", res.StatusCode)
	}
	return srv, logs
}

// The brain's secret is required; a press is required; the answer names the
// chat and who is in it; and every refusal is a code the brain can word —
// with when it frees up — and never the number.
func TestStartAnswersInCodes(t *testing.T) {
	srv, logs := startServer(t)
	path := "/v1/connections/" + connID + "/start"
	first := map[string]any{"to": "+15557654321", "text": "private first words", "pressedByPerson": true}

	if res, _ := call(t, srv, "POST", path, "wrong", first); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no secret: %d", res.StatusCode)
	}
	if res, body := call(t, srv, "POST", path, secret,
		map[string]any{"to": "+15557654321", "text": "hi", "pressedByPerson": false}); res.StatusCode != 403 || body["error"] != "not_pressed" {
		t.Fatalf("unpressed: %d %v", res.StatusCode, body)
	}
	for _, to := range []string{"5557654321", "Dana", "+1555", "@ab", "+15557654321,+15557654322"} {
		if res, body := call(t, srv, "POST", path, secret,
			map[string]any{"to": to, "text": "hi", "pressedByPerson": true}); res.StatusCode != 422 || body["error"] != "bad_recipient" {
			t.Fatalf("%q: %d %v", to, res.StatusCode, body)
		}
	}
	if res, body := call(t, srv, "POST", path, secret,
		map[string]any{"to": "+15550009999", "text": "hi", "pressedByPerson": true}); res.StatusCode != 422 || body["error"] != "not_on_whatsapp" {
		t.Fatalf("not on WhatsApp: %d %v", res.StatusCode, body)
	}
	res, body := call(t, srv, "POST", path, secret, first)
	if res.StatusCode != 200 || body["chatId"] != "8800@lid" || body["messageId"] != "3EB0FIRST" ||
		body["recipientId"] != "8800" || body["new"] != true {
		t.Fatalf("start: %d %v", res.StatusCode, body)
	}
	res, body = call(t, srv, "POST", path, secret, first)
	if res.StatusCode != 429 || body["error"] != "start_limit_spacing" {
		t.Fatalf("a second start at once: %d %v", res.StatusCode, body)
	}
	if secs, _ := body["retryAfterSeconds"].(float64); secs < 59 || secs > 60 {
		t.Fatalf("retryAfterSeconds = %v, want about 60", body["retryAfterSeconds"])
	}
	if strings.Contains(logs.String(), "5557654321") || strings.Contains(logs.String(), "private first words") {
		t.Fatalf("the number or the text reached the log: %s", logs.String())
	}
}
