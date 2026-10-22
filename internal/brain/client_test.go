package brain

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/session"
)

func TestSignedAndRetried(t *testing.T) {
	secret := []byte("events-secret-events-secret-0123")
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get(SignatureHeader)
		parts := strings.SplitN(sig, ",", 2)
		ts := strings.TrimPrefix(parts[0], "t=")
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(ts + "."))
		m.Write(body)
		if strings.TrimPrefix(parts[1], "v1=") != hex.EncodeToString(m.Sum(nil)) {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/v1/webhooks/bridge" || !strings.Contains(string(body), `"type":"message"`) {
			w.WriteHeader(400)
			return
		}
		if n == 1 {
			w.WriteHeader(503) // the brain is mid-deploy
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Secret: secret}
	err := c.Message(context.Background(), "c1", "telegram_personal", session.Inbound{ChatID: "1", Body: "hi", SentAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected one retry after a 503, got %d calls", calls.Load())
	}
}

func TestA4xxIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Secret: []byte("x")}
	if err := c.Status(context.Background(), "c1", "whatsapp", session.Status{State: "linked"}); err == nil {
		t.Fatal("a 401 must be an error")
	}
	if calls.Load() != 1 {
		t.Fatalf("a refusal was retried: %d calls", calls.Load())
	}
}
