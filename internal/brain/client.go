// Package brain delivers what the bridge sees to the brain. ADR 0093.
//
// One endpoint, POST /v1/webhooks/bridge, signed with HMAC-SHA256 under
// BRIDGE_EVENTS_SECRET over "<unix seconds>.<body>". The brain refuses a
// signature older than five minutes, so a captured request cannot be replayed
// tomorrow. This secret is not the one the brain uses to call the bridge
// (BRIDGE_SHARED_SECRET): seeing one request in either direction must not let
// anybody forge the other.
package brain

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

const SignatureHeader = "x-slyos-bridge-signature"

// Event is the one envelope the brain accepts from the bridge.
type Event struct {
	ConnectionID string           `json:"connectionId"`
	Kind         string           `json:"kind"`
	Type         string           `json:"type"` // "message" | "status"
	Message      *session.Inbound `json:"message,omitempty"`
	Status       *session.Status  `json:"status,omitempty"`
}

type Client struct {
	URL    string // the brain's public URL, e.g. https://brain.example.com
	Secret []byte
	HTTP   *http.Client
	Now    func() time.Time
	// Attempts per event. A message the brain did not take is retried with
	// backoff, then counted as lost by the manager — never silently.
	Attempts int
}

func (c *Client) Message(ctx context.Context, connID, kind string, m session.Inbound) error {
	return c.post(ctx, Event{ConnectionID: connID, Kind: kind, Type: "message", Message: &m})
}

func (c *Client) Status(ctx context.Context, connID, kind string, s session.Status) error {
	return c.post(ctx, Event{ConnectionID: connID, Kind: kind, Type: "status", Status: &s})
}

// ErrRefused is a 4xx from the brain: retrying would not help.
var ErrRefused = errors.New("brain: event refused")

func init() { logsafe.RegisterClass(ErrRefused, "brain_refused") }

func (c *Client) post(ctx context.Context, ev Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = 4
	}
	wait := 500 * time.Millisecond
	var last error
	for i := 0; i < attempts; i++ {
		last = c.once(ctx, body)
		if last == nil || errors.Is(last, ErrRefused) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
	return last
}

func (c *Client) once(ctx context.Context, body []byte) error {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/webhooks/bridge", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set(SignatureHeader, Sign(c.Secret, now(), body))
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	_ = res.Body.Close()
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return nil
	case res.StatusCode >= 400 && res.StatusCode < 500:
		return fmt.Errorf("%w: status %d", ErrRefused, res.StatusCode)
	default:
		return fmt.Errorf("brain: status %d", res.StatusCode)
	}
}

// Sign produces the header value. Exported so the brain's tests, and this
// package's, can produce the same bytes.
func Sign(secret []byte, at time.Time, body []byte) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "t=" + ts + ",v1=" + hex.EncodeToString(m.Sum(nil))
}
