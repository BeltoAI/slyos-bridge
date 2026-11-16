//go:build cgo

package signal

import (
	"context"
	"errors"
	"testing"

	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// signalmeow can start a chat with a number: contact discovery finds the ACI,
// and the first message goes to it with no timer. A second message before
// they answer is an ordinary send.
func TestSignalStartsAChatWithANumber(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.linked(t)
	h.fp.mu.Lock()
	h.fp.directory = map[string]string{"+15557654321": theirACI}
	h.fp.mu.Unlock()
	got, err := h.mgr.Start(ctx, "conn-sig", "+15557654321", "hi, it's Emil", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := (session.Started{ChatID: theirACI, MessageID: MessageID(selfACI, 42), RecipientID: theirACI, New: true}); got != want {
		t.Fatalf("started %+v, want %+v", got, want)
	}
	h.fp.mu.Lock()
	sent, timers := append([]string(nil), h.fp.sent...), append([]Timer(nil), h.fp.timers...)
	h.fp.mu.Unlock()
	if len(sent) != 1 || sent[0] != theirACI+"|hi, it's Emil" || timers[0] != (Timer{}) {
		t.Fatalf("sent %v with %v", sent, timers)
	}
	if _, err := h.mgr.Send(ctx, "conn-sig", theirACI, "and another", true); err != nil {
		t.Fatalf("a second message: %v", err)
	}
}

// A number Signal's discovery does not find is refused and nothing is sent;
// his own number is refused before Signal is asked.
func TestANumberNotOnSignalIsRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.linked(t)
	for to, want := range map[string]string{
		"+15550009999": session.RecipientNotOnSignal,
		"+15551112222": session.RecipientOwnAccount,
	} {
		_, err := h.mgr.Start(ctx, "conn-sig", to, "hi", true)
		var refused *session.RecipientError
		if !errors.As(err, &refused) || refused.Reason != want {
			t.Fatalf("%s: err = %v, want %s", to, err, want)
		}
	}
	h.fp.mu.Lock()
	defer h.fp.mu.Unlock()
	if len(h.fp.sent) != 0 || len(h.fp.lookups) != 1 {
		t.Fatalf("sent %v, looked up %v", h.fp.sent, h.fp.lookups)
	}
}
