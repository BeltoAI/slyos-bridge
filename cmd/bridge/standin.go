//go:build standin

// A STAND-IN PROVIDER, so the whole QR flow can be walked on a laptop with
// nothing real on the other end: no WhatsApp server, no Telegram server, no
// phone, no number. ADR 0093.
//
// Compiled ONLY with `-tags standin`. The Dockerfile builds without tags, so
// the image Fly runs cannot contain this file, and TestTheShippedBuildHasNoStandIn
// (main_test.go, built without the tag) fails if that ever stops being true.
//
// What it does, per connection:
//
//  1. pairing: a QR whose data is "2@standin-<random>" (WhatsApp) or
//     "tg://login?token=standin-<random>" (Telegram), the same shapes the real
//     libraries give, expiring in 60 s;
//  2. after BRIDGE_STANDIN_SCAN_MS (default 4000) it "scans": a random 32-byte
//     key is sealed into the vault, exactly where a real session keeps its
//     identity, and the state becomes linked with the made-up account
//     +1 555 000 0000 (a fictional range);
//  3. one inbound text from a made-up contact, so the signed message path to
//     the brain is walked too (only on a fresh link, never on resume);
//  4. a pressed send answers a made-up message id.
//
// Disconnect is the manager's real revoke: the wrapped key and every sealed
// record are destroyed in the real backend, which is the thing being walked.
//
// PHONE-ONLY LINKING (ADR 0093 addendum), with method "code":
//
//   - WhatsApp shows a made-up 8-character pairing code and "links" after
//     BRIDGE_STANDIN_SCAN_MS, as if it had been typed into WhatsApp;
//   - Telegram asks for a code (as if sent to the Telegram app): 12345 links,
//     anything else is "wrong_code", 54321 asks for the two-step password, and
//     the password "standin" links;
//   - a number ending 0166 is refused as WhatsApp/Telegram would ("bad_phone"),
//     and one ending 0142 is flood-waited for 300 s ("rate_limited").
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
	"github.com/BeltoAI/slyos-bridge/internal/telegram"
	"github.com/BeltoAI/slyos-bridge/internal/whatsapp"
)

func init() { standIn = standInFactories }

// A fictional number (555-0100 to 555-0199 is reserved for fiction) and a
// fictional contact, so nothing on a screen or in a database is anybody's.
const (
	standInAccount = "15555550100"
	standInContact = "15555550142"
)

func standInFactories(log *slog.Logger) (map[string]session.Factory, map[string]bool) {
	scanAfter := 4 * time.Second
	if ms, err := strconv.Atoi(os.Getenv("BRIDGE_STANDIN_SCAN_MS")); err == nil && ms > 0 {
		scanAfter = time.Duration(ms) * time.Millisecond
	}
	log.Warn("stand-in sessions: nothing real is reached", slog.String("state", "standin"))
	factory := func(kind string) session.Factory {
		return func(connID string, v *sealed.Vault, rep session.Reporter, opts session.StartOptions) (session.Session, error) {
			return &standInSession{kind: kind, vault: v, rep: rep, resume: opts.Resume, scanAfter: scanAfter,
				method: opts.Method, phone: opts.Phone, codes: make(chan [2]string, 1)}, nil
		}
	}
	return map[string]session.Factory{
			whatsapp.Kind: factory(whatsapp.Kind),
			telegram.Kind: factory(telegram.Kind),
		},
		map[string]bool{whatsapp.Kind: true, telegram.Kind: true}
}

type standInSession struct {
	kind      string
	vault     *sealed.Vault
	rep       session.Reporter
	resume    bool
	scanAfter time.Duration
	method    string
	phone     string // memory only, as in the real sessions
	codes     chan [2]string

	mu   sync.Mutex
	st   session.Status
	sent int
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *standInSession) set(st session.Status) {
	s.mu.Lock()
	st.Seq = s.st.Seq + 1
	s.st = st
	s.mu.Unlock()
	s.rep.Status(st)
}

func (s *standInSession) linked() session.Status {
	return session.Status{State: session.StateLinked, ExternalAccountID: standInAccount,
		DisplayName: "Stand-in account"}
}

func (s *standInSession) Run(ctx context.Context) error {
	if _, err := s.vault.Get(ctx, "device", "self"); err == nil {
		s.set(s.linked())
		<-ctx.Done()
		return nil
	} else if !errors.Is(err, sealed.ErrNotFound) {
		return err
	}
	if s.resume {
		// Nothing sealed to resume from: a real session would be logged out.
		return session.ErrLoggedOut
	}

	if s.method == "code" {
		if err := s.byCode(ctx); err != nil || ctx.Err() != nil {
			return err
		}
	} else {
		data := "2@standin-" + randomHex(16)
		if s.kind == telegram.Kind {
			data = "tg://login?token=standin-" + randomHex(16)
		}
		s.set(session.Status{State: session.StatePairing,
			Challenge: &session.Challenge{Kind: "qr", Data: data, ExpiresAt: time.Now().Add(60 * time.Second)}})

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.scanAfter):
		}
	}

	// "The phone scanned": key material sealed where a real session keeps it.
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := s.vault.Put(ctx, "device", "self", key); err != nil {
		return err
	}
	s.set(s.linked())

	select {
	case <-ctx.Done():
		return nil
	case <-time.After(time.Second):
	}
	chat := standInContact + "@s.whatsapp.net"
	if s.kind == telegram.Kind {
		chat = "user:" + standInContact
	}
	s.rep.Message(session.Inbound{
		ExternalAccountID: standInAccount,
		ChatID:            chat,
		MessageID:         "standin-" + randomHex(6),
		Direction:         "inbound",
		Body:              "Hello from the stand-in. Nothing real sent this.",
		SentAt:            time.Now().UTC(),
		SenderID:          standInContact,
		SenderName:        "Stand-in contact",
		ThreadKind:        "direct",
	})
	<-ctx.Done()
	return nil
}

func (s *standInSession) Status() session.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// byCode walks the phone-number link: WhatsApp's pairing code, or Telegram's
// code and password. Returns nil once "linked" should follow.
func (s *standInSession) byCode(ctx context.Context) error {
	switch {
	case len(s.phone) > 4 && s.phone[len(s.phone)-4:] == "0166":
		return &session.PairingError{Reason: session.ReasonBadPhone}
	case len(s.phone) > 4 && s.phone[len(s.phone)-4:] == "0142":
		return &session.PairingError{Reason: session.ReasonRateLimited, RetryAfter: 300 * time.Second}
	}
	if s.kind != telegram.Kind {
		const alphabet = "123456789ABCDEFGHJKLMNPQRSTVWXYZ"
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		for i := range b {
			b[i] = alphabet[int(b[i])%len(alphabet)]
		}
		s.set(session.Status{State: session.StatePairing, Challenge: &session.Challenge{
			Kind: "pairing_code", Data: string(b[:4]) + "-" + string(b[4:]), ExpiresAt: time.Now().Add(160 * time.Second)}})
		select {
		case <-ctx.Done():
		case <-time.After(s.scanAfter):
		}
		return nil
	}
	reason := ""
	for {
		s.set(session.Status{State: session.StateAwaitingCode, Reason: reason,
			Challenge: &session.Challenge{Kind: "phone_code", Via: "app", Length: 5, ExpiresAt: time.Now().Add(5 * time.Minute)}})
		var in [2]string
		select {
		case <-ctx.Done():
			return nil
		case in = <-s.codes:
		}
		switch in[0] {
		case "12345":
			return nil
		case "54321":
			preason := ""
			for {
				s.set(session.Status{State: session.StateAwaitingPassword, Reason: preason,
					Challenge: &session.Challenge{Kind: "password"}})
				select {
				case <-ctx.Done():
					return nil
				case in = <-s.codes:
				}
				if in[1] == "standin" {
					return nil
				}
				preason = session.ReasonWrongPassword
			}
		default:
			reason = session.ReasonWrongCode
		}
	}
}

func (s *standInSession) SubmitCode(_ context.Context, code, password string) error {
	switch s.Status().State {
	case session.StateAwaitingCode, session.StateAwaitingPassword:
		select {
		case s.codes <- [2]string{code, password}:
		default:
		}
		return nil
	}
	return session.ErrWrongState
}

func (s *standInSession) Send(context.Context, string, string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.State != session.StateLinked {
		return "", session.ErrNotLinked
	}
	s.sent++
	return "standin-sent-" + strconv.Itoa(s.sent), nil
}

func (s *standInSession) Logout(context.Context) error { return nil }
