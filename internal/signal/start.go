package signal

import (
	"context"
	"errors"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// ── STARTING A SIGNAL CHAT WITH A NUMBER (owner, 2026-10-23) ───────────────
//
// signalmeow can: its contact discovery (Client.LookupPhone, Signal's CDSI
// enclave, the same lookup Signal's own apps make) turns a number into the
// account's ACI, and a message to that ACI starts the chat — mautrix-signal's
// own "start a chat with a phone number" does exactly this. So:
//
//  1. the number, in E.164, is looked up (the store's own record of it
//     first, as mautrix-signal does); a number that is not on Signal, or
//     whose owner has "Who can find me by number" set to Nobody, is refused —
//     "not_on_signal" — and nothing is sent;
//  2. the first message goes to that ACI with no disappearing-message timer
//     (a new chat has none yet), and the chat is remembered (nsStarted), so a
//     second message before they answer is an ordinary send.
//
// The manager has already applied the ban-risk guard (ratelimit/start.go):
// Signal answers bursts from a new linked device with a captcha the bridge
// cannot solve, so it gets the same pace as WhatsApp.

// nsStarted holds the chats a person started from SlyOS, as nsChats holds the
// ones that wrote.
const nsStarted = "started"

func (s *Session) knownChat(ctx context.Context, chat string) (bool, error) {
	for _, ns := range []string{nsChats, nsStarted} {
		_, err := s.vault.Get(ctx, ns, chat)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, sealed.ErrNotFound) {
			return false, err
		}
	}
	return false, nil
}

// Resolve looks the number up on Signal. It sends nothing.
func (s *Session) Resolve(ctx context.Context, to string) (session.Target, error) {
	if !session.E164.MatchString(to) {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientBadShape}
	}
	s.mu.Lock()
	p, linked, acct := s.p, s.st.State == session.StateLinked, s.acct
	s.mu.Unlock()
	if p == nil || !linked {
		return session.Target{}, session.ErrNotLinked
	}
	if acct.Number != "" && session.Digits(acct.Number) == session.Digits(to) {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientOwnAccount}
	}
	aci, found, err := p.Lookup(ctx, to)
	if err != nil {
		return session.Target{}, err
	}
	if !found || aci == "" {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientNotOnSignal}
	}
	if aci == acct.ACI {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientOwnAccount}
	}
	known, err := s.knownChat(ctx, aci)
	if err != nil {
		return session.Target{}, err
	}
	// A one-to-one chat is named by the other person's service id, which for
	// an ACI is the bare UUID (signalmeow's ChatID), and the sender of their
	// reply is the same ACI.
	return session.Target{ChatID: aci, RecipientID: aci, Known: known, Peer: aci}, nil
}

// SendTo sends the first message to the ACI Resolve found, and remembers the chat.
func (s *Session) SendTo(ctx context.Context, t session.Target, text string) (string, error) {
	s.mu.Lock()
	p, linked := s.p, s.st.State == session.StateLinked
	s.mu.Unlock()
	if p == nil || !linked {
		return "", session.ErrNotLinked
	}
	aci, ok := t.Peer.(string)
	if !ok || aci == "" {
		return "", ErrUnknownChat
	}
	var timer Timer
	if b, err := s.vault.Get(ctx, nsTimers, aci); err == nil {
		timer = timerOf(b) // a chat that existed keeps its own timer
	}
	id, err := p.Send(ctx, aci, text, timer)
	if err != nil {
		return "", err
	}
	if !t.Known {
		_ = s.vault.Put(ctx, nsStarted, aci, []byte{1})
	}
	return id, nil
}

var _ session.Starter = (*Session)(nil)
