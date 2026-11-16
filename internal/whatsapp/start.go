package whatsapp

import (
	"context"
	"errors"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"google.golang.org/protobuf/proto"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// ── STARTING A WHATSAPP CHAT WITH A NUMBER (owner, 2026-10-23) ─────────────
//
// The person typed one number, in E.164, and pressed Send. In this order:
//
//  1. the number is asked about on WhatsApp (IsOnWhatsApp, one number, one
//     query); a number that is not there is refused — "That number isn't on
//     WhatsApp." — and nothing is sent;
//  2. the first message goes to the account WhatsApp answered with, and the
//     chat is remembered (nsStarted), so a second message before they answer
//     is an ordinary send and their answer is an ordinary reply.
//
// THE CHAT ID is the one WhatsApp's answer names. For most people that is now
// their LID ("…@lid"), not the number: whatsmeow sends a message for a number
// to its LID anyway (send.go), and their reply arrives from the LID, so that
// is the conversation the brain must name. RecipientID is its user part,
// which is what Normalize reports as the sender of their reply.
//
// The manager has already applied the ban-risk guard (ratelimit/start.go)
// before step 1, so a refused start looks nobody up.

// nsStarted holds the chats a person started from SlyOS, as nsChats ("chats")
// holds the ones that wrote. One byte each; the key is the chat id.
const nsStarted = "started"

// chatter is the part of *whatsmeow.Client that starting a chat uses, so it
// can be driven by a fake in tests (start_test.go).
type chatter interface {
	IsLoggedIn() bool
	IsOnWhatsApp(ctx context.Context, phones []string) ([]types.IsOnWhatsAppResponse, error)
	SendMessage(ctx context.Context, to types.JID, message *waE2E.Message, extra ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
}

func (s *Session) chatClient() chatter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.testChat != nil {
		return s.testChat
	}
	if s.cli == nil {
		return nil // never a typed nil inside the interface
	}
	return s.cli
}

// knownChat: this account already has the chat — it wrote, or a person
// started it from here.
func (s *Session) knownChat(ctx context.Context, chat string) (bool, error) {
	for _, ns := range []string{"chats", nsStarted} {
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

// Resolve asks WhatsApp whether the number has an account. It sends nothing.
func (s *Session) Resolve(ctx context.Context, to string) (session.Target, error) {
	if !session.E164.MatchString(to) {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientBadShape}
	}
	cli := s.chatClient()
	if cli == nil || !cli.IsLoggedIn() {
		return session.Target{}, session.ErrNotLinked
	}
	own := s.Status().ExternalAccountID
	if own != "" && session.Digits(to) == own {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientOwnAccount}
	}
	found, err := cli.IsOnWhatsApp(ctx, []string{to})
	if err != nil {
		var iq *whatsmeow.IQError
		if errors.As(err, &iq) && iq.Code == 429 {
			// rate-overlimit. WhatsApp names no wait, so none is invented.
			return session.Target{}, &session.RecipientError{Reason: session.RecipientProviderLimited}
		}
		return session.Target{}, err
	}
	var hit *types.IsOnWhatsAppResponse
	for i := range found {
		if found[i].IsIn && !found[i].JID.IsEmpty() {
			hit = &found[i]
			break
		}
	}
	if hit == nil {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientNotOnWhatsApp}
	}
	jid := hit.JID.ToNonAD()
	pn := hit.PhoneNumber.ToNonAD()
	if own != "" && (jid.User == own || pn.User == own) {
		return session.Target{}, &session.RecipientError{Reason: session.RecipientOwnAccount}
	}
	// Already a chat of this account's, under either of WhatsApp's names for
	// the person: the one it is known by is the one the brain must name.
	for _, name := range []types.JID{jid, pn} {
		if name.IsEmpty() {
			continue
		}
		known, err := s.knownChat(ctx, name.String())
		if err != nil {
			return session.Target{}, err
		}
		if known {
			return session.Target{ChatID: name.String(), RecipientID: name.User, Known: true, Peer: name}, nil
		}
	}
	return session.Target{ChatID: jid.String(), RecipientID: jid.User, Peer: jid}, nil
}

// SendTo sends the first message to what Resolve found, and remembers the chat.
func (s *Session) SendTo(ctx context.Context, t session.Target, text string) (string, error) {
	cli := s.chatClient()
	if cli == nil || !cli.IsLoggedIn() {
		return "", session.ErrNotLinked
	}
	jid, ok := t.Peer.(types.JID)
	if !ok || jid.IsEmpty() {
		return "", ErrUnknownChat
	}
	res, err := cli.SendMessage(ctx, jid, &waE2E.Message{Conversation: proto.String(text)})
	if err != nil {
		return "", err
	}
	if !t.Known {
		// Sealed like every other record of this account's. If it fails the
		// message has still gone; the next message would be a start again.
		_ = s.vault.Put(ctx, nsStarted, t.ChatID, []byte{1})
	}
	return res.ID, nil
}

var _ session.Starter = (*Session)(nil)
