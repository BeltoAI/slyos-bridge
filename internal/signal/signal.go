// Package signal is a person's own Signal account, linked as a secondary
// device by QR (Signal → Settings → Linked devices → +), the way Signal
// Desktop and Beeper link. ADR 0093, the Signal addendum of 2026-10-22.
//
// The protocol is mautrix-signal's signalmeow over libsignal's Rust FFI, both
// AGPL-3.0 — which is why the bridge's source is published (the owner,
// 2026-10-22). The real client is compiled in only with `-tags libsignal`
// (real.go); without it Signal is simply not served, and every test here
// drives the session through a fake provider instead.
//
// What this file keeps true, as for WhatsApp:
//
//   - it never sends on its own: Send is reached only through the manager,
//     which refuses anything a person did not press;
//   - it replies only in chats that wrote to this account;
//   - it never sends read receipts or typing, so the phone still shows what
//     is unread;
//   - disconnect unlinks the device at Signal, closes the account's database
//     and refuses to seal it again, and the manager then destroys the keys.
package signal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// Kind matches the brain's channel kind for this connection.
const Kind = "signal_personal"

// DeviceName is how this link is listed on the phone under Linked devices.
const DeviceName = "SlyOS"

// QRLifetime is how long one QR is offered before a fresh one replaces it.
// Signal's server ends a provisioning socket after 60 s; Signal Desktop opens
// a new one after 45 s, and so do we (mautrix-signal's qrRefreshInterval).
const QRLifetime = 45 * time.Second

// QRCount is how many QRs are offered before the attempt is called expired:
// four, so a person has three minutes to find Linked devices.
const QRCount = 4

// FlushEvery is how often the account's database is sealed into the vault
// when it has changed. A deploy flushes on the way out; only a crash can lose
// up to this much ratchet state, which Signal repairs with a retry receipt.
const FlushEvery = 5 * time.Second

const (
	nsChats  = "chats"
	nsTimers = "timers"
)

var (
	// ErrUnknownChat refuses a reply into a chat that never wrote to us.
	ErrUnknownChat = errors.New("signal: no chat with that id has written to this account")
	// ErrQROnly refuses a phone-code link: Signal links by QR only.
	ErrQROnly = errors.New("signal: links by QR only")
	// ErrNotServed is a build without libsignal asked for a Signal session.
	ErrNotServed = errors.New("signal: this build does not serve Signal")
)

// Account is the Signal account a link belongs to.
type Account struct {
	ACI    string // the account's stable id; the brain's externalAccountId
	Number string // E.164, when Signal shared it; never logged
	Name   string // the profile name, when known
}

// Message is one Signal message as the provider decoded it, before
// Normalize: the envelope facts plus the decoded content.
type Message struct {
	Sender     string // the sender's ACI
	SenderName string
	ChatID     string // the other person's service id, or the group id
	Group      bool
	ChatTitle  string
	Timestamp  uint64 // ms since epoch; with Sender, the message's identity
	Body       string
	// The first thing the body could not carry: "image", "video", "voice",
	// "document", "sticker", "contact". Empty for plain text.
	Attachment string
	// Mentions holds the ACIs @-mentioned; QuoteAuthor the author of the
	// message this replies to.
	Mentions    []string
	QuoteAuthor string
	// The chat's disappearing-messages timer as this message carried it.
	ExpireTimer        uint32
	ExpireTimerVersion uint32
	// TimerUpdate is an explicit disappearing-messages change (the
	// EXPIRATION_TIMER_UPDATE flag). Of the Skip messages, only it says what
	// the chat's timer is: a reaction, a delete or a call notice carries no
	// timer, and recording its zero would switch the chat's timer off with
	// the next reply.
	TimerUpdate bool
	// Skip is a message that is not a message to a person: a reaction, a
	// delete, an edit, an expiry-timer change, a group call notice.
	Skip bool
}

// Timer is a chat's disappearing-messages setting, sent with every reply:
// a Signal message without it switches the chat's timer off for everyone.
type Timer struct{ Seconds, Version uint32 }

func (t Timer) bytes() []byte {
	return []byte{byte(t.Seconds >> 24), byte(t.Seconds >> 16), byte(t.Seconds >> 8), byte(t.Seconds),
		byte(t.Version >> 24), byte(t.Version >> 16), byte(t.Version >> 8), byte(t.Version)}
}

func timerOf(b []byte) Timer {
	if len(b) != 8 {
		return Timer{}
	}
	u := func(b []byte) uint32 { return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) }
	return Timer{Seconds: u(b[:4]), Version: u(b[4:])}
}

// provider is the part of signalmeow a session uses (real.go), so linking,
// receiving and disconnecting can be driven by a fake in tests: there is no
// Signal server a test may link a real account against.
type provider interface {
	// Account is the account already linked in this store, if any.
	Account(ctx context.Context) (Account, bool, error)
	// Link offers QRs through show until the phone scans one, then returns
	// the account. ctx ending returns ctx.Err().
	Link(ctx context.Context, show func(url string, expires time.Time)) (Account, error)
	// Receive connects and delivers messages until ctx ends (nil) or Signal
	// ends the link (session.ErrLoggedOut).
	Receive(ctx context.Context, deliver func(Message)) error
	Send(ctx context.Context, chatID, text string, t Timer) (messageID string, err error)
	// Unlink asks Signal to remove this linked device.
	Unlink(ctx context.Context) error
}

// local is the account's own Signal state — identity keys, sessions,
// prekeys, contacts, groups — as an in-memory database sealed into the vault
// (store.go).
type local interface {
	Flush(ctx context.Context) error
	// Close frees the database; nothing is sealed after it.
	Close()
}

// opener builds a session's provider over its vault.
type opener func(ctx context.Context, v *sealed.Vault) (provider, local, error)

// Factory builds Signal sessions; it is nil in a build without libsignal.
func Factory() session.Factory {
	if openReal == nil {
		return nil
	}
	return factory(openReal)
}

func factory(open opener) session.Factory {
	return func(connID string, vault *sealed.Vault, rep session.Reporter, opts session.StartOptions) (session.Session, error) {
		if !opts.Resume && opts.Method != "qr" {
			return nil, ErrQROnly
		}
		return &Session{vault: vault, rep: rep, opts: opts, open: open}, nil
	}
}

// Session is one Signal connection.
type Session struct {
	vault *sealed.Vault
	rep   session.Reporter
	opts  session.StartOptions
	open  opener

	mu     sync.Mutex
	st     session.Status
	p      provider
	db     local
	acct   Account
	timers map[string]Timer // what was last sealed under nsTimers
	gone   bool             // Logout ran: the database is closed and never sealed again
}

func (s *Session) Status() session.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Session) set(st session.Status) {
	s.mu.Lock()
	st.Seq = s.st.Seq + 1
	s.st = st
	s.mu.Unlock()
	s.rep.Status(st)
}

// Run links (or resumes) and receives until ctx ends or Signal ends the link.
func (s *Session) Run(ctx context.Context) error {
	p, db, err := s.open(ctx, s.vault)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.gone {
		s.mu.Unlock()
		db.Close()
		return session.ErrLoggedOut
	}
	s.p, s.db = p, db
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		gone := s.gone
		s.p = nil
		s.mu.Unlock()
		if !gone {
			// A deploy or a dropped socket: keep what changed, sealed.
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = db.Flush(fctx)
			cancel()
		}
		db.Close()
	}()

	acct, linked, err := p.Account(ctx)
	if err != nil {
		return err
	}
	if !linked {
		if s.opts.Resume {
			return session.ErrLoggedOut
		}
		acct, err = p.Link(ctx, func(url string, expires time.Time) {
			s.set(session.Status{State: session.StatePairing,
				Challenge: &session.Challenge{Kind: "qr", Data: url, ExpiresAt: expires}})
		})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		// The identity keys exist only in memory until this succeeds.
		if err := db.Flush(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.acct = acct
	s.mu.Unlock()
	name := acct.Name
	if name == "" {
		name = acct.Number
	}
	s.set(session.Status{State: session.StateLinked, ExternalAccountID: acct.ACI, DisplayName: name})

	// The loop ends with this Run, not with the connection: a restart opens
	// a new database and starts its own loop.
	lctx, stop := context.WithCancel(ctx)
	defer stop()
	go flushLoop(lctx, db, FlushEvery)
	return p.Receive(ctx, func(m Message) { s.deliver(ctx, acct, m) })
}

func flushLoop(ctx context.Context, db local, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = db.Flush(ctx)
		}
	}
}

func (s *Session) deliver(ctx context.Context, acct Account, m Message) {
	if m.ChatID != "" && (!m.Skip || m.TimerUpdate) {
		s.noteTimer(ctx, m.ChatID, Timer{Seconds: m.ExpireTimer, Version: m.ExpireTimerVersion})
	}
	in, ok := Normalize(m, acct.ACI)
	if !ok {
		return
	}
	if in.Direction == "inbound" {
		_ = s.vault.Put(ctx, nsChats, in.ChatID, []byte{1})
	}
	s.rep.Message(in)
}

// noteTimer records a chat's disappearing-messages timer as a message carried
// it, unless what is recorded already has a newer version: a message sent
// before the timer changed and delivered after it must not roll the timer
// back. What was sealed before a restart counts as recorded.
func (s *Session) noteTimer(ctx context.Context, chat string, t Timer) {
	s.mu.Lock()
	old, seen := s.timers[chat]
	s.mu.Unlock()
	if !seen {
		if b, err := s.vault.Get(ctx, nsTimers, chat); err == nil {
			old, seen = timerOf(b), true
		}
	}
	if seen && (t == old || t.Version < old.Version) {
		t = old
	}
	s.mu.Lock()
	if s.timers == nil {
		s.timers = map[string]Timer{}
	}
	s.timers[chat] = t
	s.mu.Unlock()
	if !seen || t != old {
		_ = s.vault.Put(ctx, nsTimers, chat, t.bytes())
	}
}

// SubmitCode: Signal links by QR only.
func (s *Session) SubmitCode(context.Context, string, string) error { return session.ErrWrongState }

// Send delivers one reply, only into a chat that wrote to this account.
func (s *Session) Send(ctx context.Context, chat, text string) (string, error) {
	s.mu.Lock()
	p, linked := s.p, s.st.State == session.StateLinked
	s.mu.Unlock()
	if p == nil || !linked {
		return "", session.ErrNotLinked
	}
	if _, err := s.vault.Get(ctx, nsChats, chat); errors.Is(err, sealed.ErrNotFound) {
		return "", ErrUnknownChat
	} else if err != nil {
		return "", err
	}
	var t Timer
	if b, err := s.vault.Get(ctx, nsTimers, chat); err == nil {
		t = timerOf(b)
	}
	return p.Send(ctx, chat, text, t)
}

// Logout unlinks this device at Signal (best effort: the manager destroys the
// keys whatever Signal says), then closes the account's database and marks
// the session so that nothing seals it again — not the flush loop, not Run on
// its way out. The manager's keyring.Destroy deletes what was sealed.
func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	p, db := s.p, s.db
	s.gone = true
	s.mu.Unlock()
	var err error
	if p != nil {
		err = p.Unlink(ctx)
	}
	if db != nil {
		db.Close()
	}
	return err
}

// MessageID is a Signal message's identity: its author and its timestamp.
func MessageID(sender string, ts uint64) string { return fmt.Sprintf("%s:%d", sender, ts) }

// Normalize turns a decoded Signal message into what the brain receives, or
// false for one that is not a message to a person.
func Normalize(m Message, self string) (session.Inbound, bool) {
	if m.Skip || m.ChatID == "" || m.Sender == "" || m.Timestamp == 0 {
		return session.Inbound{}, false
	}
	body := strings.TrimSpace(m.Body)
	if body == "" && m.Attachment == "" {
		return session.Inbound{}, false
	}
	in := session.Inbound{
		ExternalAccountID: self,
		ChatID:            m.ChatID,
		MessageID:         MessageID(m.Sender, m.Timestamp),
		Direction:         "inbound",
		Body:              m.Body,
		SentAt:            time.UnixMilli(int64(m.Timestamp)).UTC(),
		SenderID:          m.Sender,
		SenderName:        m.SenderName,
		ThreadKind:        "direct",
		Unsupported:       m.Attachment,
	}
	if m.Sender == self {
		in.Direction = "outbound" // sent from his phone or another linked device
		in.SenderName = ""
	}
	if m.Group {
		in.ThreadKind = "group"
		in.ChatTitle = m.ChatTitle
	}
	if self != "" {
		for _, a := range m.Mentions {
			if a == self {
				in.MentionsMe = true
			}
		}
		if m.QuoteAuthor == self && in.Direction == "inbound" {
			in.MentionsMe = true // a reply to one of his messages
		}
	}
	return in, true
}

// AttachmentKind names what an attachment was, from its MIME type.
func AttachmentKind(contentType string, voiceNote bool) string {
	switch {
	case voiceNote || strings.HasPrefix(contentType, "audio/"):
		return "voice"
	case strings.HasPrefix(contentType, "image/"):
		return "image"
	case strings.HasPrefix(contentType, "video/"):
		return "video"
	default:
		return "document"
	}
}
