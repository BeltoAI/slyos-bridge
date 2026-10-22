// Package whatsapp is a person's own WhatsApp, linked as a device through
// whatsmeow (MPL-2.0), with no Mac in between. ADR 0093.
//
// THE RISK, AND THAT IT WAS ACCEPTED. WhatsApp's terms forbid unofficial
// clients, and this is one. ADRs 0058 and 0061 kept personal WhatsApp off our
// servers for exactly that reason. The owner reversed that on 2026-10-20 —
// "i do accept that risk, but we must be privacy diligent like beeper" — and
// the person connecting is told the same thing before the QR appears:
// "SlyOS connects as a linked device using an unofficial client. WhatsApp may
// suspend numbers that use unofficial clients. You can disconnect any time."
//
// WHAT THIS FILE DOES TO KEEP THE NUMBER SAFE, since the ban falls on the
// customer and not on us:
//
//   - it never sends on its own: Send is reached only through the manager,
//     which refuses anything a person did not press;
//   - it replies only in chats that wrote to this account (unknown chats
//     are refused here, before the rate limiter is even asked);
//   - it never marks a chat read and never sets presence, so the phone
//     still shows what is unread;
//   - the retry store is off, so no outgoing plaintext is kept.
package whatsapp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// Kind matches the brain's channel kind for this connection.
const Kind = "whatsapp_linked"

// WarningText is shown before the QR. The brain and the web carry the same
// sentence; packages/shared holds the copy the panel renders.
const WarningText = "SlyOS connects as a linked device using an unofficial client. " +
	"WhatsApp may suspend numbers that use unofficial clients. You can disconnect any time."

var ErrUnknownChat = errors.New("whatsapp: no chat with that id has written to this account")

// PairingCodeLifetime is how long a pairing code can be typed. whatsmeow keeps
// the login socket open only while it has QR codes left to offer — the first
// for 60 s, five more for 20 s each — and closes it after, so a code typed
// later has nothing to finish against. whatsmeow's PairPhone documentation:
// "there's a 160-second time limit".
const PairingCodeLifetime = 160 * time.Second

// pairDisplayName is the "Browser (OS)" WhatsApp shows for a code-linked
// device. whatsmeow: "only common browsers/OSes are allowed (the server will
// validate it and return 400 if it's wrong)" — so not "Chrome (SlyOS)", which
// the first version sent, and which a 400 would have reported to the person
// as a number WhatsApp refused. The bridge is a Linux process speaking the
// web client's protocol; this says so in the only words the server accepts.
const pairDisplayName = "Chrome (Linux)"

// pairer is the part of *whatsmeow.Client that linking uses, so the
// pairing-code flow can be driven by a fake in tests (whatsapp_test.go):
// there is no WhatsApp server a test may call with somebody's number.
type pairer interface {
	GetQRChannel(ctx context.Context) (<-chan whatsmeow.QRChannelItem, error)
	Connect() error
	PairPhone(ctx context.Context, phone string, showPushNotification bool, clientType whatsmeow.PairClientType, clientDisplayName string) (string, error)
}

// Factory returns the session factory for this kind.
func Factory() session.Factory {
	return func(connID string, vault *sealed.Vault, rep session.Reporter, opts session.StartOptions) (session.Session, error) {
		if !opts.Resume && opts.Method == "code" && opts.Phone == "" {
			return nil, errors.New("whatsapp: a pairing-code link needs a phone number")
		}
		return &Session{vault: vault, store: NewSealedStore(vault), rep: rep, opts: opts}, nil
	}
}

type Session struct {
	vault *sealed.Vault
	store *SealedStore
	rep   session.Reporter
	opts  session.StartOptions

	mu        sync.Mutex
	st        session.Status
	cli       *whatsmeow.Client
	fatal     chan error
	phoneSeen time.Time
}

func (s *Session) Status() session.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.PhoneLastSeen = s.phoneSeen
	return st
}

func (s *Session) set(st session.Status) {
	s.mu.Lock()
	st.Seq = s.st.Seq + 1
	s.st = st
	st.PhoneLastSeen = s.phoneSeen
	s.mu.Unlock()
	s.rep.Status(st)
}

func (s *Session) Run(ctx context.Context) error {
	log := libLogger{module: "whatsmeow"}
	device, err := s.store.LoadDevice(ctx, log)
	if err != nil {
		return err
	}
	if device == nil {
		if s.opts.Resume {
			return session.ErrLoggedOut
		}
		device = s.store.NewDevice(log)
	}
	s.loadPhoneSeen(ctx)
	cli := newClient(device, log)
	fatal := make(chan error, 1)
	s.mu.Lock()
	s.cli, s.fatal = cli, fatal
	s.mu.Unlock()
	cli.AddEventHandler(func(evt any) { s.handle(ctx, cli, evt) })
	defer func() {
		cli.Disconnect()
		s.mu.Lock()
		s.cli = nil
		s.mu.Unlock()
	}()

	if device.ID == nil {
		if err := s.pair(ctx, cli); err != nil {
			return err
		}
	} else if err := cli.Connect(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-fatal:
		return err
	}
}

// newClient is the whatsmeow client every session runs on.
//
// HISTORY IS NOT DOWNLOADED. On a first link the phone sends its whole chat
// history as encrypted blobs; whatsmeow by default downloads, inflates and
// decodes every one and stores what it finds — minutes of CPU and hundreds
// of megabytes on one link, for history this bridge never reads (no
// events.HistorySync handler: only new messages reach the brain).
// ManualHistorySyncDownload leaves the blobs where they are. The receipt is
// still sent (DisableManualHistorySyncReceipt stays false), so the phone
// counts the sync as delivered and does not send it again.
func newClient(device *store.Device, log waLog.Logger) *whatsmeow.Client {
	cli := whatsmeow.NewClient(device, log)
	cli.UseRetryMessageStore = false
	cli.ManualHistorySyncDownload = true
	return cli
}

// pair links a new device: by QR (the person scans what the screen shows), or
// by pairing code (the person types eight characters into WhatsApp → Linked
// devices → Link with phone number instead — for somebody whose only device
// IS the phone, who has nothing to point a camera at).
func (s *Session) pair(ctx context.Context, cli pairer) error {
	byCode := s.opts.Method == "code"
	qr, err := cli.GetQRChannel(ctx)
	if err != nil {
		return s.pairFailed(byCode, err)
	}
	if err := cli.Connect(); err != nil {
		return s.pairFailed(byCode, err)
	}
	codeShown := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case item, ok := <-qr:
			if !ok {
				if byCode {
					return session.ErrPairingExpired
				}
				return nil
			}
			switch {
			case item.Event == whatsmeow.QRChannelEventCode && !byCode:
				s.set(session.Status{State: session.StatePairing,
					Challenge: &session.Challenge{Kind: "qr", Data: item.Code, ExpiresAt: time.Now().Add(item.Timeout)}})
			case item.Event == whatsmeow.QRChannelEventCode && !codeShown:
				// NOT BEFORE THE FIRST QR. whatsmeow: "wait for the first item
				// in the channel" before PairPhone — that is the socket being
				// fully up. The first version asked straight after Connect and
				// raced it. The QR itself is never shown in code mode. WhatsApp's
				// 160 s started with this first QR.
				firstQR := time.Now()
				code, err := cli.PairPhone(ctx, s.opts.Phone, true, whatsmeow.PairClientChrome, pairDisplayName)
				if err != nil {
					return pairPhoneError(err)
				}
				codeShown = true
				s.set(session.Status{State: session.StatePairing, Challenge: &session.Challenge{
					Kind: "pairing_code", Data: code, ExpiresAt: firstQR.Add(PairingCodeLifetime)}})
			case item == whatsmeow.QRChannelSuccess:
				s.notePhone(ctx, time.Now()) // the phone was online to link
				return nil
			case item == whatsmeow.QRChannelTimeout:
				return session.ErrPairingExpired
			case strings.HasPrefix(item.Event, "err"):
				if byCode {
					return &session.PairingError{Reason: session.ReasonPairingFailed}
				}
				return fmt.Errorf("whatsapp: pairing failed (%s)", item.Event)
			}
		}
	}
}

// pairFailed: a socket that would not open. For a QR link the watchdog's
// retry is right (a new QR, nothing sent anywhere). For a code link it is not:
// a retry is another code pushed to the person's phone, so it ends here.
func (s *Session) pairFailed(byCode bool, err error) error {
	if byCode {
		return &session.PairingError{Reason: session.ReasonPairingFailed}
	}
	return err
}

// pairPhoneError turns WhatsApp's refusal of a pairing-code request into the
// reason the person reads. The number is never in the result: whatsmeow's
// errors are matched by type and code, and only the reason travels.
func pairPhoneError(err error) error {
	var iq *whatsmeow.IQError
	switch {
	case errors.Is(err, whatsmeow.ErrPhoneNumberTooShort),
		errors.Is(err, whatsmeow.ErrPhoneNumberIsNotInternational):
		return &session.PairingError{Reason: session.ReasonBadPhone}
	case errors.As(err, &iq) && iq.Code == 429:
		// rate-overlimit. WhatsApp names no wait, so none is invented.
		return &session.PairingError{Reason: session.ReasonRateLimited}
	case errors.As(err, &iq) && (iq.Code == 400 || iq.Code == 404 || iq.Code == 406):
		// bad-request / item-not-found / not-acceptable on a request whose
		// only variable part is the number: the number.
		return &session.PairingError{Reason: session.ReasonBadPhone}
	default:
		return &session.PairingError{Reason: session.ReasonPairingFailed}
	}
}

func (s *Session) handle(ctx context.Context, cli *whatsmeow.Client, evt any) {
	switch e := evt.(type) {
	case *events.Connected:
		self := cli.Store.GetJID()
		s.set(session.Status{State: session.StateLinked, ExternalAccountID: self.User, DisplayName: cli.Store.PushName})
	case *events.LoggedOut:
		s.fail(session.ErrLoggedOut)
	case *events.StreamReplaced:
		// Another client took this session's stream. Retrying would fight
		// it; the watchdog's backoff gives it room.
		s.fail(errors.New("whatsapp: stream replaced"))
	case *events.Message:
		self := cli.Store.GetJID()
		if e.Info.IsFromMe && e.Info.Sender.Device == 0 {
			s.notePhone(ctx, e.Info.Timestamp) // sent from the phone itself
		}
		in, ok := Normalize(e, self, cli.Store.GetLID())
		if !ok {
			return
		}
		if in.Direction == "inbound" {
			_ = s.vault.Put(ctx, "chats", in.ChatID, []byte{1})
		}
		s.rep.Message(in)
	case *events.Receipt:
		self := cli.Store.GetJID()
		if e.IsFromMe && e.Sender.Device == 0 && e.Sender.User == self.User {
			s.notePhone(ctx, e.Timestamp) // the phone read or received something
		}
	}
}

func (s *Session) fail(err error) {
	s.mu.Lock()
	ch := s.fatal
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- err:
		default:
		}
	}
}

// The phone's last sign of life, kept sealed so a deploy does not reset the
// 12-day clock. Multi-device gives no "phone online" event; activity from the
// primary device (device 0) — a message sent on it, a receipt from it — is the
// evidence there is, and the warning says "may", not "has".
func (s *Session) notePhone(ctx context.Context, at time.Time) {
	s.mu.Lock()
	if !at.After(s.phoneSeen) {
		s.mu.Unlock()
		return
	}
	s.phoneSeen = at
	s.mu.Unlock()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(at.Unix()))
	_ = s.vault.Put(ctx, nsMeta, "phone_last_seen", b[:])
}

func (s *Session) loadPhoneSeen(ctx context.Context) {
	b, err := s.vault.Get(ctx, nsMeta, "phone_last_seen")
	if err == nil && len(b) == 8 {
		s.mu.Lock()
		s.phoneSeen = time.Unix(int64(binary.BigEndian.Uint64(b)), 0)
		s.mu.Unlock()
	}
}

func (s *Session) SubmitCode(context.Context, string, string) error { return session.ErrWrongState }

func (s *Session) Send(ctx context.Context, chat, text string) (string, error) {
	s.mu.Lock()
	cli := s.cli
	s.mu.Unlock()
	if cli == nil || !cli.IsLoggedIn() {
		return "", session.ErrNotLinked
	}
	if _, err := s.vault.Get(ctx, "chats", chat); errors.Is(err, sealed.ErrNotFound) {
		return "", ErrUnknownChat
	} else if err != nil {
		return "", err
	}
	jid, err := types.ParseJID(chat)
	if err != nil {
		return "", ErrUnknownChat
	}
	res, err := cli.SendMessage(ctx, jid, &waE2E.Message{Conversation: proto.String(text)})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	cli := s.cli
	s.mu.Unlock()
	if cli == nil {
		return nil
	}
	return cli.Logout(ctx)
}

// Normalize turns one whatsmeow message into what the brain ingests. Pure: no
// network, no store, no clock — the unit tests drive it with constructed
// events. ok is false for what is not correspondence: status updates,
// newsletters, broadcast lists, reactions, revokes and edits (phase 1 takes
// the original message and does not follow an edit).
func Normalize(e *events.Message, self, selfLID types.JID) (session.Inbound, bool) {
	chat := e.Info.Chat
	if chat == types.StatusBroadcastJID || chat.Server == types.NewsletterServer ||
		chat.Server == types.BroadcastServer || e.IsEdit || e.Message == nil {
		return session.Inbound{}, false
	}
	m := e.Message
	if m.GetReactionMessage() != nil || m.GetProtocolMessage() != nil {
		return session.Inbound{}, false
	}
	in := session.Inbound{
		ExternalAccountID: self.User,
		ChatID:            chat.ToNonAD().String(),
		MessageID:         e.Info.ID,
		Direction:         "inbound",
		SentAt:            e.Info.Timestamp.UTC(),
		SenderID:          e.Info.Sender.ToNonAD().User,
		SenderName:        e.Info.PushName,
		ThreadKind:        "direct",
	}
	if e.Info.IsFromMe {
		in.Direction = "outbound"
		in.SenderName = ""
	}
	if e.Info.IsGroup {
		in.ThreadKind = "group"
	}
	var ctxInfo *waE2E.ContextInfo
	switch {
	case m.GetConversation() != "":
		in.Body = m.GetConversation()
	case m.GetExtendedTextMessage() != nil:
		in.Body = m.GetExtendedTextMessage().GetText()
		ctxInfo = m.GetExtendedTextMessage().GetContextInfo()
	case m.GetImageMessage() != nil:
		in.Body, in.Unsupported = m.GetImageMessage().GetCaption(), "image"
		ctxInfo = m.GetImageMessage().GetContextInfo()
	case m.GetVideoMessage() != nil:
		in.Body, in.Unsupported = m.GetVideoMessage().GetCaption(), "video"
		ctxInfo = m.GetVideoMessage().GetContextInfo()
	case m.GetDocumentMessage() != nil:
		in.Body, in.Unsupported = m.GetDocumentMessage().GetCaption(), "document"
		ctxInfo = m.GetDocumentMessage().GetContextInfo()
	case m.GetAudioMessage() != nil:
		in.Unsupported = "voice"
	case m.GetStickerMessage() != nil:
		in.Unsupported = "sticker"
	case m.GetLocationMessage() != nil:
		in.Unsupported = "location"
	case m.GetContactMessage() != nil:
		in.Unsupported = "contact"
	default:
		return session.Inbound{}, false
	}
	if ctxInfo != nil {
		for _, j := range ctxInfo.GetMentionedJID() {
			if pj, err := types.ParseJID(j); err == nil && (pj.User == self.User || (!selfLID.IsEmpty() && pj.User == selfLID.User)) {
				in.MentionsMe = true
			}
		}
		if p := ctxInfo.GetParticipant(); p != "" {
			if pj, err := types.ParseJID(p); err == nil && (pj.User == self.User || (!selfLID.IsEmpty() && pj.User == selfLID.User)) {
				in.MentionsMe = true // a reply to one of his messages
			}
		}
	}
	return in, true
}

// libLogger routes whatsmeow's logging into counts. Its messages include
// JIDs (phone numbers) and occasionally payload fragments, so the text is
// never written anywhere. ADR 0093, "zero content logging".
type libLogger struct{ module string }

func (l libLogger) Warnf(string, ...any)           { logsafe.Library.Note(l.module, "warn") }
func (l libLogger) Errorf(string, ...any)          { logsafe.Library.Note(l.module, "error") }
func (l libLogger) Infof(string, ...any)           {}
func (l libLogger) Debugf(string, ...any)          {}
func (l libLogger) Sub(module string) waLog.Logger { return libLogger{module: l.module + "/" + module} }

func to32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomUint32() uint32 { return binary.BigEndian.Uint32(randomBytes(4)) }

func sortPreKeys(ks []*keys.PreKey) {
	sort.Slice(ks, func(i, j int) bool { return ks[i].KeyID < ks[j].KeyID })
}
