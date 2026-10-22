// Package telegram is a person's own Telegram account, reached through
// Telegram's published client API (MTProto) with gotd/td (MIT). ADR 0093.
//
// TELEGRAM'S API TERMS, AND WHAT THIS FILE DOES ABOUT EACH:
//
//   - Say the app is unofficial. The device model every Telegram session
//     list shows is "SlyOS (unofficial client)", so the person sees exactly
//     that under Settings → Devices in their own Telegram.
//   - Never act without consent. Nothing here sends on its own. Send is
//     reached only from the bridge API, which the manager refuses unless the
//     brain says a person pressed it.
//   - Never alter read or online status. This file never calls
//     messages.readHistory, account.updateStatus, or anything that marks a
//     chat read or the person online. Receiving a message through the API
//     does neither.
//   - Clause 1.5 restricts using Telegram data to train or feed AI. Drafting
//     a reply with a model is a question for counsel, and the brain keeps
//     drafting for this kind behind channel.telegram.personal until the owner
//     has that opinion. Nothing in the bridge calls a model.
//
// The person's own api_id and api_hash are NOT used: SlyOS registers ONE
// application at my.telegram.org (TELEGRAM_API_ID / TELEGRAM_API_HASH on the
// bridge), as every third-party client does. That registration is an owner
// action and does not exist yet.
package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gotd/td/exchange"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	bsession "github.com/BeltoAI/slyos-bridge/internal/session"
)

const Kind = "telegram_personal"

// PairingTimeout bounds a login nobody finishes: the QR is never scanned, the
// code is never typed.
var PairingTimeout = 5 * time.Minute

// passwordHashFor is gotd's SRP proof. A variable only so flow_test.go can
// see the bytes it was handed, and that they were zeroed afterwards.
var passwordHashFor = auth.PasswordHashFor

// MaxAttempts is how many wrong login codes, and separately how many wrong
// two-step passwords, one login takes before it ends. Telegram has its own
// limits and answers a guesser with FLOOD_WAIT; this stops well before that,
// so the person's number is not the one Telegram starts to slow down.
const MaxAttempts = 5

// authAPI is the part of gotd's *auth.Client a login uses, so every branch of
// the phone-code flow — a wrong code, a flood wait, a password — can be driven
// by a fake (flow_test.go) as well as end to end (telegram_e2e_test.go).
type authAPI interface {
	SendCode(ctx context.Context, phone string, options auth.SendCodeOptions) (tg.AuthSentCodeClass, error)
	SignIn(ctx context.Context, phone, code, codeHash string) (*tg.AuthAuthorization, error)
	PasswordWith(ctx context.Context, hash auth.PasswordHashFunc) (*tg.AuthAuthorization, error)
}

var ErrUnknownPeer = errors.New("telegram: no chat with that id has written to this account")

// Config is the application registration plus, for tests, an in-process
// Telegram (gotd's tgtest cluster) instead of the real one.
type Config struct {
	AppID   int
	AppHash string

	// Test hooks. Zero in production.
	DC         int
	DCList     dcs.List
	Resolver   dcs.Resolver
	PublicKeys []exchange.PublicKey
}

// Factory returns the session factory the manager uses for this kind.
func Factory(cfg Config) bsession.Factory {
	return func(connID string, vault *sealed.Vault, rep bsession.Reporter, opts bsession.StartOptions) (bsession.Session, error) {
		if cfg.AppID == 0 || cfg.AppHash == "" {
			return nil, errors.New("telegram: TELEGRAM_API_ID and TELEGRAM_API_HASH are not set")
		}
		if !opts.Resume && opts.Method == "code" && opts.Phone == "" {
			return nil, errors.New("telegram: a phone-code login needs a phone number")
		}
		return &Session{cfg: cfg, vault: vault, rep: rep, opts: opts,
			codes: make(chan string, 1), passwords: make(chan string, 1)}, nil
	}
}

type Session struct {
	cfg   Config
	vault *sealed.Vault
	rep   bsession.Reporter
	opts  bsession.StartOptions

	codes     chan string
	passwords chan string

	mu     sync.Mutex
	st     bsession.Status
	api    *tg.Client
	selfID int64
	// Set when a login ends, however it ends: from then on SubmitCode takes
	// nothing, so no code or password can be left waiting in a channel for
	// the life of the session. login() clears it when a login begins.
	loginOver bool
}

func (s *Session) Status() bsession.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

func (s *Session) set(st bsession.Status) {
	s.mu.Lock()
	st.Seq = s.st.Seq + 1
	s.st = st
	s.mu.Unlock()
	s.rep.Status(st)
}

// sealedStorage is gotd's session storage — the MTProto auth key, which IS
// the login — kept only in the connection's vault.
type sealedStorage struct{ vault *sealed.Vault }

func (s sealedStorage) LoadSession(ctx context.Context) ([]byte, error) {
	b, err := s.vault.Get(ctx, "mtproto", "session")
	if errors.Is(err, sealed.ErrNotFound) {
		return nil, session.ErrNotFound
	}
	return b, err
}

func (s sealedStorage) StoreSession(ctx context.Context, data []byte) error {
	return s.vault.Put(ctx, "mtproto", "session", data)
}

func (s *Session) client(handler telegram.UpdateHandler) *telegram.Client {
	return telegram.NewClient(s.cfg.AppID, s.cfg.AppHash, telegram.Options{
		SessionStorage: sealedStorage{s.vault},
		UpdateHandler:  handler,
		DC:             s.cfg.DC,
		DCList:         s.cfg.DCList,
		Resolver:       s.cfg.Resolver,
		PublicKeys:     s.cfg.PublicKeys,
		RetryInterval:  time.Second,
		Device: telegram.DeviceConfig{
			DeviceModel:   "SlyOS (unofficial client)",
			SystemVersion: "SlyOS bridge",
			AppVersion:    "1.0",
		},
	})
}

func (s *Session) Run(ctx context.Context) error {
	d := tg.NewUpdateDispatcher()
	loggedIn := qrlogin.OnLoginToken(d)
	d.OnNewMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateNewMessage) error {
		s.onMessage(ctx, e, u.Message)
		return nil
	})
	d.OnNewChannelMessage(func(ctx context.Context, e tg.Entities, u *tg.UpdateNewChannelMessage) error {
		s.onMessage(ctx, e, u.Message)
		return nil
	})
	c := s.client(d)
	err := c.Run(ctx, func(ctx context.Context) error {
		status, err := c.Auth().Status(ctx)
		if err != nil {
			return err
		}
		if !status.Authorized {
			if s.opts.Resume {
				// The person ended this session in Telegram (Settings →
				// Devices). Not a failure to retry: the keys go.
				return bsession.ErrLoggedOut
			}
			if err := s.login(ctx, c, loggedIn); err != nil {
				return err
			}
		}
		self, err := c.Self(ctx)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.api = c.API()
		s.selfID = self.ID
		s.mu.Unlock()
		s.opts.Resume = true // a restart after this point resumes, never re-pairs
		s.set(bsession.Status{
			State:             bsession.StateLinked,
			ExternalAccountID: strconv.FormatInt(self.ID, 10),
			DisplayName:       strings.TrimSpace(self.FirstName + " " + self.LastName),
		})
		<-ctx.Done()
		return nil
	})
	s.mu.Lock()
	s.api = nil
	s.mu.Unlock()
	if err != nil && (auth.IsUnauthorized(err) || auth.IsKeyUnregistered(err)) {
		return bsession.ErrLoggedOut
	}
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Session) login(ctx context.Context, c *telegram.Client, loggedIn qrlogin.LoggedIn) error {
	ctx, cancel := context.WithTimeout(ctx, PairingTimeout)
	defer cancel()
	var err error
	if s.opts.Method == "code" {
		err = s.phoneLogin(ctx, c.Auth())
	} else {
		_, err = c.QR().Auth(ctx, loggedIn, func(_ context.Context, t qrlogin.Token) error {
			s.set(bsession.Status{State: bsession.StatePairing,
				Challenge: &bsession.Challenge{Kind: "qr", Data: t.URL(), ExpiresAt: t.Expires()}})
			return nil
		})
		if errors.Is(err, auth.ErrPasswordAuthNeeded) || tgerr.Is(err, "SESSION_PASSWORD_NEEDED") {
			err = s.passwordLogin(ctx, c.Auth())
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return bsession.ErrPairingExpired
	}
	return err
}

// phoneLogin is Telegram's login by phone number, for somebody with no second
// screen to scan a QR from: Telegram sends a code — inside the Telegram app on
// their phone when they are signed in there, otherwise by text — and they
// type it into SlyOS. gotd's own auth.Flow is not used because it gives up on
// the first wrong code; a person who mistypes one digit is asked again, up to
// MaxAttempts, with the same code still valid.
//
// Nothing here is kept: the number is the session's start option (memory,
// never sealed, never logged, and forgotten when the login ends), the code
// passes through a channel to SignIn.
func (s *Session) phoneLogin(ctx context.Context, a authAPI) error {
	s.beginLogin()
	defer s.endLogin()
	sent, err := a.SendCode(ctx, s.opts.Phone, auth.SendCodeOptions{})
	if err != nil {
		return loginError(err)
	}
	var hash, via string
	length := 0
	switch v := sent.(type) {
	case *tg.AuthSentCode:
		hash = v.PhoneCodeHash
		via, length = codeVia(v.Type)
	case *tg.AuthSentCodeSuccess:
		return nil // Telegram signed this session in without a code
	default:
		return &bsession.PairingError{Reason: bsession.ReasonPairingFailed}
	}
	expires, _ := ctx.Deadline()
	reason := ""
	for attempt := 1; ; attempt++ {
		s.set(bsession.Status{State: bsession.StateAwaitingCode, Reason: reason, Challenge: &bsession.Challenge{
			Kind: "phone_code", Via: via, Length: length, ExpiresAt: expires}})
		var code string
		select {
		case <-ctx.Done():
			return ctx.Err()
		case code = <-s.codes:
		}
		_, err := a.SignIn(ctx, s.opts.Phone, code, hash)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, auth.ErrPasswordAuthNeeded):
			return s.passwordLogin(ctx, a)
		case tgerr.Is(err, "PHONE_CODE_INVALID", "PHONE_CODE_EMPTY"):
			if attempt >= MaxAttempts {
				return &bsession.PairingError{Reason: bsession.ReasonTooManyAttempts}
			}
			reason = bsession.ReasonWrongCode
		default:
			return loginError(err)
		}
	}
}

// passwordLogin is two-step verification: the person's Telegram password,
// asked once and asked again only if it was wrong. It is NEVER STORED: it
// arrives over the brain's request, passes through a channel, is turned into
// bytes for the SRP proof and those bytes are zeroed when the proof is made.
// (The Go string it arrived as cannot be zeroed; it is never written anywhere
// and goes with the garbage collector.) Nor is one left waiting: a second
// press of Continue, or a password sent with a code that needed none, is
// emptied out of the channel when the login ends (endLogin).
func (s *Session) passwordLogin(ctx context.Context, a authAPI) error {
	s.beginLogin()
	defer s.endLogin()
	expires, _ := ctx.Deadline()
	reason := ""
	for attempt := 1; ; attempt++ {
		s.set(bsession.Status{State: bsession.StateAwaitingPassword, Reason: reason,
			Challenge: &bsession.Challenge{Kind: "password", ExpiresAt: expires}})
		var pw string
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pw = <-s.passwords:
		}
		secret := []byte(pw)
		_, err := a.PasswordWith(ctx, passwordHashFor(secret))
		clear(secret)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, auth.ErrPasswordInvalid):
			if attempt >= MaxAttempts {
				return &bsession.PairingError{Reason: bsession.ReasonTooManyAttempts}
			}
			reason = bsession.ReasonWrongPassword
		default:
			return loginError(err)
		}
	}
}

// loginError names what Telegram refused, so the person reads a sentence and
// not "that did not work". Matched by Telegram's error TYPE, never by text,
// and only the reason leaves this function.
func loginError(err error) error {
	if d, ok := tgerr.AsFloodWait(err); ok {
		return &bsession.PairingError{Reason: bsession.ReasonRateLimited, RetryAfter: d}
	}
	var signUp *auth.SignUpRequired
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	case tgerr.Is(err, "PHONE_NUMBER_FLOOD"):
		return &bsession.PairingError{Reason: bsession.ReasonRateLimited}
	case tgerr.Is(err, "PHONE_NUMBER_INVALID", "PHONE_NUMBER_EMPTY"):
		return &bsession.PairingError{Reason: bsession.ReasonBadPhone}
	case tgerr.Is(err, "PHONE_NUMBER_BANNED"):
		return &bsession.PairingError{Reason: bsession.ReasonPhoneBanned}
	case tgerr.Is(err, "PHONE_NUMBER_UNOCCUPIED"), errors.As(err, &signUp):
		// SlyOS never creates a Telegram account, nor accepts Telegram's
		// terms on anybody's behalf.
		return &bsession.PairingError{Reason: bsession.ReasonNoAccount}
	case tgerr.Is(err, "PHONE_CODE_EXPIRED"):
		return &bsession.PairingError{Reason: bsession.ReasonCodeExpired}
	}
	return err
}

// codeVia says where Telegram delivered the login code, and how long it is.
func codeVia(t tg.AuthSentCodeTypeClass) (via string, length int) {
	if l, ok := t.(interface{ GetLength() int }); ok {
		length = l.GetLength()
	}
	switch t.(type) {
	case *tg.AuthSentCodeTypeApp:
		return "app", length
	case *tg.AuthSentCodeTypeSMS, *tg.AuthSentCodeTypeFragmentSMS, *tg.AuthSentCodeTypeFirebaseSMS,
		*tg.AuthSentCodeTypeSMSWord, *tg.AuthSentCodeTypeSMSPhrase:
		return "sms", length
	case *tg.AuthSentCodeTypeCall, *tg.AuthSentCodeTypeFlashCall, *tg.AuthSentCodeTypeMissedCall:
		return "call", length
	case *tg.AuthSentCodeTypeEmailCode:
		return "email", length
	}
	return "other", length
}

// beginLogin opens SubmitCode for a login that is starting.
func (s *Session) beginLogin() {
	s.mu.Lock()
	s.loginOver = false
	s.mu.Unlock()
}

// endLogin closes it, however the login ended — linked, refused, run out —
// and empties the channels. A code or password that arrived and was never
// used would otherwise sit in a channel buffer for as long as the session
// lives, which for a linked account is months: "never stored" means not in
// memory either. The number goes too; nothing after a login needs it.
func (s *Session) endLogin() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loginOver = true
	for {
		select {
		case <-s.codes:
		case <-s.passwords:
		default:
			s.opts.Phone = ""
			return
		}
	}
}

// SubmitCode hands a code or a password to the login waiting for it. Under
// s.mu, so it cannot land between endLogin's drain and the login's end.
func (s *Session) SubmitCode(_ context.Context, code, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loginOver {
		return bsession.ErrWrongState
	}
	switch s.st.State {
	case bsession.StateAwaitingCode:
		if code == "" {
			return bsession.ErrWrongState
		}
		select {
		case s.codes <- code:
		default:
		}
		if password != "" {
			select {
			case s.passwords <- password:
			default:
			}
		}
		return nil
	case bsession.StateAwaitingPassword:
		if password == "" {
			return bsession.ErrWrongState
		}
		select {
		case s.passwords <- password:
		default:
		}
		return nil
	}
	return bsession.ErrWrongState
}

// peer is what Send needs to address a chat: kept in the vault, because an
// access hash is a capability for this account and must not sit in the brain.
type peer struct {
	Type       string `json:"t"` // "u" | "c" | "ch"
	ID         int64  `json:"id"`
	AccessHash int64  `json:"h"`
}

func chatID(p peer) string { return p.Type + strconv.FormatInt(p.ID, 10) }

func (s *Session) onMessage(ctx context.Context, e tg.Entities, mc tg.MessageClass) {
	m, ok := mc.(*tg.Message)
	if !ok {
		return // service messages (joins, pins) are not correspondence
	}
	var p peer
	kind := "direct"
	switch pid := m.PeerID.(type) {
	case *tg.PeerUser:
		p = peer{Type: "u", ID: pid.UserID}
		if u, ok := e.Users[pid.UserID]; ok {
			p.AccessHash = u.AccessHash
		}
	case *tg.PeerChat:
		p = peer{Type: "c", ID: pid.ChatID}
		kind = "group"
	case *tg.PeerChannel:
		p = peer{Type: "ch", ID: pid.ChannelID}
		if ch, ok := e.Channels[pid.ChannelID]; ok {
			p.AccessHash = ch.AccessHash
		}
		kind = "group"
	default:
		return
	}
	if raw, err := json.Marshal(p); err == nil {
		_ = s.vault.Put(ctx, "peers", chatID(p), raw)
	}
	in := bsession.Inbound{
		ChatID:     chatID(p),
		MessageID:  chatID(p) + ":" + strconv.Itoa(m.ID),
		Direction:  "inbound",
		Body:       m.Message,
		SentAt:     time.Unix(int64(m.Date), 0).UTC(),
		ThreadKind: kind,
		MentionsMe: m.Mentioned,
	}
	s.mu.Lock()
	in.ExternalAccountID = strconv.FormatInt(s.selfID, 10)
	s.mu.Unlock()
	if m.Out {
		in.Direction = "outbound"
	}
	if from, ok := m.FromID.(*tg.PeerUser); ok {
		in.SenderID = strconv.FormatInt(from.UserID, 10)
		if u, ok := e.Users[from.UserID]; ok {
			in.SenderName = strings.TrimSpace(u.FirstName + " " + u.LastName)
		}
	} else if p.Type == "u" && !m.Out {
		in.SenderID = strconv.FormatInt(p.ID, 10)
	}
	if m.Media != nil {
		in.Unsupported = "media"
	}
	if in.Body == "" && in.Unsupported == "" {
		return
	}
	s.rep.Message(in)
}

// Send replies in a chat that has written to this account. A chat the bridge
// has never seen has no stored peer, and is refused rather than resolved:
// the bridge does not look people up to message them.
func (s *Session) Send(ctx context.Context, chat, text string) (string, error) {
	s.mu.Lock()
	api := s.api
	s.mu.Unlock()
	if api == nil {
		return "", bsession.ErrNotLinked
	}
	raw, err := s.vault.Get(ctx, "peers", chat)
	if errors.Is(err, sealed.ErrNotFound) {
		return "", ErrUnknownPeer
	} else if err != nil {
		return "", err
	}
	var p peer
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", err
	}
	var input tg.InputPeerClass
	switch p.Type {
	case "u":
		input = &tg.InputPeerUser{UserID: p.ID, AccessHash: p.AccessHash}
	case "c":
		input = &tg.InputPeerChat{ChatID: p.ID}
	case "ch":
		input = &tg.InputPeerChannel{ChannelID: p.ID, AccessHash: p.AccessHash}
	default:
		return "", ErrUnknownPeer
	}
	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return "", err
	}
	res, err := api.MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer: input, Message: text, RandomID: int64(binary.LittleEndian.Uint64(rb[:])),
	})
	if err != nil {
		return "", err
	}
	if id := sentID(res); id != 0 {
		return chat + ":" + strconv.Itoa(id), nil
	}
	return "", fmt.Errorf("telegram: send answered %T with no message id", res)
}

func sentID(u tg.UpdatesClass) int {
	switch v := u.(type) {
	case *tg.Updates:
		for _, up := range v.Updates {
			if m, ok := up.(*tg.UpdateMessageID); ok {
				return m.ID
			}
		}
	case *tg.UpdateShortSentMessage:
		return v.ID
	}
	return 0
}

// Logout ends the session at Telegram, so it disappears from the person's
// Settings → Devices. Best effort; the manager destroys the keys either way.
func (s *Session) Logout(ctx context.Context) error {
	s.mu.Lock()
	api := s.api
	s.mu.Unlock()
	if api == nil {
		return nil
	}
	_, err := api.AuthLogOut(ctx)
	return err
}
