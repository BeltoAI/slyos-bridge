package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	bsession "github.com/BeltoAI/slyos-bridge/internal/session"
)

// ── STARTING A TELEGRAM CHAT WITH AN @USERNAME OR A NUMBER (2026-10-23) ────
//
// The person typed one @username or one number in E.164 and pressed Send.
//
//   - AN @USERNAME is asked of Telegram (contacts.resolveUsername). Only a
//     person is written to: a channel, a group or a bot is refused, and so is
//     his own account.
//   - A NUMBER is looked for in his own Telegram contacts first; if it is
//     there, that contact is used and nothing about his list changes.
//     Otherwise it is imported (contacts.importContacts — the only way
//     Telegram turns a number into somebody to write to), the message goes,
//     and the contact is REMOVED again afterwards, whether the message went
//     or not (Target.Release, which the manager always calls), so his
//     contact list is not filled with people he only wrote to once. A
//     contact that was already his is never removed.
//
// Either way the person's peer (id and access hash) is stored sealed under
// "peers", as for anybody who wrote, so their answer is an ordinary reply.
// The manager has already applied the ban-risk guard (ratelimit/start.go).
// Telegram's own terms are unchanged by this: nothing here sends on its own,
// reads a chat or changes his online status.

// startAPI is the part of *tg.Client that sending and starting a chat use, so
// both can be driven by a fake in tests (start_test.go).
type startAPI interface {
	ContactsResolveUsername(ctx context.Context, request *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error)
	ContactsGetContacts(ctx context.Context, hash int64) (tg.ContactsContactsClass, error)
	ContactsImportContacts(ctx context.Context, contacts []tg.InputPhoneContact) (*tg.ContactsImportedContacts, error)
	ContactsDeleteContacts(ctx context.Context, id []tg.InputUserClass) (tg.UpdatesClass, error)
	MessagesSendMessage(ctx context.Context, request *tg.MessagesSendMessageRequest) (tg.UpdatesClass, error)
}

func (s *Session) rpcClient() startAPI {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.testRPC != nil {
		return s.testRPC
	}
	if s.api == nil {
		return nil // never a typed nil inside the interface
	}
	return s.api
}

// Resolve finds the person `to` names. It sends nothing; a number it had to
// import comes back with a Release that removes it.
func (s *Session) Resolve(ctx context.Context, to string) (bsession.Target, error) {
	api := s.rpcClient()
	if api == nil {
		return bsession.Target{}, bsession.ErrNotLinked
	}
	s.mu.Lock()
	selfID, selfPhone := s.selfID, s.selfPhone
	s.mu.Unlock()
	switch {
	case bsession.TelegramUsername.MatchString(to):
		return s.resolveUsername(ctx, api, to[1:], selfID)
	case bsession.E164.MatchString(to):
		if selfPhone != "" && bsession.Digits(to) == selfPhone {
			return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientOwnAccount}
		}
		return s.resolvePhone(ctx, api, to, selfID)
	}
	return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientBadShape}
}

func (s *Session) resolveUsername(ctx context.Context, api startAPI, name string, selfID int64) (bsession.Target, error) {
	res, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: name})
	if err != nil {
		return bsession.Target{}, lookupError(err)
	}
	pu, ok := res.Peer.(*tg.PeerUser)
	if !ok {
		// A public channel or group has a username too; it is not a person.
		return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientNotAPerson}
	}
	u := userIn(res.Users, pu.UserID)
	if u == nil {
		return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientNotOnTelegram}
	}
	if refusal := notToWrite(u, selfID); refusal != nil {
		return bsession.Target{}, refusal
	}
	return s.targetFor(ctx, u)
}

func (s *Session) resolvePhone(ctx context.Context, api startAPI, phone string, selfID int64) (bsession.Target, error) {
	// HIS OWN CONTACTS FIRST: one already there is used as it is, and the
	// list of who was his before is what decides, below, what may be removed.
	had := map[int64]bool{}
	list, err := api.ContactsGetContacts(ctx, 0)
	if err != nil {
		return bsession.Target{}, lookupError(err)
	}
	if c, ok := list.(*tg.ContactsContacts); ok {
		for _, ct := range c.Contacts {
			had[ct.UserID] = true
		}
		for _, uc := range c.Users {
			if u, ok := uc.(*tg.User); ok && had[u.ID] && u.Phone != "" &&
				bsession.Digits(u.Phone) == bsession.Digits(phone) {
				if refusal := notToWrite(u, selfID); refusal != nil {
					return bsession.Target{}, refusal
				}
				return s.targetFor(ctx, u)
			}
		}
	}

	var rb [8]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return bsession.Target{}, err
	}
	clientID := int64(binary.LittleEndian.Uint64(rb[:]) >> 1)
	// The name is the number itself: nothing invented, and if he glances at
	// his contacts in the moment it is there, he sees exactly what he typed.
	imp, err := api.ContactsImportContacts(ctx, []tg.InputPhoneContact{{ClientID: clientID, Phone: phone, FirstName: phone}})
	if err != nil {
		return bsession.Target{}, lookupError(err)
	}
	var userID int64
	for _, ic := range imp.Imported {
		if ic.ClientID == clientID {
			userID = ic.UserID
		}
	}
	if userID == 0 {
		for _, retry := range imp.RetryContacts {
			if retry == clientID {
				// Telegram took too many imports lately and asked for this one later.
				return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientProviderLimited}
			}
		}
		// No account, or one whose privacy hides it from numbers it does not know.
		return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientNotOnTelegram}
	}
	u := userIn(imp.Users, userID)
	if u == nil {
		// Imported, but Telegram sent no access hash to write to or to
		// remove it with. Never happens in practice; refused rather than guessed.
		return bsession.Target{}, &bsession.RecipientError{Reason: bsession.RecipientNotOnTelegram}
	}
	var release func(context.Context)
	if !had[u.ID] {
		input := &tg.InputUser{UserID: u.ID, AccessHash: u.AccessHash}
		release = func(ctx context.Context) {
			_, _ = api.ContactsDeleteContacts(ctx, []tg.InputUserClass{input})
		}
	}
	if refusal := notToWrite(u, selfID); refusal != nil {
		if release != nil {
			release(ctx)
		}
		return bsession.Target{}, refusal
	}
	t, err := s.targetFor(ctx, u)
	if err != nil {
		if release != nil {
			release(ctx)
		}
		return bsession.Target{}, err
	}
	t.Release = release
	return t, nil
}

// notToWrite refuses himself and anything that is not a person.
func notToWrite(u *tg.User, selfID int64) error {
	switch {
	case u.Self || (selfID != 0 && u.ID == selfID):
		return &bsession.RecipientError{Reason: bsession.RecipientOwnAccount}
	case u.Bot || u.Deleted:
		return &bsession.RecipientError{Reason: bsession.RecipientNotAPerson}
	}
	return nil
}

func userIn(users []tg.UserClass, id int64) *tg.User {
	for _, uc := range users {
		if u, ok := uc.(*tg.User); ok && u.ID == id {
			return u
		}
	}
	return nil
}

func (s *Session) targetFor(ctx context.Context, u *tg.User) (bsession.Target, error) {
	p := peer{Type: "u", ID: u.ID, AccessHash: u.AccessHash}
	chat := chatID(p)
	_, err := s.vault.Get(ctx, "peers", chat)
	if err != nil && !errors.Is(err, sealed.ErrNotFound) {
		return bsession.Target{}, err
	}
	return bsession.Target{ChatID: chat, RecipientID: strconv.FormatInt(u.ID, 10), Known: err == nil, Peer: p}, nil
}

// lookupError names what Telegram said about a lookup, by its type, never its text.
func lookupError(err error) error {
	if d, ok := tgerr.AsFloodWait(err); ok {
		return &bsession.RecipientError{Reason: bsession.RecipientProviderLimited, RetryAfter: d}
	}
	if tgerr.Is(err, "USERNAME_NOT_OCCUPIED", "USERNAME_INVALID", "PHONE_NOT_OCCUPIED",
		"PHONE_NUMBER_INVALID", "PHONE_NUMBER_BANNED") {
		return &bsession.RecipientError{Reason: bsession.RecipientNotOnTelegram}
	}
	return err
}

// SendTo sends the first message and stores the peer, so their answer and a
// second message are ordinary.
func (s *Session) SendTo(ctx context.Context, t bsession.Target, text string) (string, error) {
	api := s.rpcClient()
	if api == nil {
		return "", bsession.ErrNotLinked
	}
	p, ok := t.Peer.(peer)
	if !ok || p.Type != "u" {
		return "", ErrUnknownPeer
	}
	id, err := sendText(ctx, api, &tg.InputPeerUser{UserID: p.ID, AccessHash: p.AccessHash}, t.ChatID, text)
	if err != nil {
		return "", err
	}
	if raw, err := json.Marshal(p); err == nil {
		_ = s.vault.Put(ctx, "peers", t.ChatID, raw)
	}
	return id, nil
}

var _ bsession.Starter = (*Session)(nil)
