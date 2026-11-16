package session

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// ── STARTING A CHAT WITH SOMEBODY WHO HAS NOT WRITTEN ──────────────────────
//
// The owner, 2026-10-23: the Brain and the Inbox's "new message to anyone"
// must be able to message people FIRST on his own WhatsApp, Telegram and
// Signal. Until then every session refused a chat that had not written to it.
//
// The rules that came with it, and where each one lives:
//
//   - PRESS-TO-SEND: Manager.Start refuses anything a person did not press,
//     exactly as Send does (the brain refused it first).
//   - ONE EXACT PERSON: `to` is one phone number in E.164 (+ and digits) or,
//     on Telegram, one @username. Never a name, never a list, never a guess.
//   - THE BAN-RISK GUARD: ratelimit/start.go — StartsPerDay a day,
//     StartSpacing apart — asked BEFORE the provider is, so a refused start
//     looks nobody up.
//   - NOTHING ABOUT THE PERSON IS LOGGED: a RecipientError's text is its
//     reason, never the number or the handle.
//
// A session that can start chats implements Starter. Resolve finds the person
// (WhatsApp: is this number on WhatsApp; Telegram: the username, or the number
// through a contact import; Signal: Signal's contact discovery) and sends
// nothing. SendTo sends the first message to what Resolve found and remembers
// the chat, so a second message before they answer is an ordinary send.
type Starter interface {
	Resolve(ctx context.Context, to string) (Target, error)
	SendTo(ctx context.Context, t Target, text string) (messageID string, err error)
}

// Target is one person a chat can be started with, as the provider named them.
type Target struct {
	// The chat id this account's messages with them carry (Inbound.ChatID):
	// the brain names its conversation by it, so their answer lands there.
	ChatID string
	// The provider's id for the person, as Inbound.SenderID carries it, so
	// the brain can tell their answer comes from the person it wrote to.
	RecipientID string
	// True when this account already has a chat with them (they wrote, or
	// it was started before): not a brand-new chat, so not counted as one.
	Known bool
	// Release undoes what Resolve did to find them — Telegram's contact
	// import is removed — however the start ends. Nil when there is nothing.
	Release func(ctx context.Context)
	// The provider's own handle on the person; only the session reads it.
	Peer any
}

// Recipient refusals. Each is a fact the person can act on, and the API
// answers with the reason itself (422), never a sentence of ours.
const (
	RecipientBadShape        = "bad_recipient"         // not a number in E.164, or not a @username
	RecipientNotOnWhatsApp   = "not_on_whatsapp"       // WhatsApp: "That number isn't on WhatsApp."
	RecipientNotOnTelegram   = "not_on_telegram"       // no Telegram account at that username or number
	RecipientNotOnSignal     = "not_on_signal"         // not on Signal, or not findable by number
	RecipientNotAPerson      = "not_a_person"          // a Telegram channel, group or bot
	RecipientOwnAccount      = "own_account"           // his own number or account
	RecipientProviderLimited = "provider_rate_limited" // the provider asked us to wait
)

// RecipientError refuses a start for a reason about the recipient. Its text is
// the reason and nothing else, so it can never carry a number into a log.
type RecipientError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *RecipientError) Error() string { return "session: recipient refused (" + e.Reason + ")" }

// ErrCannotStart is a session of a kind that cannot start chats.
var ErrCannotStart = errors.New("session: this kind cannot start a chat")

// E164 is a phone number as the brain sends it and every provider is asked
// for it: + then digits. THE + IS REQUIRED — without it a country code cannot
// be told from the first digits of a national number (api.phonePattern).
var E164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// TelegramUsername is "@" and a Telegram username: a letter first, then
// letters, digits and underscores, 4 to 32 in all (collectible usernames are
// 4; ordinary ones 5).
var TelegramUsername = regexp.MustCompile(`^@[A-Za-z][A-Za-z0-9_]{3,31}$`)

// Digits is a number's digits, for comparing two spellings of one number.
func Digits(phone string) string {
	out := make([]byte, 0, len(phone))
	for i := 0; i < len(phone); i++ {
		if c := phone[i]; c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	return string(out)
}
