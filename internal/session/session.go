// Package session runs one long-lived session per connection and keeps it
// alive: across a dropped socket, a crash in a library, and a deploy. ADR 0093.
package session

import (
	"context"
	"errors"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

// States a connection can be in. The brain shows these to the person, so each
// is a distinct fact rather than a shade of "not working".
const (
	StatePairing          = "pairing"           // a QR or a pairing code is on screen
	StateAwaitingCode     = "awaiting_code"     // Telegram sent a login code to the person's app
	StateAwaitingPassword = "awaiting_password" // Telegram two-step verification
	StateLinked           = "linked"
	StateReconnecting     = "reconnecting" // linked, socket down, the watchdog is retrying
	StateLoggedOut        = "logged_out"   // the person unlinked us from their phone
	StateExpired          = "expired"      // a pairing that nobody completed
	StateFailed           = "failed"
)

var (
	// ErrLoggedOut means the provider ended the session (the person removed
	// the linked device). Not retried: the keys are destroyed.
	ErrLoggedOut = errors.New("session: logged out by the provider")
	// ErrPairingExpired means nobody scanned or typed in time.
	ErrPairingExpired = errors.New("session: pairing expired")
	// ErrNotLinked refuses a send on a session that cannot send yet.
	ErrNotLinked = errors.New("session: not linked")
	// ErrNotPressed refuses any send that a person did not press. The brain
	// checks first (outbox.pressed_by_person); this is the second check, in
	// the process that actually talks to WhatsApp.
	ErrNotPressed = errors.New("session: send was not pressed by a person")
	// ErrUnknownConnection is an id the bridge holds nothing for.
	ErrUnknownConnection = errors.New("session: unknown connection")
	// ErrWrongState refuses a code submitted when no code is awaited.
	ErrWrongState = errors.New("session: not waiting for that")
)

// Challenge is what the person must do to finish linking.
type Challenge struct {
	// "qr": Data is the string to render as a QR code.
	// "pairing_code": Data is the 8-character code to type into WhatsApp.
	// "phone_code": Telegram sent a code; nothing to show but a field.
	// "password": Telegram two-step verification; a password field.
	Kind      string    `json:"kind"`
	Data      string    `json:"data,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	// "phone_code" only: where Telegram delivered it — "app" (inside the
	// Telegram app, the usual case), "sms", "call", "email" or "other" — so
	// the person is told where to look. Not a secret; it does travel in a
	// status event.
	Via string `json:"via,omitempty"`
	// "phone_code" only: how many characters Telegram said the code has,
	// when it said. Zero when unknown.
	Length int `json:"length,omitempty"`
}

// Reasons a status carries. Some END a link attempt (a PairingError carries
// them); two only explain why the same question is being asked again.
const (
	ReasonBadPhone        = "bad_phone"         // the provider refused the number
	ReasonRateLimited     = "rate_limited"      // the provider asked us to wait
	ReasonNoAccount       = "no_account"        // no Telegram account has that number
	ReasonPhoneBanned     = "phone_banned"      // the provider barred the number
	ReasonCodeExpired     = "code_expired"      // Telegram's code ran out
	ReasonTooManyAttempts = "too_many_attempts" // too many wrong codes or passwords
	ReasonPairingFailed   = "pairing_failed"    // anything else, said plainly
	ReasonWrongCode       = "wrong_code"        // asked again: that code was wrong
	ReasonWrongPassword   = "wrong_password"    // asked again: that password was wrong
)

// PairingError ends a link attempt for a reason the person can act on: a
// number the provider refused, a flood wait, too many wrong codes. TERMINAL —
// the watchdog does not retry it, because for a phone-number link a retry is
// another code sent to somebody's phone that nobody asked for. Its text is
// the reason and nothing else, so it can never carry the number into a log.
type PairingError struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *PairingError) Error() string { return "session: pairing refused (" + e.Reason + ")" }

// RetryAfterSeconds rounds a provider's wait up to whole seconds; zero stays
// zero, meaning the provider named no wait.
func RetryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// Status is a session's state as the brain sees it.
type Status struct {
	State     string     `json:"state"`
	Challenge *Challenge `json:"challenge,omitempty"`
	// Set once linked. The account's own id on the provider (a WhatsApp
	// number, a Telegram user id): it goes to the brain, which already holds
	// the same for every channel, and never to a log line.
	ExternalAccountID string `json:"externalAccountId,omitempty"`
	DisplayName       string `json:"displayName,omitempty"`
	// When the phone that owns a WhatsApp linked device was last seen. A
	// linked device stops working after ~14 days without its phone online;
	// the manager warns at 12. Zero where it does not apply.
	PhoneLastSeen time.Time `json:"phoneLastSeen,omitzero"`
	// Set by the manager, not the session.
	Warning string `json:"warning,omitempty"`
	// Why the state is what it is: a PairingError's reason on a "failed"
	// state, or "wrong_code" / "wrong_password" while the same question is
	// asked again. One of the Reason* constants; never free text.
	Reason string `json:"reason,omitempty"`
	// How long the provider asked us to wait before another code, when it
	// said (Telegram's FLOOD_WAIT_n), or our own per-number limit's wait.
	RetryAfterSeconds int `json:"retryAfterSeconds,omitempty"`
	// Bumped by a session every time it sets a status, so the manager can
	// tell "Telegram answered that code" from "nothing has happened yet"
	// even when the answer is the same question again. Never on the wire.
	Seq uint64 `json:"-"`
}

// Inbound is one message as the bridge hands it to the brain. Its fields map
// one to one onto NormalizedMessage in services/connectors/core, and the
// brain's bridge connector does that mapping in its pure normalize().
type Inbound struct {
	ExternalAccountID string    `json:"externalAccountId"`
	ChatID            string    `json:"chatId"`
	MessageID         string    `json:"messageId"`
	Direction         string    `json:"direction"` // "inbound" | "outbound"
	Body              string    `json:"body"`
	SentAt            time.Time `json:"sentAt"`
	SenderID          string    `json:"senderId,omitempty"`
	SenderName        string    `json:"senderName,omitempty"`
	ThreadKind        string    `json:"threadKind"` // "direct" | "group"
	ChatTitle         string    `json:"chatTitle,omitempty"`
	MentionsMe        bool      `json:"mentionsMe,omitempty"`
	// What this message carried that the bridge did not forward, e.g.
	// "image". Phase 1 forwards text only and says so, rather than dropping
	// a photo without a trace.
	Unsupported string `json:"unsupported,omitempty"`
}

// Reporter is how a session tells the manager what happened. The manager
// persists the state and forwards both to the brain.
type Reporter interface {
	Status(Status)
	Message(Inbound)
}

// Session is one connection's live link to a provider.
type Session interface {
	// Run connects and blocks until ctx is done (nil), the provider logs the
	// session out (ErrLoggedOut), a pairing expires (ErrPairingExpired), or
	// the connection fails (any other error — the watchdog retries).
	Run(ctx context.Context) error
	Status() Status
	// SubmitCode finishes a Telegram login: a phone code, and the two-step
	// password when one is asked for.
	SubmitCode(ctx context.Context, code, password string) error
	Send(ctx context.Context, chatID, text string) (messageID string, err error)
	// Logout asks the provider to forget this linked device.
	Logout(ctx context.Context) error
}

// StartOptions is how a connection was asked to begin.
type StartOptions struct {
	Method string // "qr" | "code" (WhatsApp pairing code, Telegram phone code)
	Phone  string // for "code"; never stored, never logged
	Resume bool   // true when restarting from sealed state after a deploy
}

// Factory builds a session for a kind.
type Factory func(connID string, vault *sealed.Vault, rep Reporter, opts StartOptions) (Session, error)
