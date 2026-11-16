package whatsapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// fakeChatter is WhatsApp as far as starting a chat goes: a directory of who
// is on it, and a record of what was asked and sent.
type fakeChatter struct {
	mu        sync.Mutex
	directory map[string]types.IsOnWhatsAppResponse
	asked     []string
	sentTo    []types.JID
	texts     []string
}

func (f *fakeChatter) IsLoggedIn() bool { return true }

func (f *fakeChatter) IsOnWhatsApp(_ context.Context, phones []string) ([]types.IsOnWhatsAppResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, phones...)
	out := make([]types.IsOnWhatsAppResponse, 0, len(phones))
	for _, p := range phones {
		if r, ok := f.directory[p]; ok {
			out = append(out, r)
			continue
		}
		// What WhatsApp answers for a number with no account.
		out = append(out, types.IsOnWhatsAppResponse{Query: p, JID: types.NewJID(p[1:], types.DefaultUserServer)})
	}
	return out, nil
}

func (f *fakeChatter) SendMessage(_ context.Context, to types.JID, m *waE2E.Message, _ ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentTo = append(f.sentTo, to)
	f.texts = append(f.texts, m.GetConversation())
	return whatsmeow.SendResponse{ID: "3EB0FIRST"}, nil
}

// linkedWA is the real Session with its connection to WhatsApp replaced by a
// fakeChatter: Resolve, SendTo and Send are the real ones.
type linkedWA struct{ *Session }

func (l linkedWA) Run(ctx context.Context) error { <-ctx.Done(); return nil }

const herNumber = "+15557654321"

var (
	herLID = types.NewJID("88001234567890", types.HiddenUserServer)
	herPN  = types.NewJID("15557654321", types.DefaultUserServer)
)

func startManager(t *testing.T) (*session.Manager, *Session, *fakeChatter) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	fc := &fakeChatter{directory: map[string]types.IsOnWhatsAppResponse{
		herNumber: {Query: herNumber, JID: herLID, PhoneNumber: herPN, IsIn: true},
	}}
	var made *Session
	mgr := session.NewManager(sealed.NewKeyring(root, sealed.NewMemoryBackend()), map[string]session.Factory{
		Kind: func(_ string, v *sealed.Vault, rep session.Reporter, _ session.StartOptions) (session.Session, error) {
			made = &Session{vault: v, store: NewSealedStore(v), rep: rep, testChat: fc,
				st: session.Status{State: session.StateLinked, ExternalAccountID: self.User}}
			return linkedWA{made}, nil
		},
	}, nopSink{}, ratelimit.New(nil), logsafe.New(io.Discard))
	t.Cleanup(mgr.Shutdown)
	if _, err := mgr.Connect(context.Background(), "conn-wa", Kind, session.StartOptions{Method: "qr"}); err != nil {
		t.Fatal(err)
	}
	return mgr, made, fc
}

type nopSink struct{}

func (nopSink) Message(context.Context, string, string, session.Inbound) error { return nil }
func (nopSink) Status(context.Context, string, string, session.Status) error   { return nil }

// A number that is not on WhatsApp: "That number isn't on WhatsApp." —
// refused after one question, and nothing is sent.
func TestANumberNotOnWhatsAppIsRefused(t *testing.T) {
	mgr, _, fc := startManager(t)
	_, err := mgr.Start(context.Background(), "conn-wa", "+15550009999", "hello", true)
	var refused *session.RecipientError
	if !errors.As(err, &refused) || refused.Reason != session.RecipientNotOnWhatsApp {
		t.Fatalf("err = %v, want not_on_whatsapp", err)
	}
	if len(fc.asked) != 1 || fc.asked[0] != "+15550009999" {
		t.Fatalf("asked WhatsApp about %v, want that one number", fc.asked)
	}
	if len(fc.sentTo) != 0 {
		t.Fatal("a message went to a number that is not on WhatsApp")
	}
}

// A number on WhatsApp: checked first, then the first message goes to the
// account WhatsApp named (its LID), and the brain is told that chat and who
// is in it. A second message before she answers is an ordinary send.
func TestStartingAChatSendsToTheAccountWhatsAppNamed(t *testing.T) {
	ctx := context.Background()
	mgr, _, fc := startManager(t)
	got, err := mgr.Start(ctx, "conn-wa", herNumber, "Running late, sorry!", true)
	if err != nil {
		t.Fatal(err)
	}
	want := session.Started{ChatID: herLID.String(), MessageID: "3EB0FIRST", RecipientID: herLID.User, New: true}
	if got != want {
		t.Fatalf("started %+v, want %+v", got, want)
	}
	if len(fc.asked) != 1 || len(fc.sentTo) != 1 || fc.sentTo[0] != herLID || fc.texts[0] != "Running late, sorry!" {
		t.Fatalf("asked %v, sent %v %v", fc.asked, fc.sentTo, fc.texts)
	}
	if _, err := mgr.Send(ctx, "conn-wa", herLID.String(), "and another thing", true); err != nil {
		t.Fatalf("a second message in the chat he started: %v", err)
	}
	if _, err := mgr.Send(ctx, "conn-wa", "15550001111@s.whatsapp.net", "hi", true); !errors.Is(err, ErrUnknownChat) {
		t.Fatalf("an ordinary send to a chat nobody started: %v", err)
	}
}

// Somebody he already chats with under their number: that chat is the one
// named, and it is not a brand-new chat.
func TestAChatHeAlreadyHasIsNotNew(t *testing.T) {
	ctx := context.Background()
	mgr, s, _ := startManager(t)
	if err := s.vault.Put(ctx, "chats", herPN.String(), []byte{1}); err != nil {
		t.Fatal(err)
	}
	got, err := mgr.Start(ctx, "conn-wa", herNumber, "hi", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.New || got.ChatID != herPN.String() || got.RecipientID != herPN.User {
		t.Fatalf("started %+v, want the chat he has, not counted as new", got)
	}
}

// His own number, and anything that is not one number in E.164, is refused
// before WhatsApp is asked.
func TestHisOwnNumberAndBadShapesAreRefused(t *testing.T) {
	_, s, fc := startManager(t)
	for to, reason := range map[string]string{
		"+" + self.User: session.RecipientOwnAccount,
		"5557654321":    session.RecipientBadShape,
		"@dana":         session.RecipientBadShape,
	} {
		_, err := s.Resolve(context.Background(), to)
		var refused *session.RecipientError
		if !errors.As(err, &refused) || refused.Reason != reason {
			t.Fatalf("%s: err = %v, want %s", to, err, reason)
		}
	}
	if len(fc.asked) != 0 {
		t.Fatalf("WhatsApp was asked about %v", fc.asked)
	}
}
