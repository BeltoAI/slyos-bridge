package telegram

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	bsession "github.com/BeltoAI/slyos-bridge/internal/session"
)

// fakeTG is Telegram as far as starting a chat goes: who has a username, who
// is behind a number, his contact list, and every call in order.
type fakeTG struct {
	mu           sync.Mutex
	usernames    map[string]*tg.ContactsResolvedPeer
	contacts     []tg.Contact
	contactUsers []tg.UserClass
	byPhone      map[string]*tg.User
	sendErr      error

	calls   []string
	sentTo  []tg.InputPeerUser
	deleted []tg.InputUser
	imports []tg.InputPhoneContact
}

func (f *fakeTG) note(c string) { f.calls = append(f.calls, c) }

func (f *fakeTG) ContactsResolveUsername(_ context.Context, r *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("resolve " + r.Username)
	if res, ok := f.usernames[r.Username]; ok {
		return res, nil
	}
	return nil, tgerr.New(400, "USERNAME_NOT_OCCUPIED")
}

func (f *fakeTG) ContactsGetContacts(context.Context, int64) (tg.ContactsContactsClass, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("contacts")
	return &tg.ContactsContacts{Contacts: f.contacts, Users: f.contactUsers}, nil
}

func (f *fakeTG) ContactsImportContacts(_ context.Context, cs []tg.InputPhoneContact) (*tg.ContactsImportedContacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("import")
	f.imports = append(f.imports, cs...)
	u, ok := f.byPhone[cs[0].Phone]
	if !ok {
		return &tg.ContactsImportedContacts{}, nil
	}
	return &tg.ContactsImportedContacts{
		Imported: []tg.ImportedContact{{UserID: u.ID, ClientID: cs[0].ClientID}},
		Users:    []tg.UserClass{u},
	}, nil
}

func (f *fakeTG) ContactsDeleteContacts(_ context.Context, ids []tg.InputUserClass) (tg.UpdatesClass, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("delete")
	for _, id := range ids {
		if u, ok := id.(*tg.InputUser); ok {
			f.deleted = append(f.deleted, *u)
		}
	}
	return &tg.Updates{}, nil
}

func (f *fakeTG) MessagesSendMessage(_ context.Context, r *tg.MessagesSendMessageRequest) (tg.UpdatesClass, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.note("send")
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	if p, ok := r.Peer.(*tg.InputPeerUser); ok {
		f.sentTo = append(f.sentTo, *p)
	}
	return &tg.UpdateShortSentMessage{ID: 77}, nil
}

func (f *fakeTG) order() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ",")
}

// linkedTG is the real Session, already linked, with Telegram replaced by a
// fakeTG: Resolve, SendTo and Send are the real ones.
type linkedTG struct{ *Session }

func (l linkedTG) Run(ctx context.Context) error { <-ctx.Done(); return nil }

const (
	selfUserID = int64(1000)
	theirPhone = "+447700900123"
)

type nopSink struct{}

func (nopSink) Message(context.Context, string, string, bsession.Inbound) error { return nil }
func (nopSink) Status(context.Context, string, string, bsession.Status) error   { return nil }

func startTG(t *testing.T, f *fakeTG) *bsession.Manager {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	mgr := bsession.NewManager(sealed.NewKeyring(root, sealed.NewMemoryBackend()), map[string]bsession.Factory{
		Kind: func(_ string, v *sealed.Vault, rep bsession.Reporter, _ bsession.StartOptions) (bsession.Session, error) {
			return linkedTG{&Session{vault: v, rep: rep, testRPC: f, selfID: selfUserID, selfPhone: "15551112222",
				codes: make(chan string, 1), passwords: make(chan string, 1),
				st: bsession.Status{State: bsession.StateLinked, ExternalAccountID: "1000"}}}, nil
		},
	}, nopSink{}, ratelimit.New(nil), logsafe.New(io.Discard))
	t.Cleanup(mgr.Shutdown)
	if _, err := mgr.Connect(context.Background(), "conn-tg", Kind, bsession.StartOptions{Method: "qr"}); err != nil {
		t.Fatal(err)
	}
	return mgr
}

func reason(t *testing.T, err error) string {
	t.Helper()
	var refused *bsession.RecipientError
	if !errors.As(err, &refused) {
		t.Fatalf("err = %v, want a recipient refusal", err)
	}
	return refused.Reason
}

// An @username resolves to the person, who is written to with the access hash
// Telegram gave — and nothing touches his contacts.
func TestAUsernameResolvesAndIsWrittenTo(t *testing.T) {
	ctx := context.Background()
	f := &fakeTG{usernames: map[string]*tg.ContactsResolvedPeer{
		"dana_k": {Peer: &tg.PeerUser{UserID: 42}, Users: []tg.UserClass{&tg.User{ID: 42, AccessHash: 9001, FirstName: "Dana"}}},
	}}
	mgr := startTG(t, f)
	got, err := mgr.Start(ctx, "conn-tg", "@dana_k", "hi Dana, it's Emil", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := (bsession.Started{ChatID: "u42", MessageID: "u42:77", RecipientID: "42", New: true}); got != want {
		t.Fatalf("started %+v, want %+v", got, want)
	}
	if f.order() != "resolve dana_k,send" {
		t.Fatalf("calls = %s", f.order())
	}
	if len(f.sentTo) != 1 || f.sentTo[0].UserID != 42 || f.sentTo[0].AccessHash != 9001 {
		t.Fatalf("sent to %+v", f.sentTo)
	}
	// The peer was kept: a second message before she answers is ordinary.
	if _, err := mgr.Send(ctx, "conn-tg", "u42", "and one more", true); err != nil {
		t.Fatalf("a second message: %v", err)
	}
}

// A channel, a group or a bot has a username too; none is a person. A
// username nobody has is said as that. Nothing is sent to any of them.
func TestOnlyAPersonIsWrittenTo(t *testing.T) {
	f := &fakeTG{usernames: map[string]*tg.ContactsResolvedPeer{
		"newsroom": {Peer: &tg.PeerChannel{ChannelID: 7}},
		"helpbot":  {Peer: &tg.PeerUser{UserID: 8}, Users: []tg.UserClass{&tg.User{ID: 8, Bot: true}}},
		"emil":     {Peer: &tg.PeerUser{UserID: selfUserID}, Users: []tg.UserClass{&tg.User{ID: selfUserID, Self: true}}},
	}}
	mgr := startTG(t, f)
	for to, want := range map[string]string{
		"@newsroom":   bsession.RecipientNotAPerson,
		"@helpbot":    bsession.RecipientNotAPerson,
		"@emil":       bsession.RecipientOwnAccount,
		"@nobody_xyz": bsession.RecipientNotOnTelegram,
	} {
		_, err := mgr.Start(context.Background(), "conn-tg", to, "hi", true)
		if got := reason(t, err); got != want {
			t.Fatalf("%s: %s, want %s", to, got, want)
		}
	}
	if strings.Contains(f.order(), "send") {
		t.Fatalf("something was sent: %s", f.order())
	}
}

// A number not in his contacts is imported, written to, and the imported
// contact is REMOVED afterwards — after the message, never before it.
func TestAnImportedContactIsRemovedAfterwards(t *testing.T) {
	f := &fakeTG{byPhone: map[string]*tg.User{theirPhone: {ID: 55, AccessHash: 777, Phone: "447700900123"}}}
	mgr := startTG(t, f)
	got, err := mgr.Start(context.Background(), "conn-tg", theirPhone, "hello", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.ChatID != "u55" || got.RecipientID != "55" || !got.New {
		t.Fatalf("started %+v", got)
	}
	if f.order() != "contacts,import,send,delete" {
		t.Fatalf("calls = %s, want the contact removed after the send", f.order())
	}
	if len(f.deleted) != 1 || f.deleted[0].UserID != 55 || f.deleted[0].AccessHash != 777 {
		t.Fatalf("removed %+v, want the imported contact", f.deleted)
	}
	// Imported under the number itself: no name was invented for anybody.
	if imp := f.imports[0]; imp.Phone != theirPhone || imp.FirstName != theirPhone || imp.LastName != "" {
		t.Fatalf("imported as %+v", imp)
	}
}

// The import is removed even when the message then fails.
func TestAnImportIsRemovedEvenWhenTheMessageFails(t *testing.T) {
	f := &fakeTG{byPhone: map[string]*tg.User{theirPhone: {ID: 55, AccessHash: 777}}, sendErr: tgerr.New(400, "PEER_FLOOD")}
	mgr := startTG(t, f)
	if _, err := mgr.Start(context.Background(), "conn-tg", theirPhone, "hello", true); err == nil {
		t.Fatal("a refused message reported as sent")
	}
	if f.order() != "contacts,import,send,delete" || len(f.deleted) != 1 {
		t.Fatalf("calls = %s, deleted %+v", f.order(), f.deleted)
	}
}

// A contact he already had is used as it is and never removed: found by
// number in his list, or — when his list does not show the number — found
// by the import to be somebody already in it.
func TestAContactHeHadIsNeverRemoved(t *testing.T) {
	saved := &fakeTG{
		contacts:     []tg.Contact{{UserID: 66}},
		contactUsers: []tg.UserClass{&tg.User{ID: 66, AccessHash: 6, Phone: "447700900123", Contact: true}},
	}
	if _, err := startTG(t, saved).Start(context.Background(), "conn-tg", theirPhone, "hi", true); err != nil {
		t.Fatal(err)
	}
	if saved.order() != "contacts,send" || len(saved.deleted) != 0 {
		t.Fatalf("calls = %s, deleted %+v", saved.order(), saved.deleted)
	}

	hidden := &fakeTG{
		contacts:     []tg.Contact{{UserID: 77}},
		contactUsers: []tg.UserClass{&tg.User{ID: 77, AccessHash: 7, Contact: true}},
		byPhone:      map[string]*tg.User{theirPhone: {ID: 77, AccessHash: 7}},
	}
	if _, err := startTG(t, hidden).Start(context.Background(), "conn-tg", theirPhone, "hi", true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hidden.order(), "delete") {
		t.Fatalf("a contact he had was removed: %s", hidden.order())
	}
}

// A number with no Telegram account behind it (or one hidden from strangers)
// is refused, nothing is sent, and there is nothing to remove. His own number
// is refused before anything is imported.
func TestANumberNotOnTelegramIsRefused(t *testing.T) {
	f := &fakeTG{}
	mgr := startTG(t, f)
	_, err := mgr.Start(context.Background(), "conn-tg", theirPhone, "hello", true)
	if got := reason(t, err); got != bsession.RecipientNotOnTelegram {
		t.Fatalf("reason %s", got)
	}
	if f.order() != "contacts,import" {
		t.Fatalf("calls = %s", f.order())
	}
	_, err = mgr.Start(context.Background(), "conn-tg", "+15551112222", "hello", true)
	if got := reason(t, err); got != bsession.RecipientOwnAccount {
		t.Fatalf("his own number: %s", got)
	}
	if f.order() != "contacts,import" {
		t.Fatalf("his own number reached Telegram: %s", f.order())
	}
}
