package whatsapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

func setup(t *testing.T) (*sealed.Keyring, *sealed.Vault, *sealed.MemoryBackend, sealed.RootKey) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	b := sealed.NewMemoryBackend()
	kr := sealed.NewKeyring(root, b)
	v, err := kr.Create(context.Background(), "conn-wa", Kind)
	if err != nil {
		t.Fatal(err)
	}
	return kr, v, b, root
}

var self = types.NewJID("15551112222", types.DefaultUserServer)

// The linked device survives a deploy: everything whatsmeow needs to resume is
// read back from sealed storage by a new process holding the same root key.
func TestDeviceRoundTripsThroughSealedStorage(t *testing.T) {
	ctx := context.Background()
	_, v, b, root := setup(t)
	st := NewSealedStore(v)
	d := st.NewDevice(waLog.Noop)
	jid := types.NewADJID("15551112222", 0, 12)
	d.ID = &jid
	d.PushName = "Emil"
	d.Account = &waAdv.ADVSignedDeviceIdentity{Details: []byte("details"), AccountSignatureKey: []byte("ask")}
	if err := d.Save(ctx); err != nil {
		t.Fatal(err)
	}

	v2, err := sealed.NewKeyring(root, b).Open(ctx, "conn-wa")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewSealedStore(v2).LoadDevice(ctx, waLog.Noop)
	if err != nil || got == nil {
		t.Fatalf("load: %v", err)
	}
	if *got.NoiseKey.Priv != *d.NoiseKey.Priv || *got.IdentityKey.Pub != *d.IdentityKey.Pub {
		t.Fatal("keys changed across the round trip")
	}
	if *got.SignedPreKey.Signature != *d.SignedPreKey.Signature || got.SignedPreKey.KeyID != 1 {
		t.Fatal("signed pre-key changed across the round trip")
	}
	if got.ID.String() != jid.String() || got.RegistrationID != d.RegistrationID || got.PushName != "Emil" ||
		!proto.Equal(got.Account, d.Account) || !bytes.Equal(got.AdvSecretKey, d.AdvSecretKey) {
		t.Fatalf("device fields changed: %+v", got)
	}

	// None of it is readable in storage.
	for _, blob := range b.Dump() {
		for _, secret := range [][]byte{d.NoiseKey.Priv[:], d.IdentityKey.Priv[:], d.AdvSecretKey, []byte("15551112222")} {
			if bytes.Contains(blob, secret) {
				t.Fatal("device secret or number stored in the clear")
			}
		}
	}
}

func TestSessionsAndIdentitiesAreSealedAndBehaveLikeSqlstore(t *testing.T) {
	ctx := context.Background()
	_, v, b, _ := setup(t)
	s := NewSealedStore(v)
	sess := []byte("signal-session-record")
	_ = s.PutSession(ctx, "15553334444:0", sess)
	_ = s.PutSession(ctx, "15553334444:3", sess)
	_ = s.PutSession(ctx, "15559990000:0", sess)
	if ok, _ := s.HasSession(ctx, "15553334444:0"); !ok {
		t.Fatal("HasSession")
	}
	many, _ := s.GetManySessions(ctx, []string{"15553334444:0", "nobody:0"})
	if !bytes.Equal(many["15553334444:0"], sess) || many["nobody:0"] != nil {
		t.Fatalf("GetManySessions: %v", many)
	}
	if err := s.DeleteAllSessions(ctx, "15553334444"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.HasSession(ctx, "15553334444:3"); ok {
		t.Fatal("DeleteAllSessions left a device session")
	}
	if ok, _ := s.HasSession(ctx, "15559990000:0"); !ok {
		t.Fatal("DeleteAllSessions removed another number's session")
	}

	key := [32]byte{1, 2, 3}
	if ok, _ := s.IsTrustedIdentity(ctx, "a:0", key); !ok {
		t.Fatal("an unseen identity is trusted, as in sqlstore")
	}
	_ = s.PutIdentity(ctx, "a:0", key)
	if ok, _ := s.IsTrustedIdentity(ctx, "a:0", [32]byte{9}); ok {
		t.Fatal("a changed identity must not be trusted")
	}
	for _, blob := range b.Dump() {
		if bytes.Contains(blob, sess) || bytes.Contains(blob, []byte("15559990000")) {
			t.Fatal("a Signal session or a contact's number reached storage in the clear")
		}
	}
}

func TestMigratePNToLID(t *testing.T) {
	ctx := context.Background()
	_, v, _, _ := setup(t)
	s := NewSealedStore(v)
	pn := types.NewJID("15553334444", types.DefaultUserServer)
	lid := types.NewJID("98765", types.HiddenUserServer)
	_ = s.PutSession(ctx, "15553334444:0", []byte("s"))
	_ = s.PutIdentity(ctx, "15553334444:0", [32]byte{7})
	_ = s.PutSenderKey(ctx, "group@g.us", "15553334444:0", []byte("k"))
	if err := s.MigratePNToLID(ctx, pn, lid); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.GetSession(ctx, lid.SignalAddressUser()+":0"); string(b) != "s" {
		t.Fatal("session not moved")
	}
	if b, _ := s.GetSession(ctx, "15553334444:0"); b != nil {
		t.Fatal("old session left behind")
	}
	if b, _ := s.GetSenderKey(ctx, "group@g.us", lid.SignalAddressUser()+":0"); string(b) != "k" {
		t.Fatal("sender key not moved")
	}
}

func TestPreKeys(t *testing.T) {
	ctx := context.Background()
	_, v, _, _ := setup(t)
	s := NewSealedStore(v)
	ks, err := s.GetOrGenPreKeys(ctx, 5)
	if err != nil || len(ks) != 5 || ks[0].KeyID != 1 || ks[4].KeyID != 5 {
		t.Fatalf("first batch: %v %v", len(ks), err)
	}
	if err := s.MarkPreKeysAsUploaded(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.UploadedPreKeyCount(ctx); n != 3 {
		t.Fatalf("uploaded count %d", n)
	}
	ks2, _ := s.GetOrGenPreKeys(ctx, 4)
	if len(ks2) != 4 || ks2[0].KeyID != 4 || ks2[1].KeyID != 5 || ks2[2].KeyID != 6 || ks2[3].KeyID != 7 {
		t.Fatalf("second batch should reuse 4,5 and add 6,7: %v", ids(ks2))
	}
	got, _ := s.GetPreKey(ctx, 2)
	if got == nil || *got.Priv != *ks[1].Priv {
		t.Fatal("GetPreKey round trip")
	}
	_ = s.RemovePreKey(ctx, 2)
	if got, err := s.GetPreKey(ctx, 2); got != nil || err != nil {
		t.Fatal("a removed pre-key is nil, nil, as in sqlstore")
	}
	one, _ := s.GenOnePreKey(ctx)
	if one.KeyID != 8 {
		t.Fatalf("GenOnePreKey id %d", one.KeyID)
	}
}

func ids(ks []*keys.PreKey) []uint32 {
	var out []uint32
	for _, k := range ks {
		out = append(out, k.KeyID)
	}
	return out
}

// Disconnect destroys: the device cannot be loaded from the vault again.
func TestRevokeMakesTheDeviceUnloadable(t *testing.T) {
	ctx := context.Background()
	kr, v, b, root := setup(t)
	st := NewSealedStore(v)
	d := st.NewDevice(waLog.Noop)
	jid := types.NewADJID("15551112222", 0, 12)
	d.ID = &jid
	_ = d.Save(ctx)
	if err := kr.Destroy(ctx, "conn-wa"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadDevice(ctx, waLog.Noop); !errors.Is(err, sealed.ErrDestroyed) {
		t.Fatalf("the live store still loads: %v", err)
	}
	if _, err := sealed.NewKeyring(root, b).Open(ctx, "conn-wa"); err == nil {
		t.Fatal("a new process can still open the destroyed connection")
	}
}

// A resume with no device stored means WhatsApp ended it (or it never
// finished): logged out, no network touched.
func TestResumeWithNoDeviceIsLoggedOut(t *testing.T) {
	_, v, _, _ := setup(t)
	s, _ := Factory()("conn-wa", v, nopRep{}, session.StartOptions{Resume: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Run(ctx); !errors.Is(err, session.ErrLoggedOut) {
		t.Fatalf("got %v", err)
	}
}

type nopRep struct{}

func (nopRep) Status(session.Status)   {}
func (nopRep) Message(session.Inbound) {}

func msg(chat, sender types.JID, fromMe, group bool, m *waE2E.Message) *events.Message {
	return &events.Message{
		Info: types.MessageInfo{
			MessageSource: types.MessageSource{Chat: chat, Sender: sender, IsFromMe: fromMe, IsGroup: group},
			ID:            "3EB0ABC", PushName: "Dana", Timestamp: time.Unix(1_800_000_000, 0),
		},
		Message: m,
	}
}

func TestNormalize(t *testing.T) {
	dana := types.NewJID("15557778888", types.DefaultUserServer)
	group := types.NewJID("120363000000000000", types.GroupServer)

	in, ok := Normalize(msg(dana, dana, false, false, &waE2E.Message{Conversation: proto.String("lunch?")}), self, types.EmptyJID)
	if !ok || in.Body != "lunch?" || in.Direction != "inbound" || in.ChatID != "15557778888@s.whatsapp.net" ||
		in.SenderID != "15557778888" || in.SenderName != "Dana" || in.ThreadKind != "direct" ||
		in.ExternalAccountID != "15551112222" || in.MessageID != "3EB0ABC" {
		t.Fatalf("direct text: %+v %v", in, ok)
	}

	in, ok = Normalize(msg(dana, self, true, false, &waE2E.Message{Conversation: proto.String("yes")}), self, types.EmptyJID)
	if !ok || in.Direction != "outbound" || in.SenderName != "" {
		t.Fatalf("own message: %+v", in)
	}

	mention := &waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{
		Text:        proto.String("@Emil can you?"),
		ContextInfo: &waE2E.ContextInfo{MentionedJID: []string{self.String()}},
	}}
	in, ok = Normalize(msg(group, dana, false, true, mention), self, types.EmptyJID)
	if !ok || in.ThreadKind != "group" || !in.MentionsMe || in.ChatID != group.String() {
		t.Fatalf("group mention: %+v", in)
	}

	photo := &waE2E.Message{ImageMessage: &waE2E.ImageMessage{Caption: proto.String("the lease")}}
	in, ok = Normalize(msg(dana, dana, false, false, photo), self, types.EmptyJID)
	if !ok || in.Body != "the lease" || in.Unsupported != "image" {
		t.Fatalf("photo: %+v", in)
	}

	for name, e := range map[string]*events.Message{
		"status":   msg(types.StatusBroadcastJID, dana, false, false, &waE2E.Message{Conversation: proto.String("x")}),
		"reaction": msg(dana, dana, false, false, &waE2E.Message{ReactionMessage: &waE2E.ReactionMessage{Text: proto.String("👍")}}),
		"revoke":   msg(dana, dana, false, false, &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{}}),
		"empty":    msg(dana, dana, false, false, &waE2E.Message{}),
	} {
		if _, ok := Normalize(e, self, types.EmptyJID); ok {
			t.Fatalf("%s must not become a message", name)
		}
	}
}
