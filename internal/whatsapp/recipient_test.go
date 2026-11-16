package whatsapp

import (
	"context"
	"testing"

	"go.mau.fi/whatsmeow/types"

	"github.com/BeltoAI/slyos-bridge/internal/session"
)

func TestOutgoingRecipientComesFromThisAccountsContactStore(t *testing.T) {
	ctx := context.Background()
	_, v, _, _ := setup(t)
	s := &Session{store: NewSealedStore(v)}
	pn := types.NewJID("15557778888", types.DefaultUserServer)
	lid := types.NewJID("987654321001234", types.HiddenUserServer)
	if err := s.store.PutLIDMapping(ctx, lid, pn); err != nil {
		t.Fatal(err)
	}
	if err := s.store.PutContactName(ctx, pn, "Dana Kerr", "Dana"); err != nil {
		t.Fatal(err)
	}
	in := session.Inbound{Direction: "outbound", ThreadKind: "direct", SenderName: "Owner"}
	s.enrichDirectPeer(ctx, lid, self, types.EmptyJID, &in)
	if in.RecipientID != "+15557778888" || in.RecipientName != "Dana Kerr" || in.SenderName != "Owner" {
		t.Fatalf("recipient not resolved independently: %+v", in)
	}
	// Another encrypted connection must neither see the mapping nor the name.
	_, other, _, _ := setup(t)
	isolated := &Session{store: NewSealedStore(other)}
	unknown := session.Inbound{Direction: "outbound", ThreadKind: "direct"}
	isolated.enrichDirectPeer(ctx, lid, self, types.EmptyJID, &unknown)
	if unknown.RecipientID != lid.String() || unknown.RecipientName != "" {
		t.Fatalf("another account's contact leaked: %+v", unknown)
	}
	reply := session.Inbound{Direction: "inbound", ThreadKind: "direct", SenderID: lid.User, SenderName: "Public push name"}
	s.enrichDirectPeer(ctx, lid, self, types.EmptyJID, &reply)
	if reply.SenderID != in.RecipientID || reply.SenderName != in.RecipientName || reply.RecipientID != "" {
		t.Fatalf("reply made a second identity: %+v", reply)
	}
}

func TestRecipientEnrichmentRefusesSelfAndGroups(t *testing.T) {
	ctx := context.Background()
	_, v, _, _ := setup(t)
	s := &Session{store: NewSealedStore(v)}
	peer := types.NewJID("15557778888", types.DefaultUserServer)
	for _, tc := range []struct {
		direction, kind string
		chat            types.JID
	}{
		{"outbound", "direct", self},
		{"outbound", "group", peer},
		{"outbound", "direct", types.NewJID("12345", types.GroupServer)},
	} {
		in := session.Inbound{Direction: tc.direction, ThreadKind: tc.kind}
		s.enrichDirectPeer(ctx, tc.chat, self, types.EmptyJID, &in)
		if in.RecipientID != "" || in.RecipientName != "" {
			t.Fatalf("invented recipient: %+v", in)
		}
	}
}
