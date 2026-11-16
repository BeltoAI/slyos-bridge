package whatsapp

import (
	"context"
	"strings"

	"go.mau.fi/whatsmeow/types"

	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// Outgoing messages report our own push name. The other person must instead come
// from the direct chat and this connection's encrypted WhatsApp contact store.
// A LID is not a phone number: only WhatsApp's stored mapping may resolve it.
// Both directions use the same identity, so a reply cannot create a second person.
func (s *Session) enrichDirectPeer(ctx context.Context, chat, self, selfLID types.JID, in *session.Inbound) {
	if (in.Direction != "outbound" && in.Direction != "inbound") || in.ThreadKind != "direct" || s.store == nil {
		return
	}
	chat = chat.ToNonAD()
	if chat.User == "" || (chat.Server != types.DefaultUserServer && chat.Server != types.HiddenUserServer) ||
		chat == self.ToNonAD() || chat == selfLID.ToNonAD() {
		return
	}
	peer := chat
	if chat.Server == types.HiddenUserServer {
		if pn, err := s.store.GetPNForLID(ctx, chat); err == nil && !pn.IsEmpty() {
			peer = pn.ToNonAD()
		}
	}
	if peer == self.ToNonAD() || peer == selfLID.ToNonAD() {
		return
	}
	// Keep an unresolved LID in its own namespace, never strip it into digits
	// that could collide with a person's telephone number.
	identifier := peer.String()
	if peer.Server == types.DefaultUserServer {
		identifier = "+" + peer.User
	}
	if in.Direction == "outbound" {
		in.RecipientID = identifier
	} else {
		in.SenderID = identifier
	}
	for _, jid := range []types.JID{peer, chat} {
		contact, err := s.store.GetContact(ctx, jid)
		if err != nil || !contact.Found {
			continue
		}
		for _, name := range []string{contact.FullName, contact.FirstName, contact.BusinessName, contact.PushName} {
			if strings.TrimSpace(name) != "" {
				if in.Direction == "outbound" {
					in.RecipientName = strings.TrimSpace(name)
				} else {
					in.SenderName = strings.TrimSpace(name)
				}
				return
			}
		}
	}
}
