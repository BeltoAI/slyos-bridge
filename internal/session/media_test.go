package session

import (
	"context"
	"errors"
	"testing"

	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

type receiptMediaSession struct {
	*fakeSession
	receipts map[string]string
	sends    int
}

func (s *receiptMediaSession) SendMedia(_ context.Context, _, _ string, media OutgoingMedia) (string, error) {
	s.sends++
	id := "provider-" + media.RequestID
	s.receipts[media.RequestID] = id
	return id, nil
}
func (s *receiptMediaSession) MediaReceipt(_ context.Context, _, _ string, media OutgoingMedia) (string, bool, error) {
	id, ok := s.receipts[media.RequestID]
	return id, ok, nil
}
func (s *receiptMediaSession) DownloadMedia(context.Context, string, string) ([]byte, error) {
	return nil, ErrMediaUnavailable
}

func TestCompletedFilesDoNotSpendTheRetryAllowance(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, sealed.NewMemoryBackend(), nil)
	if _, err := h.mgr.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "qr"}); err != nil {
		t.Fatal(err)
	}
	f := h.session("c1")
	f.scan(ctx)
	s := &receiptMediaSession{fakeSession: f, receipts: map[string]string{}}
	h.mgr.mu.Lock()
	h.mgr.live["c1"].session = s
	h.mgr.mu.Unlock()
	h.mgr.limiter.NoteInbound("c1", "whatsapp", "chat")
	for _, key := range []string{"file0001", "file0002", "file0003", "file0004", "file0005", "file0006"} {
		media := OutgoingMedia{RequestID: key, Filename: "test.pdf", MimeType: "application/pdf", Bytes: []byte("data")}
		if _, err := h.mgr.SendMedia(ctx, "c1", "chat", "", media, true); err != nil {
			t.Fatal(err)
		}
	}
	media := OutgoingMedia{RequestID: "file0001", Filename: "test.pdf", MimeType: "application/pdf", Bytes: []byte("data")}
	if _, err := h.mgr.SendMedia(ctx, "c1", "chat", "", media, true); err != nil {
		t.Fatal("completed file charged against full allowance", err)
	}
	if s.sends != 6 {
		t.Fatal("duplicate provider write")
	}
	if _, err := h.mgr.SendMedia(ctx, "c1", "chat", "", media, false); !errors.Is(err, ErrNotPressed) {
		t.Fatal("cache bypassed press gate", err)
	}
	media.RequestID = "file0007"
	if _, err := h.mgr.SendMedia(ctx, "c1", "chat", "", media, true); !errors.Is(err, ratelimit.ErrPerMinute) {
		t.Fatal("new file bypassed limiter", err)
	}
	if s.sends != 6 {
		t.Fatal("rate-limited file was sent")
	}
}
