package whatsapp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"
)

type fakeMedia struct {
	uploads, downloads, sends int
	data                      []byte
	msg                       *waE2E.Message
	sendErr                   error
	uploadErr                 error
	typ                       whatsmeow.MediaType
}

func (f *fakeMedia) IsLoggedIn() bool { return true }
func (f *fakeMedia) Upload(_ context.Context, b []byte, typ whatsmeow.MediaType) (whatsmeow.UploadResponse, error) {
	f.uploads++
	f.data = append([]byte(nil), b...)
	f.typ = typ
	return whatsmeow.UploadResponse{URL: "https://mmg.whatsapp.net/test", DirectPath: "/test", MediaKey: bytes.Repeat([]byte{1}, 32), FileSHA256: bytes.Repeat([]byte{2}, 32), FileEncSHA256: bytes.Repeat([]byte{3}, 32), FileLength: uint64(len(b))}, f.uploadErr
}
func (f *fakeMedia) Download(_ context.Context, m whatsmeow.DownloadableMessage) ([]byte, error) {
	f.downloads++
	return []byte("data"), nil
}
func (f *fakeMedia) SendMessage(_ context.Context, _ types.JID, m *waE2E.Message, _ ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error) {
	f.sends++
	f.msg = m
	return whatsmeow.SendResponse{ID: "sent-media-1"}, f.sendErr
}

func imageEvent() *events.Message {
	return &events.Message{Info: types.MessageInfo{MessageSource: types.MessageSource{Chat: types.NewJID("12345", types.DefaultUserServer), Sender: types.NewJID("12345", types.DefaultUserServer)}, ID: "incoming-media-1", Timestamp: time.Now()}, Message: &waE2E.Message{ImageMessage: &waE2E.ImageMessage{DirectPath: proto.String("/v/t62/real-provider-path"), MediaKey: bytes.Repeat([]byte{1}, 32), FileSHA256: bytes.Repeat([]byte{2}, 32), FileEncSHA256: bytes.Repeat([]byte{3}, 32), FileLength: proto.Uint64(4), Mimetype: proto.String("image/png")}}}
}

func TestInboundMediaIsLazyBoundAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	kr, v, b, root := setup(t)
	f := &fakeMedia{}
	s := &Session{vault: v, testMedia: f}
	e := imageEvent()
	in, ok := Normalize(e, self, types.EmptyJID)
	if !ok {
		t.Fatal("image lost")
	}
	s.attachMedia(e, &in)
	if len(in.Attachments) != 1 || in.Body != "" || !strings.HasPrefix(in.Attachments[0].Reference, "wa1:") || f.downloads != 0 {
		t.Fatal("metadata did not arrive lazily")
	}
	ref := in.Attachments[0].Reference
	for _, blob := range b.Dump() {
		if bytes.Contains(blob, []byte("real-provider-path")) {
			t.Fatal("bridge stored media plaintext")
		}
	}
	v2, err := sealed.NewKeyring(root, b).Open(ctx, "conn-wa")
	if err != nil {
		t.Fatal(err)
	}
	s2 := &Session{vault: v2, testMedia: f}
	data, err := s2.DownloadMedia(ctx, in.MessageID, ref)
	if err != nil || string(data) != "data" {
		t.Fatal("restart lost file", err)
	}
	if _, err = s2.DownloadMedia(ctx, "different-message", ref); err == nil {
		t.Fatal("wrong message opened")
	}
	_, v3, _, _ := setup(t)
	if _, err = (&Session{vault: v3, testMedia: f}).DownloadMedia(ctx, in.MessageID, ref); err == nil {
		t.Fatal("wrong account opened")
	}
	if _, err = s2.DownloadMedia(ctx, in.MessageID, ref[:len(ref)-5]+"abcde"); err == nil {
		t.Fatal("tampered reference opened")
	}
	if err = kr.Destroy(ctx, "conn-wa"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DownloadMedia(ctx, in.MessageID, ref); err == nil {
		t.Fatal("revoked reference opened")
	}
}

func TestEphemeralAndOversizeMediaNeverGetDownloadCredentials(t *testing.T) {
	for _, mode := range []string{"once", "disappearing", "too-large", "missing-key"} {
		t.Run(mode, func(t *testing.T) {
			_, v, _, _ := setup(t)
			s := &Session{vault: v, testMedia: &fakeMedia{}}
			e := imageEvent()
			switch mode {
			case "once":
				e.IsViewOnce = true
			case "disappearing":
				e.IsEphemeral = true
			case "too-large":
				e.Message.ImageMessage.FileLength = proto.Uint64(session.MaxMediaBytes + 1)
			case "missing-key":
				e.Message.ImageMessage.MediaKey = nil
			}
			in, _ := Normalize(e, self, types.EmptyJID)
			s.attachMedia(e, &in)
			if len(in.Attachments) != 1 || strings.HasPrefix(in.Attachments[0].Reference, "wa1:") {
				t.Fatal("download credential leaked")
			}
			if _, err := s.DownloadMedia(context.Background(), in.MessageID, in.Attachments[0].Reference); err == nil {
				t.Fatal("forbidden media downloaded")
			}
		})
	}
}

func mediaSession(t *testing.T) (*Session, *fakeMedia) {
	_, v, _, _ := setup(t)
	_ = v.Put(context.Background(), "chats", "12345@s.whatsapp.net", []byte{1})
	f := &fakeMedia{}
	return &Session{vault: v, testMedia: f}, f
}
func file(mime string) session.OutgoingMedia {
	return session.OutgoingMedia{RequestID: "11111111-2222-4333-8444-555555555555", Filename: "sample", MimeType: mime, Bytes: []byte("data")}
}

func TestOutgoingFilesKeepBytesCaptionAndType(t *testing.T) {
	for _, mt := range []string{"image/png", "video/mp4", "application/pdf", "audio/mpeg"} {
		t.Run(mt, func(t *testing.T) {
			s, f := mediaSession(t)
			id, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "The file you asked for", file(mt))
			if err != nil || id == "" || string(f.data) != "data" || f.sends != 1 {
				t.Fatal("file was not sent", err)
			}
			caption := f.msg.GetDocumentMessage().GetCaption()
			if mt == "image/png" {
				caption = f.msg.GetImageMessage().GetCaption()
			}
			if mt == "video/mp4" {
				caption = f.msg.GetVideoMessage().GetCaption()
			}
			if caption != "The file you asked for" {
				t.Fatal("caption lost")
			}
		})
	}
}

func TestVoiceAndRetryDoNotSendTwice(t *testing.T) {
	s, f := mediaSession(t)
	in := file("audio/ogg")
	in.Voice = true
	first, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", in)
	if err != nil || !f.msg.GetAudioMessage().GetPTT() {
		t.Fatal("not a voice note", err)
	}
	second, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", in)
	if err != nil || first != second || f.sends != 1 || f.uploads != 1 {
		t.Fatal("retry sent again", err)
	}
	in.Bytes = []byte("changed")
	if _, err = s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", in); err == nil {
		t.Fatal("id reused with different content")
	}
}

func TestUncertainSendNeverAutomaticallyResends(t *testing.T) {
	s, f := mediaSession(t)
	f.sendErr = errors.New("ack lost")
	for i := 0; i < 2; i++ {
		if _, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", file("application/pdf")); !errors.Is(err, session.ErrMediaUncertain) {
			t.Fatal(err)
		}
	}
	if f.sends != 1 || f.uploads != 1 {
		t.Fatal("uncertain send duplicated")
	}
}

func TestUploadFailureCanRetryAndUnknownChatCannotUpload(t *testing.T) {
	s, f := mediaSession(t)
	f.uploadErr = errors.New("offline")
	if _, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", file("application/pdf")); err == nil {
		t.Fatal("upload failed silently")
	}
	f.uploadErr = nil
	if _, err := s.SendMedia(context.Background(), "12345@s.whatsapp.net", "", file("application/pdf")); err != nil {
		t.Fatal(err)
	}
	if f.sends != 1 {
		t.Fatal("wrong send count")
	}
	if _, err := s.SendMedia(context.Background(), "unknown@s.whatsapp.net", "", file("application/pdf")); err == nil {
		t.Fatal("unknown chat allowed")
	}
	if f.uploads != 2 {
		t.Fatal("unknown chat uploaded")
	}
}

func TestDownloadReaderRefusesUnboundedBody(t *testing.T) {
	b := &boundedMediaBody{ReadCloser: io.NopCloser(strings.NewReader("too much")), remaining: 3}
	got, err := io.ReadAll(b)
	if err == nil || len(got) != 3 {
		t.Fatal("size limit ignored")
	}
}
