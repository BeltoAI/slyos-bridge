package whatsapp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"google.golang.org/protobuf/proto"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

type mediaClient interface {
	IsLoggedIn() bool
	Upload(context.Context, []byte, whatsmeow.MediaType) (whatsmeow.UploadResponse, error)
	Download(context.Context, whatsmeow.DownloadableMessage) ([]byte, error)
	SendMessage(context.Context, types.JID, *waE2E.Message, ...whatsmeow.SendRequestExtra) (whatsmeow.SendResponse, error)
}

func (s *Session) mediaClient() mediaClient {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.testMedia != nil {
		return s.testMedia
	}
	if s.cli == nil {
		return nil
	}
	return s.cli
}

// A minimal descriptor, encrypted with the connection key. No URL or media
// key is exposed to the browser, and the bridge stores no message records.
type mediaReference struct {
	Path             string
	Key, SHA, EncSHA []byte
	Type             whatsmeow.MediaType
	Size             uint64
}

func (m mediaReference) GetDirectPath() string             { return m.Path }
func (m mediaReference) GetMediaKey() []byte               { return m.Key }
func (m mediaReference) GetFileSHA256() []byte             { return m.SHA }
func (m mediaReference) GetFileEncSHA256() []byte          { return m.EncSHA }
func (m mediaReference) GetMediaType() whatsmeow.MediaType { return m.Type }

// Attach metadata only. WhatsApp bytes are downloaded lazily when needed.
func (s *Session) attachMedia(e *events.Message, in *session.Inbound) {
	m := e.Message
	var file whatsmeow.DownloadableMessage
	a := session.Attachment{}
	switch {
	case m.GetImageMessage() != nil:
		v := m.GetImageMessage()
		file = v
		a.MimeType, a.SizeBytes, a.MediaClass = v.GetMimetype(), v.GetFileLength(), "image"
	case m.GetVideoMessage() != nil:
		v := m.GetVideoMessage()
		file = v
		a.MimeType, a.SizeBytes, a.MediaClass, a.DurationSeconds = v.GetMimetype(), v.GetFileLength(), "video", v.GetSeconds()
	case m.GetDocumentMessage() != nil:
		v := m.GetDocumentMessage()
		file = v
		a.MimeType, a.SizeBytes, a.MediaClass, a.Filename = v.GetMimetype(), v.GetFileLength(), "document", v.GetFileName()
	case m.GetAudioMessage() != nil:
		v := m.GetAudioMessage()
		file = v
		a.MimeType, a.SizeBytes, a.MediaClass, a.DurationSeconds = v.GetMimetype(), v.GetFileLength(), "document", v.GetSeconds()
		if v.GetPTT() {
			a.MediaClass = "voice"
		}
	case m.GetStickerMessage() != nil:
		v := m.GetStickerMessage()
		file = v
		a.MimeType, a.SizeBytes, a.MediaClass = v.GetMimetype(), v.GetFileLength(), "sticker"
	default:
		return
	}
	if len(a.MimeType) > 128 {
		a.MimeType = ""
	}
	if a.MimeType == "" {
		a.MimeType = "application/octet-stream"
	}
	a.Filename = safeFilename(a.Filename, a.MimeType)
	// View-once and disappearing media remain visible placeholders, with no
	// reusable credential and no path that can fetch their bytes.
	a.Ephemeral = e.IsViewOnce || e.IsEphemeral
	a.Reference = "unavailable:" + in.MessageID
	if !a.Ephemeral && a.SizeBytes > 0 && a.SizeBytes <= session.MaxMediaBytes && len(file.GetMediaKey()) == 32 && len(file.GetFileSHA256()) == 32 && len(file.GetFileEncSHA256()) == 32 {
		r := mediaReference{Path: file.GetDirectPath(), Key: file.GetMediaKey(), SHA: file.GetFileSHA256(), EncSHA: file.GetFileEncSHA256(), Type: whatsmeow.GetMediaType(file), Size: a.SizeBytes}
		if validReference(r) {
			b, _ := json.Marshal(r)
			sealed, err := s.vault.SealReference("whatsapp-media", in.MessageID, b)
			if err == nil {
				a.Reference = "wa1:" + base64.RawURLEncoding.EncodeToString(sealed)
			}
		}
	}
	in.Attachments = []session.Attachment{a}
	in.Unsupported = ""
}

func validReference(r mediaReference) bool {
	return r.Size > 0 && r.Size <= session.MaxMediaBytes && len(r.Path) < 4096 && strings.HasPrefix(r.Path, "/") && !strings.HasPrefix(r.Path, "//") && !strings.Contains(r.Path, "://") && len(r.Key) == 32 && len(r.SHA) == 32 && len(r.EncSHA) == 32 && (r.Type == whatsmeow.MediaImage || r.Type == whatsmeow.MediaVideo || r.Type == whatsmeow.MediaAudio || r.Type == whatsmeow.MediaDocument)
}

func (s *Session) DownloadMedia(ctx context.Context, messageID, reference string) ([]byte, error) {
	if !strings.HasPrefix(reference, "wa1:") || len(reference) > 16384 {
		return nil, session.ErrMediaUnavailable
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(reference, "wa1:"))
	if err != nil {
		return nil, session.ErrInvalidMedia
	}
	b, err = s.vault.OpenReference("whatsapp-media", messageID, b)
	if err != nil {
		return nil, session.ErrMediaUnavailable
	}
	var r mediaReference
	if json.Unmarshal(b, &r) != nil || !validReference(r) {
		return nil, session.ErrInvalidMedia
	}
	cli := s.mediaClient()
	if cli == nil || !cli.IsLoggedIn() {
		return nil, session.ErrNotLinked
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	data, err := cli.Download(ctx, r)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != r.Size {
		return nil, session.ErrInvalidMedia
	}
	return data, nil
}

func safeFilename(name, mimeType string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	if len(name) > 240 {
		name = ""
	}
	if name == "" || name == "." || name == "/" {
		ext := ".bin"
		if exts, _ := mime.ExtensionsByType(mimeType); len(exts) > 0 {
			ext = exts[0]
		}
		name = "attachment" + ext
	}
	return name
}

func (s *Session) SendMedia(ctx context.Context, chat, text string, f session.OutgoingMedia) (string, error) {
	if len(f.Bytes) == 0 || len(f.Bytes) > session.MaxMediaBytes || len(f.RequestID) < 8 || len(f.RequestID) > 64 {
		return "", session.ErrInvalidMedia
	}
	mt, _, err := mime.ParseMediaType(f.MimeType)
	if err != nil {
		return "", session.ErrInvalidMedia
	}
	if f.Voice && (!strings.HasPrefix(mt, "audio/") || text != "") {
		return "", session.ErrInvalidMedia
	}
	cli := s.mediaClient()
	if cli == nil || !cli.IsLoggedIn() {
		return "", session.ErrNotLinked
	}
	known, err := s.knownChat(ctx, chat)
	if err != nil {
		return "", err
	}
	if !known {
		return "", ErrUnknownChat
	}
	jid, err := types.ParseJID(chat)
	if err != nil {
		return "", ErrUnknownChat
	}
	// A retry after a dropped HTTP response must not send a second file.
	s.mediaSendMu.Lock()
	defer s.mediaSendMu.Unlock()
	payload, _ := json.Marshal(struct {
		Chat, Text, Name, Mime string
		Voice                  bool
		Hash                   [32]byte
	}{chat, text, f.Filename, f.MimeType, f.Voice, sha256.Sum256(f.Bytes)})
	digest := sha256.Sum256(payload)
	fingerprint := hex.EncodeToString(digest[:])
	var prior struct {
		Fingerprint string
		MessageID   string
	}
	if b, readErr := s.vault.Get(ctx, "media-sends", f.RequestID); readErr == nil {
		if json.Unmarshal(b, &prior) != nil || prior.Fingerprint != fingerprint {
			return "", session.ErrInvalidMedia
		}
		if prior.MessageID != "" {
			return prior.MessageID, nil
		}
		return "", session.ErrMediaUncertain
	} else if !errors.Is(readErr, sealed.ErrNotFound) {
		return "", readErr
	}
	typ := whatsmeow.MediaDocument
	if mt == "image/jpeg" || mt == "image/png" {
		typ = whatsmeow.MediaImage
	}
	if mt == "video/mp4" {
		typ = whatsmeow.MediaVideo
	}
	if strings.HasPrefix(mt, "audio/") && text == "" {
		typ = whatsmeow.MediaAudio
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	u, err := cli.Upload(ctx, f.Bytes, typ)
	if err != nil {
		return "", err
	}
	msg := &waE2E.Message{}
	switch typ {
	case whatsmeow.MediaImage:
		msg.ImageMessage = &waE2E.ImageMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileSHA256: u.FileSHA256, FileEncSHA256: u.FileEncSHA256, FileLength: &u.FileLength, Mimetype: &mt, Caption: &text}
	case whatsmeow.MediaVideo:
		msg.VideoMessage = &waE2E.VideoMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileSHA256: u.FileSHA256, FileEncSHA256: u.FileEncSHA256, FileLength: &u.FileLength, Mimetype: &mt, Caption: &text}
	case whatsmeow.MediaAudio:
		msg.AudioMessage = &waE2E.AudioMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileSHA256: u.FileSHA256, FileEncSHA256: u.FileEncSHA256, FileLength: &u.FileLength, Mimetype: &mt, PTT: &f.Voice}
	default:
		msg.DocumentMessage = &waE2E.DocumentMessage{URL: &u.URL, DirectPath: &u.DirectPath, MediaKey: u.MediaKey, FileSHA256: u.FileSHA256, FileEncSHA256: u.FileEncSHA256, FileLength: &u.FileLength, Mimetype: &mt, Caption: &text, FileName: proto.String(safeFilename(f.Filename, mt))}
	}
	prior.Fingerprint = fingerprint
	claim, _ := json.Marshal(prior)
	if err := s.vault.Put(ctx, "media-sends", f.RequestID, claim); err != nil {
		return "", err
	}
	res, err := cli.SendMessage(ctx, jid, msg)
	if err != nil {
		return "", session.ErrMediaUncertain
	}
	if res.ID == "" {
		return "", session.ErrMediaUncertain
	}
	prior.MessageID = res.ID
	receipt, _ := json.Marshal(prior)
	_ = s.vault.Put(ctx, "media-sends", f.RequestID, receipt)
	return res.ID, nil
}

// Bound the encrypted response before whatsmeow's io.ReadAll, including a
// server that lies about Content-Length. Uploads use the same transport.
type boundedMediaTransport struct{ base http.RoundTripper }

func (t boundedMediaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	const ceiling = session.MaxMediaBytes + (64 << 10)
	if r.ContentLength > ceiling {
		r.Body.Close()
		return nil, session.ErrInvalidMedia
	}
	r.Body = &boundedMediaBody{ReadCloser: r.Body, remaining: ceiling}
	return r, nil
}

type boundedMediaBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedMediaBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, session.ErrInvalidMedia
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}
