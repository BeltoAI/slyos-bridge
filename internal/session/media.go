package session

import (
	"context"
	"errors"
)

// One file per send avoids a partially delivered multi-file reply.
const MaxMediaBytes = 25 << 20

var ErrMediaUnavailable = errors.New("session: media unavailable")
var ErrInvalidMedia = errors.New("session: invalid media")
var ErrMediaUncertain = errors.New("session: media delivery uncertain")

type Attachment struct {
	Reference       string `json:"reference"`
	Filename        string `json:"filename"`
	MimeType        string `json:"mimeType"`
	SizeBytes       uint64 `json:"sizeBytes"`
	MediaClass      string `json:"mediaClass"`
	Ephemeral       bool   `json:"ephemeral"`
	DurationSeconds uint32 `json:"durationSeconds,omitempty"`
}

type OutgoingMedia struct {
	RequestID string `json:"requestId"`
	Filename  string `json:"filename"`
	MimeType  string `json:"mimeType"`
	Bytes     []byte `json:"bytes"`
	Voice     bool   `json:"voice,omitempty"`
}

// Optional: text-only providers do not accidentally advertise media support.
type MediaSession interface {
	SendMedia(context.Context, string, string, OutgoingMedia) (string, error)
	DownloadMedia(context.Context, string, string) ([]byte, error)
}

func (m *Manager) SendMedia(ctx context.Context, connID, chatID, text string, media OutgoingMedia, pressed bool) (string, error) {
	if !pressed {
		return "", ErrNotPressed
	}
	if len(media.Bytes) == 0 || len(media.Bytes) > MaxMediaBytes || len(media.Filename) == 0 || len(media.Filename) > 255 || len(media.MimeType) > 128 {
		return "", ErrInvalidMedia
	}
	r, err := m.get(connID)
	if err != nil {
		return "", err
	}
	if r.session.Status().State != StateLinked {
		return "", ErrNotLinked
	}
	ms, ok := r.session.(MediaSession)
	if !ok {
		return "", ErrMediaUnavailable
	}
	if err := m.limiter.Allow(connID, r.kind, chatID); err != nil {
		return "", err
	}
	id, err := ms.SendMedia(ctx, chatID, text, media)
	if err == nil {
		m.count("sent")
	}
	return id, err
}

func (m *Manager) DownloadMedia(ctx context.Context, connID, messageID, reference string) ([]byte, error) {
	if messageID == "" || len(messageID) > 256 || len(reference) > 16384 {
		return nil, ErrInvalidMedia
	}
	r, err := m.get(connID)
	if err != nil {
		return nil, err
	}
	if r.session.Status().State != StateLinked {
		return nil, ErrNotLinked
	}
	ms, ok := r.session.(MediaSession)
	if !ok {
		return nil, ErrMediaUnavailable
	}
	return ms.DownloadMedia(ctx, messageID, reference)
}
