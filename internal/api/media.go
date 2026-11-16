package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

// Two bounded uploads/downloads at a time avoid unbounded per-request buffers.
var mediaSlots = make(chan struct{}, 2)

func (s *Server) mediaSlot(w http.ResponseWriter) bool {
	select {
	case mediaSlots <- struct{}{}:
		return true
	default:
		writeErr(w, 429, "media_busy")
		return false
	}
}

func (s *Server) sendMedia(w http.ResponseWriter, r *http.Request) {
	if !s.mediaSlot(w) {
		return
	}
	defer func() { <-mediaSlots }()
	var b struct {
		ChatID          string                `json:"chatId"`
		Text            string                `json:"text"`
		PressedByPerson bool                  `json:"pressedByPerson"`
		Media           session.OutgoingMedia `json:"media"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, (session.MaxMediaBytes*4/3)+(64<<10))
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || b.ChatID == "" || len(b.ChatID) > 256 || len(b.Text) > 65536 {
		writeErr(w, 400, "bad_media")
		return
	}
	if !idPattern.MatchString(b.Media.RequestID) {
		writeErr(w, 400, "bad_media")
		return
	}
	id, err := s.Manager.SendMedia(r.Context(), r.PathValue("id"), b.ChatID, b.Text, b.Media, b.PressedByPerson)
	if err != nil {
		mediaError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"messageId": id})
}

func (s *Server) downloadMedia(w http.ResponseWriter, r *http.Request) {
	if !s.mediaSlot(w) {
		return
	}
	defer func() { <-mediaSlots }()
	var b struct {
		MessageID string `json:"messageId"`
		Reference string `json:"reference"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	data, err := s.Manager.DownloadMedia(r.Context(), r.PathValue("id"), b.MessageID, b.Reference)
	if err != nil {
		mediaError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func mediaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrNotPressed):
		writeErr(w, 403, "not_pressed")
	case errors.Is(err, session.ErrUnknownConnection):
		writeErr(w, 404, "unknown_connection")
	case errors.Is(err, session.ErrNotLinked):
		writeErr(w, 409, "not_linked")
	case errors.Is(err, session.ErrInvalidMedia):
		writeErr(w, 422, "bad_media")
	case errors.Is(err, session.ErrMediaUncertain):
		writeErr(w, 409, "media_delivery_uncertain")
	case errors.Is(err, session.ErrMediaUnavailable):
		writeErr(w, 422, "media_unavailable")
	case errors.Is(err, ratelimit.ErrPerMinute), errors.Is(err, ratelimit.ErrPerDay), errors.Is(err, ratelimit.ErrFirstContact):
		writeErr(w, 429, logsafe.Class(err))
	default:
		writeErr(w, 502, "provider_refused")
	}
}
