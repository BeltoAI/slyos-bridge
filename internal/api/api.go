// Package api is the bridge's HTTP surface. Only the brain calls it, with
// BRIDGE_SHARED_SECRET in the x-slyos-bridge header — the same arrangement as
// services/browser's x-slyos-browser. /health is the only open route and it
// says counts, never names. ADR 0093.
//
//	POST   /v1/connections                 {connectionId, kind, method, phone?} -> Status
//	                                       429 {error: too_many_codes, retryAfterSeconds}
//	GET    /v1/connections/{id}            -> Status (live, or how it ended)
//	POST   /v1/connections/{id}/code       {code?, password?} -> Status after Telegram answered
//	POST   /v1/connections/{id}/send       {chatId, text, pressedByPerson, outboxId} -> {messageId}
//	DELETE /v1/connections/{id}            -> 204, keys destroyed
//	GET    /health                         -> counts
//
// Request bodies carry message text on /send and a phone number on connect.
// Neither is logged; the access log line is method, route pattern, status and
// milliseconds.
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

const AuthHeader = "x-slyos-bridge"

// A connection id is the brain's channel id: a UUID. Anything else is refused
// before it reaches a map key, a log line or a SQL parameter.
var idPattern = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

type Server struct {
	Manager *session.Manager
	Secret  []byte
	Log     *slog.Logger
	// Kinds this deployment will connect. A kind whose flag is off in the
	// brain is never asked for; this is the bridge's own refusal of a kind it
	// was not deployed to serve (Google Messages, in phase 1).
	Kinds map[string]bool
	// How often one phone number may be sent a code (ratelimit/pair.go).
	// Nil gets the default limiter: a server without one would let anybody
	// pester a stranger's phone through us.
	Pairs *ratelimit.PairLimiter
}

func (s *Server) Handler() http.Handler {
	if s.Pairs == nil {
		s.Pairs = ratelimit.NewPairLimiter(nil)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /v1/connections", s.auth(s.connect))
	mux.HandleFunc("GET /v1/connections/{id}", s.auth(s.status))
	mux.HandleFunc("POST /v1/connections/{id}/code", s.auth(s.code))
	mux.HandleFunc("POST /v1/connections/{id}/send", s.auth(s.send))
	mux.HandleFunc("DELETE /v1/connections/{id}", s.auth(s.revoke))
	return s.accessLog(mux)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		// r.Pattern is the route TEMPLATE ("/v1/connections/{id}"), never
		// the path with the id in it.
		s.Log.Info("request", slog.String("method", r.Method), slog.String("route", r.Pattern),
			slog.Int("status", rw.status), slog.Int64("ms", time.Since(start).Milliseconds()))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	want := sha256.Sum256(s.Secret)
	return func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(r.Header.Get(AuthHeader)))
		if len(s.Secret) < 32 || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if id := r.PathValue("id"); id != "" && !idPattern.MatchString(id) {
			writeErr(w, http.StatusBadRequest, "bad_connection_id")
			return
		}
		next(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "sessions": s.Manager.Health(), "library": logsafe.Library.Snapshot(),
	})
}

type connectBody struct {
	ConnectionID string `json:"connectionId"`
	Kind         string `json:"kind"`
	Method       string `json:"method"`
	Phone        string `json:"phone"`
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	var b connectBody
	if !readJSON(w, r, &b) {
		return
	}
	if !idPattern.MatchString(b.ConnectionID) {
		writeErr(w, http.StatusBadRequest, "bad_connection_id")
		return
	}
	if !s.Kinds[b.Kind] {
		writeErr(w, http.StatusNotFound, "kind_not_served")
		return
	}
	if b.Method != "qr" && b.Method != "code" {
		writeErr(w, http.StatusBadRequest, "bad_method")
		return
	}
	if b.Method == "code" && !phonePattern.MatchString(b.Phone) {
		writeErr(w, http.StatusBadRequest, "bad_phone")
		return
	}
	if b.Method == "code" {
		// Before the session exists: a refused request reaches nobody's phone.
		if wait, ok := s.Pairs.Allow(b.Phone); !ok {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": "too_many_codes", "retryAfterSeconds": session.RetryAfterSeconds(wait)})
			return
		}
	}
	st, err := s.Manager.Connect(r.Context(), b.ConnectionID, b.Kind,
		session.StartOptions{Method: b.Method, Phone: b.Phone})
	if err != nil {
		s.Log.Warn("connect failed", slog.String("kind", b.Kind), logsafe.Err(err))
		writeErr(w, http.StatusConflict, "connect_failed")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// International format: + then digits, as WhatsApp's and Telegram's own
// phone-number login expect. THE + IS REQUIRED. Without it there is no telling
// a country code from the first digits of a number written the way people
// write their own at home — "9515550123" is Riverside, California to the person
// who typed it and +95, Myanmar, to WhatsApp — and a guess sends a code to a
// stranger's phone. The brain only ever sends + and digits
// (normalizeBridgePhone); this is the same rule in the process that asks.
var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// A login code: Telegram's are digits; empty when only a password is sent.
var codePattern = regexp.MustCompile(`^[0-9A-Za-z-]{0,16}$`)

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.Manager.Status(r.PathValue("id"))
	if errors.Is(err, session.ErrUnknownConnection) {
		writeErr(w, http.StatusNotFound, "unknown_connection")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) code(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if (b.Code == "" && b.Password == "") || len(b.Code) > 16 || len(b.Password) > 256 ||
		!codePattern.MatchString(b.Code) {
		writeErr(w, http.StatusBadRequest, "bad_code")
		return
	}
	st, err := s.Manager.SubmitCode(r.Context(), r.PathValue("id"), b.Code, b.Password)
	switch {
	case errors.Is(err, session.ErrUnknownConnection):
		writeErr(w, http.StatusNotFound, "unknown_connection")
	case errors.Is(err, session.ErrWrongState):
		writeErr(w, http.StatusConflict, "not_waiting_for_a_code")
	case err != nil:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "code_refused", "status": st})
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ChatID          string `json:"chatId"`
		Text            string `json:"text"`
		PressedByPerson bool   `json:"pressedByPerson"`
		OutboxID        string `json:"outboxId"`
	}
	if !readJSON(w, r, &b) {
		return
	}
	if b.ChatID == "" || b.Text == "" {
		writeErr(w, http.StatusBadRequest, "chat_and_text_required")
		return
	}
	id, err := s.Manager.Send(r.Context(), r.PathValue("id"), b.ChatID, b.Text, b.PressedByPerson)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"messageId": id})
	case errors.Is(err, session.ErrNotPressed):
		writeErr(w, http.StatusForbidden, "not_pressed")
	case errors.Is(err, session.ErrUnknownConnection):
		writeErr(w, http.StatusNotFound, "unknown_connection")
	case errors.Is(err, session.ErrNotLinked):
		writeErr(w, http.StatusConflict, "not_linked")
	case errors.Is(err, ratelimit.ErrPerMinute), errors.Is(err, ratelimit.ErrPerDay),
		errors.Is(err, ratelimit.ErrFirstContact):
		writeErr(w, http.StatusTooManyRequests, logsafe.Class(err))
	default:
		writeErr(w, http.StatusBadGateway, "provider_refused")
	}
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.Manager.Revoke(r.Context(), r.PathValue("id")); err != nil {
		s.Log.Warn("revoke failed", logsafe.Err(err))
		writeErr(w, http.StatusInternalServerError, "revoke_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_json")
		return false
	}
	return true
}

func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
