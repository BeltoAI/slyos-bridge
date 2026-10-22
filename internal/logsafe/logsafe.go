// Package logsafe is the only logger in the bridge, and it is built so that a
// message, a name, a phone number or a key cannot reach a log line by
// accident. ADR 0093: "zero content logging".
//
// Three rules, enforced here rather than by care at every call site:
//
//  1. ONLY ALLOWLISTED ATTRIBUTE KEYS ARE WRITTEN. Any other attribute is
//     replaced by its key and "[dropped]". A future `slog.String("body", ...)`
//     produces `body=[dropped]`, not the body.
//  2. ATTRIBUTE VALUES ARE BOUNDED: strings longer than 64 characters are
//     dropped too, so a sentence smuggled in under an allowed key such as
//     "state" does not survive either.
//  3. ERRORS ARE LOGGED BY CLASS, NEVER BY TEXT. A library error message can
//     carry a JID (a phone number) or a server reply. Err(e) writes the Go type
//     name and nothing else.
//
// The libraries' own loggers (whatsmeow's waLog, gotd's zap) are routed to
// Library(), which counts by module and level and writes no text at all.
package logsafe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
)

var allowed = map[string]bool{
	"conn": true, "kind": true, "state": true, "event": true, "count": true,
	"ms": true, "err_class": true, "status": true, "attempt": true,
	"method": true, "route": true, "module": true, "level": true,
	"reason": true, "addr": true, "sessions": true, "days": true,
}

const maxValueChars = 64

// New returns a JSON logger with the allowlist applied.
func New(w io.Writer) *slog.Logger {
	return slog.New(&handler{inner: slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})})
}

type handler struct{ inner slog.Handler }

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.inner.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	clean := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(scrub(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = scrub(a)
	}
	return &handler{inner: h.inner.WithAttrs(out)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	// Groups would let a key hide under an allowed prefix. There are none.
	return h
}

func scrub(a slog.Attr) slog.Attr {
	if !allowed[a.Key] {
		return slog.String(a.Key, "[dropped]")
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindInt64, slog.KindUint64, slog.KindFloat64, slog.KindBool, slog.KindDuration, slog.KindTime:
		return slog.Attr{Key: a.Key, Value: v}
	case slog.KindString:
		if len(v.String()) > maxValueChars {
			return slog.String(a.Key, "[dropped]")
		}
		return slog.Attr{Key: a.Key, Value: v}
	default:
		// Anything structured — a struct, a byte slice, an error — could
		// carry anything. Its type is what we can say about it.
		return slog.String(a.Key, "[dropped]")
	}
}

// Err logs an error by its class. Known sentinels name themselves; anything
// else is its Go type, which says what went wrong without what it was about.
func Err(err error) slog.Attr {
	return slog.String("err_class", Class(err))
}

var classes sync.Map // sentinel error -> class name

// RegisterClass names a sentinel error so Err can say more than its type.
func RegisterClass(sentinel error, name string) { classes.Store(sentinel, name) }

func Class(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	name := ""
	classes.Range(func(k, v any) bool {
		if errors.Is(err, k.(error)) {
			name = v.(string)
			return false
		}
		return true
	})
	if name != "" {
		return name
	}
	return fmt.Sprintf("%T", err)
}

// LibraryCounts is what the libraries said, by module and level, with no text.
// /health/deep publishes it so a burst of whatsmeow errors is visible without
// any of them being readable.
type LibraryCounts struct {
	mu     sync.Mutex
	counts map[string]*atomic.Int64
}

var Library = &LibraryCounts{counts: map[string]*atomic.Int64{}}

func (l *LibraryCounts) Note(module, level string) {
	key := module + ":" + level
	l.mu.Lock()
	c, ok := l.counts[key]
	if !ok {
		c = &atomic.Int64{}
		l.counts[key] = c
	}
	l.mu.Unlock()
	c.Add(1)
}

func (l *LibraryCounts) Snapshot() map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int64, len(l.counts))
	for k, v := range l.counts {
		out[k] = v.Load()
	}
	return out
}
