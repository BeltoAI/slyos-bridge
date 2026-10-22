package logsafe

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestUnknownKeysAreDropped(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf)
	log.Info("inbound", slog.String("body", "meet me at the clinic at 4"), slog.String("conn", "c-1"))
	out := buf.String()
	if strings.Contains(out, "clinic") {
		t.Fatalf("a message body reached the log: %s", out)
	}
	if !strings.Contains(out, `"body":"[dropped]"`) || !strings.Contains(out, `"conn":"c-1"`) {
		t.Fatalf("unexpected line: %s", out)
	}
}

func TestLongValuesUnderAllowedKeysAreDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x", slog.String("state", strings.Repeat("a sentence smuggled in ", 5)))
	if strings.Contains(buf.String(), "smuggled") {
		t.Fatalf("a long value survived: %s", buf.String())
	}
}

func TestStructuredValuesAreDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x", slog.Any("kind", []byte("raw-key-bytes")), slog.Any("state", struct{ S string }{"secret"}))
	if strings.Contains(buf.String(), "raw-key-bytes") || strings.Contains(buf.String(), "secret") {
		t.Fatalf("a structured value survived: %s", buf.String())
	}
}

func TestWithAttrsIsScrubbedToo(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).With(slog.String("phone", "+15551234567")).Info("x")
	if strings.Contains(buf.String(), "5551234567") {
		t.Fatalf("With() leaked: %s", buf.String())
	}
}

type wrapped struct{ msg string }

func (w wrapped) Error() string { return w.msg }

func TestErrorsAreLoggedByClassNotText(t *testing.T) {
	var buf bytes.Buffer
	e := fmt.Errorf("send to 15551234567@s.whatsapp.net failed: %w", wrapped{"hello there"})
	New(&buf).Warn("send failed", Err(e))
	if strings.Contains(buf.String(), "5551234567") || strings.Contains(buf.String(), "hello") {
		t.Fatalf("error text reached the log: %s", buf.String())
	}
	sentinel := errors.New("rate limited")
	RegisterClass(sentinel, "rate_limited")
	buf.Reset()
	New(&buf).Warn("send refused", Err(fmt.Errorf("conn x: %w", sentinel)))
	if !strings.Contains(buf.String(), `"err_class":"rate_limited"`) {
		t.Fatalf("a registered sentinel should name itself: %s", buf.String())
	}
}
