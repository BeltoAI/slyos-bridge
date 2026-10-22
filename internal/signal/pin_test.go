package signal

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo/signalversion"
)

// The image links the libsignal that the pinned signalmeow was written
// against. Two numbers in two files, so one test reads both: a mismatch
// links (the FFI is C) and then fails at the first call that changed shape.
func TestTheImagePinsTheLibsignalSignalmeowWants(t *testing.T) {
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	df := string(b)
	m := regexp.MustCompile(`(?m)^ARG LIBSIGNAL_VERSION=(\S+)$`).FindStringSubmatch(df)
	if m == nil || m[1] != signalversion.Version {
		t.Fatalf("Dockerfile LIBSIGNAL_VERSION = %v, signalmeow wants %s", m, signalversion.Version)
	}
	if !strings.Contains(df, "-tags libsignal,") || !strings.Contains(df, "CGO_ENABLED=1") {
		t.Fatal("the Dockerfile no longer builds the bridge with libsignal: Signal would silently not be served")
	}
}
