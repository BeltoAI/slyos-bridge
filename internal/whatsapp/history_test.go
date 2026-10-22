package whatsapp

import (
	"os"
	"strings"
	"testing"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// A first link does not download the phone's history: whatsmeow would fetch,
// inflate and decode every blob for history nothing here reads. The receipt
// still goes back, so the phone does not send it again.
func TestTheFirstLinkDoesNotDownloadHistory(t *testing.T) {
	_, v, _, _ := setup(t)
	cli := newClient(NewSealedStore(v).NewDevice(waLog.Noop), waLog.Noop)
	if !cli.ManualHistorySyncDownload {
		t.Fatal("ManualHistorySyncDownload is off: every first link downloads and decodes the whole history")
	}
	if cli.DisableManualHistorySyncReceipt {
		t.Fatal("the history-sync receipt is off: the phone would keep resending what it thinks was lost")
	}
	if cli.UseRetryMessageStore {
		t.Fatal("UseRetryMessageStore is on: sent messages would be kept for retries")
	}
}

// And the session runs on that client: one constructor, and Run uses it.
func TestEverySessionRunsOnTheClientThatSkipsHistory(t *testing.T) {
	src, err := os.ReadFile("whatsapp.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	if n := strings.Count(code, "whatsmeow.NewClient("); n != 1 {
		t.Fatalf("whatsmeow.NewClient( appears %d times; newClient must be the only constructor", n)
	}
	if !strings.Contains(code, "cli := newClient(device, log)") {
		t.Fatal("Session.Run does not build its client with newClient")
	}
}
