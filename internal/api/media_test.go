package api

import (
	"bytes"
	"context"
	"github.com/BeltoAI/slyos-bridge/internal/session"
	"io"
	"net/http"
	"strings"
	"testing"
)

func (l *linkedSession) SendMedia(_ context.Context, _ string, _ string, m session.OutgoingMedia) (string, error) {
	return "media-sent", nil
}
func (l *linkedSession) DownloadMedia(_ context.Context, _ string, _ string) ([]byte, error) {
	return []byte{0, 255, 128, 10}, nil
}

func TestMediaRoutesAuthenticateAndKeepBytesPrivate(t *testing.T) {
	srv, _, logs, _ := newServer(t)
	call(t, srv, "POST", "/v1/connections", secret, map[string]string{"connectionId": connID, "kind": "whatsapp", "method": "qr"})
	for _, endpoint := range []string{"media", "send-media"} {
		res, _ := call(t, srv, "POST", "/v1/connections/"+connID+"/"+endpoint, "wrong", map[string]string{"reference": "private-reference"})
		if res.StatusCode != 401 {
			t.Fatal("unauthenticated media route", res.StatusCode)
		}
	}
	large := session.OutgoingMedia{RequestID: connID, Filename: "qa.pdf", MimeType: "application/pdf", Bytes: bytes.Repeat([]byte{127}, 2<<20)}
	res, out := call(t, srv, "POST", "/v1/connections/"+connID+"/send-media", secret, map[string]any{"chatId": "c", "text": "private-caption", "media": large, "pressedByPerson": false})
	if res.StatusCode != 403 || out["error"] != "not_pressed" {
		t.Fatal("large file parser or press gate", res.StatusCode, out)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v1/connections/"+connID+"/media", strings.NewReader(`{"messageId":"m1","reference":"private-reference"}`))
	req.Header.Set(AuthHeader, secret)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode != 200 || !bytes.Equal(data, []byte{0, 255, 128, 10}) || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("binary download changed")
	}
	if strings.Contains(logs.String(), "private-") {
		t.Fatal("media data logged")
	}
}
