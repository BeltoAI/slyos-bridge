package sealed

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func testRoot(t *testing.T) RootKey {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	k, err := ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const phone = "15551234567@s.whatsapp.net"

var secret = []byte("signal-session-state-that-must-never-be-stored-in-the-clear")

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	b := NewMemoryBackend()
	kr := NewKeyring(testRoot(t), b)
	v, err := kr.Create(ctx, "conn-1", "whatsapp")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, "session", phone, secret); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, "session", phone)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: got %q, %v", got, err)
	}
	if _, err := v.Get(ctx, "session", "someone-else"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing record must be ErrNotFound, got %v", err)
	}
	list, err := v.List(ctx, "session")
	if err != nil || len(list) != 1 || list[0].Key != phone || !bytes.Equal(list[0].Value, secret) {
		t.Fatalf("list: %+v %v", list, err)
	}
}

// Nothing a person could recognise reaches storage: not the value, and not the
// record key either — a WhatsApp record key is a phone number.
func TestNothingInTheClearInStorage(t *testing.T) {
	ctx := context.Background()
	b := NewMemoryBackend()
	kr := NewKeyring(testRoot(t), b)
	v, _ := kr.Create(ctx, "conn-1", "whatsapp")
	if err := v.Put(ctx, "session", phone, secret); err != nil {
		t.Fatal(err)
	}
	for _, blob := range b.Dump() {
		if bytes.Contains(blob, secret) {
			t.Fatal("the plaintext value reached storage")
		}
		if bytes.Contains(blob, []byte("15551234567")) {
			t.Fatal("the record key (a phone number) reached storage")
		}
	}
}

// A sealed record moved to another connection, or to another namespace, does
// not open as the wrong thing.
func TestMovedRecordDoesNotOpen(t *testing.T) {
	ctx := context.Background()
	b := NewMemoryBackend()
	kr := NewKeyring(testRoot(t), b)
	a, _ := kr.Create(ctx, "conn-a", "whatsapp")
	_ = a.Put(ctx, "session", phone, secret)
	raws, _ := b.ListRecords(ctx, "conn-a", "session")
	if len(raws) != 1 {
		t.Fatal("expected one record")
	}
	// Same connection, other namespace, same hash.
	_ = b.PutRecord(ctx, "conn-a", "identity", raws[0].KeyHash, raws[0].Value)
	if _, err := a.List(ctx, "identity"); !errors.Is(err, ErrOpen) {
		t.Fatalf("a record moved between namespaces must fail to open, got %v", err)
	}
	// Another connection's vault.
	c, _ := kr.Create(ctx, "conn-c", "whatsapp")
	_ = b.PutRecord(ctx, "conn-c", "session", raws[0].KeyHash, raws[0].Value)
	if _, err := c.List(ctx, "session"); !errors.Is(err, ErrOpen) {
		t.Fatalf("a record moved between connections must fail to open, got %v", err)
	}
}

func TestWrappedKeyIsBoundToItsConnection(t *testing.T) {
	root := testRoot(t)
	wrapped, _, err := NewDataKey(root, "conn-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDataKey(root, "conn-b", wrapped); !errors.Is(err, ErrOpen) {
		t.Fatalf("a data key must not unwrap for another connection, got %v", err)
	}
	if _, err := UnwrapDataKey(testRoot(t), "conn-a", wrapped); !errors.Is(err, ErrOpen) {
		t.Fatalf("a data key must not unwrap under another root key, got %v", err)
	}
}

// The deploy story: a new process with the same root key and the same storage
// resumes every connection.
func TestResumeAfterRestart(t *testing.T) {
	ctx := context.Background()
	root := testRoot(t)
	b := NewMemoryBackend()
	v, _ := NewKeyring(root, b).Create(ctx, "conn-1", "telegram_personal")
	_ = v.Put(ctx, "mtproto", "session", secret)

	restarted := NewKeyring(root, b)
	v2, err := restarted.Open(ctx, "conn-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := v2.Get(ctx, "mtproto", "session")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("resume: %q %v", got, err)
	}
}

// failingRecords lets DeleteRecords fail, to prove the key is gone before the
// step that can fail.
type failingRecords struct{ *MemoryBackend }

func (f failingRecords) DeleteRecords(context.Context, string) error {
	return errors.New("database went away")
}

// Revoke destroys: the wrapped key is gone first, the open vault refuses, and
// even records left behind by a failed delete can no longer be opened by a
// fresh process holding the same root key.
func TestDestroyShredsBeforeAnythingCanFail(t *testing.T) {
	ctx := context.Background()
	root := testRoot(t)
	mem := NewMemoryBackend()
	kr := NewKeyring(root, failingRecords{mem})
	v, _ := kr.Create(ctx, "conn-1", "whatsapp")
	_ = v.Put(ctx, "session", phone, secret)

	if err := kr.Destroy(ctx, "conn-1"); err == nil {
		t.Fatal("expected the injected record-delete failure")
	}
	if _, err := v.Get(ctx, "session", phone); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("an open vault must refuse after destroy, got %v", err)
	}
	if err := v.Put(ctx, "session", phone, secret); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("an open vault must refuse writes after destroy, got %v", err)
	}
	c, err := mem.GetConnection(ctx, "conn-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.WrappedKey) != 0 {
		t.Fatal("the wrapped data key survived destroy")
	}
	if _, err := NewKeyring(root, mem).Open(ctx, "conn-1"); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("a destroyed connection must not reopen, got %v", err)
	}
	raws, _ := mem.ListRecords(ctx, "conn-1", "session")
	if len(raws) != 1 {
		t.Fatal("the failure was meant to leave the record behind")
	}
}

func TestDestroyRemovesEverything(t *testing.T) {
	ctx := context.Background()
	mem := NewMemoryBackend()
	kr := NewKeyring(testRoot(t), mem)
	v, _ := kr.Create(ctx, "conn-1", "whatsapp")
	_ = v.Put(ctx, "session", phone, secret)
	if err := kr.Destroy(ctx, "conn-1"); err != nil {
		t.Fatal(err)
	}
	if d := mem.Dump(); len(d) != 0 {
		t.Fatalf("destroy left %d stored values", len(d))
	}
}

// The keys never print, whatever verb a careless log line uses.
func TestKeysDoNotFormat(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, 32)
	root, _ := ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	_, ck, _ := NewDataKey(root, "c")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		for _, val := range []any{root, &root, ck, *ck} {
			out := fmt.Sprintf(verb, val)
			if bytes.Contains([]byte(out), []byte("abab")) || bytes.Contains([]byte(out), []byte("ABAB")) ||
				bytes.Contains([]byte(out), raw) || bytes.Contains([]byte(out), []byte("q6ur")) {
				t.Fatalf("%s printed key material: %s", verb, out)
			}
		}
	}
}

func TestShortRootKeyIsRefused(t *testing.T) {
	if _, err := ParseRootKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); err == nil {
		t.Fatal("a 16-byte root key must be refused, not stretched")
	}
}

// Against a real Postgres when BRIDGE_TEST_DATABASE_URL names a private
// database: the deploy story end to end, through a second pool.
func TestPostgresResumeAndDestroy(t *testing.T) {
	url := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	root := testRoot(t)
	p1, err := NewPostgresBackend(ctx, url, 0)
	if err != nil {
		t.Fatal(err)
	}
	id := "pg-conn-" + base64.RawURLEncoding.EncodeToString(root.k[:6])
	v, err := NewKeyring(root, p1).Create(ctx, id, "telegram_personal")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, "mtproto", "session", secret); err != nil {
		t.Fatal(err)
	}
	p1.Close()

	p2, err := NewPostgresBackend(ctx, url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	var raw []byte
	if err := p2.pool.QueryRow(ctx, `SELECT value FROM bridge_records WHERE connection_id = $1`, id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext in the database")
	}
	kr := NewKeyring(root, p2)
	v2, err := kr.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.Get(ctx, "mtproto", "session"); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("resume from Postgres: %v", err)
	}
	if err := kr.Destroy(ctx, id); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = p2.pool.QueryRow(ctx, `SELECT count(*) FROM bridge_records WHERE connection_id = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatalf("%d records survived destroy", n)
	}
	if _, err := p2.GetConnection(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("connection row survived destroy: %v", err)
	}
}

func TestPostgresLeaderLockAdmitsOneProcess(t *testing.T) {
	url := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	a, err := NewPostgresBackend(ctx, url, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AcquireLeader(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := NewPostgresBackend(ctx, url, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	short, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := b.AcquireLeader(short); err == nil {
		t.Fatal("a second process took the lock while the first held it")
	}
	a.Close()
	if err := b.AcquireLeader(ctx); err != nil {
		t.Fatalf("the lock was not released with the first process: %v", err)
	}
}
