//go:build cgo

package signal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

const (
	selfACI   = "11111111-1111-4111-8111-111111111111"
	theirACI  = "22222222-2222-4222-8222-222222222222"
	groupID   = "Z3JvdXAtaWQtYmFzZTY0LXRoaXJ0eS10d28tYnl0ZXM="
	secretKey = "ACI-IDENTITY-PRIVATE-KEY-never-in-the-clear"
)

// fakeProvider stands in for signalmeow. It writes into the real sealed
// database what signalmeow would: an identity key at link, a ratchet step
// per message.
type fakeProvider struct {
	mu       sync.Mutex
	db       *sealedDB
	linked   bool
	unlinked bool
	sent     []string
	timers   []Timer
	msgs     chan Message
}

func (f *fakeProvider) Account(context.Context) (Account, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Account{ACI: selfACI, Number: "+15551112222", Name: "Emil"}, f.linked, nil
}

func (f *fakeProvider) Link(ctx context.Context, show func(string, time.Time)) (Account, error) {
	show("sgnl://linkdevice?uuid=abc&pub_key=def", time.Now().Add(QRLifetime))
	if _, err := f.db.DB().ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS k (v TEXT); INSERT INTO k VALUES (?)`, secretKey); err != nil {
		return Account{}, err
	}
	f.mu.Lock()
	f.linked = true
	f.mu.Unlock()
	return Account{ACI: selfACI, Number: "+15551112222", Name: "Emil"}, nil
}

func (f *fakeProvider) Receive(ctx context.Context, deliver func(Message)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case m := <-f.msgs:
			_, _ = f.db.DB().ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ratchet (n INTEGER); INSERT INTO ratchet VALUES (1)`)
			deliver(m)
		}
	}
}

func (f *fakeProvider) Send(_ context.Context, chat, text string, t Timer) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, chat+"|"+text)
	f.timers = append(f.timers, t)
	return MessageID(selfACI, 42), nil
}

func (f *fakeProvider) Unlink(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlinked = true
	return nil
}

func (f *fakeProvider) isUnlinked() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.unlinked }

type recSink struct {
	mu   sync.Mutex
	msgs []session.Inbound
	sts  []session.Status
}

func (r *recSink) Message(_ context.Context, _, _ string, m session.Inbound) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, m)
	return nil
}

func (r *recSink) Status(_ context.Context, _, _ string, s session.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sts = append(r.sts, s)
	return nil
}

func (r *recSink) last() session.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sts) == 0 {
		return session.Status{}
	}
	return r.sts[len(r.sts)-1]
}

func rootKey(t *testing.T) sealed.RootKey {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	k, err := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

type harness struct {
	backend *sealed.MemoryBackend
	mgr     *session.Manager
	sink    *recSink
	fp      *fakeProvider
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{backend: sealed.NewMemoryBackend(), sink: &recSink{},
		fp: &fakeProvider{msgs: make(chan Message, 8)}}
	open := func(ctx context.Context, v *sealed.Vault) (provider, local, error) {
		db, err := openSealedDB(ctx, v)
		if err != nil {
			return nil, nil, err
		}
		h.fp.db = db
		return h.fp, db, nil
	}
	h.mgr = session.NewManager(sealed.NewKeyring(rootKey(t), h.backend),
		map[string]session.Factory{Kind: factory(open)}, h.sink, ratelimit.New(nil), logsafe.New(io.Discard))
	t.Cleanup(h.mgr.Shutdown)
	return h
}

func (h *harness) linked(t *testing.T) {
	t.Helper()
	if _, err := h.mgr.Connect(context.Background(), "conn-sig", Kind, session.StartOptions{Method: "qr"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "linked", func() bool { return h.sink.last().State == session.StateLinked })
}

func (h *harness) dumpHas(needle string) bool {
	for _, b := range h.backend.Dump() {
		if bytes.Contains(b, []byte(needle)) {
			return true
		}
	}
	return false
}

// A person scans one QR and the account is linked; the keys signalmeow made
// are sealed before the session says "linked", and never stored in the clear.
func TestALinkShowsAQRThenSealsTheKeys(t *testing.T) {
	h := newHarness(t)
	h.linked(t)
	h.sink.mu.Lock()
	first := h.sink.sts[0]
	h.sink.mu.Unlock()
	// The QR's data is served by the status route only; an event never carries it.
	if first.State != session.StatePairing || first.Challenge == nil || first.Challenge.Kind != "qr" ||
		first.Challenge.Data != "" {
		t.Fatalf("first status = %+v, want a QR challenge without its data", first)
	}
	if got := h.sink.last(); got.ExternalAccountID != selfACI || got.DisplayName != "Emil" {
		t.Fatalf("linked as %+v", got)
	}
	recs, _ := h.backend.ListRecords(context.Background(), "conn-sig", nsDB)
	if len(recs) != 1 {
		t.Fatalf("sealed database records = %d, want 1", len(recs))
	}
	if h.dumpHas(secretKey) {
		t.Fatal("the identity key reached storage in the clear")
	}
}

// Signal links by QR only; a phone-code link is refused before anything starts.
func TestAPhoneCodeLinkIsRefused(t *testing.T) {
	_, err := factory(nil)("c", nil, nil, session.StartOptions{Method: "code", Phone: "+15551112222"})
	if !errors.Is(err, ErrQROnly) {
		t.Fatalf("err = %v, want ErrQROnly", err)
	}
}

// The sealed database survives a deploy: a new process with the same root
// key reads back exactly what was sealed.
func TestTheAccountDatabaseSurvivesADeploy(t *testing.T) {
	ctx := context.Background()
	root, b := rootKey(t), sealed.NewMemoryBackend()
	v, err := sealed.NewKeyring(root, b).Create(ctx, "conn-sig", Kind)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openSealedDB(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, `CREATE TABLE k (v TEXT); INSERT INTO k VALUES (?)`, secretKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	db.Close()

	v2, err := sealed.NewKeyring(root, b).Open(ctx, "conn-sig")
	if err != nil {
		t.Fatal(err)
	}
	db2, err := openSealedDB(ctx, v2)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var got string
	if err := db2.DB().QueryRowContext(ctx, `SELECT v FROM k`).Scan(&got); err != nil || got != secretKey {
		t.Fatalf("restored %q, %v", got, err)
	}
}

// A message signalmeow buffered and then cleared is not in the next sealed
// snapshot: SQLite overwrites what it deletes (secure_delete).
func TestAClearedMessageIsNotSealed(t *testing.T) {
	ctx := context.Background()
	v, _ := sealed.NewKeyring(rootKey(t), sealed.NewMemoryBackend()).Create(ctx, "c", Kind)
	db, err := openSealedDB(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const words = "the-decrypted-words-of-a-message-0123456789"
	for _, q := range []string{
		`CREATE TABLE buf (h TEXT, plaintext BLOB)`,
		`INSERT INTO buf VALUES ('x', '` + words + `')`,
		`UPDATE buf SET plaintext = NULL`,
	} {
		if _, err := db.DB().ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	snap, err := v.Get(ctx, nsDB, keySnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snap, []byte(words)) {
		t.Fatal("a cleared message was sealed into the vault")
	}
}

// Messages reach the brain normalized; a reply goes only into a chat that
// wrote to this account.
func TestRepliesOnlyIntoChatsThatWrote(t *testing.T) {
	h := newHarness(t)
	h.linked(t)
	h.fp.msgs <- Message{Sender: theirACI, SenderName: "Ana", ChatID: theirACI, Timestamp: 1_700_000_000_000, Body: "hi",
		ExpireTimer: 604800, ExpireTimerVersion: 3}
	eventually(t, "message delivered", func() bool { h.sink.mu.Lock(); defer h.sink.mu.Unlock(); return len(h.sink.msgs) == 1 })
	h.sink.mu.Lock()
	in := h.sink.msgs[0]
	h.sink.mu.Unlock()
	if in.Direction != "inbound" || in.MessageID != theirACI+":1700000000000" || in.SenderName != "Ana" {
		t.Fatalf("inbound = %+v", in)
	}
	ctx := context.Background()
	if _, err := h.mgr.Send(ctx, "conn-sig", theirACI, "hello", true); err != nil {
		t.Fatalf("reply into a chat that wrote: %v", err)
	}
	h.fp.mu.Lock()
	sentTimer := h.fp.timers[0]
	h.fp.mu.Unlock()
	if sentTimer != (Timer{Seconds: 604800, Version: 3}) {
		t.Fatalf("the reply carried timer %+v; it would switch the chat's disappearing messages off", sentTimer)
	}
	if _, err := h.mgr.Send(ctx, "conn-sig", "33333333-3333-4333-8333-333333333333", "cold", true); !errors.Is(err, ErrUnknownChat) {
		t.Fatalf("cold send err = %v, want ErrUnknownChat", err)
	}
	if _, err := h.mgr.Send(ctx, "conn-sig", theirACI, "auto", false); !errors.Is(err, session.ErrNotPressed) {
		t.Fatalf("unpressed send err = %v, want ErrNotPressed", err)
	}
}

// DISCONNECT DESTROYS THE KEYS. Signal is told to unlink the device; the
// account's database is closed and refuses to be sealed again; the wrapped
// data key and every sealed record are gone.
func TestDisconnectUnlinksAndDestroysTheKeys(t *testing.T) {
	h := newHarness(t)
	h.linked(t)
	ctx := context.Background()
	if err := h.mgr.Revoke(ctx, "conn-sig"); err != nil {
		t.Fatal(err)
	}
	if !h.fp.isUnlinked() {
		t.Fatal("Signal was not asked to unlink the device")
	}
	if err := h.fp.db.Flush(ctx); !errors.Is(err, errClosed) {
		t.Fatalf("flush after disconnect = %v, want errClosed", err)
	}
	if _, err := h.backend.GetConnection(ctx, "conn-sig"); !errors.Is(err, sealed.ErrNotFound) {
		t.Fatalf("connection row after disconnect: %v", err)
	}
	if recs, _ := h.backend.ListRecords(ctx, "conn-sig", nsDB); len(recs) != 0 {
		t.Fatalf("%d sealed records survived disconnect", len(recs))
	}
	if len(h.backend.Dump()) != 0 {
		t.Fatal("something of the connection is still stored")
	}
}

// After Logout nothing seals the account again — not Run on its way out,
// even when the database changed after the last flush.
func TestNothingResealsTheAccountAfterLogout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := sealed.NewMemoryBackend()
	v, err := sealed.NewKeyring(rootKey(t), b).Create(ctx, "conn-sig", Kind)
	if err != nil {
		t.Fatal(err)
	}
	fp := &fakeProvider{msgs: make(chan Message, 1)}
	var opened *sealedDB
	open := func(ctx context.Context, v *sealed.Vault) (provider, local, error) {
		db, err := openSealedDB(ctx, v)
		opened, fp.db = db, db
		return fp, db, err
	}
	sink := &recSink{}
	s, _ := factory(open)("conn-sig", v, reporter{sink}, session.StartOptions{Method: "qr"})
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	eventually(t, "linked", func() bool { return s.Status().State == session.StateLinked })
	snapshot := func() []byte {
		recs, _ := b.ListRecords(context.Background(), "conn-sig", nsDB)
		if len(recs) != 1 {
			return nil
		}
		return recs[0].Value
	}
	before := snapshot()

	// The ratchet moves after the last flush, then the person disconnects.
	if _, err := opened.DB().ExecContext(ctx, `INSERT INTO k VALUES ('moved')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	after := snapshot()
	if before == nil || !bytes.Equal(before, after) {
		t.Fatal("the account was sealed again after Logout")
	}
}

type reporter struct{ s *recSink }

func (r reporter) Status(st session.Status)  { _ = r.s.Status(context.Background(), "", "", st) }
func (r reporter) Message(m session.Inbound) { _ = r.s.Message(context.Background(), "", "", m) }

// A resumed session whose account is gone from the store is logged out, not
// asked to show a QR nobody is looking at.
func TestAResumeWithNoAccountIsLoggedOut(t *testing.T) {
	ctx := context.Background()
	v, _ := sealed.NewKeyring(rootKey(t), sealed.NewMemoryBackend()).Create(ctx, "c", Kind)
	fp := &fakeProvider{}
	open := func(ctx context.Context, v *sealed.Vault) (provider, local, error) {
		db, err := openSealedDB(ctx, v)
		fp.db = db
		return fp, db, err
	}
	s, _ := factory(open)("c", v, reporter{&recSink{}}, session.StartOptions{Resume: true})
	if err := s.Run(ctx); !errors.Is(err, session.ErrLoggedOut) {
		t.Fatalf("err = %v, want ErrLoggedOut", err)
	}
}

func TestNormalize(t *testing.T) {
	ts := uint64(1_700_000_000_000)
	cases := []struct {
		name string
		m    Message
		ok   bool
		want func(session.Inbound) bool
	}{
		{"a reaction is not a message", Message{Sender: theirACI, ChatID: theirACI, Timestamp: ts, Skip: true}, false, nil},
		{"an empty body is not a message", Message{Sender: theirACI, ChatID: theirACI, Timestamp: ts}, false, nil},
		{"his own message from the phone is outbound", Message{Sender: selfACI, SenderName: "Emil", ChatID: theirACI, Timestamp: ts, Body: "on my way"}, true,
			func(in session.Inbound) bool { return in.Direction == "outbound" && in.SenderName == "" }},
		{"a group mention", Message{Sender: theirACI, ChatID: groupID, Group: true, ChatTitle: "Climbing", Timestamp: ts, Body: "@Emil?", Mentions: []string{selfACI}}, true,
			func(in session.Inbound) bool {
				return in.ThreadKind == "group" && in.ChatTitle == "Climbing" && in.MentionsMe && in.ChatID == groupID
			}},
		{"a reply to his message", Message{Sender: theirACI, ChatID: theirACI, Timestamp: ts, Body: "yes", QuoteAuthor: selfACI}, true,
			func(in session.Inbound) bool { return in.MentionsMe }},
		{"a photo says so", Message{Sender: theirACI, ChatID: theirACI, Timestamp: ts, Attachment: AttachmentKind("image/jpeg", false)}, true,
			func(in session.Inbound) bool { return in.Unsupported == "image" && in.Body == "" }},
	}
	for _, c := range cases {
		in, ok := Normalize(c.m, selfACI)
		if ok != c.ok || (ok && !c.want(in)) {
			t.Errorf("%s: ok=%v in=%+v", c.name, ok, in)
		}
	}
}

// A REPLY KEEPS THE CHAT'S DISAPPEARING TIMER. A reaction carries no timer and
// a message sent before the timer changed carries an older one; neither may
// become what the next reply sends, or the reply would switch the chat's
// disappearing messages off (or back) on everybody's phone. An explicit timer
// change is still followed.
func TestAReplyKeepsTheChatsTimer(t *testing.T) {
	h := newHarness(t)
	h.linked(t)
	ctx := context.Background()
	week := Timer{Seconds: 604800, Version: 3}
	reply := func(n int) Timer {
		t.Helper()
		eventually(t, "messages delivered", func() bool { h.sink.mu.Lock(); defer h.sink.mu.Unlock(); return len(h.sink.msgs) == n })
		if _, err := h.mgr.Send(ctx, "conn-sig", theirACI, "ok", true); err != nil {
			t.Fatal(err)
		}
		h.fp.mu.Lock()
		defer h.fp.mu.Unlock()
		return h.fp.timers[len(h.fp.timers)-1]
	}
	msg := func(ts uint64, secs, ver uint32) Message {
		return Message{Sender: theirACI, ChatID: theirACI, Timestamp: ts, Body: "hi", ExpireTimer: secs, ExpireTimerVersion: ver}
	}
	// A chat whose clients never sent a timer version, then a reaction.
	h.fp.msgs <- msg(1, week.Seconds, 0)
	h.fp.msgs <- Message{Sender: theirACI, ChatID: theirACI, Timestamp: 2, Skip: true}
	if got := reply(1); got != (Timer{Seconds: week.Seconds}) {
		t.Fatalf("after a reaction the reply carried timer %+v", got)
	}
	// Versioned, then a message sent before the change arrives after it.
	h.fp.msgs <- msg(3, week.Seconds, week.Version)
	h.fp.msgs <- msg(4, 86400, 2)
	if got := reply(3); got != week {
		t.Fatalf("after a stale message the reply carried timer %+v, want %+v", got, week)
	}
	h.fp.msgs <- Message{Sender: theirACI, ChatID: theirACI, Timestamp: 5, Skip: true, TimerUpdate: true, ExpireTimerVersion: 4}
	h.fp.msgs <- msg(6, 0, 0)
	if got := reply(4); got != (Timer{Version: 4}) {
		t.Fatalf("after the timer was switched off the reply carried %+v", got)
	}
}

// The flush loop ends with the Run that started it: a dropped socket restarts
// Run with a new database and a new loop, and the old one must not tick on.
func TestTheFlushLoopEndsWithItsRun(t *testing.T) {
	ctx := context.Background() // the connection's context: it outlives this Run
	v, _ := sealed.NewKeyring(rootKey(t), sealed.NewMemoryBackend()).Create(ctx, "c", Kind)
	fp := &droppingProvider{&fakeProvider{}}
	open := func(ctx context.Context, v *sealed.Vault) (provider, local, error) {
		db, err := openSealedDB(ctx, v)
		fp.db = db
		return fp, db, err
	}
	s, _ := factory(open)("c", v, reporter{&recSink{}}, session.StartOptions{Method: "qr"})
	if err := s.Run(ctx); err == nil {
		t.Fatal("Run did not report the dropped socket")
	}
	eventually(t, "the flush loop ended", func() bool {
		buf := make([]byte, 1<<20)
		return !bytes.Contains(buf[:runtime.Stack(buf, true)], []byte("signal.flushLoop"))
	})
}

type droppingProvider struct{ *fakeProvider }

func (droppingProvider) Receive(context.Context, func(Message)) error {
	return errors.New("socket dropped")
}

// Nothing of the account's database is written to the machine's disk, not
// even SQLite's temporary files.
func TestTemporaryFilesStayInMemory(t *testing.T) {
	ctx := context.Background()
	v, _ := sealed.NewKeyring(rootKey(t), sealed.NewMemoryBackend()).Create(ctx, "c", Kind)
	db, err := openSealedDB(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode int
	if err := db.DB().QueryRowContext(ctx, "PRAGMA temp_store").Scan(&mode); err != nil || mode != 2 {
		t.Fatalf("temp_store = %d (%v), want 2 (memory)", mode, err)
	}
}
