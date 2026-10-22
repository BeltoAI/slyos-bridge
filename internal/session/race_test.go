package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

// ── ONE CONNECTION, ONE SESSION, WHATEVER ARRIVES AT ONCE ─────────────────
//
// Connect used to check "is this connection already running?" under the lock,
// let go of it, create the keys and only then put the session in the map. Two
// Connects for one connection that arrived together both passed the check:
// the second overwrote the first in the map AND the first's wrapped key in the
// database, and the first session ran on with nothing pointing at it. Revoke
// cancels what the map holds, so Disconnect could never stop it — a second
// WhatsApp socket from us, still delivering his messages after he pressed
// Disconnect, until the process restarted.
//
// TWENTY RACERS, NOT TWO. Two goroutines rarely interleave inside the window,
// so a two-way version of this test can pass with the lock deleted; twenty
// do interleave. Checked by deleting the lock: both tests below go red.

type countingSession struct {
	rep     Reporter
	running *atomic.Int64
	mu      sync.Mutex
	st      Status
}

func (c *countingSession) Run(ctx context.Context) error {
	c.running.Add(1)
	defer c.running.Add(-1)
	c.mu.Lock()
	c.st = Status{State: StatePairing, Challenge: &Challenge{Kind: "qr", Data: "2@qr"}}
	c.mu.Unlock()
	<-ctx.Done()
	return nil
}
func (c *countingSession) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}
func (c *countingSession) SubmitCode(context.Context, string, string) error { return ErrWrongState }
func (c *countingSession) Send(context.Context, string, string) (string, error) {
	return "", ErrNotLinked
}
func (c *countingSession) Logout(context.Context) error { return nil }

func raceManager(t *testing.T, made, running *atomic.Int64) (*Manager, *sealed.MemoryBackend) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	root, _ := sealed.ParseRootKey(base64.StdEncoding.EncodeToString(raw))
	b := sealed.NewMemoryBackend()
	factory := func(_ string, _ *sealed.Vault, rep Reporter, _ StartOptions) (Session, error) {
		made.Add(1)
		// The window a real Create spends in the database.
		time.Sleep(2 * time.Millisecond)
		return &countingSession{rep: rep, running: running}, nil
	}
	m := NewManager(sealed.NewKeyring(root, b), map[string]Factory{"whatsapp": factory},
		&recSink{}, ratelimit.New(nil), logsafe.New(&discard{}))
	t.Cleanup(m.Shutdown)
	return m, b
}

type discard struct{}

func (*discard) Write(p []byte) (int, error) { return len(p), nil }

func TestTwentyConnectsAtOnceStartOneSessionAndRevokeStopsIt(t *testing.T) {
	ctx := context.Background()
	var made, running atomic.Int64
	m, b := raceManager(t, &made, &running)

	var wg sync.WaitGroup
	var ok atomic.Int64
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := m.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "qr"}); err == nil {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if made.Load() != 1 || ok.Load() != 1 {
		t.Fatalf("one connection started %d sessions (%d connects answered ok); it must be exactly one",
			made.Load(), ok.Load())
	}
	if err := m.Revoke(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "every session of the revoked connection to stop", func() bool { return running.Load() == 0 })
	if len(b.Dump()) != 0 {
		t.Fatal("revoke left sealed bytes behind")
	}
}

// Disconnect pressed while a Connect for the same connection is still making
// its keys: whichever wins, nothing is left running without keys, and nothing
// is left with keys that nothing runs.
func TestRevokeDuringConnectLeavesNoHalfSession(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		var made, running atomic.Int64
		m, b := raceManager(t, &made, &running)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _ = m.Connect(ctx, "c1", "whatsapp", StartOptions{Method: "qr"})
		}()
		go func() {
			defer wg.Done()
			<-start
			time.Sleep(time.Millisecond)
			_ = m.Revoke(ctx, "c1")
		}()
		close(start)
		wg.Wait()

		_, live := m.Status("c1")
		_, stored := b.GetConnection(ctx, "c1")
		if live == nil && stored != nil {
			t.Fatalf("round %d: a session is running whose keys were destroyed", i)
		}
		if live != nil {
			eventually(t, "a revoked session to stop", func() bool { return running.Load() == 0 })
			if stored == nil {
				t.Fatalf("round %d: keys were kept for a connection nothing runs", i)
			}
		}
		m.Shutdown()
	}
}
