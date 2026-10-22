package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

// PhoneOfflineWarnAfter is when the brain is told the phone has been away too
// long. WhatsApp ends a linked device after roughly 14 days without its phone
// online; 12 leaves two days to open WhatsApp on the phone. Research note of
// 2026-10-20, ADR 0093.
const PhoneOfflineWarnAfter = 12 * 24 * time.Hour

// Sink is the brain, as the manager sees it.
type Sink interface {
	Message(ctx context.Context, connID, kind string, m Inbound) error
	Status(ctx context.Context, connID, kind string, s Status) error
}

// Manager owns every live session in the process.
type Manager struct {
	keyring   *sealed.Keyring
	factories map[string]Factory
	sink      Sink
	limiter   *ratelimit.Limiter
	log       *slog.Logger
	now       func() time.Time

	// Backoff between restarts of a failed session. Exposed for tests.
	BackoffMin, BackoffMax time.Duration
	// How long SubmitCode waits for the provider's answer to a code, so the
	// person reads "that code is not right" on the press that sent it rather
	// than on a poll two seconds later. Exposed for tests.
	SubmitWait time.Duration

	mu    sync.Mutex
	live  map[string]*running
	stats map[string]int
	// How each connection that ENDED ended, kept for EndedFor so the brain's
	// next poll reads "WhatsApp did not accept that number" instead of a 404
	// it can only call "expired". In memory, a state and a reason — never a
	// number or a code — and gone after EndedFor or on the next Connect.
	ended map[string]endedStatus

	// One lock per connection id, held by Connect from its "already
	// running?" check until the session is in `live`, and by Revoke for its
	// whole length. Without it two Connects arriving together both passed the
	// check: the second overwrote the first in `live` and its wrapped key in
	// the database, and the first ran on where Revoke could never reach it.
	// race_test.go. A *sync.Mutex per id ever connected; never deleted, so a
	// waiter can never be holding a lock somebody else has replaced.
	connLocks sync.Map
}

func (m *Manager) lockConn(connID string) (unlock func()) {
	v, _ := m.connLocks.LoadOrStore(connID, &sync.Mutex{})
	l := v.(*sync.Mutex)
	l.Lock()
	return l.Unlock
}

type running struct {
	connID  string
	kind    string
	method  string // "qr" | "code" | "" (resumed); never the phone number
	session Session
	cancel  context.CancelFunc
	done    chan struct{}
	warned  bool
}

type endedStatus struct {
	st Status
	at time.Time
}

// EndedFor is how long the way a connection ended stays readable.
const EndedFor = 15 * time.Minute

func NewManager(kr *sealed.Keyring, factories map[string]Factory, sink Sink, lim *ratelimit.Limiter, log *slog.Logger) *Manager {
	return &Manager{
		keyring: kr, factories: factories, sink: sink, limiter: lim, log: log, now: time.Now,
		BackoffMin: time.Second, BackoffMax: 5 * time.Minute, SubmitWait: 15 * time.Second,
		live: map[string]*running{}, stats: map[string]int{}, ended: map[string]endedStatus{},
	}
}

func init() {
	logsafe.RegisterClass(ErrLoggedOut, "logged_out")
	logsafe.RegisterClass(ErrPairingExpired, "pairing_expired")
	logsafe.RegisterClass(ErrNotLinked, "not_linked")
	logsafe.RegisterClass(ErrNotPressed, "not_pressed")
	logsafe.RegisterClass(ErrUnknownConnection, "unknown_connection")
	logsafe.RegisterClass(ErrWrongState, "wrong_state")
	logsafe.RegisterClass(ratelimit.ErrPerMinute, "rate_per_minute")
	logsafe.RegisterClass(ratelimit.ErrPerDay, "rate_per_day")
	logsafe.RegisterClass(ratelimit.ErrFirstContact, "rate_first_contact")
	logsafe.RegisterClass(sealed.ErrOpen, "sealed_open_failed")
	logsafe.RegisterClass(sealed.ErrDestroyed, "sealed_destroyed")
}

// Connect starts a new connection and waits briefly for its first challenge
// (the QR, the pairing code) so the brain can show it in the same request.
func (m *Manager) Connect(ctx context.Context, connID, kind string, opts StartOptions) (Status, error) {
	f, ok := m.factories[kind]
	if !ok {
		return Status{}, fmt.Errorf("session: no factory for kind %q", kind)
	}
	unlock := m.lockConn(connID)
	m.mu.Lock()
	if _, exists := m.live[connID]; exists {
		m.mu.Unlock()
		unlock()
		return Status{}, errors.New("session: connection already running")
	}
	delete(m.ended, connID) // a new attempt; the last one's ending is history
	m.mu.Unlock()
	vault, err := m.keyring.Create(ctx, connID, kind)
	if err != nil {
		unlock()
		return Status{}, err
	}
	r, err := m.start(connID, kind, f, vault, opts)
	if err != nil {
		_ = m.keyring.Destroy(context.Background(), connID)
		unlock()
		return Status{}, err
	}
	// In `live` now: a second Connect is refused and a Revoke reaches it.
	// Not held through the wait below, so Disconnect is never kept waiting
	// on a QR.
	unlock()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		st := r.session.Status()
		if st.Challenge != nil || (st.State != "" && st.State != StatePairing) {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-r.done:
			// It ended before showing anything — a number WhatsApp refused,
			// a flood wait. The answer is how it ended, now, not ten seconds
			// of "pairing" followed by a 404.
			if end, err := m.Status(connID); err == nil {
				return end, nil
			}
			return Status{State: StateFailed, Reason: ReasonPairingFailed}, nil
		case <-deadline:
			return st, nil
		case <-tick.C:
		}
	}
}

// Resume restarts every connection that was linked before this process
// started. This is the whole deploy story: sessions are sealed in the
// bridge's database, so a new machine with the same root key picks them up.
// A connection that was still pairing when the old process died is destroyed
// — its QR is gone with the process, and a half-made link is not worth a key.
func (m *Manager) Resume(ctx context.Context) error {
	conns, err := m.keyring.Backend().ListConnections(ctx)
	if err != nil {
		return err
	}
	resumed := 0
	for _, c := range conns {
		switch c.State {
		case StateLinked, StateReconnecting:
		default:
			_ = m.keyring.Destroy(ctx, c.ID)
			continue
		}
		f, ok := m.factories[c.Kind]
		if !ok {
			m.log.Warn("resume: no factory", slog.String("kind", c.Kind), slog.String("conn", c.ID))
			continue
		}
		vault, err := m.keyring.Open(ctx, c.ID)
		if err != nil {
			m.log.Warn("resume: vault would not open", slog.String("conn", c.ID), logsafe.Err(err))
			continue
		}
		if _, err := m.start(c.ID, c.Kind, f, vault, StartOptions{Resume: true}); err != nil {
			m.log.Warn("resume: session would not start", slog.String("conn", c.ID), logsafe.Err(err))
			continue
		}
		resumed++
	}
	m.log.Info("resumed", slog.Int("sessions", resumed))
	return nil
}

func (m *Manager) start(connID, kind string, f Factory, vault *sealed.Vault, opts StartOptions) (*running, error) {
	rep := &reporter{m: m, connID: connID, kind: kind}
	s, err := f(connID, vault, rep, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{connID: connID, kind: kind, method: opts.Method, session: s, cancel: cancel, done: make(chan struct{})}
	m.mu.Lock()
	m.live[connID] = r
	m.mu.Unlock()
	go m.watch(ctx, r)
	return r, nil
}

// watch is the watchdog: it runs the session, restarts it with backoff when
// it fails, and stops for good on a logout, an expired pairing or a revoke.
// A panic in a library is caught and treated as a failure, so one bad
// payload cannot take every other customer's session down with the process.
func (m *Manager) watch(ctx context.Context, r *running) {
	defer close(r.done)
	backoff := m.BackoffMin
	for attempt := 1; ; attempt++ {
		err := m.runOnce(ctx, r.session)
		if ctx.Err() != nil {
			return
		}
		var refused *PairingError
		switch {
		case errors.Is(err, ErrLoggedOut):
			m.finish(r, Status{State: StateLoggedOut, Reason: "unlinked_on_phone"})
			return
		case errors.Is(err, ErrPairingExpired):
			m.finish(r, Status{State: StateExpired, Reason: "pairing_expired"})
			return
		case errors.As(err, &refused):
			m.log.Info("pairing refused", slog.String("conn", r.connID), slog.String("kind", r.kind),
				slog.String("reason", refused.Reason))
			m.finish(r, Status{State: StateFailed, Reason: refused.Reason,
				RetryAfterSeconds: RetryAfterSeconds(refused.RetryAfter)})
			return
		case err != nil && r.method == "code" && !everLinked(r.session.Status()):
			// A PHONE-NUMBER LINK IS NEVER RETRIED BY ITSELF. Each attempt
			// sends the person's phone a new code (a WhatsApp notification, a
			// Telegram message) and makes the one on their screen worthless.
			// The person presses "Get a new code" when they want one.
			m.log.Warn("code link failed", slog.String("conn", r.connID), slog.String("kind", r.kind), logsafe.Err(err))
			m.finish(r, Status{State: StateFailed, Reason: ReasonPairingFailed})
			return
		}
		m.count("restart")
		m.log.Warn("session stopped; restarting", slog.String("conn", r.connID),
			slog.String("kind", r.kind), slog.Int("attempt", attempt), logsafe.Err(err))
		if st := r.session.Status(); st.State == StateLinked || st.State == StateReconnecting {
			m.persist(r.connID, StateReconnecting)
			_ = m.sink.Status(context.Background(), r.connID, r.kind, Status{State: StateReconnecting})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > m.BackoffMax {
			backoff = m.BackoffMax
		}
	}
}

func (m *Manager) runOnce(ctx context.Context, s Session) (err error) {
	defer func() {
		if p := recover(); p != nil {
			m.count("panic")
			err = errors.New("session panicked")
		}
	}()
	return s.Run(ctx)
}

func everLinked(st Status) bool { return st.State == StateLinked || st.State == StateReconnecting }

// finish ends a connection the provider ended, or a link attempt that cannot
// go on: the brain is told, then the keys are destroyed. A session WhatsApp
// has unlinked cannot be resumed, and a half-made link is not worth a key, so
// keeping either would be keeping secrets for nothing. How it ended stays
// readable for EndedFor.
func (m *Manager) finish(r *running, end Status) {
	_ = m.sink.Status(context.Background(), r.connID, r.kind, end)
	now := m.now()
	m.mu.Lock()
	delete(m.live, r.connID)
	for id, e := range m.ended {
		if now.Sub(e.at) >= EndedFor {
			delete(m.ended, id)
		}
	}
	m.ended[r.connID] = endedStatus{st: end, at: now}
	m.mu.Unlock()
	_ = m.keyring.Destroy(context.Background(), r.connID)
	m.limiter.Forget(r.connID)
	m.count(end.State)
}

// SubmitCode passes a Telegram login code or two-step password through, and
// waits (up to SubmitWait) for Telegram's answer to it: linked, a password
// asked for, the same question again because the code was wrong, or the end
// of the attempt. Neither the code nor the password is kept or logged here.
func (m *Manager) SubmitCode(ctx context.Context, connID, code, password string) (Status, error) {
	r, err := m.get(connID)
	if err != nil {
		return Status{}, err
	}
	before := r.session.Status().Seq
	if err := r.session.SubmitCode(ctx, code, password); err != nil {
		return r.session.Status(), err
	}
	deadline := time.After(m.SubmitWait)
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.done:
			if end, err := m.Status(connID); err == nil {
				return end, nil
			}
			return Status{State: StateFailed, Reason: ReasonPairingFailed}, nil
		case <-ctx.Done():
			return r.session.Status(), nil
		case <-deadline:
			return r.session.Status(), nil
		case <-tick.C:
			if st := r.session.Status(); st.Seq != before {
				return st, nil
			}
		}
	}
}

// Send delivers one reply. Both checks happen here, in the process that talks
// to the provider, whatever the brain already decided: a person pressed it,
// and the pace is human.
func (m *Manager) Send(ctx context.Context, connID, chatID, text string, pressedByPerson bool) (string, error) {
	if !pressedByPerson {
		m.count("refused_unpressed")
		return "", ErrNotPressed
	}
	r, err := m.get(connID)
	if err != nil {
		return "", err
	}
	if r.session.Status().State != StateLinked {
		return "", ErrNotLinked
	}
	if err := m.limiter.Allow(connID, r.kind, chatID); err != nil {
		m.count("refused_rate")
		return "", err
	}
	id, err := r.session.Send(ctx, chatID, text)
	if err != nil {
		m.log.Warn("send failed", slog.String("conn", connID), logsafe.Err(err))
		return "", err
	}
	m.count("sent")
	return id, nil
}

// Revoke is disconnect: unlink at the provider (best effort, bounded), stop
// the session, destroy the keys. The destroy happens even when the provider
// call fails — a person who pressed Disconnect has asked for the keys to go,
// and a WhatsApp outage is not a reason to keep them.
func (m *Manager) Revoke(ctx context.Context, connID string) error {
	// A Connect for this id still making its keys finishes first, so what it
	// starts is in `live` for the lines below to stop and destroy.
	defer m.lockConn(connID)()
	m.mu.Lock()
	r := m.live[connID]
	delete(m.live, connID)
	m.mu.Unlock()
	if r != nil {
		lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := r.session.Logout(lctx); err != nil {
			m.log.Warn("provider logout failed; destroying keys anyway", slog.String("conn", connID), logsafe.Err(err))
		}
		cancel()
		r.cancel()
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
		}
	}
	m.limiter.Forget(connID)
	m.mu.Lock()
	delete(m.ended, connID)
	m.mu.Unlock()
	m.count("revoked")
	return m.keyring.Destroy(ctx, connID)
}

// Status of one connection: the live session's, or — for EndedFor after it
// ended — how it ended.
func (m *Manager) Status(connID string) (Status, error) {
	r, err := m.get(connID)
	if err == nil {
		return r.session.Status(), nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.ended[connID]; ok {
		if m.now().Sub(e.at) < EndedFor {
			return e.st, nil
		}
		delete(m.ended, connID)
	}
	return Status{}, err
}

// CheckPhones warns the brain, once per connection, when a WhatsApp phone has
// been offline long enough that the linked device is about to stop. Called on
// a timer by main.
func (m *Manager) CheckPhones(ctx context.Context) {
	m.mu.Lock()
	rs := make([]*running, 0, len(m.live))
	for _, r := range m.live {
		rs = append(rs, r)
	}
	m.mu.Unlock()
	now := m.now()
	for _, r := range rs {
		st := r.session.Status()
		if st.State != StateLinked || st.PhoneLastSeen.IsZero() {
			continue
		}
		away := now.Sub(st.PhoneLastSeen)
		if away < PhoneOfflineWarnAfter {
			r.warned = false
			continue
		}
		if r.warned {
			continue
		}
		r.warned = true
		st.Warning = "phone_offline"
		_ = m.sink.Status(ctx, r.connID, r.kind, st)
		m.log.Info("phone offline warning", slog.String("conn", r.connID), slog.Int("days", int(away.Hours()/24)))
	}
}

// Health is counts only: how many sessions in each state, and what happened.
func (m *Manager) Health() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for k, v := range m.stats {
		out["events."+k] = v
	}
	for _, r := range m.live {
		out["state."+r.session.Status().State]++
	}
	out["sessions"] = len(m.live)
	return out
}

// Shutdown stops every session WITHOUT logging out or destroying anything —
// what a deploy does. The next process resumes them.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	rs := make([]*running, 0, len(m.live))
	for _, r := range m.live {
		rs = append(rs, r)
	}
	m.live = map[string]*running{}
	m.mu.Unlock()
	for _, r := range rs {
		r.cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	}
}

func (m *Manager) get(connID string) (*running, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.live[connID]
	if !ok {
		return nil, ErrUnknownConnection
	}
	return r, nil
}

func (m *Manager) count(k string) {
	m.mu.Lock()
	m.stats[k]++
	m.mu.Unlock()
}

func (m *Manager) persist(connID, state string) {
	if err := m.keyring.Backend().SetConnectionState(context.Background(), connID, state); err != nil &&
		!errors.Is(err, sealed.ErrNotFound) {
		m.log.Warn("could not persist state", slog.String("conn", connID), logsafe.Err(err))
	}
}

type reporter struct {
	m      *Manager
	connID string
	kind   string
}

func (r *reporter) Status(s Status) {
	switch s.State {
	case StateLinked, StateReconnecting:
		r.m.persist(r.connID, s.State)
	}
	// The QR and the pairing code do not travel in status events: the brain
	// fetches them on the person's own request (GET /v1/connections/{id}), so
	// a pairing secret is never pushed anywhere it was not asked for.
	if s.Challenge != nil {
		s.Challenge = &Challenge{Kind: s.Challenge.Kind, ExpiresAt: s.Challenge.ExpiresAt,
			Via: s.Challenge.Via, Length: s.Challenge.Length}
	}
	if err := r.m.sink.Status(context.Background(), r.connID, r.kind, s); err != nil {
		r.m.log.Warn("status not delivered to the brain", slog.String("conn", r.connID), logsafe.Err(err))
	}
}

func (r *reporter) Message(in Inbound) {
	if in.Direction == "inbound" {
		r.m.limiter.NoteInbound(r.connID, r.kind, in.ChatID)
	}
	if err := r.m.sink.Message(context.Background(), r.connID, r.kind, in); err != nil {
		r.m.count("brain_delivery_failed")
		r.m.log.Warn("message not delivered to the brain", slog.String("conn", r.connID), logsafe.Err(err))
		return
	}
	r.m.count("delivered")
}
