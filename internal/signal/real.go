//go:build cgo && libsignal

package signal

// The real Signal client: mautrix-signal's signalmeow over libsignal's Rust
// FFI (both AGPL-3.0). Compiled in only with `-tags libsignal`, which the
// Dockerfile passes after building libsignal_ffi.a; see notserved.go for the
// build without it.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-signal/pkg/libsignalgo"
	"go.mau.fi/mautrix-signal/pkg/signalmeow"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/events"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/store"
	"go.mau.fi/mautrix-signal/pkg/signalmeow/types"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
)

var openReal opener = openSignalmeow

func openSignalmeow(ctx context.Context, v *sealed.Vault) (provider, local, error) {
	db, err := openSealedDB(ctx, v)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := dbutil.NewWithDB(db.DB(), "sqlite3")
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	c := store.NewStore(wrapped, dbutil.NoopLogger)
	if err := c.Upgrade(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("signal: preparing the account database: %w", err)
	}
	return &meow{c: c, log: quietLog()}, db, nil
}

// quietLog drops every line signalmeow writes — its debug lines carry
// message metadata — and only counts warnings and errors (logsafe.Library).
func quietLog() zerolog.Logger {
	return zerolog.New(io.Discard).Level(zerolog.WarnLevel).Hook(zerolog.HookFunc(
		func(_ *zerolog.Event, level zerolog.Level, _ string) {
			logsafe.Library.Note("signalmeow", level.String())
		}))
}

type meow struct {
	c   *store.Container
	log zerolog.Logger

	mu  sync.Mutex
	dev *store.Device
	cli *signalmeow.Client
}

func accountOf(d *store.Device) Account {
	a := Account{ACI: d.ACI.String(), Number: d.Number}
	if rec := d.AccountRecord; rec != nil {
		a.Name = strings.TrimSpace(rec.GetGivenName() + " " + rec.GetFamilyName())
	}
	return a
}

func (r *meow) Account(ctx context.Context) (Account, bool, error) {
	devs, err := r.c.GetAllDevices(ctx)
	if err != nil {
		return Account{}, false, err
	}
	for _, d := range devs {
		if d.IsDeviceLoggedIn() {
			r.mu.Lock()
			r.dev = d
			r.mu.Unlock()
			return accountOf(d), true, nil
		}
	}
	return Account{}, false, nil
}

func (r *meow) Link(ctx context.Context, show func(string, time.Time)) (Account, error) {
	ctx = r.log.WithContext(ctx)
	for range QRCount {
		acct, again, err := r.offerOne(ctx, show)
		if !again {
			return acct, err
		}
	}
	return Account{}, session.ErrPairingExpired
}

// offerOne opens one provisioning socket and shows its QR. again is true when
// the QR's time ran out with nobody scanning it.
func (r *meow) offerOne(ctx context.Context, show func(string, time.Time)) (Account, bool, error) {
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := signalmeow.PerformProvisioning(pctx, r.c, DeviceName, false)
	var resp signalmeow.ProvisioningResponse
	select {
	case resp = <-ch:
	case <-ctx.Done():
		return Account{}, false, ctx.Err()
	}
	if resp.Err != nil || resp.State != signalmeow.StateProvisioningURLReceived {
		// Signal's socket did not open: not the person's doing, so the
		// watchdog may try again.
		return Account{}, false, errors.New("signal: the linking socket did not open")
	}
	show(resp.ProvisioningURL, time.Now().Add(QRLifetime))
	select {
	case <-ctx.Done():
		return Account{}, false, ctx.Err()
	case <-time.After(QRLifetime):
		return Account{}, true, nil
	case resp = <-ch:
	}
	if resp.Err != nil || resp.State != signalmeow.StateProvisioningDataReceived ||
		resp.ProvisioningData == nil || resp.ProvisioningData.ACI == uuid.Nil {
		// Scanned, then refused — e.g. the account already has five linked
		// devices. Terminal: the person reads why and tries again.
		return Account{}, false, &session.PairingError{Reason: session.ReasonPairingFailed}
	}
	dev, err := r.c.DeviceByACI(ctx, resp.ProvisioningData.ACI)
	if err != nil || dev == nil {
		return Account{}, false, errors.New("signal: the linked device was not stored")
	}
	r.mu.Lock()
	r.dev = dev
	r.mu.Unlock()
	return accountOf(dev), false, nil
}

func (r *meow) Receive(ctx context.Context, deliver func(Message)) error {
	r.mu.Lock()
	dev := r.dev
	r.mu.Unlock()
	if dev == nil {
		return session.ErrNotLinked
	}
	ctx = r.log.WithContext(ctx)
	loggedOut := make(chan struct{}, 1)
	var cli *signalmeow.Client
	cli = signalmeow.NewClient(dev, r.log, func(evt events.SignalEvent) bool {
		switch e := evt.(type) {
		case *events.ChatEvent:
			if m, ok := r.decode(ctx, cli, e); ok {
				deliver(m)
			}
		case *events.LoggedOut:
			select {
			case loggedOut <- struct{}{}:
			default:
			}
		}
		return true
	})
	statuses, err := cli.StartReceiveLoops(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cli = cli
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.cli = nil
		r.mu.Unlock()
		_ = cli.StopReceiveLoops()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-loggedOut:
			return session.ErrLoggedOut
		case st, ok := <-statuses:
			if !ok {
				return errors.New("signal: the connection closed")
			}
			switch st.Event {
			case signalmeow.SignalConnectionEventLoggedOut:
				return session.ErrLoggedOut
			case signalmeow.SignalConnectionEventFatalError:
				return errors.New("signal: the connection failed")
			}
		}
	}
}

// decode turns a ChatEvent into a Message. Typing and edits are not messages
// to a person; control messages are returned with Skip set so their
// disappearing-message timer is still recorded.
func (r *meow) decode(ctx context.Context, cli *signalmeow.Client, e *events.ChatEvent) (Message, bool) {
	dm, ok := e.Event.(*signalpb.DataMessage)
	if !ok || dm == nil {
		return Message{}, false
	}
	m := Message{
		Sender:             e.Info.Sender.String(),
		ChatID:             e.Info.ChatID,
		Group:              dm.GetGroupV2() != nil,
		Timestamp:          dm.GetTimestamp(),
		Body:               dm.GetBody(),
		QuoteAuthor:        dm.GetQuote().GetAuthorAci(),
		ExpireTimer:        dm.GetExpireTimer(),
		ExpireTimerVersion: dm.GetExpireTimerVersion(),
		TimerUpdate:        dm.GetFlags()&uint32(signalpb.DataMessage_EXPIRATION_TIMER_UPDATE) != 0,
		Skip: dm.GetReaction() != nil || dm.GetDelete() != nil || dm.GetGroupCallUpdate() != nil ||
			dm.GetFlags() != 0,
	}
	for _, br := range dm.GetBodyRanges() {
		if a := br.GetMentionAci(); a != "" {
			m.Mentions = append(m.Mentions, a)
		}
	}
	switch {
	case len(dm.GetAttachments()) > 0:
		a := dm.GetAttachments()[0]
		m.Attachment = AttachmentKind(a.GetContentType(), a.GetFlags()&uint32(signalpb.AttachmentPointer_VOICE_MESSAGE) != 0)
	case dm.GetSticker() != nil:
		m.Attachment = "sticker"
	case len(dm.GetContact()) > 0:
		m.Attachment = "contact"
	}
	if m.Skip {
		return m, true
	}
	if rec, err := cli.ContactByACI(ctx, e.Info.Sender); err == nil && rec != nil {
		for _, n := range []string{rec.Nickname, rec.ContactName, rec.Profile.Name} {
			if n = strings.TrimSpace(n); n != "" {
				m.SenderName = n
				break
			}
		}
	}
	if m.Group {
		if g, _, err := cli.RetrieveGroupByID(ctx, types.GroupIdentifier(e.Info.ChatID), e.Info.GroupRevision); err == nil && g != nil {
			m.ChatTitle = g.Title
		}
	}
	return m, true
}

func (r *meow) Send(ctx context.Context, chat, text string, t Timer) (string, error) {
	r.mu.Lock()
	cli := r.cli
	r.mu.Unlock()
	if cli == nil {
		return "", session.ErrNotLinked
	}
	ctx = r.log.WithContext(ctx)
	ts := uint64(time.Now().UnixMilli())
	dm := &signalpb.DataMessage{Body: proto.String(text), Timestamp: proto.Uint64(ts)}
	// Without the chat's own timer, a reply would switch its disappearing
	// messages off on everybody's phone.
	if t.Seconds > 0 {
		dm.ExpireTimer = proto.Uint32(t.Seconds)
	}
	if t.Version > 0 {
		dm.ExpireTimerVersion = proto.Uint32(t.Version)
	}
	content := &signalpb.Content{Content: &signalpb.Content_DataMessage{DataMessage: dm}}
	if sid, err := libsignalgo.ServiceIDFromString(chat); err == nil {
		if res := cli.SendMessage(ctx, sid, content); !res.WasSuccessful {
			return "", errors.New("signal: the message was not delivered")
		}
	} else {
		res, err := cli.SendGroupMessage(ctx, types.GroupIdentifier(chat), content)
		if err != nil {
			return "", errors.New("signal: the group message was not sent")
		}
		if len(res.SuccessfullySentTo) == 0 && len(res.FailedToSendTo) > 0 {
			return "", errors.New("signal: the group message reached nobody")
		}
	}
	return MessageID(cli.Store.ACI.String(), ts), nil
}

// Unlink removes this device from the account's Linked devices, then the
// device from the local database. It needs a live connection; without one
// the device stays listed on the phone until removed there, and the manager
// destroys the keys anyway.
func (r *meow) Unlink(ctx context.Context) error {
	r.mu.Lock()
	cli, dev := r.cli, r.dev
	r.mu.Unlock()
	var err error
	if cli != nil {
		err = cli.Unlink(r.log.WithContext(ctx))
	} else {
		err = errors.New("signal: not connected, so the device could not be unlinked at Signal")
	}
	if dev != nil {
		_ = r.c.DeleteDevice(ctx, &dev.DeviceData)
	}
	return err
}
