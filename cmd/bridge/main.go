// The SlyOS bridge: one isolated service that holds personal-channel sessions
// (WhatsApp as a linked device, a person's own Telegram) so they work without
// the Mac companion. ADR 0093 is the design; read it before changing this.
//
// It refuses to start without its secrets rather than starting weak:
//
//	BRIDGE_ROOT_KEY_BASE64   32 bytes. Wraps every connection's data key.
//	                         A Fly secret on the bridge app only. No KMS/HSM.
//	BRIDGE_SHARED_SECRET     >= 32 chars. The brain sends it to call us.
//	BRIDGE_EVENTS_SECRET     >= 32 chars. We sign what we send the brain.
//	BRAIN_URL                the brain's public URL, e.g. https://brain.example.com
//	BRIDGE_DATABASE_URL      the bridge's own Postgres. Without it the
//	                         bridge runs in memory ONLY if BRIDGE_ALLOW_MEMORY=1
//	                         (tests, local), and every session dies with it.
//	BRIDGE_DB_MAX_CONNS      the pool's ceiling, 2-100 (default 10), so the
//	                         secret URL never has to be edited for it. Not secret.
//	TELEGRAM_API_ID/_HASH    SlyOS's registration at my.telegram.org. Without
//	                         them Telegram is simply not served.
//
// Signal needs no secret of its own: it is served when the binary was built
// with `-tags libsignal` (the Dockerfile does), and not otherwise.
//
// SIGTERM stops sessions WITHOUT logging them out: that is a deploy, and the
// next machine resumes them from sealed state.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/BeltoAI/slyos-bridge/internal/api"
	"github.com/BeltoAI/slyos-bridge/internal/brain"
	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
	"github.com/BeltoAI/slyos-bridge/internal/ratelimit"
	"github.com/BeltoAI/slyos-bridge/internal/sealed"
	"github.com/BeltoAI/slyos-bridge/internal/session"
	signalbridge "github.com/BeltoAI/slyos-bridge/internal/signal"
	"github.com/BeltoAI/slyos-bridge/internal/telegram"
	"github.com/BeltoAI/slyos-bridge/internal/whatsapp"
)

func main() {
	log := logsafe.New(os.Stdout)
	if err := run(log); err != nil {
		var ce configError
		if errors.As(err, &ce) {
			// Our own sentence, naming a variable and never its value.
			log.Error(string(ce))
		} else {
			log.Error("bridge stopped", logsafe.Err(err))
		}
		os.Exit(1)
	}
}

// standIn is set only by standin.go, which is compiled only with
// `-tags standin`: a provider that is nothing real, for walking the QR flow
// on a laptop. Nil in every build Fly runs (TestTheShippedBuildHasNoStandIn).
var standIn func(log *slog.Logger) (map[string]session.Factory, map[string]bool)

// configError messages are ours and name a variable, never a value.
type configError string

func (e configError) Error() string { return string(e) }

func run(log *slog.Logger) error {
	root, err := sealed.ParseRootKey(os.Getenv("BRIDGE_ROOT_KEY_BASE64"))
	if err != nil {
		return configError("BRIDGE_ROOT_KEY_BASE64 is missing or not 32 bytes")
	}
	shared := os.Getenv("BRIDGE_SHARED_SECRET")
	events := os.Getenv("BRIDGE_EVENTS_SECRET")
	if len(shared) < 32 || len(events) < 32 || shared == events {
		return configError("BRIDGE_SHARED_SECRET and BRIDGE_EVENTS_SECRET must be set, 32+ chars, and different")
	}
	brainURL := os.Getenv("BRAIN_URL")
	if brainURL == "" {
		return configError("BRAIN_URL is not set")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var backend sealed.Backend
	if url := os.Getenv("BRIDGE_DATABASE_URL"); url != "" {
		maxConns, err := sealed.MaxConnsFromEnv(os.Getenv("BRIDGE_DB_MAX_CONNS"))
		if err != nil {
			return configError(err.Error())
		}
		pg, err := sealed.NewPostgresBackend(ctx, url, maxConns)
		if err != nil {
			return configError("BRIDGE_DATABASE_URL could not be opened")
		}
		defer pg.Close()
		log.Info("database pool", slog.Int("max_conns", int(pg.MaxConns())))
		log.Info("waiting for the leader lock", slog.String("state", "standby"))
		if err := pg.AcquireLeader(ctx); err != nil {
			return err
		}
		backend = pg
	} else if os.Getenv("BRIDGE_ALLOW_MEMORY") == "1" {
		log.Warn("no database: every session is lost on restart", slog.String("state", "memory"))
		backend = sealed.NewMemoryBackend()
	} else {
		return configError("BRIDGE_DATABASE_URL is not set")
	}

	factories := map[string]session.Factory{whatsapp.Kind: whatsapp.Factory()}
	kinds := map[string]bool{whatsapp.Kind: true}
	if id, _ := strconv.Atoi(os.Getenv("TELEGRAM_API_ID")); id != 0 && os.Getenv("TELEGRAM_API_HASH") != "" {
		factories[telegram.Kind] = telegram.Factory(telegram.Config{AppID: id, AppHash: os.Getenv("TELEGRAM_API_HASH")})
		kinds[telegram.Kind] = true
	} else {
		log.Info("telegram not served", slog.String("reason", "no_api_id"))
	}
	if f := signalbridge.Factory(); f != nil {
		factories[signalbridge.Kind] = f
		kinds[signalbridge.Kind] = true
	} else {
		log.Info("signal not served", slog.String("reason", "built_without_libsignal"))
	}

	if standIn != nil {
		factories, kinds = standIn(log)
	}

	sink := &brain.Client{URL: brainURL, Secret: []byte(events)}
	mgr := session.NewManager(sealed.NewKeyring(root, backend), factories, sink, ratelimit.New(nil), log)
	if err := mgr.Resume(ctx); err != nil {
		return err
	}

	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mgr.CheckPhones(ctx)
			}
		}
	}()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr: ":" + port,
		Handler: (&api.Server{Manager: mgr, Secret: []byte(shared), Log: log, Kinds: kinds,
			Pairs: ratelimit.NewPairLimiter(nil)}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", slog.String("addr", srv.Addr))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	mgr.Shutdown()
	return nil
}
