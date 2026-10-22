//go:build !standin

package main

import (
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/BeltoAI/slyos-bridge/internal/logsafe"
)

// The stand-in provider (standin.go) answers a QR with nothing real behind it
// and "links" by itself after a few seconds. In a build Fly runs that would be
// a bridge that reports linked accounts nobody linked, so it is compiled only
// with `-tags standin`, and this test, compiled only WITHOUT the tag, is the
// proof the default build — the one the Dockerfile makes — does not carry it.
func TestTheShippedBuildHasNoStandIn(t *testing.T) {
	if standIn != nil {
		t.Fatal("the default build carries the stand-in provider; standin.go must keep its //go:build standin line")
	}
}

// A wrong BRIDGE_DB_MAX_CONNS stops the bridge at boot with a sentence naming
// the variable, before the database is opened — never a bridge whose leader
// lock holds the only connection.
func TestABadPoolCeilingIsRefusedAtBoot(t *testing.T) {
	t.Setenv("BRIDGE_ROOT_KEY_BASE64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("BRIDGE_SHARED_SECRET", "shared-secret-shared-secret-shared-secret")
	t.Setenv("BRIDGE_EVENTS_SECRET", "events-secret-events-secret-events-secret")
	t.Setenv("BRAIN_URL", "http://brain.invalid")
	t.Setenv("BRIDGE_DATABASE_URL", "postgres://bridge@db.invalid:5432/bridge")
	t.Setenv("BRIDGE_DB_MAX_CONNS", "1")
	err := run(logsafe.New(io.Discard))
	var ce configError
	if !errors.As(err, &ce) || !strings.Contains(string(ce), "BRIDGE_DB_MAX_CONNS") {
		t.Fatalf("run() = %v; want the BRIDGE_DB_MAX_CONNS refusal", err)
	}
}

// The capacity the deploy carries (infra/fly-bridge.toml in the monorepo,
// kept out of this tree because the tree is published): a VM a first link
// fits in, the Go runtime's soft ceiling under it, and the pool ceiling as a
// plain variable rather than an edit to the secret URL.
func TestFlyTomlCarriesTheBridgeCapacity(t *testing.T) {
	if _, err := os.Stat("../../../brain"); err != nil {
		t.Skip("published alone: the deployment config is not part of this tree")
	}
	// Inside the monorepo the file must be there; a missing one fails.
	raw, err := os.ReadFile("../../../../infra/fly-bridge.toml")
	if err != nil {
		t.Fatal(err)
	}
	var env, vm []string
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch section {
		case "[env]":
			env = append(env, line)
		case "[[vm]]":
			vm = append(vm, line)
		}
	}
	for _, want := range []string{`GOMEMLIMIT = "1600MiB"`, `BRIDGE_DB_MAX_CONNS = "10"`} {
		if !slices.Contains(env, want) {
			t.Fatalf("fly.toml [env] lacks %s (has %q)", want, env)
		}
	}
	for _, want := range []string{`size = "shared-cpu-2x"`, `memory = "2048mb"`} {
		if !slices.Contains(vm, want) {
			t.Fatalf("fly.toml [[vm]] lacks %s (has %q)", want, vm)
		}
	}
}
