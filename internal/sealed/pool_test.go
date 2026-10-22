package sealed

import (
	"context"
	"os"
	"testing"
)

// The pool's ceiling. pgx's default is max(4, CPUs) — four on a shared-cpu
// machine — and the leader lock holds one connection for the life of the
// process, so every live session's store queued on the other three.
// BRIDGE_DB_MAX_CONNS sets it without editing the secret URL.
func TestBridgeDBMaxConnsIsReadAndRefusedWhenWrong(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int32
		ok   bool
	}{
		{"", 0, true},
		{"10", 10, true},
		{" 25 ", 25, true},
		{"2", 2, true},
		{"100", 100, true},
		{"1", 0, false}, // the leader lock would hold the only one
		{"0", 0, false},
		{"-3", 0, false},
		{"101", 0, false},
		{"ten", 0, false},
		{"10.5", 0, false},
	} {
		got, err := MaxConnsFromEnv(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("MaxConnsFromEnv(%q) = %d, %v; want %d, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
		// One fixed sentence: it names the variable and never echoes a value.
		if err != nil && err.Error() != "BRIDGE_DB_MAX_CONNS must be a whole number from 2 to 100" {
			t.Fatalf("the refusal must be the fixed sentence: %q", err)
		}
	}
}

func TestThePoolCeilingIsAppliedToThePgxConfig(t *testing.T) {
	const url = "postgres://bridge:pw@db.invalid:5432/bridge?sslmode=disable"
	for _, tc := range []struct {
		name     string
		url      string
		maxConns int32
		want     int32
	}{
		{"unset: the default, not pgx's four", url, 0, DefaultMaxConns},
		{"set: the variable", url, 25, 25},
		{"set: the variable over the URL's own", url + "&pool_max_conns=3", 12, 12},
		{"unset: the URL's own stands", url + "&pool_max_conns=3", 0, 3},
	} {
		cfg, err := poolConfig(tc.url, tc.maxConns)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if cfg.MaxConns != tc.want {
			t.Fatalf("%s: MaxConns = %d, want %d", tc.name, cfg.MaxConns, tc.want)
		}
	}
	if DefaultMaxConns != 10 {
		t.Fatalf("DefaultMaxConns = %d; fly.toml and ADR 0093 say 10", DefaultMaxConns)
	}
}

// Against a real Postgres when BRIDGE_TEST_DATABASE_URL names a private
// database: the pool NewPostgresBackend opens carries the ceiling.
func TestPostgresBackendOpensWithTheCeiling(t *testing.T) {
	url := os.Getenv("BRIDGE_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BRIDGE_TEST_DATABASE_URL not set")
	}
	p, err := NewPostgresBackend(context.Background(), url, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if got := p.MaxConns(); got != 7 {
		t.Fatalf("MaxConns = %d, want 7", got)
	}
}
