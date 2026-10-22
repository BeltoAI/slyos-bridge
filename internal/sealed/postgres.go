package sealed

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresBackend stores sealed bytes in the BRIDGE's own database
// (BRIDGE_DATABASE_URL). Not the brain's: the brain has no reason to hold a
// linked-device key even sealed, and a database it cannot reach is one its
// bugs cannot leak from. ADR 0093.
type PostgresBackend struct {
	pool   *pgxpool.Pool
	leader *pgxpool.Conn
}

// Schema is applied at boot. Two tables, and what is NOT in them matters as
// much as what is: no phone number, no name, no message. Record keys (which
// are JIDs, i.e. phone numbers) are stored only as an HMAC.
const Schema = `
CREATE TABLE IF NOT EXISTS bridge_connections (
  id          text PRIMARY KEY,
  kind        text NOT NULL,
  state       text NOT NULL,
  wrapped_key bytea,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bridge_records (
  connection_id text NOT NULL,
  ns            text NOT NULL,
  key_hash      text NOT NULL,
  value         bytea NOT NULL,
  PRIMARY KEY (connection_id, ns, key_hash)
);
`

// DefaultMaxConns is the pool's ceiling when BRIDGE_DB_MAX_CONNS is unset and
// the URL does not carry pool_max_conns. pgx's own default is max(4, CPUs):
// four on a shared-cpu machine, and the leader lock holds one of them for
// the life of the process, so every session's store shared three.
const DefaultMaxConns int32 = 10

// MaxConnsFromEnv reads BRIDGE_DB_MAX_CONNS: "" is 0 (not set); anything
// that is not a whole number from 2 to 100 is refused, because one
// connection is the leader lock's and a typo must not start a bridge with
// none left for its sessions. The error names the variable, never a value.
func MaxConnsFromEnv(v string) (int32, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 2 || n > 100 {
		return 0, fmt.Errorf("BRIDGE_DB_MAX_CONNS must be a whole number from 2 to 100")
	}
	return int32(n), nil
}

// poolConfig is the pool NewPostgresBackend opens: the URL's own settings,
// with the ceiling set by BRIDGE_DB_MAX_CONNS (maxConns > 0) so the secret
// URL never has to be edited; unset, a pool_max_conns in the URL stands and
// otherwise DefaultMaxConns applies.
func poolConfig(url string, maxConns int32) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	switch {
	case maxConns > 0:
		cfg.MaxConns = maxConns
	case !strings.Contains(url, "pool_max_conns="):
		cfg.MaxConns = DefaultMaxConns
	}
	return cfg, nil
}

// NewPostgresBackend opens the bridge's database. maxConns is
// BRIDGE_DB_MAX_CONNS as MaxConnsFromEnv read it (0: not set).
func NewPostgresBackend(ctx context.Context, url string, maxConns int32) (*PostgresBackend, error) {
	cfg, err := poolConfig(url, maxConns)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, Schema); err != nil {
		pool.Close()
		return nil, err
	}
	return &PostgresBackend{pool: pool}, nil
}

// MaxConns is the pool's ceiling, for the boot log.
func (p *PostgresBackend) MaxConns() int32 { return p.pool.Config().MaxConns }

func (p *PostgresBackend) Close() {
	if p.leader != nil {
		p.leader.Release()
	}
	p.pool.Close()
}

func (p *PostgresBackend) PutConnection(ctx context.Context, c Connection) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO bridge_connections (id, kind, state, wrapped_key, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, state = EXCLUDED.state, wrapped_key = EXCLUDED.wrapped_key`,
		c.ID, c.Kind, c.State, c.WrappedKey, c.CreatedAt)
	return err
}

func (p *PostgresBackend) GetConnection(ctx context.Context, id string) (Connection, error) {
	var c Connection
	err := p.pool.QueryRow(ctx,
		`SELECT id, kind, state, wrapped_key, created_at FROM bridge_connections WHERE id = $1`, id).
		Scan(&c.ID, &c.Kind, &c.State, &c.WrappedKey, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrNotFound
	}
	return c, err
}

func (p *PostgresBackend) ListConnections(ctx context.Context) ([]Connection, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT id, kind, state, wrapped_key, created_at FROM bridge_connections ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.Kind, &c.State, &c.WrappedKey, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *PostgresBackend) SetConnectionState(ctx context.Context, id, state string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE bridge_connections SET state = $2 WHERE id = $1`, id, state)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PostgresBackend) DeleteConnectionKey(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE bridge_connections SET wrapped_key = NULL, state = 'destroyed' WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PostgresBackend) DeleteConnection(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM bridge_connections WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *PostgresBackend) PutRecord(ctx context.Context, connID, ns, keyHash string, value []byte) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO bridge_records (connection_id, ns, key_hash, value) VALUES ($1, $2, $3, $4)
		ON CONFLICT (connection_id, ns, key_hash) DO UPDATE SET value = EXCLUDED.value`,
		connID, ns, keyHash, value)
	return err
}

func (p *PostgresBackend) GetRecord(ctx context.Context, connID, ns, keyHash string) ([]byte, error) {
	var v []byte
	err := p.pool.QueryRow(ctx,
		`SELECT value FROM bridge_records WHERE connection_id = $1 AND ns = $2 AND key_hash = $3`,
		connID, ns, keyHash).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

func (p *PostgresBackend) DeleteRecord(ctx context.Context, connID, ns, keyHash string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM bridge_records WHERE connection_id = $1 AND ns = $2 AND key_hash = $3`,
		connID, ns, keyHash)
	return err
}

func (p *PostgresBackend) ListRecords(ctx context.Context, connID, ns string) ([]RawRecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT key_hash, value FROM bridge_records WHERE connection_id = $1 AND ns = $2 ORDER BY key_hash`,
		connID, ns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RawRecord
	for rows.Next() {
		var r RawRecord
		if err := rows.Scan(&r.KeyHash, &r.Value); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *PostgresBackend) DeleteRecords(ctx context.Context, connID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM bridge_records WHERE connection_id = $1`, connID)
	return err
}

// leaderLockID is an arbitrary constant: "only one bridge process holds
// sessions at a time". WhatsApp allows one live socket per linked device; two
// machines resuming the same sessions (a deploy that overlaps, a second
// machine somebody scaled up) would fight with StreamReplaced until one gave
// up. The lock makes the second process wait instead. ADR 0093.
const leaderLockID = 7_420_931_202

// AcquireLeader blocks until this process holds the bridge-wide advisory
// lock, and keeps the connection that holds it for the life of the process.
func (p *PostgresBackend) AcquireLeader(ctx context.Context) error {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	for {
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, leaderLockID).Scan(&ok); err != nil {
			conn.Release()
			return err
		}
		if ok {
			p.leader = conn
			return nil
		}
		select {
		case <-ctx.Done():
			conn.Release()
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}
