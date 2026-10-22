//go:build cgo

package signal

// THE ACCOUNT'S DATABASE, SEALED LIKE EVERY OTHER KIND'S STATE.
//
// signalmeow keeps its keys, sessions, prekeys, contacts and groups in SQL,
// and its store cannot be swapped for the vault record by record the way
// whatsmeow's can (store.Device holds the *dbutil.Database itself, for its
// transactions). So each connection gets a private in-memory SQLite database,
// and its durable copy is ONE vault record: the serialized database, sealed
// with the connection's data key under the same AEAD and AAD scheme as every
// WhatsApp and Telegram record, in the same bridge_records table of the same
// Neon database. Nothing of it touches the machine's disk.
//
// Disconnect destroys it the same way too: keyring.Destroy deletes the
// wrapped data key, then the record. Close below frees the in-memory copy and
// refuses every later Flush, so no flush loop and no Run on its way out can
// seal the account again after Logout.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"sync"

	"github.com/mattn/go-sqlite3"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

const (
	nsDB        = "signal"
	keySnapshot = "db"
	driverName  = "slyos-signal-sqlite"
)

var errClosed = errors.New("signal: the account database is closed")

var registerOnce sync.Once

type sealedDB struct {
	vault *sealed.Vault
	raw   *sql.DB

	mu     sync.Mutex
	last   [32]byte // sha256 of what was last sealed, so an unchanged database is not rewritten
	closed bool
}

// openSealedDB opens the connection's database, restored from its sealed
// copy when there is one.
func openSealedDB(ctx context.Context, v *sealed.Vault) (*sealedDB, error) {
	registerOnce.Do(func() {
		sql.Register(driverName, &sqlite3.SQLiteDriver{ConnectHook: func(c *sqlite3.SQLiteConn) error {
			// temp_store: go-sqlite3 builds with SQLite's default of temp
			// FILES, so a large sort or a TEMP table could spill decrypted
			// rows to the machine's /tmp. Kept in memory like the rest.
			_, err := c.Exec("PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY", nil)
			return err
		}})
	})
	raw, err := sql.Open(driverName, ":memory:")
	if err != nil {
		return nil, err
	}
	// ONE connection, never recycled: a second ":memory:" connection would be
	// a second, empty database. signalmeow runs its transactions through the
	// context, as mautrix's own in-memory tests do with one connection.
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)
	raw.SetConnMaxLifetime(0)
	raw.SetConnMaxIdleTime(0)
	d := &sealedDB{vault: v, raw: raw}

	snap, err := v.Get(ctx, nsDB, keySnapshot)
	switch {
	case errors.Is(err, sealed.ErrNotFound):
		if err := d.withConn(ctx, secureDelete); err != nil {
			_ = raw.Close()
			return nil, err
		}
	case err != nil:
		_ = raw.Close()
		return nil, err
	default:
		d.last = sha256.Sum256(snap)
		err = d.withConn(ctx, func(c *sqlite3.SQLiteConn) error {
			if err := c.Deserialize(snap, "main"); err != nil {
				return err
			}
			return secureDelete(c)
		})
		clear(snap)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	return d, nil
}

// secureDelete makes SQLite overwrite what it deletes. signalmeow buffers a
// decrypted message in its event table until it is handled, then clears it;
// without this the cleared bytes stay in the page, and the next snapshot
// would seal a message into the vault after SlyOS was done with it.
func secureDelete(c *sqlite3.SQLiteConn) error {
	_, err := c.Exec("PRAGMA secure_delete = ON", nil)
	return err
}

// DB is the database signalmeow is given.
func (d *sealedDB) DB() *sql.DB { return d.raw }

func (d *sealedDB) withConn(ctx context.Context, f func(*sqlite3.SQLiteConn) error) error {
	conn, err := d.raw.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Raw(func(dc any) error {
		c, ok := dc.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("signal: not a sqlite connection")
		}
		return f(c)
	})
}

// Flush seals the database into the vault if it changed since the last
// flush. The single connection is only free between transactions, so what is
// sealed is always a committed state.
func (d *sealedDB) Flush(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errClosed
	}
	var snap []byte
	if err := d.withConn(ctx, func(c *sqlite3.SQLiteConn) (err error) {
		snap, err = c.Serialize("main")
		return err
	}); err != nil {
		return err
	}
	defer clear(snap)
	sum := sha256.Sum256(snap)
	if sum == d.last {
		return nil
	}
	if err := d.vault.Put(ctx, nsDB, keySnapshot, snap); err != nil {
		return err
	}
	d.last = sum
	return nil
}

// Close frees the in-memory database. Every later Flush is refused.
func (d *sealedDB) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	d.closed = true
	_ = d.raw.Close()
}
