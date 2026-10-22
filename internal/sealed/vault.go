package sealed

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// ErrNotFound is the legitimate empty answer: no such connection or record.
// It is never returned for a record that exists and failed to open — that is
// ErrOpen, and the two must not be folded together.
var ErrNotFound = errors.New("sealed: not found")

// ErrDestroyed is returned by a Vault after its connection was destroyed. A
// session goroutine that outlives a revoke by a few milliseconds must fail
// loudly rather than write a fresh record under a key that no longer exists.
var ErrDestroyed = errors.New("sealed: connection was destroyed")

// Connection is the one row per connection the bridge keeps in the clear. It
// holds no message, no phone number and no name — only what the bridge needs
// to resume the session after a deploy.
type Connection struct {
	ID         string
	Kind       string
	State      string
	WrappedKey []byte
	CreatedAt  time.Time
}

// RawRecord is a stored, still-sealed record.
type RawRecord struct {
	KeyHash string
	Value   []byte
}

// Backend is where sealed bytes live. It never sees a key or a plaintext.
type Backend interface {
	PutConnection(ctx context.Context, c Connection) error
	GetConnection(ctx context.Context, id string) (Connection, error)
	ListConnections(ctx context.Context) ([]Connection, error)
	SetConnectionState(ctx context.Context, id, state string) error
	// DeleteConnectionKey removes the wrapped data key and nothing else. It is
	// the crypto-shred, and Destroy calls it before anything that can fail.
	DeleteConnectionKey(ctx context.Context, id string) error
	DeleteConnection(ctx context.Context, id string) error

	PutRecord(ctx context.Context, connID, ns, keyHash string, value []byte) error
	GetRecord(ctx context.Context, connID, ns, keyHash string) ([]byte, error)
	DeleteRecord(ctx context.Context, connID, ns, keyHash string) error
	ListRecords(ctx context.Context, connID, ns string) ([]RawRecord, error)
	DeleteRecords(ctx context.Context, connID string) error
}

// Keyring opens and destroys connection vaults. It is the only holder of the
// root key in the process.
type Keyring struct {
	root    RootKey
	backend Backend

	mu   sync.Mutex
	open map[string]*Vault
}

func NewKeyring(root RootKey, backend Backend) *Keyring {
	return &Keyring{root: root, backend: backend, open: map[string]*Vault{}}
}

func (k *Keyring) Backend() Backend { return k.backend }

// Create makes a new connection with a fresh data key.
func (k *Keyring) Create(ctx context.Context, connID, kind string) (*Vault, error) {
	wrapped, key, err := NewDataKey(k.root, connID)
	if err != nil {
		return nil, err
	}
	if err := k.backend.PutConnection(ctx, Connection{
		ID: connID, Kind: kind, State: "pairing", WrappedKey: wrapped, CreatedAt: time.Now().UTC(),
	}); err != nil {
		key.Zero()
		return nil, err
	}
	v := &Vault{connID: connID, key: key, backend: k.backend}
	k.mu.Lock()
	k.open[connID] = v
	k.mu.Unlock()
	return v, nil
}

// Open unwraps an existing connection's data key — what a deploy does for
// every live connection when the bridge boots.
func (k *Keyring) Open(ctx context.Context, connID string) (*Vault, error) {
	k.mu.Lock()
	if v, ok := k.open[connID]; ok {
		k.mu.Unlock()
		return v, nil
	}
	k.mu.Unlock()
	c, err := k.backend.GetConnection(ctx, connID)
	if err != nil {
		return nil, err
	}
	if len(c.WrappedKey) == 0 {
		return nil, ErrDestroyed
	}
	key, err := UnwrapDataKey(k.root, connID, c.WrappedKey)
	if err != nil {
		return nil, err
	}
	v := &Vault{connID: connID, key: key, backend: k.backend}
	k.mu.Lock()
	if existing, ok := k.open[connID]; ok {
		k.mu.Unlock()
		key.Zero()
		return existing, nil
	}
	k.open[connID] = v
	k.mu.Unlock()
	return v, nil
}

// Destroy crypto-shreds a connection. Order matters and is the point:
//
//  1. the wrapped data key is deleted — from here every record is noise;
//  2. the in-memory key is zeroed and the vault refuses further use;
//  3. the sealed records and the connection row are deleted.
//
// If step 3 fails the records that remain cannot be opened by anybody,
// including us, and a retry finishes the job.
func (k *Keyring) Destroy(ctx context.Context, connID string) error {
	if err := k.backend.DeleteConnectionKey(ctx, connID); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	k.mu.Lock()
	v := k.open[connID]
	delete(k.open, connID)
	k.mu.Unlock()
	if v != nil {
		v.destroy()
	}
	if err := k.backend.DeleteRecords(ctx, connID); err != nil {
		return err
	}
	if err := k.backend.DeleteConnection(ctx, connID); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// Vault is one connection's sealed key-value store.
type Vault struct {
	connID  string
	backend Backend

	mu        sync.RWMutex
	key       *ConnectionKey
	destroyed bool
}

// Entry is one opened record.
type Entry struct {
	Key   string
	Value []byte
}

func (v *Vault) ConnectionID() string { return v.connID }

func (v *Vault) destroy() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key != nil {
		v.key.Zero()
	}
	v.key = nil
	v.destroyed = true
}

func (v *Vault) withKey() (*ConnectionKey, func(), error) {
	v.mu.RLock()
	if v.destroyed || v.key == nil {
		v.mu.RUnlock()
		return nil, nil, ErrDestroyed
	}
	return v.key, v.mu.RUnlock, nil
}

// Put seals and stores a value. The record key travels INSIDE the sealed
// payload, so List can return it without the database ever holding it.
func (v *Vault) Put(ctx context.Context, ns, key string, value []byte) error {
	k, done, err := v.withKey()
	if err != nil {
		return err
	}
	defer done()
	h := k.KeyHash(ns, key)
	ct, err := k.Seal(ns, h, encodeEntry(key, value))
	if err != nil {
		return err
	}
	return v.backend.PutRecord(ctx, v.connID, ns, h, ct)
}

// Get returns ErrNotFound for a missing record and ErrOpen for one that exists
// and cannot be opened.
func (v *Vault) Get(ctx context.Context, ns, key string) ([]byte, error) {
	k, done, err := v.withKey()
	if err != nil {
		return nil, err
	}
	defer done()
	h := k.KeyHash(ns, key)
	ct, err := v.backend.GetRecord(ctx, v.connID, ns, h)
	if err != nil {
		return nil, err
	}
	pt, err := k.Open(ns, h, ct)
	if err != nil {
		return nil, err
	}
	gotKey, val, ok := decodeEntry(pt)
	if !ok || gotKey != key {
		return nil, ErrOpen
	}
	return val, nil
}

func (v *Vault) Delete(ctx context.Context, ns, key string) error {
	k, done, err := v.withKey()
	if err != nil {
		return err
	}
	defer done()
	return v.backend.DeleteRecord(ctx, v.connID, ns, k.KeyHash(ns, key))
}

// List opens every record in a namespace. One that fails to open is an error,
// never a silent skip: a skipped Signal session is a conversation that stops
// decrypting with no explanation.
func (v *Vault) List(ctx context.Context, ns string) ([]Entry, error) {
	k, done, err := v.withKey()
	if err != nil {
		return nil, err
	}
	defer done()
	raws, err := v.backend.ListRecords(ctx, v.connID, ns)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(raws))
	for _, r := range raws {
		pt, err := k.Open(ns, r.KeyHash, r.Value)
		if err != nil {
			return nil, err
		}
		key, val, ok := decodeEntry(pt)
		if !ok {
			return nil, ErrOpen
		}
		out = append(out, Entry{Key: key, Value: val})
	}
	return out, nil
}

func encodeEntry(key string, value []byte) []byte {
	out := make([]byte, 4+len(key)+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(key)))
	copy(out[4:], key)
	copy(out[4+len(key):], value)
	return out
}

func decodeEntry(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > len(b)-4 {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}
