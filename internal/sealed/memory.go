package sealed

import (
	"context"
	"sort"
	"sync"
)

// MemoryBackend keeps sealed bytes in a map. Tests use it; so does a bridge
// started without BRIDGE_DATABASE_URL, which then loses every session on
// restart and says so at boot.
type MemoryBackend struct {
	mu      sync.Mutex
	conns   map[string]Connection
	records map[string]map[string][]byte // connID -> ns\x00hash -> value
}

func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{conns: map[string]Connection{}, records: map[string]map[string][]byte{}}
}

func (m *MemoryBackend) PutConnection(_ context.Context, c Connection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.WrappedKey = append([]byte(nil), c.WrappedKey...)
	m.conns[c.ID] = c
	return nil
}

func (m *MemoryBackend) GetConnection(_ context.Context, id string) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[id]
	if !ok {
		return Connection{}, ErrNotFound
	}
	c.WrappedKey = append([]byte(nil), c.WrappedKey...)
	return c, nil
}

func (m *MemoryBackend) ListConnections(_ context.Context) ([]Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Connection, 0, len(m.conns))
	for _, c := range m.conns {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemoryBackend) SetConnectionState(_ context.Context, id, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[id]
	if !ok {
		return ErrNotFound
	}
	c.State = state
	m.conns[id] = c
	return nil
}

func (m *MemoryBackend) DeleteConnectionKey(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[id]
	if !ok {
		return ErrNotFound
	}
	for i := range c.WrappedKey {
		c.WrappedKey[i] = 0
	}
	c.WrappedKey = nil
	c.State = "destroyed"
	m.conns[id] = c
	return nil
}

func (m *MemoryBackend) DeleteConnection(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.conns[id]; !ok {
		return ErrNotFound
	}
	delete(m.conns, id)
	return nil
}

func (m *MemoryBackend) PutRecord(_ context.Context, connID, ns, keyHash string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[connID]
	if r == nil {
		r = map[string][]byte{}
		m.records[connID] = r
	}
	r[ns+"\x00"+keyHash] = append([]byte(nil), value...)
	return nil
}

func (m *MemoryBackend) GetRecord(_ context.Context, connID, ns, keyHash string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.records[connID][ns+"\x00"+keyHash]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (m *MemoryBackend) DeleteRecord(_ context.Context, connID, ns, keyHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records[connID], ns+"\x00"+keyHash)
	return nil
}

func (m *MemoryBackend) ListRecords(_ context.Context, connID, ns string) ([]RawRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []RawRecord
	prefix := ns + "\x00"
	for k, v := range m.records[connID] {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, RawRecord{KeyHash: k[len(prefix):], Value: append([]byte(nil), v...)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyHash < out[j].KeyHash })
	return out, nil
}

func (m *MemoryBackend) DeleteRecords(_ context.Context, connID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, connID)
	return nil
}

// Dump returns every stored byte, for tests that assert a secret never
// reaches storage in the clear.
func (m *MemoryBackend) Dump() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out [][]byte
	for _, c := range m.conns {
		out = append(out, []byte(c.ID), []byte(c.Kind), []byte(c.State), c.WrappedKey)
	}
	for _, rs := range m.records {
		for k, v := range rs {
			out = append(out, []byte(k), v)
		}
	}
	return out
}
