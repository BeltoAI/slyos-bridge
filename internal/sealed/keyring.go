// Package sealed holds every secret the bridge keeps for a connection: the
// WhatsApp linked-device keys, the Telegram MTProto auth key, and anything a
// later channel needs. ADR 0093.
//
// TWO LAYERS, THE SAME SHAPE AS services/brain/src/crypto/envelope.ts:
//
//	ROOT KEY — 32 bytes read from BRIDGE_ROOT_KEY_BASE64 at boot and held in
//	           this process's memory. In production it is a Fly secret on the
//	           bridge app, set by the owner with `fly secrets set`, and nothing
//	           else holds it: the brain does not, the database does not.
//
//	           THERE IS NO KMS AND NO HSM. Nothing in this module talks to one,
//	           and go.mod carries no client for one. Anyone with the Fly
//	           secret and a copy of the bridge database can open every
//	           session. That is the honest boundary, and it is written here so
//	           nobody answers a security questionnaire with a stronger one.
//
//	DATA KEY — 32 random bytes PER CONNECTION (one WhatsApp, one Telegram),
//	           generated at connect, stored only wrapped by the root key.
//	           Every record of that connection is sealed under keys derived
//	           from it.
//
// Destroying a connection deletes its wrapped data key FIRST. From that moment
// every sealed record of that connection is undecryptable — in the live
// database and in every backup taken afterwards — before the record rows are
// even deleted. That is crypto-shredding, and it is what "disconnect destroys
// the keys" means here.
//
// AES-256-GCM throughout. The connection id, the record's namespace and its
// hashed key are bound in as additional authenticated data, so a record moved
// to another connection, or from the "session" namespace to the "identity"
// one, fails to open rather than opening as the wrong thing.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	keyBytes   = 32
	nonceBytes = 12
	formatV1   = 1
)

// ErrOpen is the only error a failed decryption produces. It never carries
// the ciphertext, the key, or which of tampering, a wrong key or a moved row
// caused it — those three look the same from here, and the message is logged.
var ErrOpen = errors.New("sealed: record failed authentication")

// RootKey is the bridge-wide key-wrapping key. It has no String method that
// could print it, and fmt verbs see only the redaction below.
type RootKey struct{ k []byte }

// Format keeps the key out of every %v, %s, %+v and %#v.
func (RootKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("RootKey(redacted)")) }

// ParseRootKey reads the base64 value of BRIDGE_ROOT_KEY_BASE64. It refuses
// anything that is not exactly 32 bytes rather than padding or hashing a short
// value into shape, which would turn a typo into a weak key that works.
func ParseRootKey(b64 string) (RootKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return RootKey{}, errors.New("sealed: root key is not base64")
	}
	if len(raw) != keyBytes {
		return RootKey{}, fmt.Errorf("sealed: root key must be %d bytes, got %d", keyBytes, len(raw))
	}
	return RootKey{k: raw}, nil
}

// ConnectionKey is one connection's data key, unwrapped, in memory only. It is
// split by HKDF into an encryption key and an index key so the hash that names
// a record can never be used to open it.
type ConnectionKey struct {
	connID string
	enc    []byte
	index  []byte
}

func (ConnectionKey) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("ConnectionKey(redacted)"))
}

// Zero overwrites the key material. Called on revoke so a heap dump taken
// after a disconnect does not still hold the key.
func (c *ConnectionKey) Zero() {
	for i := range c.enc {
		c.enc[i] = 0
	}
	for i := range c.index {
		c.index[i] = 0
	}
}

// NewDataKey makes a fresh data key and returns it wrapped by the root key —
// the only form that is ever stored — together with its unwrapped form.
func NewDataKey(root RootKey, connID string) (wrapped []byte, key *ConnectionKey, err error) {
	dek := make([]byte, keyBytes)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, err
	}
	wrapped, err = seal(root.k, dek, wrapAAD(connID))
	if err != nil {
		return nil, nil, err
	}
	key, err = derive(connID, dek)
	for i := range dek {
		dek[i] = 0
	}
	return wrapped, key, err
}

// UnwrapDataKey opens a stored data key. A key wrapped for one connection does
// not unwrap as another's: the connection id is the additional data.
func UnwrapDataKey(root RootKey, connID string, wrapped []byte) (*ConnectionKey, error) {
	dek, err := open(root.k, wrapped, wrapAAD(connID))
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	if len(dek) != keyBytes {
		return nil, ErrOpen
	}
	return derive(connID, dek)
}

func wrapAAD(connID string) []byte { return []byte("slyos-bridge:dek:v1:" + connID) }

func derive(connID string, dek []byte) (*ConnectionKey, error) {
	enc, err := hkdf.Key(sha256.New, dek, nil, "slyos-bridge:record-encryption:v1", keyBytes)
	if err != nil {
		return nil, err
	}
	idx, err := hkdf.Key(sha256.New, dek, nil, "slyos-bridge:record-index:v1", keyBytes)
	if err != nil {
		return nil, err
	}
	return &ConnectionKey{connID: connID, enc: enc, index: idx}, nil
}

// KeyHash names a record without saying what it is. Record keys are things
// like a WhatsApp JID — which is a phone number — so they are never stored in
// the clear; the bridge database holds this HMAC instead.
func (c *ConnectionKey) KeyHash(ns, key string) string {
	m := hmac.New(sha256.New, c.index)
	m.Write([]byte(ns))
	m.Write([]byte{0})
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))
}

// Seal encrypts one record's value.
func (c *ConnectionKey) Seal(ns, keyHash string, plaintext []byte) ([]byte, error) {
	return seal(c.enc, plaintext, c.recordAAD(ns, keyHash))
}

// Open decrypts one record's value.
func (c *ConnectionKey) Open(ns, keyHash string, sealed []byte) ([]byte, error) {
	return open(c.enc, sealed, c.recordAAD(ns, keyHash))
}

func (c *ConnectionKey) recordAAD(ns, keyHash string) []byte {
	return []byte("slyos-bridge:record:v1:" + c.connID + "\x00" + ns + "\x00" + keyHash)
}

// [version:1][nonce:12][ciphertext+tag]
func seal(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != keyBytes {
		return nil, errors.New("sealed: key has the wrong length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+nonceBytes, 1+nonceBytes+len(plaintext)+gcm.Overhead())
	out[0] = formatV1
	if _, err := rand.Read(out[1 : 1+nonceBytes]); err != nil {
		return nil, err
	}
	return gcm.Seal(out, out[1:1+nonceBytes], plaintext, aad), nil
}

func open(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != keyBytes || len(sealed) < 1+nonceBytes+16 || sealed[0] != formatV1 {
		return nil, ErrOpen
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrOpen
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := gcm.Open(nil, sealed[1:1+nonceBytes], sealed[1+nonceBytes:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
