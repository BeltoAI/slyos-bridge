package whatsapp

// A whatsmeow store whose every byte is sealed in the connection's vault.
//
// WHY NOT whatsmeow's sqlstore: it keeps the linked device's noise key,
// identity key, every Signal session and every pre-key in plain bytea
// columns, keyed by the contact's phone number in plain text. Anyone holding a
// database backup could impersonate the person's WhatsApp. Here the same data
// is AES-256-GCM sealed under a per-connection key, and the record keys
// (phone numbers, group ids) are stored only as HMACs. ADR 0093.
//
// The semantics copy sqlstore's, method by method, including its quieter
// choices ("trust an identity not seen before", "a missing pre-key is nil,
// nil"), because whatsmeow is written against those answers. Each one is noted
// where it is not obvious.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
	"google.golang.org/protobuf/proto"

	"github.com/BeltoAI/slyos-bridge/internal/sealed"
)

const (
	nsDevice     = "device"
	nsIdentity   = "identity"
	nsSession    = "session"
	nsPreKey     = "prekey"
	nsMeta       = "meta"
	nsSenderKey  = "senderkey"
	nsAppKey     = "appstate_key"
	nsAppVersion = "appstate_version"
	nsAppMAC     = "appstate_mac"
	nsContact    = "contact"
	nsChat       = "chat"
	nsMsgSecret  = "msgsecret"
	nsPrivacy    = "privacy"
	nsBuffered   = "buffered"
	nsOutgoing   = "outgoing"
	nsLID        = "lid"
)

// SealedStore implements every whatsmeow store interface over one vault.
type SealedStore struct {
	v *sealed.Vault

	preKeyMu  sync.Mutex
	contactMu sync.Mutex
}

var (
	_ store.AllStores       = (*SealedStore)(nil)
	_ store.DeviceContainer = (*SealedStore)(nil)
)

func NewSealedStore(v *sealed.Vault) *SealedStore { return &SealedStore{v: v} }

func (s *SealedStore) getJSON(ctx context.Context, ns, key string, out any) (bool, error) {
	b, err := s.v.Get(ctx, ns, key)
	if errors.Is(err, sealed.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, out)
}

func (s *SealedStore) putJSON(ctx context.Context, ns, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.v.Put(ctx, ns, key, b)
}

func (s *SealedStore) getBytes(ctx context.Context, ns, key string) ([]byte, error) {
	b, err := s.v.Get(ctx, ns, key)
	if errors.Is(err, sealed.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// deletePrefix is sqlstore's `LIKE phone || ':%'`.
func (s *SealedStore) deletePrefix(ctx context.Context, ns, prefix string) error {
	es, err := s.v.List(ctx, ns)
	if err != nil {
		return err
	}
	for _, e := range es {
		if strings.HasPrefix(e.Key, prefix) {
			if err := s.v.Delete(ctx, ns, e.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── Device ──────────────────────────────────────────────────────────────────

type deviceRecord struct {
	NoiseKey              []byte `json:"noise"`
	IdentityKey           []byte `json:"identity"`
	SignedPreKey          []byte `json:"spk"`
	SignedPreKeyID        uint32 `json:"spk_id"`
	SignedPreKeySig       []byte `json:"spk_sig"`
	RegistrationID        uint32 `json:"reg_id"`
	AdvSecretKey          []byte `json:"adv"`
	ID                    string `json:"jid"`
	LID                   string `json:"lid"`
	Account               []byte `json:"account"`
	Platform              string `json:"platform"`
	BusinessName          string `json:"business_name"`
	PushName              string `json:"push_name"`
	LIDMigrationTimestamp int64  `json:"lid_migration_ts"`
	CompanionMetaNonce    string `json:"companion_meta_nonce"`
	FacebookUUID          string `json:"fb_uuid"`
}

// NewDevice is sqlstore's Container.NewDevice, bound to this store.
func (s *SealedStore) NewDevice(log waLog.Logger) *store.Device {
	d := &store.Device{
		Log:            log,
		Container:      s,
		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: randomUint32(),
		AdvSecretKey:   randomBytes(32),
	}
	d.SignedPreKey = d.IdentityKey.CreateSignedPreKey(1)
	d.SetAllStores(s)
	d.LIDs = s
	return d
}

// LoadDevice returns the stored device, or nil when none was ever saved (a
// pairing that never completed).
func (s *SealedStore) LoadDevice(ctx context.Context, log waLog.Logger) (*store.Device, error) {
	var r deviceRecord
	ok, err := s.getJSON(ctx, nsDevice, "self", &r)
	if err != nil || !ok {
		return nil, err
	}
	d := &store.Device{
		Log:            log,
		Container:      s,
		NoiseKey:       keys.NewKeyPairFromPrivateKey(to32(r.NoiseKey)),
		IdentityKey:    keys.NewKeyPairFromPrivateKey(to32(r.IdentityKey)),
		RegistrationID: r.RegistrationID,
		AdvSecretKey:   r.AdvSecretKey,
		Platform:       r.Platform, BusinessName: r.BusinessName, PushName: r.PushName,
		LIDMigrationTimestamp: r.LIDMigrationTimestamp, CompanionMetaNonce: r.CompanionMetaNonce,
		Initialized: true,
	}
	spk := &keys.PreKey{KeyPair: *keys.NewKeyPairFromPrivateKey(to32(r.SignedPreKey)), KeyID: r.SignedPreKeyID}
	if len(r.SignedPreKeySig) == 64 {
		sig := [64]byte(r.SignedPreKeySig)
		spk.Signature = &sig
	}
	d.SignedPreKey = spk
	if r.ID != "" {
		jid, err := types.ParseJID(r.ID)
		if err != nil {
			return nil, err
		}
		d.ID = &jid
	}
	if r.LID != "" {
		if d.LID, err = types.ParseJID(r.LID); err != nil {
			return nil, err
		}
	}
	if len(r.Account) > 0 {
		var acc waAdv.ADVSignedDeviceIdentity
		if err := proto.Unmarshal(r.Account, &acc); err != nil {
			return nil, err
		}
		d.Account = &acc
	}
	if r.FacebookUUID != "" {
		d.FacebookUUID, _ = uuid.Parse(r.FacebookUUID)
	}
	d.SetAllStores(s)
	d.LIDs = s
	return d, nil
}

func (s *SealedStore) PutDevice(ctx context.Context, d *store.Device) error {
	if d.ID == nil {
		return errors.New("whatsapp: device JID must be known before it is saved")
	}
	r := deviceRecord{
		NoiseKey: d.NoiseKey.Priv[:], IdentityKey: d.IdentityKey.Priv[:],
		SignedPreKey: d.SignedPreKey.Priv[:], SignedPreKeyID: d.SignedPreKey.KeyID,
		RegistrationID: d.RegistrationID, AdvSecretKey: d.AdvSecretKey,
		ID: d.ID.String(), Platform: d.Platform, BusinessName: d.BusinessName, PushName: d.PushName,
		LIDMigrationTimestamp: d.LIDMigrationTimestamp, CompanionMetaNonce: d.CompanionMetaNonce,
	}
	if d.SignedPreKey.Signature != nil {
		r.SignedPreKeySig = d.SignedPreKey.Signature[:]
	}
	if !d.LID.IsEmpty() {
		r.LID = d.LID.String()
	}
	if d.Account != nil {
		b, err := proto.Marshal(d.Account)
		if err != nil {
			return err
		}
		r.Account = b
	}
	if d.FacebookUUID != uuid.Nil {
		r.FacebookUUID = d.FacebookUUID.String()
	}
	d.Initialized = true
	return s.putJSON(ctx, nsDevice, "self", r)
}

// DeleteDevice is whatsmeow's own logout path. The manager destroys the whole
// vault right after; this removes the device record so that even a vault
// that survived would not resume.
func (s *SealedStore) DeleteDevice(ctx context.Context, _ *store.Device) error {
	return s.v.Delete(ctx, nsDevice, "self")
}

// ── Identities and sessions ────────────────────────────────────────────────

func (s *SealedStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	return s.v.Put(ctx, nsIdentity, address, key[:])
}
func (s *SealedStore) DeleteAllIdentities(ctx context.Context, phone string) error {
	return s.deletePrefix(ctx, nsIdentity, phone+":")
}
func (s *SealedStore) DeleteIdentity(ctx context.Context, address string) error {
	return s.v.Delete(ctx, nsIdentity, address)
}

// IsTrustedIdentity trusts an identity it has never seen, as sqlstore does:
// whatsmeow saves it right after, and the next change is the one checked.
func (s *SealedStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	b, err := s.getBytes(ctx, nsIdentity, address)
	if err != nil {
		return false, err
	}
	if b == nil {
		return true, nil
	}
	if len(b) != 32 {
		return false, errors.New("whatsapp: stored identity has the wrong length")
	}
	return [32]byte(b) == key, nil
}

func (s *SealedStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	return s.getBytes(ctx, nsSession, address)
}
func (s *SealedStore) HasSession(ctx context.Context, address string) (bool, error) {
	b, err := s.getBytes(ctx, nsSession, address)
	return b != nil, err
}
func (s *SealedStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(addresses))
	for _, a := range addresses {
		b, err := s.getBytes(ctx, nsSession, a)
		if err != nil {
			return nil, err
		}
		out[a] = b // nil for missing, as sqlstore leaves it
	}
	return out, nil
}
func (s *SealedStore) PutSession(ctx context.Context, address string, session []byte) error {
	return s.v.Put(ctx, nsSession, address, session)
}
func (s *SealedStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	for a, b := range sessions {
		if err := s.v.Put(ctx, nsSession, a, b); err != nil {
			return err
		}
	}
	return nil
}
func (s *SealedStore) DeleteAllSessions(ctx context.Context, phone string) error {
	return s.deletePrefix(ctx, nsSession, phone+":")
}
func (s *SealedStore) DeleteSession(ctx context.Context, address string) error {
	return s.v.Delete(ctx, nsSession, address)
}

// MigratePNToLID moves sessions, identities and sender keys from a phone
// number address to its LID address, as sqlstore's three INSERT…SELECTs do.
func (s *SealedStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	from, to := pn.SignalAddressUser(), lid.SignalAddressUser()
	for _, ns := range []string{nsSession, nsIdentity} {
		es, err := s.v.List(ctx, ns)
		if err != nil {
			return err
		}
		for _, e := range es {
			if strings.HasPrefix(e.Key, from+":") {
				if err := s.v.Put(ctx, ns, to+e.Key[len(from):], e.Value); err != nil {
					return err
				}
				if err := s.v.Delete(ctx, ns, e.Key); err != nil {
					return err
				}
			}
		}
	}
	es, err := s.v.List(ctx, nsSenderKey)
	if err != nil {
		return err
	}
	for _, e := range es {
		group, user, ok := strings.Cut(e.Key, "\x00")
		if ok && strings.HasPrefix(user, from+":") {
			if err := s.v.Put(ctx, nsSenderKey, group+"\x00"+to+user[len(from):], e.Value); err != nil {
				return err
			}
			if err := s.v.Delete(ctx, nsSenderKey, e.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

// ── Pre-keys ─────────────────────────────────────────────────────────────────

type preKeyRecord struct {
	Priv     []byte `json:"priv"`
	Uploaded bool   `json:"uploaded"`
}

func (s *SealedStore) nextPreKeyID(ctx context.Context) (uint32, error) {
	b, err := s.getBytes(ctx, nsMeta, "next_prekey_id")
	if err != nil {
		return 0, err
	}
	if len(b) == 4 {
		return binary.BigEndian.Uint32(b), nil
	}
	return 1, nil
}

func (s *SealedStore) setNextPreKeyID(ctx context.Context, id uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], id)
	return s.v.Put(ctx, nsMeta, "next_prekey_id", b[:])
}

func (s *SealedStore) genPreKey(ctx context.Context, id uint32, uploaded bool) (*keys.PreKey, error) {
	k := keys.NewPreKey(id)
	if err := s.putJSON(ctx, nsPreKey, strconv.FormatUint(uint64(id), 10),
		preKeyRecord{Priv: k.Priv[:], Uploaded: uploaded}); err != nil {
		return nil, err
	}
	return k, s.setNextPreKeyID(ctx, id+1)
}

func (s *SealedStore) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	s.preKeyMu.Lock()
	defer s.preKeyMu.Unlock()
	es, err := s.v.List(ctx, nsPreKey)
	if err != nil {
		return nil, err
	}
	var out []*keys.PreKey
	for _, e := range es {
		var r preKeyRecord
		if err := json.Unmarshal(e.Value, &r); err != nil {
			return nil, err
		}
		if r.Uploaded {
			continue
		}
		id, _ := strconv.ParseUint(e.Key, 10, 32)
		out = append(out, &keys.PreKey{KeyPair: *keys.NewKeyPairFromPrivateKey(to32(r.Priv)), KeyID: uint32(id)})
	}
	sortPreKeys(out)
	if uint32(len(out)) > count {
		out = out[:count]
	}
	next, err := s.nextPreKeyID(ctx)
	if err != nil {
		return nil, err
	}
	for uint32(len(out)) < count {
		k, err := s.genPreKey(ctx, next, false)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		next++
	}
	return out, nil
}

func (s *SealedStore) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	s.preKeyMu.Lock()
	defer s.preKeyMu.Unlock()
	next, err := s.nextPreKeyID(ctx)
	if err != nil {
		return nil, err
	}
	return s.genPreKey(ctx, next, true)
}

func (s *SealedStore) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	var r preKeyRecord
	ok, err := s.getJSON(ctx, nsPreKey, strconv.FormatUint(uint64(id), 10), &r)
	if err != nil || !ok {
		return nil, err
	}
	return &keys.PreKey{KeyPair: *keys.NewKeyPairFromPrivateKey(to32(r.Priv)), KeyID: id}, nil
}

func (s *SealedStore) RemovePreKey(ctx context.Context, id uint32) error {
	return s.v.Delete(ctx, nsPreKey, strconv.FormatUint(uint64(id), 10))
}

func (s *SealedStore) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	s.preKeyMu.Lock()
	defer s.preKeyMu.Unlock()
	es, err := s.v.List(ctx, nsPreKey)
	if err != nil {
		return err
	}
	for _, e := range es {
		id, _ := strconv.ParseUint(e.Key, 10, 32)
		if uint32(id) > upToID {
			continue
		}
		var r preKeyRecord
		if err := json.Unmarshal(e.Value, &r); err != nil {
			return err
		}
		if !r.Uploaded {
			r.Uploaded = true
			if err := s.putJSON(ctx, nsPreKey, e.Key, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *SealedStore) UploadedPreKeyCount(ctx context.Context) (int, error) {
	es, err := s.v.List(ctx, nsPreKey)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range es {
		var r preKeyRecord
		if json.Unmarshal(e.Value, &r) == nil && r.Uploaded {
			n++
		}
	}
	return n, nil
}

// ── Sender keys and app state ──────────────────────────────────────────────

func (s *SealedStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	return s.v.Put(ctx, nsSenderKey, group+"\x00"+user, session)
}
func (s *SealedStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	return s.getBytes(ctx, nsSenderKey, group+"\x00"+user)
}

func (s *SealedStore) PutAppStateSyncKey(ctx context.Context, id []byte, key store.AppStateSyncKey) error {
	return s.putJSON(ctx, nsAppKey, hex.EncodeToString(id), key)
}
func (s *SealedStore) GetAppStateSyncKey(ctx context.Context, id []byte) (*store.AppStateSyncKey, error) {
	var k store.AppStateSyncKey
	ok, err := s.getJSON(ctx, nsAppKey, hex.EncodeToString(id), &k)
	if err != nil || !ok {
		return nil, err
	}
	return &k, nil
}
func (s *SealedStore) GetLatestAppStateSyncKeyID(ctx context.Context) ([]byte, error) {
	es, err := s.v.List(ctx, nsAppKey)
	if err != nil {
		return nil, err
	}
	var best []byte
	var bestTS int64 = -1
	for _, e := range es {
		var k store.AppStateSyncKey
		if err := json.Unmarshal(e.Value, &k); err != nil {
			return nil, err
		}
		if k.Timestamp > bestTS {
			bestTS = k.Timestamp
			best, _ = hex.DecodeString(e.Key)
		}
	}
	return best, nil
}
func (s *SealedStore) GetAllAppStateSyncKeys(ctx context.Context) ([]*store.AppStateSyncKey, error) {
	es, err := s.v.List(ctx, nsAppKey)
	if err != nil {
		return nil, err
	}
	out := make([]*store.AppStateSyncKey, 0, len(es))
	for _, e := range es {
		var k store.AppStateSyncKey
		if err := json.Unmarshal(e.Value, &k); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, nil
}

type appVersion struct {
	Version uint64 `json:"v"`
	Hash    []byte `json:"h"`
}

func (s *SealedStore) PutAppStateVersion(ctx context.Context, name string, version uint64, hash [128]byte) error {
	return s.putJSON(ctx, nsAppVersion, name, appVersion{Version: version, Hash: hash[:]})
}
func (s *SealedStore) GetAppStateVersion(ctx context.Context, name string) (uint64, [128]byte, error) {
	var v appVersion
	var h [128]byte
	ok, err := s.getJSON(ctx, nsAppVersion, name, &v)
	if err != nil || !ok {
		return 0, h, err
	}
	copy(h[:], v.Hash)
	return v.Version, h, nil
}
func (s *SealedStore) DeleteAppStateVersion(ctx context.Context, name string) error {
	return s.v.Delete(ctx, nsAppVersion, name)
}

type appMAC struct {
	Version  uint64 `json:"v"`
	ValueMAC []byte `json:"m"`
}

// Mutation MACs are keyed by (name, indexMAC); sqlstore keeps every version
// and reads the highest, so only the highest is kept here.
func (s *SealedStore) PutAppStateMutationMACs(ctx context.Context, name string, version uint64, ms []store.AppStateMutationMAC) error {
	for _, m := range ms {
		key := name + "\x00" + hex.EncodeToString(m.IndexMAC)
		var cur appMAC
		ok, err := s.getJSON(ctx, nsAppMAC, key, &cur)
		if err != nil {
			return err
		}
		if ok && cur.Version > version {
			continue
		}
		if err := s.putJSON(ctx, nsAppMAC, key, appMAC{Version: version, ValueMAC: m.ValueMAC}); err != nil {
			return err
		}
	}
	return nil
}
func (s *SealedStore) DeleteAppStateMutationMACs(ctx context.Context, name string, indexMACs [][]byte) error {
	for _, im := range indexMACs {
		if err := s.v.Delete(ctx, nsAppMAC, name+"\x00"+hex.EncodeToString(im)); err != nil {
			return err
		}
	}
	return nil
}
func (s *SealedStore) GetAppStateMutationMAC(ctx context.Context, name string, indexMAC []byte) ([]byte, error) {
	var m appMAC
	ok, err := s.getJSON(ctx, nsAppMAC, name+"\x00"+hex.EncodeToString(indexMAC), &m)
	if err != nil || !ok {
		return nil, err
	}
	return m.ValueMAC, nil
}

// ── Contacts and chat settings ─────────────────────────────────────────────

func (s *SealedStore) contact(ctx context.Context, user types.JID) (types.ContactInfo, error) {
	var c types.ContactInfo
	_, err := s.getJSON(ctx, nsContact, user.String(), &c)
	return c, err
}

func (s *SealedStore) PutPushName(ctx context.Context, user types.JID, pushName string) (bool, string, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	c, err := s.contact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if c.PushName == pushName {
		return false, "", nil
	}
	prev := c.PushName
	c.PushName, c.Found = pushName, true
	return true, prev, s.putJSON(ctx, nsContact, user.String(), c)
}

func (s *SealedStore) PutBusinessName(ctx context.Context, user types.JID, name string) (bool, string, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	c, err := s.contact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if c.BusinessName == name {
		return false, "", nil
	}
	prev := c.BusinessName
	c.BusinessName, c.Found = name, true
	return true, prev, s.putJSON(ctx, nsContact, user.String(), c)
}

func (s *SealedStore) PutContactName(ctx context.Context, user types.JID, fullName, firstName string) error {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	c, err := s.contact(ctx, user)
	if err != nil {
		return err
	}
	c.FullName, c.FirstName, c.Found = fullName, firstName, true
	return s.putJSON(ctx, nsContact, user.String(), c)
}

func (s *SealedStore) PutAllContactNames(ctx context.Context, contacts []store.ContactEntry) error {
	for _, ce := range contacts {
		if err := s.PutContactName(ctx, ce.JID, ce.FullName, ce.FirstName); err != nil {
			return err
		}
	}
	return nil
}

func (s *SealedStore) PutManyRedactedPhones(ctx context.Context, entries []store.RedactedPhoneEntry) error {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	for _, e := range entries {
		c, err := s.contact(ctx, e.JID)
		if err != nil {
			return err
		}
		c.RedactedPhone = e.RedactedPhone
		if err := s.putJSON(ctx, nsContact, e.JID.String(), c); err != nil {
			return err
		}
	}
	return nil
}

func (s *SealedStore) GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error) {
	return s.contact(ctx, user)
}

func (s *SealedStore) GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error) {
	es, err := s.v.List(ctx, nsContact)
	if err != nil {
		return nil, err
	}
	out := make(map[types.JID]types.ContactInfo, len(es))
	for _, e := range es {
		jid, err := types.ParseJID(e.Key)
		if err != nil {
			continue
		}
		var c types.ContactInfo
		if err := json.Unmarshal(e.Value, &c); err != nil {
			return nil, err
		}
		out[jid] = c
	}
	return out, nil
}

type chatRecord struct {
	types.LocalChatSettings
	WASARoot string `json:"wasa_root,omitempty"`
}

func (s *SealedStore) chat(ctx context.Context, jid types.JID) (chatRecord, error) {
	var c chatRecord
	_, err := s.getJSON(ctx, nsChat, jid.String(), &c)
	return c, err
}

func (s *SealedStore) updateChat(ctx context.Context, jid types.JID, f func(*chatRecord)) error {
	c, err := s.chat(ctx, jid)
	if err != nil {
		return err
	}
	f(&c)
	c.Found = true
	return s.putJSON(ctx, nsChat, jid.String(), c)
}

func (s *SealedStore) PutMutedUntil(ctx context.Context, chat types.JID, t time.Time) error {
	return s.updateChat(ctx, chat, func(c *chatRecord) { c.MutedUntil = t })
}
func (s *SealedStore) PutPinned(ctx context.Context, chat types.JID, pinned bool) error {
	return s.updateChat(ctx, chat, func(c *chatRecord) { c.Pinned = pinned })
}
func (s *SealedStore) PutArchived(ctx context.Context, chat types.JID, archived bool) error {
	return s.updateChat(ctx, chat, func(c *chatRecord) { c.Archived = archived })
}
func (s *SealedStore) PutWASARootSecretID(ctx context.Context, chat types.JID, id types.MessageID) error {
	return s.updateChat(ctx, chat, func(c *chatRecord) { c.WASARoot = id })
}
func (s *SealedStore) GetWASARootSecretID(ctx context.Context, chat types.JID) (types.MessageID, error) {
	c, err := s.chat(ctx, chat)
	return c.WASARoot, err
}
func (s *SealedStore) GetChatSettings(ctx context.Context, chat types.JID) (types.LocalChatSettings, error) {
	c, err := s.chat(ctx, chat)
	return c.LocalChatSettings, err
}

// ── Message secrets, privacy tokens, NCT salt ──────────────────────────────

type secretRecord struct {
	Secret []byte `json:"s"`
	Sender string `json:"from"`
}

func secretKey(chat, sender types.JID, id types.MessageID) string {
	return chat.ToNonAD().String() + "\x00" + sender.ToNonAD().String() + "\x00" + id
}

func (s *SealedStore) PutMessageSecrets(ctx context.Context, inserts []store.MessageSecretInsert) error {
	for _, in := range inserts {
		if err := s.PutMessageSecret(ctx, in.Chat, in.Sender, in.ID, in.Secret); err != nil {
			return err
		}
	}
	return nil
}

// PutMessageSecret keeps the first secret for a message, as sqlstore's
// ON CONFLICT DO NOTHING does.
func (s *SealedStore) PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	k := secretKey(chat, sender, id)
	if b, err := s.getBytes(ctx, nsMsgSecret, k); err != nil || b != nil {
		return err
	}
	return s.putJSON(ctx, nsMsgSecret, k, secretRecord{Secret: secret, Sender: sender.ToNonAD().String()})
}

func (s *SealedStore) GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error) {
	var r secretRecord
	ok, err := s.getJSON(ctx, nsMsgSecret, secretKey(chat, sender, id), &r)
	if err != nil || !ok {
		return nil, types.EmptyJID, err
	}
	from, _ := types.ParseJID(r.Sender)
	return r.Secret, from, nil
}

type privacyRecord struct {
	Token           []byte    `json:"t"`
	Timestamp       time.Time `json:"ts"`
	SenderTimestamp time.Time `json:"sts"`
}

func (s *SealedStore) PutPrivacyTokens(ctx context.Context, tokens ...store.PrivacyToken) error {
	for _, t := range tokens {
		var cur privacyRecord
		ok, err := s.getJSON(ctx, nsPrivacy, t.User.ToNonAD().String(), &cur)
		if err != nil {
			return err
		}
		if ok && t.Timestamp.Before(cur.Timestamp) {
			continue
		}
		next := privacyRecord{Token: t.Token, Timestamp: t.Timestamp, SenderTimestamp: t.SenderTimestamp}
		if next.SenderTimestamp.IsZero() {
			next.SenderTimestamp = cur.SenderTimestamp
		}
		if err := s.putJSON(ctx, nsPrivacy, t.User.ToNonAD().String(), next); err != nil {
			return err
		}
	}
	return nil
}

func (s *SealedStore) GetPrivacyToken(ctx context.Context, user types.JID) (*store.PrivacyToken, error) {
	var r privacyRecord
	ok, err := s.getJSON(ctx, nsPrivacy, user.ToNonAD().String(), &r)
	if err != nil {
		return nil, err
	}
	if !ok && user.Server == types.HiddenUserServer {
		// sqlstore also looks the token up under the LID's phone number.
		pn, err := s.GetPNForLID(ctx, user)
		if err != nil || pn.IsEmpty() {
			return nil, err
		}
		ok, err = s.getJSON(ctx, nsPrivacy, pn.ToNonAD().String(), &r)
		if err != nil {
			return nil, err
		}
	}
	if !ok {
		return nil, nil
	}
	return &store.PrivacyToken{User: user, Token: r.Token, Timestamp: r.Timestamp, SenderTimestamp: r.SenderTimestamp}, nil
}

func (s *SealedStore) DeleteExpiredPrivacyTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	es, err := s.v.List(ctx, nsPrivacy)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range es {
		var r privacyRecord
		if json.Unmarshal(e.Value, &r) == nil && r.Timestamp.Before(cutoff) {
			if err := s.v.Delete(ctx, nsPrivacy, e.Key); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

func (s *SealedStore) PutNCTSalt(ctx context.Context, salt []byte) error {
	return s.v.Put(ctx, nsMeta, "nct_salt", salt)
}
func (s *SealedStore) GetNCTSalt(ctx context.Context) ([]byte, error) {
	return s.getBytes(ctx, nsMeta, "nct_salt")
}
func (s *SealedStore) DeleteNCTSalt(ctx context.Context) error {
	return s.v.Delete(ctx, nsMeta, "nct_salt")
}

// ── Event buffer ────────────────────────────────────────────────────────────
//
// whatsmeow buffers a decrypted message's plaintext against its ciphertext
// hash, so a redelivery is not decrypted twice (which would ratchet a Signal
// session past it). That plaintext IS message content, so it is sealed like
// everything else, and DeleteOldBufferedHashes drops it after the 14 days
// WhatsApp's servers buffer for.

type bufferedRecord struct {
	Plaintext  []byte    `json:"p"`
	InsertTime time.Time `json:"i"`
	ServerTime time.Time `json:"s"`
}

func (s *SealedStore) GetBufferedEvent(ctx context.Context, h [32]byte) (*store.BufferedEvent, error) {
	var r bufferedRecord
	ok, err := s.getJSON(ctx, nsBuffered, hex.EncodeToString(h[:]), &r)
	if err != nil || !ok {
		return nil, err
	}
	return &store.BufferedEvent{Plaintext: r.Plaintext, InsertTime: r.InsertTime, ServerTime: r.ServerTime}, nil
}

func (s *SealedStore) PutBufferedEvent(ctx context.Context, h [32]byte, plaintext []byte, serverTime time.Time) error {
	return s.putJSON(ctx, nsBuffered, hex.EncodeToString(h[:]),
		bufferedRecord{Plaintext: plaintext, InsertTime: time.Now(), ServerTime: serverTime})
}

// DoDecryptionTxn has no transaction to offer: the vault writes one record at
// a time. A crash between the session update and the buffered event can
// cost one message a redelivery, which whatsmeow already handles by asking
// for a retry. Stated in ADR 0093 as a known limit of phase 1.
func (s *SealedStore) DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func (s *SealedStore) ClearBufferedEventPlaintext(ctx context.Context, h [32]byte) error {
	var r bufferedRecord
	ok, err := s.getJSON(ctx, nsBuffered, hex.EncodeToString(h[:]), &r)
	if err != nil || !ok {
		return err
	}
	r.Plaintext = nil
	return s.putJSON(ctx, nsBuffered, hex.EncodeToString(h[:]), r)
}

func (s *SealedStore) DeleteOldBufferedHashes(ctx context.Context) error {
	cutoff := time.Now().Add(-14 * 24 * time.Hour)
	es, err := s.v.List(ctx, nsBuffered)
	if err != nil {
		return err
	}
	for _, e := range es {
		var r bufferedRecord
		if json.Unmarshal(e.Value, &r) == nil && r.InsertTime.Before(cutoff) {
			if err := s.v.Delete(ctx, nsBuffered, e.Key); err != nil {
				return err
			}
		}
	}
	return nil
}

// The retry store is off (Client.UseRetryMessageStore stays false): it would
// keep every outgoing message's plaintext for seven days. Nothing writes
// here, and a read is "not found".
func (s *SealedStore) GetOutgoingEvent(context.Context, types.JID, types.JID, types.MessageID) (string, []byte, error) {
	return "", nil, sealed.ErrNotFound
}
func (s *SealedStore) AddOutgoingEvent(context.Context, types.JID, types.MessageID, string, []byte) error {
	return nil
}
func (s *SealedStore) DeleteOldOutgoingEvents(context.Context) error { return nil }

// ── LID map ─────────────────────────────────────────────────────────────────

func (s *SealedStore) PutManyLIDMappings(ctx context.Context, ms []store.LIDMapping) error {
	for _, m := range ms {
		if err := s.PutLIDMapping(ctx, m.LID, m.PN); err != nil {
			return err
		}
	}
	return nil
}
func (s *SealedStore) PutLIDMapping(ctx context.Context, lid, pn types.JID) error {
	if err := s.v.Put(ctx, nsLID, "lid:"+lid.User, []byte(pn.User)); err != nil {
		return err
	}
	return s.v.Put(ctx, nsLID, "pn:"+pn.User, []byte(lid.User))
}
func (s *SealedStore) GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error) {
	b, err := s.getBytes(ctx, nsLID, "lid:"+lid.User)
	if err != nil || b == nil {
		return types.EmptyJID, err
	}
	return types.NewJID(string(b), types.DefaultUserServer), nil
}
func (s *SealedStore) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	b, err := s.getBytes(ctx, nsLID, "pn:"+pn.User)
	if err != nil || b == nil {
		return types.EmptyJID, err
	}
	return types.NewJID(string(b), types.HiddenUserServer), nil
}
func (s *SealedStore) GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error) {
	out := map[types.JID]types.JID{}
	for _, pn := range pns {
		lid, err := s.GetLIDForPN(ctx, pn)
		if err != nil {
			return nil, err
		}
		if !lid.IsEmpty() {
			out[pn] = lid
		}
	}
	return out, nil
}

var _ = nsOutgoing
