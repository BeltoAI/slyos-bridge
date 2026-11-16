package sealed

// SealReference returns an authenticated opaque reference without persisting
// plaintext or message metadata in the bridge. The caller stores it beside the
// attachment in the Brain. Namespace and message ID are authenticated; another
// account, message, purpose or destroyed connection cannot open it.
func (v *Vault) SealReference(namespace, messageID string, value []byte) ([]byte, error) {
	k, done, err := v.withKey()
	if err != nil {
		return nil, err
	}
	defer done()
	return k.Seal("reference:"+namespace, messageID, value)
}

func (v *Vault) OpenReference(namespace, messageID string, ciphertext []byte) ([]byte, error) {
	k, done, err := v.withKey()
	if err != nil {
		return nil, err
	}
	defer done()
	return k.Open("reference:"+namespace, messageID, ciphertext)
}
