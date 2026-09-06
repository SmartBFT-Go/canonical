package canonical

// NonceLen is the fixed width of a client-chosen read-index nonce, in bytes.
const NonceLen = 16

// ReadIndexV1 is SignedV1.Payload under PurposeReadIndex. SignerID is inside the signed
// bytes so an attestation cannot be re-attributed by whoever relays it.
type ReadIndexV1 struct {
	Version  int64 // V-RULE: first field
	SignerID int64
	View     int64
	Seq      int64
	Nonce    []byte // exactly NonceLen bytes, chosen by the client
}

// MarshalReadIndexV1 encodes r, rejecting every value checkReadIndexV1 refuses.
func MarshalReadIndexV1(r ReadIndexV1) ([]byte, error) {
	if err := checkReadIndexV1(r); err != nil {
		return nil, err
	}
	return marshal(r)
}

// UnmarshalReadIndexV1 decodes b under the R-RULE, then applies the same checks as
// MarshalReadIndexV1: what a client verifies must be what a replica could have signed.
func UnmarshalReadIndexV1(b []byte) (ReadIndexV1, error) {
	var r ReadIndexV1
	if err := unmarshal(b, &r); err != nil {
		return ReadIndexV1{}, err
	}
	if err := checkReadIndexV1(r); err != nil {
		return ReadIndexV1{}, err
	}
	return r, nil
}

func checkReadIndexV1(r ReadIndexV1) error {
	if r.Version != VersionV1 {
		return ErrVersion
	}
	// Node identifiers are 1-based; 0 is the consensus library's "no node", so an
	// attestation carrying it names nobody.
	if r.SignerID <= 0 {
		return ErrRange
	}
	if r.View < 0 || r.Seq < 0 {
		return ErrRange
	}
	// A short nonce narrows the client's freshness challenge, which is the whole
	// mechanism, so the width is fixed rather than bounded.
	if len(r.Nonce) != NonceLen {
		return ErrLength
	}
	return nil
}
