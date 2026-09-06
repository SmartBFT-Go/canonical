package canonical

// GenesisDigestLen is the fixed width of the genesis digest bound into every signature.
const GenesisDigestLen = 32

// The frozen purpose values. Adding one is an additive change under WIRE-SPEC 7;
// changing or reusing one invalidates every signature ever made under it.
const (
	PurposeCommitSig     int64 = 1 // api.Signer.SignProposal
	PurposeOpaqueSign    int64 = 2 // api.Signer.Sign, view-change RawViewData
	PurposeClientRequest int64 = 3
	PurposeReadIndex     int64 = 4 // attestation over (view, seq, nonce)
)

// ValidPurpose reports whether p is one of the frozen purpose values. It is exported so
// that consumers test against one definition of the set rather than a copy of the list.
func ValidPurpose(p int64) bool {
	return p >= PurposeCommitSig && p <= PurposeReadIndex
}

// SignedV1 is the only structure whose bytes are ever handed to ed25519.Sign.
// Field order is wire order and is frozen.
type SignedV1 struct {
	Version       int64 // V-RULE: first field
	Purpose       int64
	GenesisDigest []byte // exactly GenesisDigestLen bytes
	Payload       []byte // the purpose's own structure, DER, opaque here
}

// MarshalSignedV1 encodes s, rejecting every value checkSignedV1 refuses.
func MarshalSignedV1(s SignedV1) ([]byte, error) {
	if err := checkSignedV1(s); err != nil {
		return nil, err
	}
	return marshal(s)
}

// UnmarshalSignedV1 decodes b under the R-RULE, then applies the same checks as
// MarshalSignedV1: what a verifier reconstructs must be what a signer could have emitted.
func UnmarshalSignedV1(b []byte) (SignedV1, error) {
	var s SignedV1
	if err := unmarshal(b, &s); err != nil {
		return SignedV1{}, err
	}
	if err := checkSignedV1(s); err != nil {
		return SignedV1{}, err
	}
	return s, nil
}

func checkSignedV1(s SignedV1) error {
	if s.Version != VersionV1 {
		return ErrVersion
	}
	if !ValidPurpose(s.Purpose) {
		return ErrFormat
	}
	// A short digest would reach a verifier that compares a prefix, which is a cluster
	// binding an attacker can shorten.
	if len(s.GenesisDigest) != GenesisDigestLen {
		return ErrLength
	}
	return nil
}
