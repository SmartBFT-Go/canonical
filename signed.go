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

// SignatureLen is the fixed width of an Ed25519 signature.
const SignatureLen = 64

// DigestLen is the fixed width of a SHA-256 digest.
const DigestLen = 32

// SignedBlobV1 carries a signature beside the payload it was made over. The envelope of
// WIRE-SPEC 3.8 is reconstructed by the verifier, never transmitted, and there is no
// signer field: every payload names its own signer, and one named here could be rewritten
// by whoever relays it.
type SignedBlobV1 struct {
	Version int64
	Purpose int64
	Payload []byte // the purpose's own structure, DER
	Value   []byte // Ed25519 over DER(SignedV1{1, Purpose, <verifier's own genesis digest>, Payload})
}

// CommitPayloadV1 is SignedV1.Payload under PurposeCommitSig. Binding the proposal digest
// and the aux in one structure is what makes a consenter signature non-transplantable.
type CommitPayloadV1 struct {
	Version        int64
	ProposalDigest []byte // exactly DigestLen bytes
	Aux            []byte // the fork's auxiliary input, relayed verbatim
}

// MarshalSignedBlobV1 encodes b, rejecting every value checkSignedBlobV1 refuses.
func MarshalSignedBlobV1(b SignedBlobV1) ([]byte, error) {
	if err := checkSignedBlobV1(b); err != nil {
		return nil, err
	}
	return marshal(b)
}

// UnmarshalSignedBlobV1 decodes der under the R-RULE, then applies the same checks as
// MarshalSignedBlobV1.
func UnmarshalSignedBlobV1(der []byte) (SignedBlobV1, error) {
	var b SignedBlobV1
	if err := unmarshal(der, &b); err != nil {
		return SignedBlobV1{}, err
	}
	if err := checkSignedBlobV1(b); err != nil {
		return SignedBlobV1{}, err
	}
	return b, nil
}

func checkSignedBlobV1(b SignedBlobV1) error {
	if b.Version != VersionV1 {
		return ErrVersion
	}
	if !ValidPurpose(b.Purpose) {
		return ErrFormat
	}
	// An empty payload gives an envelope over nothing, which every purpose would have
	// to reject anyway; refusing it here keeps that out of four verifiers.
	if len(b.Payload) == 0 {
		return ErrEmpty
	}
	if len(b.Value) != SignatureLen {
		return ErrLength
	}
	return nil
}

// MarshalCommitPayloadV1 encodes p, rejecting an unknown version or a wrong-width digest.
func MarshalCommitPayloadV1(p CommitPayloadV1) ([]byte, error) {
	if err := checkCommitPayloadV1(p); err != nil {
		return nil, err
	}
	return marshal(p)
}

// UnmarshalCommitPayloadV1 decodes b under the R-RULE, then applies the same checks as
// MarshalCommitPayloadV1.
func UnmarshalCommitPayloadV1(b []byte) (CommitPayloadV1, error) {
	var p CommitPayloadV1
	if err := unmarshal(b, &p); err != nil {
		return CommitPayloadV1{}, err
	}
	if err := checkCommitPayloadV1(p); err != nil {
		return CommitPayloadV1{}, err
	}
	return p, nil
}

func checkCommitPayloadV1(p CommitPayloadV1) error {
	if p.Version != VersionV1 {
		return ErrVersion
	}
	if len(p.ProposalDigest) != DigestLen {
		return ErrLength
	}
	return nil
}
