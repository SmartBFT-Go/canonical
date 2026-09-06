package canonical

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func testSigned(payload []byte) SignedV1 {
	return SignedV1{
		Version:       VersionV1,
		Purpose:       PurposeCommitSig,
		GenesisDigest: bytes.Repeat([]byte{0x9e}, GenesisDigestLen),
		Payload:       payload,
	}
}

func signedEqual(a, b SignedV1) bool {
	return a.Version == b.Version && a.Purpose == b.Purpose &&
		bytes.Equal(a.GenesisDigest, b.GenesisDigest) && bytes.Equal(a.Payload, b.Payload)
}

func TestSignedV1RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		s      SignedV1
		minLen int
	}{
		{name: "empty payload", s: testSigned(nil)},
		{name: "one byte payload", s: testSigned([]byte{0x2a})},
		// 131 total bytes means the outer SEQUENCE holds at least 128 content bytes,
		// which is exactly where DER switches to the long length form.
		{name: "long form length", s: testSigned(bytes.Repeat([]byte{0x5a}, 200)), minLen: 131},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalSignedV1(tc.s)
			if err != nil {
				t.Fatalf("MarshalSignedV1: %v", err)
			}
			if len(b) < tc.minLen {
				t.Errorf("encoding is %d bytes, want at least %d; this case no longer exercises what it claims",
					len(b), tc.minLen)
			}
			got, err := UnmarshalSignedV1(b)
			if err != nil {
				t.Fatalf("UnmarshalSignedV1: %v", err)
			}
			if !signedEqual(got, tc.s) {
				t.Errorf("round trip changed the envelope: got %+v want %+v", got, tc.s)
			}
		})
	}
}

func TestSignedV1Determinism(t *testing.T) {
	s := testSigned([]byte("payload"))
	first, err := MarshalSignedV1(s)
	if err != nil {
		t.Fatalf("MarshalSignedV1: %v", err)
	}
	for range 100 {
		again, err := MarshalSignedV1(s)
		if err != nil {
			t.Fatalf("MarshalSignedV1: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("MarshalSignedV1 is not deterministic")
		}
	}
}

// TestSignedPurposeSetIsFrozen pins the four values themselves: they are carried in
// signed bytes, so a renumbering invalidates every signature ever made.
func TestSignedPurposeSetIsFrozen(t *testing.T) {
	frozen := []struct {
		name  string
		got   int64
		value int64
	}{
		{"PurposeCommitSig", PurposeCommitSig, 1},
		{"PurposeOpaqueSign", PurposeOpaqueSign, 2},
		{"PurposeClientRequest", PurposeClientRequest, 3},
		{"PurposeReadIndex", PurposeReadIndex, 4},
	}
	for _, f := range frozen {
		if f.got != f.value {
			t.Errorf("%s is %d, want %d; renumbering a purpose invalidates every signature made under it",
				f.name, f.got, f.value)
		}
		if !ValidPurpose(f.value) {
			t.Errorf("ValidPurpose(%d) is false, but %s is a frozen purpose", f.value, f.name)
		}
	}
	for _, p := range []int64{math.MinInt64, -1, 0, 5, 6, math.MaxInt64} {
		if ValidPurpose(p) {
			t.Errorf("ValidPurpose(%d) is true, want false", p)
		}
	}
}

// TestSignedV1PurposeSeparatesTheBytes is the encoding half of non-substitutability:
// a signature made under one purpose covers bytes no other purpose can produce.
func TestSignedV1PurposeSeparatesTheBytes(t *testing.T) {
	purposes := []int64{PurposeCommitSig, PurposeOpaqueSign, PurposeClientRequest, PurposeReadIndex}
	seen := map[string]int64{}
	for _, p := range purposes {
		s := testSigned([]byte("one payload, four purposes"))
		s.Purpose = p
		b, err := MarshalSignedV1(s)
		if err != nil {
			t.Fatalf("MarshalSignedV1 purpose %d: %v", p, err)
		}
		if other, dup := seen[string(b)]; dup {
			t.Errorf("purposes %d and %d marshal to identical bytes, so a signature under one verifies under the other",
				other, p)
		}
		seen[string(b)] = p
	}
}

func TestSignedV1GenesisDigestSeparatesTheBytes(t *testing.T) {
	a := testSigned([]byte("same payload"))
	b := testSigned([]byte("same payload"))
	b.GenesisDigest = bytes.Repeat([]byte{0x01}, GenesisDigestLen)

	ab, err := MarshalSignedV1(a)
	if err != nil {
		t.Fatalf("MarshalSignedV1: %v", err)
	}
	bb, err := MarshalSignedV1(b)
	if err != nil {
		t.Fatalf("MarshalSignedV1: %v", err)
	}
	if bytes.Equal(ab, bb) {
		t.Error("two clusters' envelopes over one payload are identical, so a signature crosses clusters")
	}
}

func TestSignedV1TrailingBytesRejected(t *testing.T) {
	b, err := MarshalSignedV1(testSigned([]byte("payload")))
	if err != nil {
		t.Fatalf("MarshalSignedV1: %v", err)
	}
	if _, err := UnmarshalSignedV1(append(bytes.Clone(b), 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalSignedV1 with a trailing byte gave %v, want ErrTrailing", err)
	}
}

// invalidSignedV1 is shared by the encode and decode rejection tests: every value here
// must be refused on both sides, or bytes this package would never emit are still
// accepted and the envelope has two spellings.
func invalidSignedV1() []struct {
	name string
	s    SignedV1
	want error
} {
	withVersion := func(v int64) SignedV1 {
		s := testSigned([]byte("payload"))
		s.Version = v
		return s
	}
	withDigest := func(n int) SignedV1 {
		s := testSigned([]byte("payload"))
		s.GenesisDigest = bytes.Repeat([]byte{0x9e}, n)
		return s
	}
	withPurpose := func(p int64) SignedV1 {
		s := testSigned([]byte("payload"))
		s.Purpose = p
		return s
	}
	nilDigest := testSigned([]byte("payload"))
	nilDigest.GenesisDigest = nil

	return []struct {
		name string
		s    SignedV1
		want error
	}{
		{"version zero", withVersion(0), ErrVersion},
		{"version two", withVersion(2), ErrVersion},
		{"version max int64", withVersion(math.MaxInt64), ErrVersion},
		{"genesis digest one byte short", withDigest(GenesisDigestLen - 1), ErrLength},
		{"genesis digest one byte long", withDigest(GenesisDigestLen + 1), ErrLength},
		{"genesis digest absent", nilDigest, ErrLength},
		{"purpose zero", withPurpose(0), ErrFormat},
		{"purpose five", withPurpose(5), ErrFormat},
		{"purpose negative", withPurpose(-1), ErrFormat},
		{"purpose max int64", withPurpose(math.MaxInt64), ErrFormat},
	}
}

func TestSignedV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidSignedV1() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalSignedV1(tc.s); !errors.Is(err, tc.want) {
				t.Errorf("MarshalSignedV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSignedV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidSignedV1() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshal(tc.s)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalSignedV1(b); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalSignedV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func testBlob(payload []byte) SignedBlobV1 {
	return SignedBlobV1{
		Version: VersionV1,
		Purpose: PurposeOpaqueSign,
		Payload: payload,
		Value:   bytes.Repeat([]byte{0x51}, SignatureLen),
	}
}

func blobEqual(a, b SignedBlobV1) bool {
	return a.Version == b.Version && a.Purpose == b.Purpose &&
		bytes.Equal(a.Payload, b.Payload) && bytes.Equal(a.Value, b.Value)
}

// reconstructEnvelope is the verifier's half of the rule: the envelope is built from a
// blob plus the verifier's own genesis digest, and is never received.
func reconstructEnvelope(t *testing.T, b SignedBlobV1, genesisDigest []byte) []byte {
	t.Helper()
	der, err := MarshalSignedV1(SignedV1{
		Version:       VersionV1,
		Purpose:       b.Purpose,
		GenesisDigest: genesisDigest,
		Payload:       b.Payload,
	})
	if err != nil {
		t.Fatalf("reconstructing the envelope: %v", err)
	}
	return der
}

func TestSignedBlobV1RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		b      SignedBlobV1
		minLen int
	}{
		{name: "one byte payload", b: testBlob([]byte{0x2a})},
		// 131 total bytes means the outer SEQUENCE crossed into the long length form.
		{name: "long form length", b: testBlob(bytes.Repeat([]byte{0x5a}, 200)), minLen: 131},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := MarshalSignedBlobV1(tc.b)
			if err != nil {
				t.Fatalf("MarshalSignedBlobV1: %v", err)
			}
			if len(der) < tc.minLen {
				t.Errorf("encoding is %d bytes, want at least %d; this case no longer exercises what it claims",
					len(der), tc.minLen)
			}
			got, err := UnmarshalSignedBlobV1(der)
			if err != nil {
				t.Fatalf("UnmarshalSignedBlobV1: %v", err)
			}
			if !blobEqual(got, tc.b) {
				t.Errorf("round trip changed the blob: got %+v want %+v", got, tc.b)
			}
			// The blob is only useful if what a verifier reconstructs from the decoded
			// form is byte-identical to what the signer signed.
			digest := bytes.Repeat([]byte{0x9e}, GenesisDigestLen)
			if want, have := reconstructEnvelope(t, tc.b, digest), reconstructEnvelope(t, got, digest); !bytes.Equal(want, have) {
				t.Errorf("the envelope reconstructed after a round trip differs:\nwant %x\n got %x", want, have)
			}
		})
	}
}

// TestSignedBlobV1CarriesNoGenesisDigest is the cross-cluster binding in full: the blob
// has no field naming a cluster, so the digest can only come from the verifier.
func TestSignedBlobV1CarriesNoGenesisDigest(t *testing.T) {
	b := testBlob([]byte("one payload, two clusters"))
	ours := reconstructEnvelope(t, b, bytes.Repeat([]byte{0x9e}, GenesisDigestLen))
	theirs := reconstructEnvelope(t, b, bytes.Repeat([]byte{0x01}, GenesisDigestLen))
	if bytes.Equal(ours, theirs) {
		t.Fatal("two clusters reconstruct the same envelope from one blob, so a signature crosses clusters")
	}

	der, err := MarshalSignedBlobV1(b)
	if err != nil {
		t.Fatalf("MarshalSignedBlobV1: %v", err)
	}
	// Neither cluster's digest is on the wire, so there is no field to lie in.
	if bytes.Contains(der, bytes.Repeat([]byte{0x9e}, GenesisDigestLen)) {
		t.Error("the blob encoding carries the genesis digest; it must be supplied by the verifier, never received")
	}
}

func invalidSignedBlobV1() []struct {
	name string
	b    SignedBlobV1
	want error
} {
	withVersion := func(v int64) SignedBlobV1 {
		b := testBlob([]byte("payload"))
		b.Version = v
		return b
	}
	withValue := func(n int) SignedBlobV1 {
		b := testBlob([]byte("payload"))
		b.Value = bytes.Repeat([]byte{0x51}, n)
		return b
	}
	withPurpose := func(p int64) SignedBlobV1 {
		b := testBlob([]byte("payload"))
		b.Purpose = p
		return b
	}
	emptyPayload := testBlob(nil)

	return []struct {
		name string
		b    SignedBlobV1
		want error
	}{
		{"version zero", withVersion(0), ErrVersion},
		{"version two", withVersion(2), ErrVersion},
		{"version max int64", withVersion(math.MaxInt64), ErrVersion},
		{"signature one byte short", withValue(SignatureLen - 1), ErrLength},
		{"signature one byte long", withValue(SignatureLen + 1), ErrLength},
		{"signature absent", withValue(0), ErrLength},
		{"purpose zero", withPurpose(0), ErrFormat},
		{"purpose five", withPurpose(5), ErrFormat},
		{"purpose negative", withPurpose(-1), ErrFormat},
		{"empty payload", emptyPayload, ErrEmpty},
	}
}

func TestSignedBlobV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidSignedBlobV1() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalSignedBlobV1(tc.b); !errors.Is(err, tc.want) {
				t.Errorf("MarshalSignedBlobV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSignedBlobV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidSignedBlobV1() {
		t.Run(tc.name, func(t *testing.T) {
			der, err := marshal(tc.b)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalSignedBlobV1(der); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalSignedBlobV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func testCommitPayload(aux []byte) CommitPayloadV1 {
	return CommitPayloadV1{
		Version:        VersionV1,
		ProposalDigest: bytes.Repeat([]byte{0x35}, DigestLen),
		Aux:            aux,
	}
}

func commitPayloadEqual(a, b CommitPayloadV1) bool {
	return a.Version == b.Version &&
		bytes.Equal(a.ProposalDigest, b.ProposalDigest) && bytes.Equal(a.Aux, b.Aux)
}

func TestCommitPayloadV1RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		p    CommitPayloadV1
	}{
		{name: "empty aux", p: testCommitPayload(nil)},
		{name: "with aux", p: testCommitPayload([]byte("prepares-from"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := MarshalCommitPayloadV1(tc.p)
			if err != nil {
				t.Fatalf("MarshalCommitPayloadV1: %v", err)
			}
			got, err := UnmarshalCommitPayloadV1(der)
			if err != nil {
				t.Fatalf("UnmarshalCommitPayloadV1: %v", err)
			}
			if !commitPayloadEqual(got, tc.p) {
				t.Errorf("round trip changed the payload: got %+v want %+v", got, tc.p)
			}
		})
	}
}

// TestCommitPayloadV1IsNotTransplantable is non-transplantability in its encoding form:
// the proposal digest and the aux are covered by one signature, so neither moves alone.
func TestCommitPayloadV1IsNotTransplantable(t *testing.T) {
	base, err := MarshalCommitPayloadV1(testCommitPayload([]byte("prepares-from")))
	if err != nil {
		t.Fatalf("MarshalCommitPayloadV1: %v", err)
	}

	otherProposal := testCommitPayload([]byte("prepares-from"))
	otherProposal.ProposalDigest = bytes.Repeat([]byte{0x36}, DigestLen)
	moved, err := MarshalCommitPayloadV1(otherProposal)
	if err != nil {
		t.Fatalf("MarshalCommitPayloadV1: %v", err)
	}
	if bytes.Equal(base, moved) {
		t.Error("two proposals share a signed payload, so a consenter signature transplants between them")
	}

	forgedAux, err := MarshalCommitPayloadV1(testCommitPayload([]byte("chosen-aux")))
	if err != nil {
		t.Fatalf("MarshalCommitPayloadV1: %v", err)
	}
	if bytes.Equal(base, forgedAux) {
		t.Error("the aux is outside the signed bytes, so it can be replaced by whoever relays the signature")
	}
}

func invalidCommitPayloadV1() []struct {
	name string
	p    CommitPayloadV1
	want error
} {
	withVersion := func(v int64) CommitPayloadV1 {
		p := testCommitPayload([]byte("aux"))
		p.Version = v
		return p
	}
	withDigest := func(n int) CommitPayloadV1 {
		p := testCommitPayload([]byte("aux"))
		p.ProposalDigest = bytes.Repeat([]byte{0x35}, n)
		return p
	}

	return []struct {
		name string
		p    CommitPayloadV1
		want error
	}{
		{"version zero", withVersion(0), ErrVersion},
		{"version two", withVersion(2), ErrVersion},
		{"version max int64", withVersion(math.MaxInt64), ErrVersion},
		{"proposal digest one byte short", withDigest(DigestLen - 1), ErrLength},
		{"proposal digest one byte long", withDigest(DigestLen + 1), ErrLength},
		{"proposal digest absent", withDigest(0), ErrLength},
	}
}

func TestCommitPayloadV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidCommitPayloadV1() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalCommitPayloadV1(tc.p); !errors.Is(err, tc.want) {
				t.Errorf("MarshalCommitPayloadV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCommitPayloadV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidCommitPayloadV1() {
		t.Run(tc.name, func(t *testing.T) {
			der, err := marshal(tc.p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalCommitPayloadV1(der); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalCommitPayloadV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}
