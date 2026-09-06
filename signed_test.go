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
	frozen := map[int64]string{
		1: "PurposeCommitSig",
		2: "PurposeOpaqueSign",
		3: "PurposeClientRequest",
		4: "PurposeReadIndex",
	}
	for value, name := range frozen {
		if !ValidPurpose(value) {
			t.Errorf("ValidPurpose(%d) is false, but %s is a frozen purpose", value, name)
		}
	}
	for _, p := range []int64{PurposeCommitSig, PurposeOpaqueSign, PurposeClientRequest, PurposeReadIndex} {
		if frozen[p] == "" {
			t.Errorf("purpose constant has value %d, which is outside the frozen set", p)
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
