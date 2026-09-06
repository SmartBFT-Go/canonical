package canonical

import (
	"bytes"
	"errors"
	"testing"
)

func testReadIndex() ReadIndexV1 {
	return ReadIndexV1{
		Version:  VersionV1,
		SignerID: 3,
		View:     7,
		Seq:      42,
		Nonce:    bytes.Repeat([]byte{0xa7}, NonceLen),
	}
}

func readIndexEqual(a, b ReadIndexV1) bool {
	return a.Version == b.Version && a.SignerID == b.SignerID &&
		a.View == b.View && a.Seq == b.Seq && bytes.Equal(a.Nonce, b.Nonce)
}

func TestReadIndexV1RoundTrip(t *testing.T) {
	highSeq := testReadIndex()
	// Past 2^31, so an implementer reading Seq into a 32-bit integer fails loudly.
	highSeq.Seq = 1 << 40

	for _, tc := range []struct {
		name string
		r    ReadIndexV1
	}{
		{"basic", testReadIndex()},
		{"high seq", highSeq},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalReadIndexV1(tc.r)
			if err != nil {
				t.Fatalf("MarshalReadIndexV1: %v", err)
			}
			got, err := UnmarshalReadIndexV1(b)
			if err != nil {
				t.Fatalf("UnmarshalReadIndexV1: %v", err)
			}
			if !readIndexEqual(got, tc.r) {
				t.Errorf("round trip changed the attestation: got %+v want %+v", got, tc.r)
			}
		})
	}
}

func TestReadIndexV1Determinism(t *testing.T) {
	r := testReadIndex()
	first, err := MarshalReadIndexV1(r)
	if err != nil {
		t.Fatalf("MarshalReadIndexV1: %v", err)
	}
	second, err := MarshalReadIndexV1(r)
	if err != nil {
		t.Fatalf("MarshalReadIndexV1: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two encodings of one attestation differ:\nfirst  %x\nsecond %x", first, second)
	}
}

// Each field is separately what a client relies on being bound, so each gets its own
// assertion rather than one combined value that could pass by moving any single byte.
func TestReadIndexV1FieldsSeparateTheBytes(t *testing.T) {
	otherSigner := testReadIndex()
	otherSigner.SignerID++

	otherView := testReadIndex()
	otherView.View++

	otherSeq := testReadIndex()
	otherSeq.Seq++

	otherNonce := testReadIndex()
	otherNonce.Nonce = bytes.Repeat([]byte{0x5b}, NonceLen)

	base, err := MarshalReadIndexV1(testReadIndex())
	if err != nil {
		t.Fatalf("MarshalReadIndexV1: %v", err)
	}
	for _, tc := range []struct {
		name string
		r    ReadIndexV1
	}{
		{"signer id", otherSigner},
		{"view", otherView},
		{"seq", otherSeq},
		{"nonce", otherNonce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalReadIndexV1(tc.r)
			if err != nil {
				t.Fatalf("MarshalReadIndexV1: %v", err)
			}
			if bytes.Equal(base, b) {
				t.Errorf("two attestations differing only in %s encode alike: %x", tc.name, b)
			}
		})
	}
}

func TestReadIndexV1TrailingBytesRejected(t *testing.T) {
	b, err := MarshalReadIndexV1(testReadIndex())
	if err != nil {
		t.Fatalf("MarshalReadIndexV1: %v", err)
	}
	if _, err := UnmarshalReadIndexV1(append(bytes.Clone(b), 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalReadIndexV1 with a trailing byte gave %v, want ErrTrailing", err)
	}
}

// invalidReadIndex is shared by the encode and decode rejection tests: every value here
// must be refused on both sides, or the encoding is asymmetric.
func invalidReadIndex() []struct {
	name string
	r    ReadIndexV1
	want error
} {
	zeroVersion := testReadIndex()
	zeroVersion.Version = 0

	futureVersion := testReadIndex()
	futureVersion.Version = 2

	zeroSigner := testReadIndex()
	zeroSigner.SignerID = 0

	negativeSigner := testReadIndex()
	negativeSigner.SignerID = -1

	negativeView := testReadIndex()
	negativeView.View = -1

	negativeSeq := testReadIndex()
	negativeSeq.Seq = -1

	noNonce := testReadIndex()
	noNonce.Nonce = nil

	shortNonce := testReadIndex()
	shortNonce.Nonce = bytes.Repeat([]byte{0xa7}, NonceLen-1)

	longNonce := testReadIndex()
	longNonce.Nonce = bytes.Repeat([]byte{0xa7}, NonceLen+1)

	return []struct {
		name string
		r    ReadIndexV1
		want error
	}{
		{"version zero", zeroVersion, ErrVersion},
		{"version from the future", futureVersion, ErrVersion},
		{"signer id zero", zeroSigner, ErrRange},
		{"negative signer id", negativeSigner, ErrRange},
		{"negative view", negativeView, ErrRange},
		{"negative seq", negativeSeq, ErrRange},
		{"absent nonce", noNonce, ErrLength},
		{"nonce one byte short", shortNonce, ErrLength},
		{"nonce one byte long", longNonce, ErrLength},
	}
}

func TestReadIndexV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidReadIndex() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalReadIndexV1(tc.r); !errors.Is(err, tc.want) {
				t.Errorf("MarshalReadIndexV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadIndexV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidReadIndex() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshal(tc.r)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalReadIndexV1(b); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalReadIndexV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}
