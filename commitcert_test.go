package canonical

import (
	"bytes"
	"errors"
	"testing"
)

func testCommitCertificate(n int) CommitCertificateV1 {
	c := CommitCertificateV1{
		Version:        VersionV1,
		ProposalDigest: bytes.Repeat([]byte{0x35}, DigestLen),
		View:           7,
		Seq:            42,
	}
	for i := 1; i <= n; i++ {
		c.Sigs = append(c.Sigs, SignerSigV0{
			Signer: int64(i),
			Value:  bytes.Repeat([]byte{byte(i)}, SignatureLen),
			Msg:    []byte{'M', byte('0' + i)},
		})
	}
	return c
}

func commitCertificateEqual(a, b CommitCertificateV1) bool {
	if len(a.Sigs) != len(b.Sigs) {
		return false
	}
	for i := range a.Sigs {
		if a.Sigs[i].Signer != b.Sigs[i].Signer ||
			!bytes.Equal(a.Sigs[i].Value, b.Sigs[i].Value) ||
			!bytes.Equal(a.Sigs[i].Msg, b.Sigs[i].Msg) {
			return false
		}
	}
	return a.Version == b.Version && bytes.Equal(a.ProposalDigest, b.ProposalDigest) &&
		a.View == b.View && a.Seq == b.Seq
}

func TestCommitCertificateV1RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    CommitCertificateV1
	}{
		{"n4 quorum of three", testCommitCertificate(3)},
		{"n13 quorum of nine", testCommitCertificate(9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalCommitCertificateV1(tc.c)
			if err != nil {
				t.Fatalf("MarshalCommitCertificateV1: %v", err)
			}
			got, err := UnmarshalCommitCertificateV1(b)
			if err != nil {
				t.Fatalf("UnmarshalCommitCertificateV1: %v", err)
			}
			if !commitCertificateEqual(got, tc.c) {
				t.Errorf("round trip changed the certificate: got %+v want %+v", got, tc.c)
			}
		})
	}
}

func TestCommitCertificateV1Determinism(t *testing.T) {
	c := testCommitCertificate(3)
	first, err := MarshalCommitCertificateV1(c)
	if err != nil {
		t.Fatalf("MarshalCommitCertificateV1: %v", err)
	}
	second, err := MarshalCommitCertificateV1(c)
	if err != nil {
		t.Fatalf("MarshalCommitCertificateV1: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two encodings of one certificate differ:\nfirst  %x\nsecond %x", first, second)
	}
}

func TestCommitCertificateV1TrailingBytesRejected(t *testing.T) {
	b, err := MarshalCommitCertificateV1(testCommitCertificate(3))
	if err != nil {
		t.Fatalf("MarshalCommitCertificateV1: %v", err)
	}
	if _, err := UnmarshalCommitCertificateV1(append(bytes.Clone(b), 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalCommitCertificateV1 with a trailing byte gave %v, want ErrTrailing", err)
	}
}

// invalidCommitCertificate is shared by the encode and decode rejection tests: an
// unsorted certificate must have no second spelling on either side.
func invalidCommitCertificate() []struct {
	name string
	c    CommitCertificateV1
	want error
} {
	zeroVersion := testCommitCertificate(3)
	zeroVersion.Version = 0

	futureVersion := testCommitCertificate(3)
	futureVersion.Version = 2

	shortDigest := testCommitCertificate(3)
	shortDigest.ProposalDigest = bytes.Repeat([]byte{0x35}, DigestLen-1)

	longDigest := testCommitCertificate(3)
	longDigest.ProposalDigest = bytes.Repeat([]byte{0x35}, DigestLen+1)

	negativeView := testCommitCertificate(3)
	negativeView.View = -1

	negativeSeq := testCommitCertificate(3)
	negativeSeq.Seq = -1

	noSigs := testCommitCertificate(0)

	unsorted := testCommitCertificate(3)
	unsorted.Sigs[0], unsorted.Sigs[2] = unsorted.Sigs[2], unsorted.Sigs[0]

	duplicate := testCommitCertificate(3)
	duplicate.Sigs[1].Signer = duplicate.Sigs[0].Signer

	shortSig := testCommitCertificate(3)
	shortSig.Sigs[1].Value = bytes.Repeat([]byte{0x02}, SignatureLen-1)

	longSig := testCommitCertificate(3)
	longSig.Sigs[1].Value = bytes.Repeat([]byte{0x02}, SignatureLen+1)

	noMsg := testCommitCertificate(3)
	noMsg.Sigs[2].Msg = nil

	return []struct {
		name string
		c    CommitCertificateV1
		want error
	}{
		{"version zero", zeroVersion, ErrVersion},
		{"version from the future", futureVersion, ErrVersion},
		{"proposal digest one byte short", shortDigest, ErrLength},
		{"proposal digest one byte long", longDigest, ErrLength},
		{"negative view", negativeView, ErrRange},
		{"negative seq", negativeSeq, ErrRange},
		{"no signatures", noSigs, ErrEmpty},
		{"signatures out of order", unsorted, ErrOrder},
		{"duplicate signer", duplicate, ErrOrder},
		{"signature one byte short", shortSig, ErrLength},
		{"signature one byte long", longSig, ErrLength},
		{"entry with no signed message", noMsg, ErrEmpty},
	}
}

func TestCommitCertificateV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidCommitCertificate() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalCommitCertificateV1(tc.c); !errors.Is(err, tc.want) {
				t.Errorf("MarshalCommitCertificateV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCommitCertificateV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidCommitCertificate() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshal(tc.c)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalCommitCertificateV1(b); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalCommitCertificateV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}
