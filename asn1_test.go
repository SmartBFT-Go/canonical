package canonical

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func testHeader() Header {
	return Header{
		Version:       VersionV1,
		PrevStateRoot: bytes.Repeat([]byte{0xab}, 32),
	}
}

func headerEqual(a, b Header) bool {
	return a.Version == b.Version &&
		bytes.Equal(a.PrevStateRoot, b.PrevStateRoot) &&
		a.PrevSeq == b.PrevSeq &&
		a.ConsensusTime == b.ConsensusTime
}

func proposalEqual(a, b ProposalV0) bool {
	return bytes.Equal(a.Payload, b.Payload) &&
		bytes.Equal(a.Header, b.Header) &&
		bytes.Equal(a.Metadata, b.Metadata) &&
		a.VerificationSequence == b.VerificationSequence
}

func TestRoundTrip(t *testing.T) {
	headers := []struct {
		name string
		h    Header
	}{
		{"zero seq and time", testHeader()},
		{"max seq and time", Header{
			Version:       VersionV1,
			PrevStateRoot: bytes.Repeat([]byte{0x01}, 32),
			PrevSeq:       math.MaxInt64,
			ConsensusTime: math.MaxInt64,
		}},
	}
	for _, tc := range headers {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalHeader(tc.h)
			if err != nil {
				t.Fatalf("MarshalHeader: %v", err)
			}
			got, err := UnmarshalHeader(b)
			if err != nil {
				t.Fatalf("UnmarshalHeader: %v", err)
			}
			if !headerEqual(got, tc.h) {
				t.Errorf("round trip changed the header: got %+v want %+v", got, tc.h)
			}
		})
	}

	proposals := []struct {
		name string
		p    ProposalV0
	}{
		{"nil payload", ProposalV0{Header: []byte("hdr"), Metadata: []byte("met"), VerificationSequence: 7}},
		{"empty payload", ProposalV0{Payload: []byte{}, Header: []byte("hdr"), Metadata: []byte("met"), VerificationSequence: 7}},
		{"populated", ProposalV0{Payload: []byte("pay"), Header: []byte("hdr"), Metadata: []byte("met"), VerificationSequence: 7}},
	}
	for _, tc := range proposals {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalProposalV0(tc.p)
			if err != nil {
				t.Fatalf("MarshalProposalV0: %v", err)
			}
			got, err := UnmarshalProposalV0(b)
			if err != nil {
				t.Fatalf("UnmarshalProposalV0: %v", err)
			}
			if !proposalEqual(got, tc.p) {
				t.Errorf("round trip changed the proposal: got %+v want %+v", got, tc.p)
			}
		})
	}
}

// A nil and an empty []byte both encode to 04 00, so the two cases above must be
// byte-identical on the wire; a decoder cannot tell them apart.
func TestNilAndEmptyPayloadEncodeIdentically(t *testing.T) {
	withNil, err := MarshalProposalV0(ProposalV0{Header: []byte("hdr")})
	if err != nil {
		t.Fatalf("MarshalProposalV0: %v", err)
	}
	withEmpty, err := MarshalProposalV0(ProposalV0{Payload: []byte{}, Header: []byte("hdr")})
	if err != nil {
		t.Fatalf("MarshalProposalV0: %v", err)
	}
	if !bytes.Equal(withNil, withEmpty) {
		t.Errorf("nil and empty payload encode differently: %x vs %x", withNil, withEmpty)
	}
}

func TestVersionRejected(t *testing.T) {
	h := testHeader()
	h.Version = 2
	b, err := MarshalHeader(h)
	if !errors.Is(err, ErrVersion) {
		t.Errorf("MarshalHeader(version 2) error = %v, want ErrVersion", err)
	}
	if b != nil {
		t.Errorf("MarshalHeader(version 2) returned %x, want nil", b)
	}

	valid, err := MarshalHeader(testHeader())
	if err != nil {
		t.Fatalf("MarshalHeader: %v", err)
	}
	// The header content is under 128 bytes, so the SEQUENCE header is 2 bytes and the
	// version INTEGER (02 01 01) starts at index 2.
	if !bytes.Equal(valid[2:5], []byte{0x02, 0x01, 0x01}) {
		t.Fatalf("version INTEGER not at the expected offset in %x", valid)
	}
	patched := bytes.Clone(valid)
	patched[4] = 0x02
	if _, err := UnmarshalHeader(patched); !errors.Is(err, ErrVersion) {
		t.Errorf("UnmarshalHeader(version 2) error = %v, want ErrVersion", err)
	}
}

func TestTrailingBytesRejected(t *testing.T) {
	header, err := MarshalHeader(testHeader())
	if err != nil {
		t.Fatalf("MarshalHeader: %v", err)
	}
	for _, suffix := range [][]byte{{0xff}, {0x00, 0x00}} {
		if _, uerr := UnmarshalHeader(append(bytes.Clone(header), suffix...)); !errors.Is(uerr, ErrTrailing) {
			t.Errorf("UnmarshalHeader(trailing %x) error = %v, want ErrTrailing", suffix, uerr)
		}
	}

	proposal, err := MarshalProposalV0(ProposalV0{Payload: []byte("pay")})
	if err != nil {
		t.Fatalf("MarshalProposalV0: %v", err)
	}
	if _, err := UnmarshalProposalV0(append(proposal, 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalProposalV0(trailing ff) error = %v, want ErrTrailing", err)
	}
}

func TestFixedWidthRejected(t *testing.T) {
	for _, n := range []int{31, 33} {
		h := testHeader()
		h.PrevStateRoot = bytes.Repeat([]byte{0xab}, n)
		if _, err := MarshalHeader(h); !errors.Is(err, ErrLength) {
			t.Errorf("MarshalHeader(%d-byte root) error = %v, want ErrLength", n, err)
		}
	}
}

func TestDeterminism(t *testing.T) {
	h := Header{
		Version:       VersionV1,
		PrevStateRoot: bytes.Repeat([]byte{0x5a}, 32),
		PrevSeq:       42,
		ConsensusTime: 1699999999123456789,
	}
	want, err := MarshalHeader(h)
	if err != nil {
		t.Fatalf("MarshalHeader: %v", err)
	}
	for i := range 1000 {
		got, err := MarshalHeader(h)
		if err != nil {
			t.Fatalf("MarshalHeader (iteration %d): %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("iteration %d encoded differently: got %x want %x", i, got, want)
		}
	}
}
