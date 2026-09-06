package canonical

import (
	"bytes"
	"errors"
	"testing"
)

func testClientRequest(intermediates int) ClientRequestV1 {
	r := ClientRequestV1{
		Version:    VersionV1,
		ClientCert: []byte("CLIENT-LEAF-DER"),
		RequestID:  bytes.Repeat([]byte{0x11}, RequestIDLen),
		Expiry:     1700000000000000000,
		Payload:    []byte("SET k v"),
	}
	for i := range intermediates {
		r.Intermediates = append(r.Intermediates, CertificateV1{DER: []byte{byte('A' + i)}})
	}
	return r
}

// asn1.Unmarshal yields a nil slice for an empty SEQUENCE OF, so an absent chain and an
// empty one are one value here. WIRE-SPEC 3.11.2.
func clientRequestEqual(a, b ClientRequestV1) bool {
	if len(a.Intermediates) != len(b.Intermediates) {
		return false
	}
	for i := range a.Intermediates {
		if !bytes.Equal(a.Intermediates[i].DER, b.Intermediates[i].DER) {
			return false
		}
	}
	return a.Version == b.Version &&
		bytes.Equal(a.ClientCert, b.ClientCert) &&
		bytes.Equal(a.RequestID, b.RequestID) &&
		a.Expiry == b.Expiry &&
		bytes.Equal(a.Payload, b.Payload)
}

func TestClientRequestV1RoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		r      ClientRequestV1
		minLen int
	}{
		{name: "no intermediates", r: testClientRequest(0)},
		{name: "one intermediate", r: testClientRequest(1)},
		{name: "three intermediates", r: testClientRequest(3)},
	}
	long := testClientRequest(1)
	long.Payload = bytes.Repeat([]byte{0x5a}, 200)
	// 131 total bytes means the outer SEQUENCE holds at least 128 content bytes, which
	// is exactly where DER switches to the long length form.
	cases = append(cases, struct {
		name   string
		r      ClientRequestV1
		minLen int
	}{name: "long form length", r: long, minLen: 131})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalClientRequestV1(tc.r)
			if err != nil {
				t.Fatalf("MarshalClientRequestV1: %v", err)
			}
			if len(b) < tc.minLen {
				t.Errorf("encoding is %d bytes, want at least %d; this case no longer exercises what it claims",
					len(b), tc.minLen)
			}
			got, err := UnmarshalClientRequestV1(b)
			if err != nil {
				t.Fatalf("UnmarshalClientRequestV1: %v", err)
			}
			if !clientRequestEqual(got, tc.r) {
				t.Errorf("round trip changed the request: got %+v want %+v", got, tc.r)
			}
		})
	}
}

func TestClientRequestV1Determinism(t *testing.T) {
	r := testClientRequest(2)
	first, err := MarshalClientRequestV1(r)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1: %v", err)
	}
	second, err := MarshalClientRequestV1(r)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("two encodings of one request differ:\nfirst  %x\nsecond %x", first, second)
	}
}

// An absent chain and an empty one are the same value, and neither is spelled OPTIONAL:
// 2.3 bans it, so the encoding has one spelling and the decode has one result.
func TestClientRequestV1EmptyChainHasOneSpelling(t *testing.T) {
	absent := testClientRequest(0)
	empty := testClientRequest(0)
	empty.Intermediates = []CertificateV1{}

	a, err := MarshalClientRequestV1(absent)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1(absent): %v", err)
	}
	e, err := MarshalClientRequestV1(empty)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1(empty): %v", err)
	}
	if !bytes.Equal(a, e) {
		t.Errorf("a nil chain and an empty chain encode differently:\nnil   %x\nempty %x", a, e)
	}
	if !bytes.Contains(a, []byte{0x30, 0x00}) {
		t.Errorf("no empty SEQUENCE OF in %x; the chain is not encoded as 30 00", a)
	}

	got, err := UnmarshalClientRequestV1(a)
	if err != nil {
		t.Fatalf("UnmarshalClientRequestV1: %v", err)
	}
	if got.Intermediates != nil {
		t.Errorf("decoding an empty SEQUENCE OF gave %#v, want a nil slice", got.Intermediates)
	}
	if !clientRequestEqual(got, empty) || !clientRequestEqual(got, absent) {
		t.Error("the decoded request must equal both the nil-chain and the empty-chain value")
	}
}

func TestClientRequestV1FieldsSeparateTheBytes(t *testing.T) {
	otherID := testClientRequest(1)
	otherID.RequestID = bytes.Repeat([]byte{0x22}, RequestIDLen)

	otherExpiry := testClientRequest(1)
	otherExpiry.Expiry++

	otherCert := testClientRequest(1)
	otherCert.ClientCert = []byte("ANOTHER-CLIENT-LEAF")

	base, err := MarshalClientRequestV1(testClientRequest(1))
	if err != nil {
		t.Fatalf("MarshalClientRequestV1: %v", err)
	}
	for _, tc := range []struct {
		name string
		r    ClientRequestV1
	}{
		{"request id", otherID},
		{"expiry", otherExpiry},
		{"client cert", otherCert},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalClientRequestV1(tc.r)
			if err != nil {
				t.Fatalf("MarshalClientRequestV1: %v", err)
			}
			if bytes.Equal(base, b) {
				t.Errorf("two requests differing only in %s encode alike: %x", tc.name, b)
			}
		})
	}
}

// The chain is ordered leaf-ward to root-ward, and the order is inside the signed bytes:
// a relay cannot reorder it and keep the signature.
func TestClientRequestV1ChainOrderIsBound(t *testing.T) {
	forward := testClientRequest(3)
	reversed := testClientRequest(3)
	chain := reversed.Intermediates
	chain[0], chain[2] = chain[2], chain[0]

	a, err := MarshalClientRequestV1(forward)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1(forward): %v", err)
	}
	b, err := MarshalClientRequestV1(reversed)
	if err != nil {
		t.Fatalf("MarshalClientRequestV1(reversed): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Errorf("the same chain in two orders encodes alike: %x", a)
	}
	if len(a) != len(b) {
		t.Errorf("the two orders differ in length (%d vs %d), so the test proves less than it claims",
			len(a), len(b))
	}
}

func TestClientRequestV1TrailingBytesRejected(t *testing.T) {
	b, err := MarshalClientRequestV1(testClientRequest(1))
	if err != nil {
		t.Fatalf("MarshalClientRequestV1: %v", err)
	}
	if _, err := UnmarshalClientRequestV1(append(bytes.Clone(b), 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalClientRequestV1 with a trailing byte gave %v, want ErrTrailing", err)
	}
}

// invalidClientRequest is shared by the encode and decode rejection tests: every value
// here must be refused on both sides, or the encoding is asymmetric.
func invalidClientRequest() []struct {
	name string
	r    ClientRequestV1
	want error
} {
	zeroVersion := testClientRequest(1)
	zeroVersion.Version = 0

	futureVersion := testClientRequest(1)
	futureVersion.Version = 2

	noCert := testClientRequest(1)
	noCert.ClientCert = nil

	noID := testClientRequest(1)
	noID.RequestID = nil

	shortID := testClientRequest(1)
	shortID.RequestID = bytes.Repeat([]byte{0x11}, RequestIDLen-1)

	longID := testClientRequest(1)
	longID.RequestID = bytes.Repeat([]byte{0x11}, RequestIDLen+1)

	zeroExpiry := testClientRequest(1)
	zeroExpiry.Expiry = 0

	negativeExpiry := testClientRequest(1)
	negativeExpiry.Expiry = -1

	emptyIntermediate := testClientRequest(2)
	emptyIntermediate.Intermediates[1].DER = nil

	return []struct {
		name string
		r    ClientRequestV1
		want error
	}{
		{"version zero", zeroVersion, ErrVersion},
		{"version from the future", futureVersion, ErrVersion},
		{"absent client certificate", noCert, ErrEmpty},
		{"request id of zero bytes", noID, ErrLength},
		{"request id one byte short", shortID, ErrLength},
		{"request id one byte long", longID, ErrLength},
		{"expiry of zero", zeroExpiry, ErrRange},
		{"negative expiry", negativeExpiry, ErrRange},
		{"intermediate with no DER", emptyIntermediate, ErrEmpty},
	}
}

func TestClientRequestV1MarshalRejects(t *testing.T) {
	for _, tc := range invalidClientRequest() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalClientRequestV1(tc.r); !errors.Is(err, tc.want) {
				t.Errorf("MarshalClientRequestV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestClientRequestV1UnmarshalRejects(t *testing.T) {
	for _, tc := range invalidClientRequest() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshal(tc.r)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalClientRequestV1(b); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalClientRequestV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}
