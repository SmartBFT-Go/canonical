package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// The expected digests are SmartBFT's pre-migration CommitSignaturesDigest output.
// They are the contract this structure exists to reproduce.
func TestSignatureSetV0MatchesSmartBFT(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  SignatureSetV0
		want string
	}{
		{
			name: "single",
			set: SignatureSetV0{Sigs: []SignerSigV0{
				{Signer: 1, Value: []byte("V1"), Msg: []byte("M1")},
			}},
			want: "376078b3b0ae99400a035f534579a528a42479773ab94a00b41f2c563edd9eb1",
		},
		{
			name: "three",
			set: SignatureSetV0{Sigs: []SignerSigV0{
				{Signer: 1, Value: []byte("V1"), Msg: []byte("M1")},
				{Signer: 2, Value: nil, Msg: nil},
				{Signer: 300, Value: []byte("V3"), Msg: []byte("M3")},
			}},
			want: "a31acfda5d67bf0c8bec72cb89f9b5abf3ea568fa6b2df6a9bb385e8baae376b",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalSignatureSetV0(tc.set)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			sum := sha256.Sum256(b)
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Fatalf("digest mismatch\n got: %s\nwant: %s", got, tc.want)
			}
			back, err := UnmarshalSignatureSetV0(b)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if len(back.Sigs) != len(tc.set.Sigs) {
				t.Fatalf("round trip lost entries: %d != %d", len(back.Sigs), len(tc.set.Sigs))
			}
		})
	}
}

func TestSignatureSetV0RejectsTrailing(t *testing.T) {
	b, err := MarshalSignatureSetV0(SignatureSetV0{Sigs: []SignerSigV0{{Signer: 1}}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := UnmarshalSignatureSetV0(append(b, 0xff)); !errors.Is(err, ErrTrailing) {
		t.Fatalf("want ErrTrailing, got %v", err)
	}
}
