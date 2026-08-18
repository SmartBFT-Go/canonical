package canonical

// SignerSigV0 and SignatureSetV0 mirror SmartBFT's internal IntDoubleByte and
// IntDoubleBytes in declaration order, which is what the wire encoding follows.
//
// V-RULE exception: no Version field. These inherit SmartBFT's pre-existing frozen
// encoding for ViewMetadata.PrevCommitSignatureDigest; adding one would invalidate
// every digest already stored in a ledger.
type SignerSigV0 struct {
	Signer int64
	Value  []byte
	Msg    []byte
}

// SignatureSetV0 is the outer SEQUENCE holding the per-signer entries.
type SignatureSetV0 struct {
	Sigs []SignerSigV0
}

// MarshalSignatureSetV0 encodes s in SmartBFT's frozen declaration order.
func MarshalSignatureSetV0(s SignatureSetV0) ([]byte, error) {
	return marshal(s)
}

// UnmarshalSignatureSetV0 decodes b under the R-RULE. There is no version to check.
func UnmarshalSignatureSetV0(b []byte) (SignatureSetV0, error) {
	var s SignatureSetV0
	if err := unmarshal(b, &s); err != nil {
		return SignatureSetV0{}, err
	}
	return s, nil
}
