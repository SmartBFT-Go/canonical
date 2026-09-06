package canonical

// RequestIDLen is the fixed width of a request ID, in bytes. Fixed width is what stops one
// client spelling an ID into another's namespace: RequestInfo.String() concatenates unescaped.
const RequestIDLen = 16

// CertificateV1 is one DER certificate. It exists because the type profile has no [][]byte.
//
// V-RULE exception: no Version field. It is an element of ClientRequestV1 and never travels
// alone, so the containing structure's Version already governs its layout.
type CertificateV1 struct {
	DER []byte
}

// ClientRequestV1 is SignedV1.Payload under PurposeClientRequest. It is self-contained:
// verification needs these bytes and the genesis CA root, nothing else.
//
// There is no ClientID field. The client's identity is the SPIFFE ID of the verified
// ClientCert, derived and never asserted.
type ClientRequestV1 struct {
	Version       int64           // V-RULE: first field
	ClientCert    []byte          // DER of the client leaf
	Intermediates []CertificateV1 // ordered leaf-ward to root-ward; empty is legal
	RequestID     []byte          // exactly RequestIDLen bytes
	Expiry        int64           // Unix nanoseconds, compared against the header's ConsensusTime
	Payload       []byte          // the application request, opaque here
}

// MarshalClientRequestV1 encodes r, rejecting every value checkClientRequestV1 refuses.
func MarshalClientRequestV1(r ClientRequestV1) ([]byte, error) {
	if err := checkClientRequestV1(r); err != nil {
		return nil, err
	}
	return marshal(r)
}

// UnmarshalClientRequestV1 decodes b under the R-RULE, then applies the same checks as
// MarshalClientRequestV1: what a replica validates must be what a client could have signed.
func UnmarshalClientRequestV1(b []byte) (ClientRequestV1, error) {
	var r ClientRequestV1
	if err := unmarshal(b, &r); err != nil {
		return ClientRequestV1{}, err
	}
	if err := checkClientRequestV1(r); err != nil {
		return ClientRequestV1{}, err
	}
	return r, nil
}

func checkClientRequestV1(r ClientRequestV1) error {
	if r.Version != VersionV1 {
		return ErrVersion
	}
	// Without the leaf a replica catching up by state transfer cannot reach the same
	// verdict as one that saw the request live.
	if len(r.ClientCert) == 0 {
		return ErrEmpty
	}
	for _, c := range r.Intermediates {
		if len(c.DER) == 0 {
			return ErrEmpty
		}
	}
	if len(r.RequestID) != RequestIDLen {
		return ErrLength
	}
	// A non-positive expiry is a request no ConsensusTime admits, so it is malformed
	// rather than merely expired.
	if r.Expiry <= 0 {
		return ErrRange
	}
	return nil
}
