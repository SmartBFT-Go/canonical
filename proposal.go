package canonical

// ProposalV0 mirrors SmartBFT's types.Proposal in struct DECLARATION order, which is
// what asn1.Marshal emits; the keyed literal in the fork's Digest() lists it differently.
//
// V-RULE exception: no Version field. ProposalV0 inherits SmartBFT's pre-existing frozen
// encoding, and adding one would change every digest the fork has ever produced.
type ProposalV0 struct {
	Payload              []byte
	Header               []byte
	Metadata             []byte
	VerificationSequence int64
}

// MarshalProposalV0 encodes p in SmartBFT's frozen declaration order.
func MarshalProposalV0(p ProposalV0) ([]byte, error) {
	return marshal(p)
}

// UnmarshalProposalV0 decodes b under the R-RULE. There is no version to check.
func UnmarshalProposalV0(b []byte) (ProposalV0, error) {
	var p ProposalV0
	if err := unmarshal(b, &p); err != nil {
		return ProposalV0{}, err
	}
	return p, nil
}
