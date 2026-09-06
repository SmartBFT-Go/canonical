package canonical

// CommitCertificateV1 is what a client checks to know a proposal was decided. It is not
// itself signed: it is a container for the consenter signatures, each of which is an
// Ed25519 signature over a SignedV1 under PurposeCommitSig.
type CommitCertificateV1 struct {
	Version        int64  // V-RULE: first field
	ProposalDigest []byte // exactly DigestLen bytes
	View           int64
	Seq            int64
	Sigs           []SignerSigV0 // strictly ascending by Signer
}

// MarshalCommitCertificateV1 encodes c, rejecting every value checkCommitCertificateV1 refuses.
func MarshalCommitCertificateV1(c CommitCertificateV1) ([]byte, error) {
	if err := checkCommitCertificateV1(c); err != nil {
		return nil, err
	}
	return marshal(c)
}

// UnmarshalCommitCertificateV1 decodes b under the R-RULE, then applies the same checks as
// MarshalCommitCertificateV1, so an unsorted certificate has no second spelling.
func UnmarshalCommitCertificateV1(b []byte) (CommitCertificateV1, error) {
	var c CommitCertificateV1
	if err := unmarshal(b, &c); err != nil {
		return CommitCertificateV1{}, err
	}
	if err := checkCommitCertificateV1(c); err != nil {
		return CommitCertificateV1{}, err
	}
	return c, nil
}

func checkCommitCertificateV1(c CommitCertificateV1) error {
	if c.Version != VersionV1 {
		return ErrVersion
	}
	if len(c.ProposalDigest) != DigestLen {
		return ErrLength
	}
	if c.View < 0 || c.Seq < 0 {
		return ErrRange
	}
	// A certificate with no signatures attests to nothing, whatever threshold the
	// client applies.
	if len(c.Sigs) == 0 {
		return ErrEmpty
	}
	for i, s := range c.Sigs {
		// Sorted by the caller, never sorted for them: unlike 3.7.4 nothing already
		// stored depends on this order, so 2.2's rule applies with no exception.
		if i > 0 && s.Signer <= c.Sigs[i-1].Signer {
			return ErrOrder
		}
		if len(s.Value) != SignatureLen {
			return ErrLength
		}
		// Msg is the CommitPayloadV1 the entry signed; without it a client cannot
		// reconstruct the envelope, so the entry is unverifiable by construction.
		if len(s.Msg) == 0 {
			return ErrEmpty
		}
	}
	return nil
}
