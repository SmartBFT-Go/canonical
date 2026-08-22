package canonical

import (
	"bytes"
	"strconv"
)

// LeafPubKeyLen is the fixed width of a member's Ed25519 public key, in bytes.
const LeafPubKeyLen = 32

// GenesisMemberV1 is one cluster member as pinned at genesis.
//
// V-RULE exception: no Version field. It is an element of GenesisV1 and never travels
// alone, so the containing structure's Version already governs its layout.
type GenesisMemberV1 struct {
	NodeID     int64  // logically unsigned, range-checked here; see WIRE-SPEC 3.5
	SpiffeID   []byte // exactly spiffeIDV1 of the two fields; string is banned by 2.3
	LeafPubKey []byte // exactly LeafPubKeyLen bytes
}

// GenesisV1 pins a cluster's trust anchor and membership. Its SHA-256 is the value an
// operator distributes out of band, so the field order below is frozen.
type GenesisV1 struct {
	Version     int64 // V-RULE: first field
	TrustDomain []byte
	CARoot      []byte // DER of the root certificate
	MaxNodes    int64
	Members     []GenesisMemberV1 // strictly ascending by NodeID
}

// MarshalGenesisV1 encodes g, rejecting every value checkGenesisV1 refuses.
func MarshalGenesisV1(g GenesisV1) ([]byte, error) {
	if err := checkGenesisV1(g); err != nil {
		return nil, err
	}
	return marshal(g)
}

// UnmarshalGenesisV1 decodes b under the R-RULE, then applies the same checks as
// MarshalGenesisV1: bytes this package would not have produced are not accepted here.
func UnmarshalGenesisV1(b []byte) (GenesisV1, error) {
	var g GenesisV1
	if err := unmarshal(b, &g); err != nil {
		return GenesisV1{}, err
	}
	if err := checkGenesisV1(g); err != nil {
		return GenesisV1{}, err
	}
	return g, nil
}

func checkGenesisV1(g GenesisV1) error {
	if g.Version != VersionV1 {
		return ErrVersion
	}
	if len(g.TrustDomain) == 0 {
		return ErrEmpty
	}
	if g.MaxNodes < 0 || int64(len(g.Members)) > g.MaxNodes {
		return ErrRange
	}
	for i, m := range g.Members {
		if m.NodeID < 0 {
			return ErrRange
		}
		// Sorted by the caller, never sorted for them: an unsorted set is a second
		// spelling of one membership, and only one spelling has the pinned digest.
		if i > 0 && m.NodeID <= g.Members[i-1].NodeID {
			return ErrOrder
		}
		if len(m.SpiffeID) == 0 {
			return ErrEmpty
		}
		if !bytes.Equal(m.SpiffeID, spiffeIDV1(g.TrustDomain, m.NodeID)) {
			return ErrFormat
		}
		if len(m.LeafPubKey) != LeafPubKeyLen {
			return ErrLength
		}
	}
	return nil
}

// WIRE-SPEC 3.6 gives the SpiffeID's value, not merely its shape, so the one legal
// spelling is derived here rather than pattern-matched.
func spiffeIDV1(trustDomain []byte, nodeID int64) []byte {
	id := make([]byte, 0, len("spiffe://")+len(trustDomain)+len("/node/")+20)
	id = append(id, "spiffe://"...)
	id = append(id, trustDomain...)
	id = append(id, "/node/"...)
	return strconv.AppendInt(id, nodeID, 10)
}
