package canonical

// PrevStateRootLen is the fixed width of a state root, in bytes.
const PrevStateRootLen = 32

// Header is the proposal header. Field order is wire order and is frozen.
type Header struct {
	Version       int64  // V-RULE: first field; decoders reject versions they do not know
	PrevStateRoot []byte // exactly PrevStateRootLen bytes
	PrevSeq       int64
	ConsensusTime int64 // Unix nanoseconds; time.Time is banned, see doc.go
}

// MarshalHeader encodes h, rejecting an unknown version or a wrong-width root.
func MarshalHeader(h Header) ([]byte, error) {
	if h.Version != VersionV1 {
		return nil, ErrVersion
	}
	if len(h.PrevStateRoot) != PrevStateRootLen {
		return nil, ErrLength
	}
	return marshal(h)
}

// UnmarshalHeader decodes b under the R-RULE, then applies the same checks as MarshalHeader.
func UnmarshalHeader(b []byte) (Header, error) {
	var h Header
	if err := unmarshal(b, &h); err != nil {
		return Header{}, err
	}
	if h.Version != VersionV1 {
		return Header{}, ErrVersion
	}
	// Symmetric with MarshalHeader: a short root would otherwise reach callers that
	// copy it into a fixed-size array and silently zero-pad.
	if len(h.PrevStateRoot) != PrevStateRootLen {
		return Header{}, ErrLength
	}
	return h, nil
}
