package canonical

import "encoding/asn1"

// VersionV1 is the only structure version this package encodes or accepts.
const VersionV1 int64 = 1

// marshal and unmarshal are the only asn1.Marshal / asn1.Unmarshal call sites
// permitted anywhere in the system.
func marshal(v any) ([]byte, error) {
	return asn1.Marshal(v)
}

// R-RULE: asn1.Unmarshal reports leftover bytes in rest instead of erroring, and a
// caller that ignores rest makes the digest malleable.
func unmarshal(b []byte, v any) error {
	rest, err := asn1.Unmarshal(b, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return ErrTrailing
	}
	return nil
}
