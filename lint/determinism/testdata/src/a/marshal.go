package a

import (
	"crypto/sha256"
	"encoding/json"

	"google.golang.org/protobuf/proto"
)

func DigestProto(m proto.Message) [32]byte {
	b, _ := proto.Marshal(m) // want `proto\.Marshal in a package that hashes`
	return sha256.Sum256(b)
}

func DigestJSON(v any) [32]byte {
	b, _ := json.Marshal(v) // want `json\.Marshal in a package that hashes`
	return sha256.Sum256(b)
}

func DigestOpts(m proto.Message) [32]byte {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m) // want `proto\.Marshal in a package that hashes`
	return sha256.Sum256(b)
}
