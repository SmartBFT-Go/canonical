package a

import (
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func AllowedAbove(m proto.Message) []byte {
	// determinism:allow bytes travel verbatim, never re-marshaled for comparison
	b, _ := proto.Marshal(m)
	return b
}

func AllowedInline(m proto.Message) []byte {
	b, _ := proto.Marshal(m) // determinism:allow same reason, directive on the line
	return b
}

// determinism:allow a directive on the func does not cover calls further down
func NotAdjacent(m proto.Message) []byte {
	b, _ := proto.Marshal(m) // want `proto\.Marshal in a package that hashes`
	return b
}

func BareDirective(m proto.Message) []byte {
	// determinism:allow
	b, _ := proto.Marshal(m) // want `proto\.Marshal in a package that hashes`
	return b
}

func stillHashes(b []byte) [32]byte { return sha256.Sum256(b) }
