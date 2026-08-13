package a

import . "google.golang.org/protobuf/proto"

// A dot-import: the other case a text grep misses.
func DotMarshal(m Message) []byte {
	b, _ := Marshal(m) // want `proto\.Marshal in a package that hashes`
	return b
}
