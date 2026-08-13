package a

import pb "google.golang.org/protobuf/proto"

// An aliased import: the case a text grep for "proto.Marshal" misses.
func AliasMarshal(m pb.Message) []byte {
	b, _ := pb.Marshal(m) // want `proto\.Marshal in a package that hashes`
	return b
}
