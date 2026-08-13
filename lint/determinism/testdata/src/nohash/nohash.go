package nohash

import "google.golang.org/protobuf/proto"

// No hash import anywhere in this package, so no diagnostic is expected.
// An unexpected one fails analysistest, which is the assertion.
func Encode(m proto.Message) []byte {
	b, _ := proto.Marshal(m)
	return b
}
