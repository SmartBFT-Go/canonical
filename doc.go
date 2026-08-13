// Package canonical is the sole producer of every byte sequence this system hashes
// or signs. It depends on nothing outside the standard library, and it never imports
// protobuf or encoding/json.
//
// Two encodings, each for its own job: ASN.1 DER for structured, evolving values
// (proposals, attestations, commit certificates), and fixed-width domain-separated
// concatenation for Merkle node hashing, where DER measured 23x slower on a path that
// runs millions of times per compaction.
//
// # The type profile
//
// The safety of the DER encoding comes from the subset of Go types used, not from
// encoding/asn1 itself. A canonical structure may contain only:
//
//	Version int64        // MUST be the first field of every top-level structure
//	[]byte               // OCTET STRING — hashes, keys, values, opaque blobs
//	int64                // INTEGER — sequences, nanosecond timestamps, enums
//	bool                 // BOOLEAN
//	nested exported struct                 // SEQUENCE
//	[]T where T is an allowed struct       // SEQUENCE OF, caller-sorted
//
// Banned, with the reason each ban exists:
//
//	string          tag flips PrintableString <-> UTF8String on content
//	time.Time       second truncation, tag flip at 1950/2050, timezone in the bytes
//	int             platform width
//	uint*           unsupported by asn1.Marshal
//	[N]byte         unsupported by asn1.Marshal; a 32-byte hash is a []byte
//	float64         unsupported by asn1.Marshal, and floats are banned anyway
//	map             unsupported by asn1.Marshal, and iteration order is unordered
//	pointer-to-struct              unsupported by asn1.Marshal
//	*big.Int        allowed only with a written justification
//	asn1:"optional" / omitempty    absent and zero become indistinguishable
//	asn1:"set"      sorted on marshal but unsorted accepted on parse — malleable
//	unexported fields              hard marshal error
//
// TestTypeProfile parses this package's own source and fails if a structure gains a
// field outside the list above.
//
// # The two rules
//
// V-RULE: every top-level structure's first field is Version int64, and every decoder
// rejects a version it does not know. This is load-bearing because asn1.Unmarshal
// silently ignores trailing elements inside a SEQUENCE: without a version tag, an old
// replica handed a new-format structure decodes it successfully and never sees the new
// field. ProposalV0 is the single exception and carries its justification in
// proposal.go.
//
// R-RULE: every exported Unmarshal function returns an error unless zero bytes remain.
// asn1.Unmarshal returns leftovers in rest rather than erroring, so a caller that
// ignores rest lets an attacker append arbitrary bytes and obtain a different digest
// over a structure that decodes identically. The unexported wrappers in asn1.go are the
// only asn1.Marshal and asn1.Unmarshal call sites permitted anywhere in the system.
//
// # Frozen v1
//
// Once a structure's encoding ships, its bytes never change. New fields mean a new
// structure or a new version tag. Changing an existing encoding is a breaking release
// requiring a coordinated cluster upgrade.
//
// Two consequences of the encoding worth knowing at the call site: a nil []byte and an
// empty []byte both encode to 04 00, so absent and empty are indistinguishable and a
// caller needing to tell them apart must carry a separate field; and int64 Unix
// nanoseconds overflow in 2262.
//
// # What is and is not mechanically enforced
//
// Enforced by tests in this package: the type profile, V-RULE, R-RULE, determinism of
// the encoder, and the zero-dependency property. Enforced by lint in the deterministic
// core: the import bans, unordered map iteration, floating-point arithmetic, unsafe and
// reflect.
//
// NOT enforced: goroutines and channels are permitted in the deterministic core. The
// single-writer discipline (STORE-02) is therefore a design rule, and anything relying
// on it needs its own test rather than trust in the linter.
package canonical
