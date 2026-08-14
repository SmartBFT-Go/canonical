package canonical

import (
	"crypto/sha256"
	"encoding/binary"
)

// Domain separation prefixes. Three, not two: an empty subtree must not be
// constructible as a leaf, or non-membership and membership-of-empty collide.
const (
	prefixLeaf     byte = 0x00
	prefixInternal byte = 0x01
	prefixEmpty    byte = 0x02
)

// Merkle nodes are fixed-width domain-separated concatenation, not DER: DER measured
// 23x slower on a path that runs millions of times per compaction.

// LeafHash length-prefixes both components: without it ("ab","c") and ("a","bc") hash
// identically and two distinct states share a root.
func LeafHash(treeID uint64, depth uint8, key, val []byte) [32]byte {
	h := sha256.New()
	var w [8]byte
	h.Write([]byte{prefixLeaf})
	binary.BigEndian.PutUint64(w[:], treeID)
	h.Write(w[:])
	h.Write([]byte{depth})
	binary.BigEndian.PutUint64(w[:], uint64(len(key)))
	h.Write(w[:])
	h.Write(key)
	binary.BigEndian.PutUint64(w[:], uint64(len(val)))
	h.Write(w[:])
	h.Write(val)
	return [32]byte(h.Sum(nil))
}

// InternalHash takes its children as [32]byte so a wrong-width child cannot be written.
func InternalHash(treeID uint64, depth uint8, left, right [32]byte) [32]byte {
	h := sha256.New()
	var w [8]byte
	h.Write([]byte{prefixInternal})
	binary.BigEndian.PutUint64(w[:], treeID)
	h.Write(w[:])
	h.Write([]byte{depth})
	h.Write(left[:])
	h.Write(right[:])
	return [32]byte(h.Sum(nil))
}

// EmptyHash binds treeID and depth so an empty subtree cannot be relocated.
func EmptyHash(treeID uint64, depth uint8) [32]byte {
	h := sha256.New()
	var w [8]byte
	h.Write([]byte{prefixEmpty})
	binary.BigEndian.PutUint64(w[:], treeID)
	h.Write(w[:])
	h.Write([]byte{depth})
	return [32]byte(h.Sum(nil))
}
