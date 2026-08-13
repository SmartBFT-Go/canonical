package canonical

import "testing"

func TestMerkleDomainSeparation(t *testing.T) {
	key, val := []byte("k"), []byte("v")
	left := LeafHash(1, 1, []byte("l"), val)
	right := LeafHash(1, 1, []byte("r"), val)

	distinct := []struct {
		name string
		a, b [32]byte
	}{
		{"treeID binds the leaf", LeafHash(1, 0, key, val), LeafHash(2, 0, key, val)},
		{"depth binds the leaf", LeafHash(1, 0, key, val), LeafHash(1, 1, key, val)},
		{"key and value are length-prefixed",
			LeafHash(1, 0, []byte("ab"), []byte("c")),
			LeafHash(1, 0, []byte("a"), []byte("bc"))},
		{"internal is not a leaf", InternalHash(1, 0, left, right), LeafHash(1, 0, left[:], right[:])},
		{"empty is not a leaf", EmptyHash(1, 0), LeafHash(1, 0, nil, nil)},
		{"depth binds the empty subtree", EmptyHash(1, 0), EmptyHash(1, 1)},
		{"treeID binds the empty subtree", EmptyHash(1, 0), EmptyHash(2, 0)},
		{"child order is significant", InternalHash(1, 0, left, right), InternalHash(1, 0, right, left)},
	}
	for _, tc := range distinct {
		if tc.a == tc.b {
			t.Errorf("%s: both inputs hash to %x", tc.name, tc.a)
		}
	}

	if EmptyHash(1, 1) == EmptyHash(2, 0) {
		t.Errorf("empty subtrees at different tree and depth collide: %x", EmptyHash(1, 1))
	}
}

func TestMerkleDeterminism(t *testing.T) {
	key, val := []byte("k"), []byte("v")
	left, right := LeafHash(1, 1, key, val), LeafHash(1, 1, val, key)

	if LeafHash(3, 4, key, val) != LeafHash(3, 4, key, val) {
		t.Error("LeafHash is not deterministic")
	}
	if InternalHash(3, 4, left, right) != InternalHash(3, 4, left, right) {
		t.Error("InternalHash is not deterministic")
	}
	if EmptyHash(3, 4) != EmptyHash(3, 4) {
		t.Error("EmptyHash is not deterministic")
	}
}
