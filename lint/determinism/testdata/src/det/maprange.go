package det

import "slices"

type Index map[string][]byte

func Plain(m map[string][]byte) int {
	n := 0
	for k := range m { // want `range over map is unordered`
		n += len(k)
	}
	return n
}

// A named map type is a *types.Named; without Underlying() it escapes the rule.
func Named(idx Index) int {
	n := 0
	for k, v := range idx { // want `range over map is unordered`
		n += len(k) + len(v)
	}
	return n
}

// Ranging without a key observes no order.
func Count(m map[string][]byte) int {
	n := 0
	for range m {
		n++
	}
	return n
}

func Repeat(n int) int {
	total := 0
	for range n {
		total++
	}
	return total
}

// The corrected pattern: collect, sort, then iterate.
func Sorted(m map[string][]byte) []byte {
	keys := make([]string, 0, len(m))
	for k := range m { // want `range over map is unordered`
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var out []byte
	for _, k := range keys {
		out = append(out, m[k]...)
	}
	return out
}
