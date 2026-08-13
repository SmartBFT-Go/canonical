package edge

// Outside the deterministic core: the map rule must not fire here, or the
// SmartBFT fork lights up with pre-existing violations on day one.
func Plain(m map[string][]byte) int {
	n := 0
	for k := range m {
		n += len(k)
	}
	return n
}
