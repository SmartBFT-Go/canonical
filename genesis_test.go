package canonical

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"testing"
)

func testMember(id int64) GenesisMemberV1 {
	return GenesisMemberV1{
		NodeID:     id,
		SpiffeID:   []byte("spiffe://cluster.example/node/" + strconv.FormatInt(id, 10)),
		LeafPubKey: bytes.Repeat([]byte{byte(id)}, LeafPubKeyLen),
	}
}

func testGenesis(n int) GenesisV1 {
	g := GenesisV1{
		Version:     VersionV1,
		TrustDomain: []byte("cluster.example"),
		CARoot:      bytes.Repeat([]byte{0xca}, 32),
		MaxNodes:    10,
	}
	for i := 1; i <= n; i++ {
		g.Members = append(g.Members, testMember(int64(i)))
	}
	return g
}

func genesisEqual(a, b GenesisV1) bool {
	if a.Version != b.Version || a.MaxNodes != b.MaxNodes ||
		!bytes.Equal(a.TrustDomain, b.TrustDomain) || !bytes.Equal(a.CARoot, b.CARoot) ||
		len(a.Members) != len(b.Members) {
		return false
	}
	for i := range a.Members {
		x, y := a.Members[i], b.Members[i]
		if x.NodeID != y.NodeID || !bytes.Equal(x.SpiffeID, y.SpiffeID) ||
			!bytes.Equal(x.LeafPubKey, y.LeafPubKey) {
			return false
		}
	}
	return true
}

func TestGenesisRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		g       GenesisV1
		minLen  int
		longest bool
	}{
		{name: "no members", g: testGenesis(0)},
		{name: "four members", g: testGenesis(4)},
		// Two members already push the Members SEQUENCE OF past 127 content bytes, which
		// is where DER switches to the long length form.
		{name: "long form length", g: testGenesis(2), minLen: 130},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := MarshalGenesisV1(tc.g)
			if err != nil {
				t.Fatalf("MarshalGenesisV1: %v", err)
			}
			if len(b) < tc.minLen {
				t.Errorf("encoding is %d bytes, want at least %d; this case no longer exercises what it claims",
					len(b), tc.minLen)
			}
			got, err := UnmarshalGenesisV1(b)
			if err != nil {
				t.Fatalf("UnmarshalGenesisV1: %v", err)
			}
			if !genesisEqual(got, tc.g) {
				t.Errorf("round trip changed the genesis: got %+v want %+v", got, tc.g)
			}
		})
	}
}

func TestGenesisDeterminism(t *testing.T) {
	g := testGenesis(4)
	first, err := MarshalGenesisV1(g)
	if err != nil {
		t.Fatalf("MarshalGenesisV1: %v", err)
	}
	for range 100 {
		again, err := MarshalGenesisV1(g)
		if err != nil {
			t.Fatalf("MarshalGenesisV1: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("MarshalGenesisV1 is not deterministic")
		}
	}
}

func TestGenesisVersionRejected(t *testing.T) {
	for _, v := range []int64{0, 2, math.MaxInt64} {
		g := testGenesis(1)
		g.Version = v
		if _, err := MarshalGenesisV1(g); !errors.Is(err, ErrVersion) {
			t.Errorf("MarshalGenesisV1 with Version %d gave %v, want ErrVersion", v, err)
		}
		// The decoder must refuse it too: bytes minted elsewhere never reach the checks
		// the encoder would have run.
		b, err := marshal(g)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := UnmarshalGenesisV1(b); !errors.Is(err, ErrVersion) {
			t.Errorf("UnmarshalGenesisV1 with Version %d gave %v, want ErrVersion", v, err)
		}
	}
}

func TestGenesisTrailingBytesRejected(t *testing.T) {
	b, err := MarshalGenesisV1(testGenesis(2))
	if err != nil {
		t.Fatalf("MarshalGenesisV1: %v", err)
	}
	if _, err := UnmarshalGenesisV1(append(bytes.Clone(b), 0xff)); !errors.Is(err, ErrTrailing) {
		t.Errorf("UnmarshalGenesisV1 with a trailing byte gave %v, want ErrTrailing", err)
	}
}

// invalidGenesis is shared by the encode and decode rejection tests: every value here
// must be refused on both sides, or the encoding is asymmetric.
func invalidGenesis() []struct {
	name string
	g    GenesisV1
	want error
} {
	shortKey := testGenesis(1)
	shortKey.Members[0].LeafPubKey = bytes.Repeat([]byte{0x01}, LeafPubKeyLen-1)

	longKey := testGenesis(1)
	longKey.Members[0].LeafPubKey = bytes.Repeat([]byte{0x01}, LeafPubKeyLen+1)

	noTrustDomain := testGenesis(1)
	noTrustDomain.TrustDomain = nil

	noSpiffeID := testGenesis(1)
	noSpiffeID.Members[0].SpiffeID = nil

	negativeNodeID := testGenesis(1)
	negativeNodeID.Members[0].NodeID = -1

	negativeMaxNodes := testGenesis(1)
	negativeMaxNodes.MaxNodes = -1

	unsorted := testGenesis(2)
	unsorted.Members[0], unsorted.Members[1] = unsorted.Members[1], unsorted.Members[0]

	duplicate := testGenesis(2)
	duplicate.Members[1].NodeID = duplicate.Members[0].NodeID

	tooMany := testGenesis(4)
	tooMany.MaxNodes = 3

	return []struct {
		name string
		g    GenesisV1
		want error
	}{
		{"leaf public key one byte short", shortKey, ErrLength},
		{"leaf public key one byte long", longKey, ErrLength},
		{"empty trust domain", noTrustDomain, ErrEmpty},
		{"empty spiffe id", noSpiffeID, ErrEmpty},
		{"negative node id", negativeNodeID, ErrRange},
		{"negative max nodes", negativeMaxNodes, ErrRange},
		{"members out of order", unsorted, ErrOrder},
		{"duplicate node id", duplicate, ErrOrder},
		{"more members than MaxNodes", tooMany, ErrRange},
	}
}

func TestGenesisMarshalRejects(t *testing.T) {
	for _, tc := range invalidGenesis() {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MarshalGenesisV1(tc.g); !errors.Is(err, tc.want) {
				t.Errorf("MarshalGenesisV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGenesisUnmarshalRejects(t *testing.T) {
	for _, tc := range invalidGenesis() {
		t.Run(tc.name, func(t *testing.T) {
			b, err := marshal(tc.g)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if _, err := UnmarshalGenesisV1(b); !errors.Is(err, tc.want) {
				t.Errorf("UnmarshalGenesisV1 gave %v, want %v", err, tc.want)
			}
		})
	}
}
