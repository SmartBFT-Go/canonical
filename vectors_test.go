package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// encoding/json is legal here and only here: this is a _test.go file, and the depguard
// rule scopes the ban with !$test for exactly this reason.

const vectorsPath = "testdata/vectors.json"

// There is deliberately no -update flag. Regenerating a frozen wire format on one
// keystroke turns a breaking-change alarm into a silencer.

type goldenFile struct {
	Comment string         `json:"$comment"`
	Vectors []derVector    `json:"vectors"`
	Merkle  []merkleVector `json:"merkle"`
}

type derVector struct {
	Name       string       `json:"name"`
	Structure  string       `json:"structure"`
	Fields     vectorFields `json:"fields"`
	DER        string       `json:"der"`
	SHA256     string       `json:"sha256"`
	Annotation []string     `json:"annotation"`
}

type vectorFields struct {
	Version              int64          `json:"Version"`
	PrevStateRoot        string         `json:"PrevStateRoot"`
	PrevSeq              int64          `json:"PrevSeq"`
	ConsensusTime        int64          `json:"ConsensusTime"`
	Payload              string         `json:"Payload"`
	Header               string         `json:"Header"`
	Metadata             string         `json:"Metadata"`
	VerificationSequence int64          `json:"VerificationSequence"`
	TrustDomain          string         `json:"TrustDomain"`
	CARoot               string         `json:"CARoot"`
	MaxNodes             int64          `json:"MaxNodes"`
	Members              []vectorMember `json:"Members"`
}

type vectorMember struct {
	NodeID     int64  `json:"NodeID"`
	SpiffeID   string `json:"SpiffeID"`
	LeafPubKey string `json:"LeafPubKey"`
}

type merkleVector struct {
	Name       string   `json:"name"`
	Fn         string   `json:"fn"`
	TreeID     uint64   `json:"treeID"`
	Depth      uint8    `json:"depth"`
	Key        string   `json:"key"`
	Val        string   `json:"val"`
	Left       string   `json:"left"`
	Right      string   `json:"right"`
	Hash       string   `json:"hash"`
	Annotation []string `json:"annotation"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", vectorsPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// An unknown key is a typo in the annex, and a typo'd key would silently assert
	// against a zero value.
	dec.DisallowUnknownFields()
	var g goldenFile
	if err := dec.Decode(&g); err != nil {
		t.Fatalf("parse %s: %v", vectorsPath, err)
	}
	return g
}

func mustHex(t *testing.T, name, field, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("vector %s: field %s is not hex: %v", name, field, err)
	}
	return b
}

func genesisFromVector(t *testing.T, v derVector) GenesisV1 {
	t.Helper()
	g := GenesisV1{
		Version:     v.Fields.Version,
		TrustDomain: mustHex(t, v.Name, "TrustDomain", v.Fields.TrustDomain),
		CARoot:      mustHex(t, v.Name, "CARoot", v.Fields.CARoot),
		MaxNodes:    v.Fields.MaxNodes,
	}
	for _, m := range v.Fields.Members {
		g.Members = append(g.Members, GenesisMemberV1{
			NodeID:     m.NodeID,
			SpiffeID:   mustHex(t, v.Name, "SpiffeID", m.SpiffeID),
			LeafPubKey: mustHex(t, v.Name, "LeafPubKey", m.LeafPubKey),
		})
	}
	return g
}

// encodeVector dispatches by structure name with an explicit switch, not reflection.
func encodeVector(t *testing.T, v derVector) []byte {
	t.Helper()
	switch v.Structure {
	case "Header":
		b, err := MarshalHeader(Header{
			Version:       v.Fields.Version,
			PrevStateRoot: mustHex(t, v.Name, "PrevStateRoot", v.Fields.PrevStateRoot),
			PrevSeq:       v.Fields.PrevSeq,
			ConsensusTime: v.Fields.ConsensusTime,
		})
		if err != nil {
			t.Fatalf("vector %s: MarshalHeader: %v", v.Name, err)
		}
		return b
	case "ProposalV0":
		b, err := MarshalProposalV0(ProposalV0{
			Payload:              mustHex(t, v.Name, "Payload", v.Fields.Payload),
			Header:               mustHex(t, v.Name, "Header", v.Fields.Header),
			Metadata:             mustHex(t, v.Name, "Metadata", v.Fields.Metadata),
			VerificationSequence: v.Fields.VerificationSequence,
		})
		if err != nil {
			t.Fatalf("vector %s: MarshalProposalV0: %v", v.Name, err)
		}
		return b
	case "GenesisV1":
		b, err := MarshalGenesisV1(genesisFromVector(t, v))
		if err != nil {
			t.Fatalf("vector %s: MarshalGenesisV1: %v", v.Name, err)
		}
		return b
	default:
		t.Fatalf("vector %s: unknown structure %q", v.Name, v.Structure)
		return nil
	}
}

func decodeVector(t *testing.T, v derVector, der []byte) []byte {
	t.Helper()
	switch v.Structure {
	case "Header":
		h, err := UnmarshalHeader(der)
		if err != nil {
			t.Fatalf("vector %s: UnmarshalHeader: %v", v.Name, err)
		}
		b, err := MarshalHeader(h)
		if err != nil {
			t.Fatalf("vector %s: re-MarshalHeader: %v", v.Name, err)
		}
		return b
	case "ProposalV0":
		p, err := UnmarshalProposalV0(der)
		if err != nil {
			t.Fatalf("vector %s: UnmarshalProposalV0: %v", v.Name, err)
		}
		b, err := MarshalProposalV0(p)
		if err != nil {
			t.Fatalf("vector %s: re-MarshalProposalV0: %v", v.Name, err)
		}
		return b
	case "GenesisV1":
		g, err := UnmarshalGenesisV1(der)
		if err != nil {
			t.Fatalf("vector %s: UnmarshalGenesisV1: %v", v.Name, err)
		}
		b, err := MarshalGenesisV1(g)
		if err != nil {
			t.Fatalf("vector %s: re-MarshalGenesisV1: %v", v.Name, err)
		}
		return b
	default:
		t.Fatalf("vector %s: unknown structure %q", v.Name, v.Structure)
		return nil
	}
}

func TestGoldenVectors(t *testing.T) {
	g := loadGolden(t)
	if len(g.Vectors) == 0 {
		t.Fatal("no DER vectors in " + vectorsPath)
	}
	seen := make(map[string]bool, len(g.Vectors))
	for _, v := range g.Vectors {
		if seen[v.Name] {
			t.Fatalf("duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true
		t.Run(v.Name, func(t *testing.T) {
			if len(v.Annotation) == 0 {
				t.Errorf("vector %s has no annotation; the annex is what a non-Go implementer reads", v.Name)
			}
			want := mustHex(t, v.Name, "der", v.DER)
			got := encodeVector(t, v)
			if !bytes.Equal(want, got) {
				t.Error(breakingChange(v, want, got))
				return
			}
			sum := sha256.Sum256(got)
			if h := hex.EncodeToString(sum[:]); h != v.SHA256 {
				t.Errorf("vector %s: sha256 of the recorded DER is %s, vector says %s", v.Name, h, v.SHA256)
			}
		})
	}
}

func TestVectorRoundTrip(t *testing.T) {
	g := loadGolden(t)
	for _, v := range g.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			der := mustHex(t, v.Name, "der", v.DER)
			if got := decodeVector(t, v, der); !bytes.Equal(der, got) {
				t.Error(breakingChange(v, der, got))
			}
		})
	}
}

func TestMerkleVectors(t *testing.T) {
	g := loadGolden(t)
	if len(g.Merkle) == 0 {
		t.Fatal("no Merkle vectors in " + vectorsPath)
	}
	for _, v := range g.Merkle {
		t.Run(v.Name, func(t *testing.T) {
			var got [32]byte
			switch v.Fn {
			case "leaf":
				got = LeafHash(v.TreeID, v.Depth,
					mustHex(t, v.Name, "key", v.Key), mustHex(t, v.Name, "val", v.Val))
			case "internal":
				got = InternalHash(v.TreeID, v.Depth,
					child(t, v.Name, "left", v.Left), child(t, v.Name, "right", v.Right))
			case "empty":
				got = EmptyHash(v.TreeID, v.Depth)
			default:
				t.Fatalf("vector %s: unknown fn %q", v.Name, v.Fn)
			}
			if h := hex.EncodeToString(got[:]); h != v.Hash {
				t.Errorf(`Merkle %s hashing changed (vector %s).
This is a BREAKING WIRE CHANGE: every state root ever computed by this cluster becomes
unreachable, and no existing proof verifies. Coordinated cluster upgrade required, see
WIRE-SPEC.md section 7. If intended, define a new node type; do not edit this vector.
want %s
 got %s`, v.Fn, v.Name, v.Hash, h)
			}
		})
	}
}

// TestVectorRules pins V-RULE and R-RULE against real golden bytes rather than
// synthesised ones, so the rules are asserted over exactly what ships.
func TestVectorRules(t *testing.T) {
	g := loadGolden(t)
	for _, v := range g.Vectors {
		if v.Structure != "Header" {
			continue
		}
		der := mustHex(t, v.Name, "der", v.DER)

		bumped := bytes.Clone(der)
		if bumped[2] != 0x02 || bumped[3] != 0x01 {
			t.Fatalf("vector %s: expected a one-byte INTEGER Version at offset 2", v.Name)
		}
		bumped[4]++
		if _, err := UnmarshalHeader(bumped); !errors.Is(err, ErrVersion) {
			t.Errorf("V-RULE: vector %s with a bumped Version gave %v, want ErrVersion", v.Name, err)
		}

		if _, err := UnmarshalHeader(append(bytes.Clone(der), 0xff)); !errors.Is(err, ErrTrailing) {
			t.Errorf("R-RULE: vector %s with a trailing byte gave %v, want ErrTrailing", v.Name, err)
		}
	}
}

func child(t *testing.T, name, field, s string) [32]byte {
	t.Helper()
	b := mustHex(t, name, field, s)
	if len(b) != sha256.Size {
		t.Fatalf("vector %s: field %s is %d bytes, want %d", name, field, len(b), sha256.Size)
	}
	return [32]byte(b)
}

func breakingChange(v derVector, want, got []byte) string {
	return fmt.Sprintf(`canonical encoding of %s changed (vector %s).
This is a BREAKING WIRE CHANGE requiring a coordinated cluster upgrade: every digest,
signature and state root produced under the old bytes stops verifying. See WIRE-SPEC.md
section 7. If the change is intended, bump Version and add a NEW vector; do not edit this one.

want %d bytes, got %d bytes:
%s`, v.Structure, v.Name, len(want), len(got), diffTLV(tlvLines(want, ""), tlvLines(got, "")))
}

// diffTLV interleaves the two encodings one TLV run per line, so a failure shows which
// field moved instead of two opaque hex strings.
func diffTLV(want, got []string) string {
	var b strings.Builder
	for i := range max(len(want), len(got)) {
		w, g := "", ""
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w == g {
			fmt.Fprintf(&b, "        %s\n", w)
			continue
		}
		fmt.Fprintf(&b, "  want: %s\n   got: %s   <-- differs\n", w, g)
	}
	return b.String()
}

func tlvLines(b []byte, indent string) []string {
	var out []string
	for len(b) > 0 {
		if len(b) < 2 {
			return append(out, indent+"<truncated> "+hex.EncodeToString(b))
		}
		tag, n, hdr := b[0], int(b[1]), 2
		if n&0x80 != 0 {
			w := n & 0x7f
			if w == 0 || w > 4 || len(b) < 2+w {
				return append(out, indent+"<bad length> "+hex.EncodeToString(b))
			}
			n, hdr = 0, 2+w
			for _, c := range b[2:hdr] {
				n = n<<8 | int(c)
			}
		}
		if len(b) < hdr+n {
			return append(out, indent+"<truncated> "+hex.EncodeToString(b))
		}
		line := fmt.Sprintf("%s%s  %s (%d bytes)", indent, hex.EncodeToString(b[:hdr]), tagName(tag), n)
		if tag == 0x30 {
			out = append(out, line)
			out = append(out, tlvLines(b[hdr:hdr+n], indent+"  ")...)
		} else {
			out = append(out, line+" "+hex.EncodeToString(b[hdr:hdr+n]))
		}
		b = b[hdr+n:]
	}
	return out
}

func tagName(t byte) string {
	switch t {
	case 0x30:
		return "SEQUENCE"
	case 0x04:
		return "OCTET STRING"
	case 0x02:
		return "INTEGER"
	case 0x01:
		return "BOOLEAN"
	default:
		return fmt.Sprintf("tag 0x%02x", t)
	}
}
