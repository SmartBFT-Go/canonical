#!/usr/bin/env bash
# Proves the gates fire on deliberately bad code, and only where they should.
# Everything happens in a temp module, so the working tree is never touched.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cfg="$root/ci/templates/golangci-det-core.yml"
export GOWORK=off

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

tree="$work/tree"
mkdir -p "$tree/det" "$tree/edge" "$tree/stub/proto"

# .go.txt in the repo, .go only here: the bad code never builds into the product.
cp "$root/ci/negative/proto_marshal_into_hash.go.txt" "$tree/det/marshal.go"
cp "$root/ci/negative/wallclock_import.go.txt" "$tree/det/wallclock.go"
cp "$root/ci/negative/maprange.go.txt" "$tree/det/maprange.go"
cp "$root/ci/negative/outside_core_ok.go.txt" "$tree/edge/edge.go"

cat >"$tree/stub/proto/proto.go" <<'EOF'
package proto

type Message interface{}

func Marshal(Message) ([]byte, error) { return nil, nil }
EOF

goversion="$(go mod edit -json "$root/go.mod" | sed -n 's/.*"Go": "\([^"]*\)".*/\1/p')"

cat >"$tree/stub/go.mod" <<EOF
module google.golang.org/protobuf

go $goversion
EOF

# replace is fine in a module that exists for four seconds and is never committed.
cat >"$tree/go.mod" <<EOF
module example.com/negative

go $goversion

require google.golang.org/protobuf v0.0.0

replace google.golang.org/protobuf => ./stub
EOF

# Built fresh: a stale bin/detcheck could report on code that no longer exists.
detcheck="$work/detcheck"
(cd "$root/lint" && go build -o "$detcheck" ./cmd/detcheck)

rc=0
out=""

fail() {
    echo "negative gate FAILED: $1" >&2
    echo "--- output ---" >&2
    echo "$out" >&2
    exit 1
}

run_lint() {
    rc=0
    out="$(cd "$tree" && golangci-lint run --config "$cfg" "$1" 2>&1)" || rc=$?
}

run_vet() {
    rc=0
    out="$(cd "$tree" && go vet -vettool="$detcheck" -detpath='(^|/)det(/|$)' "$1" 2>&1)" || rc=$?
}

echo "==> depguard over the deterministic core"
run_lint ./det/...
# Exactly 1. Exit 3 is a config error, and accepting it would pass a broken gate.
[ "$rc" -eq 1 ] || fail "expected golangci-lint exit 1 (issues), got $rc"
grep -q "import 'time' is not allowed" <<<"$out" ||
    fail "the deterministic-core import gate did NOT fire"

echo "==> detcheck over the deterministic core"
run_vet ./det/...
[ "$rc" -eq 1 ] || fail "expected go vet exit 1 (diagnostics), got $rc"
grep -q "proto.Marshal in a package that hashes" <<<"$out" ||
    fail "the marshal-reaching-hash gate did NOT fire"
grep -q "range over map is unordered" <<<"$out" ||
    fail "the unordered-map-range gate did NOT fire"

echo "==> the same code outside the core"
run_lint ./edge/...
[ "$rc" -eq 0 ] || fail "depguard fired outside the deterministic core (exit $rc)"
if grep -q "is not allowed" <<<"$out"; then
    fail "depguard reported outside the deterministic core"
fi

run_vet ./edge/...
[ "$rc" -eq 0 ] || fail "detcheck fired outside the deterministic core (exit $rc)"
if grep -q "range over map is unordered" <<<"$out"; then
    fail "the map-range rule reported outside the deterministic core"
fi

# --- the cross-language conformance checker, on a deliberately broken annex ---

annex="$root/testdata/vectors.json"
scratch="$work/vectors.json"

mutate() {
    python3 - "$annex" "$scratch" "$1" <<'EOF'
import hashlib
import json
import sys

src, dst, case = sys.argv[1], sys.argv[2], sys.argv[3]
annex = json.load(open(src))
for v in annex["vectors"]:
    # One byte of Payload: der alone changes, so the fields object catches it.
    if case == "der" and v["name"] == "signed/v1/commit":
        der = bytearray.fromhex(v["der"])
        der[-1] ^= 0xff
        v["der"] = der.hex()
    # One bit of Value, with fields and sha256 kept consistent, so only the
    # signature is wrong and nothing else can report the failure first.
    if case == "value" and v["name"] == "blob/v1/signed-by-test-key":
        der = bytearray.fromhex(v["der"])
        der[-64] ^= 0x01
        v["der"] = der.hex()
        v["fields"]["Value"] = bytes(der[-64:]).hex()
        v["sha256"] = hashlib.sha256(der).hexdigest()
json.dump(annex, open(dst, "w"))
EOF
}

run_verifier() {
    rc=0
    mutate "$1"
    out="$(python3 "$root/ci/verify_vectors.py" "$scratch" 2>&1)" || rc=$?
}

echo "==> the cross-verifier on a mutated der"
run_verifier der
[ "$rc" -eq 1 ] || fail "expected verify_vectors.py exit 1, got $rc"
grep -q "field Payload: der decodes to" <<<"$out" ||
    fail "the cross-verifier did NOT report the field the mutated der disagrees on"

echo "==> the cross-verifier on a flipped signature bit"
run_verifier value
[ "$rc" -eq 1 ] || fail "expected verify_vectors.py exit 1, got $rc"
grep -q "Ed25519 signature does not verify over the reconstructed SignedV1 envelope" <<<"$out" ||
    fail "the cross-verifier did NOT reject a signature with one flipped bit"

echo "both gates fired as expected; scoping confirmed"
