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

echo "both gates fired as expected; scoping confirmed"
