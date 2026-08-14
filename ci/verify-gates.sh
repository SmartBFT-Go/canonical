#!/usr/bin/env bash
# The complete gate sequence. CI runs this same script, so there is no second
# definition of "the gates" that can drift out of sync with the first.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOWORK=off

step() { echo "==> $*"; }

step "go.work must not be tracked"
if git ls-files --error-unmatch go.work >/dev/null 2>&1; then
    echo "go.work is tracked; it is local-iteration-only" >&2
    exit 1
fi

step "no replace directives"
for mod in . lint; do
    # Parsed directives, not go.mod text: a replace is seen whatever the syntax.
    modjson="$(cd "$mod" && go mod edit -json)"
    if ! grep -q '"Replace":' <<<"$modjson"; then
        echo "go mod edit -json has no Replace key; this check is broken" >&2
        exit 1
    fi
    # Absent replaces print as null; any replace prints an array.
    if ! grep -q '"Replace": null' <<<"$modjson"; then
        echo "replace is not permitted in $mod; pin by version or commit" >&2
        sed -n '/"Replace": \[/,/^\t\],$/p' <<<"$modjson" >&2
        exit 1
    fi
done

step "tests"
go test -count 1 -race -shuffle=on ./...

# ./... at the root does not descend into lint/. Omitting this line silently
# disables every analyzer test.
step "analyzer tests"
(cd lint && go test -count 1 -race -shuffle=on ./...)

step "build detcheck"
(cd lint && go build -o ../bin/detcheck ./cmd/detcheck)

# -detpath='.', not the default: the whole module is deterministic core.
step "determinism analyzer"
go vet -vettool="$PWD/bin/detcheck" -detpath='.' ./...

step "lint config"
golangci-lint config verify

step "lint"
golangci-lint run ./...

# `golangci-lint fmt --diff` exits 0 even when it prints a diff, so the drift
# has to be caught by git.
step "format drift"
golangci-lint fmt ./...
git diff --exit-code

step "negative gate"
bash ci/negative-gate.sh

echo "all gates green"
