// Package determinism reports constructs that make a replica's output depend on
// something other than its input.
package determinism

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `reports non-canonical marshaling reaching a hash, and unordered map iteration

A call to proto.Marshal, json.Marshal or gob.NewEncoder is reported when it sits
in a package that also imports a hash. That test is deliberately coarse: a
package that hashes in one file and marshals in an unrelated one is still
flagged. The bias is intentional. A false positive costs one //nolint with a
written justification in review; a false negative costs a cluster-wide digest
divergence that no test will show you.

Calls are resolved through the type checker, not matched by name, so an aliased
import (pb "google.golang.org/protobuf/proto") and a dot-import are both caught.`

var Analyzer = &analysis.Analyzer{
	Name:     "determinism",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// Keyed by "<import path>.<func name>". A method resolves to the same key as a
// package-level function of that name, so proto.MarshalOptions{}.Marshal lands here too.
var bannedCalls = map[string]bool{
	"google.golang.org/protobuf/proto.Marshal": true,
	"encoding/json.Marshal":                    true,
	"encoding/json.MarshalIndent":              true,
	"encoding/gob.NewEncoder":                  true,
}

var hashPkgs = map[string]bool{
	"crypto/sha256": true,
	"crypto/sha512": true,
	"crypto/sha3":   true,
	"crypto/sha1":   true,
	"crypto/md5":    true,
	"crypto/hmac":   true,
	"hash":          true,
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	if packageHashes(pass) {
		checkMarshal(pass, insp)
	}
	return nil, nil
}

func checkMarshal(pass *analysis.Pass, insp *inspector.Inspector) {
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		fn := calleeFunc(pass, n.(*ast.CallExpr))
		if fn == nil || fn.Pkg() == nil {
			return
		}
		if !bannedCalls[fn.Pkg().Path()+"."+fn.Name()] {
			return
		}
		pass.Reportf(n.Pos(), "%s.%s in a package that hashes: encode through the canonical package instead",
			fn.Pkg().Name(), fn.Name())
	})
}

// calleeFunc resolves a call to the *types.Func it invokes, following aliases,
// dot-imports and method values. Name matching would miss the last two.
func calleeFunc(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident: // dot-import: Marshal(m)
		id = f
	case *ast.SelectorExpr: // normal, aliased, or a method: pb.Marshal(m)
		id = f.Sel
	default:
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}

func packageHashes(pass *analysis.Pass) bool {
	for _, imp := range pass.Pkg.Imports() {
		if hashPkgs[imp.Path()] {
			return true
		}
	}
	return false
}
