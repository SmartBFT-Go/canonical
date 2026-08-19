// Package determinism reports constructs that make a replica's output depend on
// something other than its input.
package determinism

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `reports non-canonical marshaling reaching a hash, and unordered map iteration

A call to proto.Marshal, json.Marshal or gob.NewEncoder is reported when it sits
in a package that also imports a hash. That test is deliberately coarse: a
package that hashes in one file and marshals in an unrelated one is still
flagged. The bias is intentional. A false positive costs one
//determinism:allow comment carrying a written reason; a false negative costs a
cluster-wide digest divergence that no test will show you. A bare directive with
no reason suppresses nothing, so the justification cannot be skipped.

Calls are resolved through the type checker, not matched by name, so an aliased
import (pb "google.golang.org/protobuf/proto") and a dot-import are both caught.

Ranging over a map with a key variable is reported only in packages whose import
path matches -detpath, because the rule is a deterministic-core rule and firing
it repo-wide would bury real findings under pre-existing ones. Generic map
ranges need types.CoreType and are not covered today.`

const detpathDefault = `(^|/)det(/|$)`

var Analyzer = &analysis.Analyzer{
	Name:     "determinism",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

var detpath string

func init() {
	Analyzer.Flags.StringVar(&detpath, "detpath", detpathDefault,
		"regexp matched against the package import path; the map-range rule fires only where it matches")
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
	allow := allowed(pass)

	if packageHashes(pass) {
		checkMarshal(pass, insp, allow)
	}

	core, err := regexp.Compile(detpath)
	if err != nil {
		return nil, fmt.Errorf("bad -detpath regexp %q: %w", detpath, err)
	}
	if core.MatchString(pass.Pkg.Path()) {
		checkMapRange(pass, insp, allow)
	}
	return nil, nil
}

func checkMapRange(pass *analysis.Pass, insp *inspector.Inspector, allow map[string]bool) {
	insp.Preorder([]ast.Node{(*ast.RangeStmt)(nil)}, func(n ast.Node) {
		node := n.(*ast.RangeStmt)
		if node.Key == nil {
			return // observing no key observes no order
		}
		t := pass.TypesInfo.TypeOf(node.X)
		if t == nil {
			return
		}
		// Underlying(), not a direct assertion: type Index map[string][]byte is
		// a *types.Named and would otherwise escape the rule.
		if _, isMap := t.Underlying().(*types.Map); isMap {
			if suppressed(pass, allow, node.Pos()) {
				return
			}
			pass.Reportf(node.Pos(), "range over map is unordered; collect keys, slices.Sort, then iterate")
		}
	})
}

func checkMarshal(pass *analysis.Pass, insp *inspector.Inspector, allow map[string]bool) {
	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		fn := calleeFunc(pass, n.(*ast.CallExpr))
		if fn == nil || fn.Pkg() == nil {
			return
		}
		if !bannedCalls[fn.Pkg().Path()+"."+fn.Name()] {
			return
		}
		if suppressed(pass, allow, n.Pos()) {
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

const directive = "determinism:allow"

// allowed maps "file:line" for every line carrying a //determinism:allow directive
// with a reason, and the line after it, so the comment may sit above the finding.
func allowed(pass *analysis.Pass) map[string]bool {
	out := map[string]bool{}
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				txt := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				if !strings.HasPrefix(txt, directive) {
					continue
				}
				// A directive with no reason suppresses nothing.
				if strings.TrimSpace(strings.TrimPrefix(txt, directive)) == "" {
					continue
				}
				at := pass.Fset.Position(c.Pos())
				out[key(at.Filename, at.Line)] = true
				out[key(at.Filename, at.Line+1)] = true
			}
		}
	}
	return out
}

func suppressed(pass *analysis.Pass, allow map[string]bool, pos token.Pos) bool {
	at := pass.Fset.Position(pos)
	return allow[key(at.Filename, at.Line)]
}

func key(file string, line int) string { return fmt.Sprintf("%s:%d", file, line) }
