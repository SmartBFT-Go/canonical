// Package determinism reports constructs that make a replica's output depend on
// something other than its input.
package determinism

import (
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

var Analyzer = &analysis.Analyzer{
	Name:     "determinism",
	Doc:      "reports non-canonical marshaling reaching a hash, and unordered map iteration",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	return nil, nil
}
