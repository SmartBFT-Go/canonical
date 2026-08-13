// Command detcheck runs the determinism analyzer, standalone or as a go vet -vettool.
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/SmartBFT-Go/canonical/lint/determinism"
)

func main() { singlechecker.Main(determinism.Analyzer) }
