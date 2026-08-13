package determinism_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/SmartBFT-Go/canonical/lint/determinism"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), determinism.Analyzer, "a", "nohash")
}
