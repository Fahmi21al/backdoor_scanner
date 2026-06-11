package diff

import (
	"os"
	"path/filepath"

	"github.com/pmezard/go-difflib/difflib"
)

type DiffResult struct {
	UnifiedDiff string `json:"unifiedDiff"`
	Error       string `json:"error,omitempty"`
}

func GenerateDiff(baselinePath string, targetPath string, relPath string) DiffResult {
	baseFile := filepath.Join(baselinePath, relPath)
	targetFile := filepath.Join(targetPath, relPath)

	baseContent, err := os.ReadFile(baseFile)
	if err != nil {
		return DiffResult{Error: "Cannot read baseline file: " + err.Error()}
	}

	targetContent, err := os.ReadFile(targetFile)
	if err != nil {
		return DiffResult{Error: "Cannot read target file: " + err.Error()}
	}

	// Limit to 1MB to avoid memory issues with huge binaries
	if len(baseContent) > 1024*1024 || len(targetContent) > 1024*1024 {
		return DiffResult{Error: "File too large to generate diff (>1MB)"}
	}

	diff := difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(baseContent)),
		B:        difflib.SplitLines(string(targetContent)),
		FromFile: "Baseline",
		ToFile:   "Target",
		Context:  3,
	}

	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		return DiffResult{Error: "Failed to generate diff: " + err.Error()}
	}

	return DiffResult{UnifiedDiff: text}
}
