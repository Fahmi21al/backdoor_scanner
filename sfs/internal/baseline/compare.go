package baseline

import (
	"sfs/internal/diff"
	"sfs/internal/hash"
)

type CompareResult struct {
	Added    []hash.FileHashInfo `json:"added"`
	Deleted  []hash.FileHashInfo `json:"deleted"`
	Modified []ModifiedFile      `json:"modified"`
}

type ModifiedFile struct {
	File hash.FileHashInfo `json:"file"`
	Diff diff.DiffResult   `json:"diff"`
}

func Compare(baselineDir string, targetDir string, logChan chan string) (*CompareResult, error) {
	res := &CompareResult{
		Added:    make([]hash.FileHashInfo, 0),
		Deleted:  make([]hash.FileHashInfo, 0),
		Modified: make([]ModifiedFile, 0),
	}

	if logChan != nil { logChan <- "[SYS] Reading baseline hashes from " + baselineDir }
	baseHashes, err := hash.GenerateHashes(baselineDir, logChan)
	if err != nil {
		return nil, err
	}

	if logChan != nil { logChan <- "[SYS] Reading target hashes from " + targetDir }
	targetHashes, err := hash.GenerateHashes(targetDir, logChan)
	if err != nil {
		return nil, err
	}

	// Check for Modified and Deleted
	for relPath, baseInfo := range baseHashes {
		targetInfo, exists := targetHashes[relPath]
		if !exists {
			// File is in baseline but not in target -> DELETED
			res.Deleted = append(res.Deleted, baseInfo)
		} else {
			if baseInfo.Hash != targetInfo.Hash {
				if logChan != nil {
					select {
					case logChan <- "[DIFF] Generating unified diff for: " + relPath:
					default:
					}
				}
				// File exists in both but hash differs -> MODIFIED
				diffRes := diff.GenerateDiff(baselineDir, targetDir, relPath)
				res.Modified = append(res.Modified, ModifiedFile{
					File: targetInfo,
					Diff: diffRes,
				})
			}
		}
	}

	// Check for Added
	for relPath, targetInfo := range targetHashes {
		_, exists := baseHashes[relPath]
		if !exists {
			// File is in target but not in baseline -> ADDED
			res.Added = append(res.Added, targetInfo)
		}
	}

	return res, nil
}
