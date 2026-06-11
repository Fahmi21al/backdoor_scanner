package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type FileHashInfo struct {
	Path       string    `json:"path"`
	Hash       string    `json:"hash"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"mtime"`
}

type hashJob struct {
	path    string
	relPath string
	info    os.FileInfo
}

// GenerateHashes traverses the directory and computes SHA256 for all files concurrently.
// It returns a map of relative paths to their FileHashInfo.
func GenerateHashes(dirPath string, logChan chan string) (map[string]FileHashInfo, error) {
	result := make(map[string]FileHashInfo)
	var mutex sync.Mutex

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return result, err
	}

	numWorkers := runtime.NumCPU()
	if numWorkers > 8 {
		numWorkers = 8
	}
	// Sisakan 1 atau 2 thread agar laptop tidak freeze jika CPU terbebani 100%
	if numWorkers > 2 {
		numWorkers -= 1
	}

	jobs := make(chan hashJob, 100)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if logChan != nil {
					select {
					case logChan <- "Hashing file: " + job.relPath:
					default:
					}
				}

				hashStr, err := hashFile(job.path)
				if err != nil {
					continue
				}

				mutex.Lock()
				result[job.relPath] = FileHashInfo{
					Path:       job.relPath,
					Hash:       hashStr,
					Size:       job.info.Size(),
					ModifiedAt: job.info.ModTime(),
				}
				mutex.Unlock()
			}
		}()
	}

	// Produce jobs
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(dirPath, path)
			if err != nil {
				return err
			}
			relPath = strings.ReplaceAll(relPath, "\\", "/")
			
			jobs <- hashJob{
				path:    path,
				relPath: relPath,
				info:    info,
			}
		}
		return nil
	})

	close(jobs)
	wg.Wait()

	return result, err
}

func hashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
