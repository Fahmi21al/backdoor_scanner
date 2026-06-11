package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"runtime"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"sfs/internal/baseline"
	"sfs/internal/database"
	"sfs/internal/hash"
	"sfs/internal/malware"
	"sfs/internal/project"
	"sfs/internal/report"
)

type MalwareFinding struct {
	Path    string   `json:"path"`
	Matches []string `json:"matches"`
}

type FullScanResult struct {
	*baseline.CompareResult
	Malware    []MalwareFinding     `json:"malware"`
	DbUsers    []database.DBUser    `json:"dbUsers"`
	DbPayloads []database.DBPayload `json:"dbPayloads"`
	Risk         report.RiskResult    `json:"risk"`
	JsonReport   string               `json:"jsonReport"`
	HtmlReport   string               `json:"htmlReport"`
	TotalAdded   int                  `json:"totalAdded"`
	TotalDeleted int                  `json:"totalDeleted"`
}

type Handler struct {
	projectRepo *project.Repository
}

func NewHandler(projectRepo *project.Repository) *Handler {
	return &Handler{projectRepo: projectRepo}
}

func (h *Handler) StreamScan(c *gin.Context) {
	projectId := c.Query("projectId")
	if projectId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "projectId query param is required"})
		return
	}

	p, err := h.projectRepo.GetByID(projectId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
		return
	}

	if p.TargetPath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Project must have a targetPath"})
		return
	}

	// Set headers for SSE
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	logChan := make(chan string, 100)

	go func() {
		defer close(logChan)
		yaraScanner, _ := malware.NewYaraScanner("rules")
		iocScanner := malware.NewIOCScanner()

		logChan <- "[SYS] Starting scan process..."
		
		p.TargetPath = strings.Trim(p.TargetPath, " \"'")
		p.BaselinePath = strings.Trim(p.BaselinePath, " \"'")
		p.DbDumpPath = strings.Trim(p.DbDumpPath, " \"'")

		var res *baseline.CompareResult
		var err error
		if p.BaselinePath != "" {
			res, err = baseline.Compare(p.BaselinePath, p.TargetPath, logChan)
			if err != nil {
				logChan <- "[ERROR] Failed to run baseline compare: " + err.Error()
				return
			}
		} else {
			logChan <- "[SYS] No baseline provided. Scanning all target files..."
			res = &baseline.CompareResult{
				Added:    make([]hash.FileHashInfo, 0),
				Deleted:  make([]hash.FileHashInfo, 0),
				Modified: make([]baseline.ModifiedFile, 0),
			}
			targetHashes, err := hash.GenerateHashes(p.TargetPath, logChan)
			if err != nil {
				logChan <- "[ERROR] Failed to hash target files: " + err.Error()
				return
			}
			for _, info := range targetHashes {
				res.Added = append(res.Added, info)
			}
		}
		
		fullRes := FullScanResult{
			CompareResult: res,
			Malware:       make([]MalwareFinding, 0),
			DbUsers:       make([]database.DBUser, 0),
			DbPayloads:    make([]database.DBPayload, 0),
		}

		logChan <- "[SYS] Starting Malware Scan (YARA & IOC) on modified and added files..."

		// Scan Added and Modified files concurrently
		var scanMutex sync.Mutex
		var scanWg sync.WaitGroup
		
		numWorkers := runtime.NumCPU()
		if numWorkers > 8 {
			numWorkers = 8
		}
		// Sisakan 1 thread agar laptop tidak freeze
		if numWorkers > 2 {
			numWorkers -= 1
		}
		
		type scanJob struct {
			index   int
			total   int
			path    string
			relPath string
			isAdded bool
		}
		
		scanJobs := make(chan scanJob, 100)
		
		for w := 0; w < numWorkers; w++ {
			scanWg.Add(1)
			go func() {
				defer scanWg.Done()
				for job := range scanJobs {
					if job.index%50 == 0 || job.index == job.total-1 {
						jobType := "Added"
						if !job.isAdded {
							jobType = "Modified"
						}
						select {
						case logChan <- fmt.Sprintf("[SCAN] Malware check on %s files: %d / %d", jobType, job.index+1, job.total):
						default:
						}
					}
					
					absPath := job.path
					yaraMatches, _ := yaraScanner.ScanFile(absPath)
					iocMatches, _ := iocScanner.ScanFile(absPath)
					
					// New Analysis: Magic Bytes Verification
					if spoofMatch := malware.VerifyMagicBytes(absPath); spoofMatch != "" {
						iocMatches = append(iocMatches, spoofMatch)
					}
					
					// New Analysis: Entropy Calculation for Source Code
					ext := strings.ToLower(filepath.Ext(absPath))
					if ext == ".php" || ext == ".js" || ext == ".py" || ext == ".go" {
						entropy, _ := malware.CalculateShannonEntropy(absPath)
						if entropy > 6.0 {
							iocMatches = append(iocMatches, fmt.Sprintf("High Entropy Detected (%.2f): Potential Obfuscated/Encrypted Loader", entropy))
						}
					}
					
					matches := append(yaraMatches, iocMatches...)
					if len(matches) > 0 {
						scanMutex.Lock()
						fullRes.Malware = append(fullRes.Malware, MalwareFinding{
							Path:    job.relPath,
							Matches: matches,
						})
						scanMutex.Unlock()
						
						select {
						case logChan <- "[ALERT] Malware detected in: " + job.relPath:
						default:
						}
					}
				}
			}()
		}
		
		// Produce Jobs for Added
		for i, f := range res.Added {
			scanJobs <- scanJob{
				index:   i,
				total:   len(res.Added),
				path:    filepath.Join(p.TargetPath, f.Path),
				relPath: f.Path,
				isAdded: true,
			}
		}
		
		// Produce Jobs for Modified
		for i, m := range res.Modified {
			scanJobs <- scanJob{
				index:   i,
				total:   len(res.Modified),
				path:    filepath.Join(p.TargetPath, m.File.Path),
				relPath: m.File.Path,
				isAdded: false,
			}
		}
		
		close(scanJobs)
		scanWg.Wait()

		if p.DbDumpPath != "" {
			logChan <- "[SYS] Starting Database Forensics (SQL Parsing + YARA/IOC)..."
			dbUsers, dbPayloads, err := database.ParseSQLDump(p.DbDumpPath, p.TargetType, iocScanner, yaraScanner)
			if err != nil {
				logChan <- "[ERROR] Failed to parse SQL dump: " + err.Error()
			} else {
				fullRes.DbUsers = dbUsers
				fullRes.DbPayloads = dbPayloads
				logChan <- fmt.Sprintf("[SYS] Extracted %d user records and %d payloads from DB.", len(dbUsers), len(dbPayloads))
				for _, u := range dbUsers {
					if u.Suspicious {
						logChan <- "[ALERT] Suspicious Database User detected: " + u.Username + " (" + u.Email + ")"
					}
				}
				for _, py := range dbPayloads {
					logChan <- "[ALERT] Malicious DB Payload in table: " + py.Table + " (" + py.Matched + ")"
				}
			}
		}

		logChan <- "[SYS] Scan complete, calculating risk score..."
		resJSON, _ := json.Marshal(fullRes)
		risk := report.CalculateRisk(resJSON)
		fullRes.Risk = risk

		// Prevent massive arrays from freezing browser / blowing up report
		fullRes.TotalAdded = len(fullRes.Added)
		fullRes.TotalDeleted = len(fullRes.Deleted)
		
		if len(fullRes.Added) > 1000 {
			fullRes.Added = fullRes.Added[:1000]
		}
		if len(fullRes.Deleted) > 1000 {
			fullRes.Deleted = fullRes.Deleted[:1000]
		}

		finalJSON, _ := json.Marshal(fullRes)
		
		logChan <- "[SYS] Generating and saving reports..."
		jsonPath, htmlPath, err := report.SaveReport(projectId, finalJSON)
		if err == nil {
			fullRes.JsonReport = jsonPath
			fullRes.HtmlReport = htmlPath
			finalJSON, _ = json.Marshal(fullRes) // Marshal one last time to include paths
			logChan <- fmt.Sprintf("[SYS] Reports saved to: %s", filepath.Dir(htmlPath))
		} else {
			logChan <- "[ERROR] Failed to save reports: " + err.Error()
		}

		logChan <- "RESULT:" + string(finalJSON)
	}()

	// Listen to connection close
	clientGone := c.Request.Context().Done()

	for {
		select {
		case <-clientGone:
			return
		case msg, ok := <-logChan:
			if !ok {
				return
			}
			c.SSEvent("message", msg)
			c.Writer.Flush()
		}
	}
}
