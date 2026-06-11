package database

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"sfs/internal/malware"
)

type DBUser struct {
	Username   string `json:"username"`
	Email      string `json:"email"`
	Suspicious bool   `json:"suspicious"`
}

type DBPayload struct {
	Table   string `json:"table"`
	Matched string `json:"matched"`
	Content string `json:"content"`
}

// ParseSQLDump reads a .sql file in a streaming fashion (O(1) memory)
// to extract both user records and malicious payloads across all tables.
func ParseSQLDump(filePath string, targetType string, ioc *malware.IOCScanner, yara *malware.YaraScanner) ([]DBUser, []DBPayload, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var users []DBUser
	var payloads []DBPayload

	// Track current table context
	currentTable := "Unknown"
	tableRegex := regexp.MustCompile(`(?i)(?:CREATE TABLE|INSERT INTO)\s*(?:IF NOT EXISTS\s*)?[^` + "`" + `"' ]*[` + "`" + `"]?([a-zA-Z0-9_]+)[` + "`" + `"]?`)

	// Extract values inside parentheses (...)
	valuesRegex := regexp.MustCompile(`\((.*?)\)`)

	// Heuristics for suspicious emails/usernames
	suspiciousRegex := regexp.MustCompile(`(?i)(hacker|tempmail|10minutemail|guerrillamail|malware|admin_siluman|pwned|exploit|backdoor|shell)`)
	
	// Payload detection heuristics
	payloadHeuristics := regexp.MustCompile(`(?i)(<\?php|eval\(|system\(|passthru\(|<script|javascript:|vbscript:|SELECT .* INTO OUTFILE)`)

	scanner := bufio.NewScanner(file)
	
	// Support large lines in mysqldump (up to 20MB per line)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 20*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		
		// Update table context
		if tMatch := tableRegex.FindStringSubmatch(line); len(tMatch) > 1 {
			currentTable = tMatch[1]
		}
		
		// 1. Payload Analysis (Any Table)
		// We scan the entire line for malware signatures, regardless of whether it's an INSERT or not
		var matchedStr string
		if payloadHeuristics.MatchString(line) {
			matchedStr = "Basic Heuristic: " + payloadHeuristics.FindString(line)
		} else if ioc != nil {
			iocRes := ioc.ScanMem([]byte(line))
			if len(iocRes) > 0 {
				matchedStr = iocRes[0]
			}
		}
		
		if matchedStr == "" && yara != nil {
			yaraRes := yara.ScanMem([]byte(line))
			if len(yaraRes) > 0 {
				matchedStr = "YARA Match: " + yaraRes[0]
			}
		}

		if matchedStr != "" {
			displayContent := line
			if len(displayContent) > 150 {
				displayContent = displayContent[:150] + "..."
			}
			payloads = append(payloads, DBPayload{
				Table:   currentTable,
				Matched: matchedStr,
				Content: displayContent,
			})
		}

		// 2. User Analysis
		isUserTable := false
		if targetType == "wordpress" && strings.Contains(strings.ToLower(currentTable), "wp_users") {
			isUserTable = true
		} else if strings.Contains(strings.ToLower(currentTable), "users") {
			isUserTable = true
		}

		// Check if it looks like an INSERT line (either contains INSERT INTO or starts with (, )
		isInsertData := strings.Contains(strings.ToUpper(line), "INSERT INTO") || strings.HasPrefix(strings.TrimSpace(line), "(") || strings.HasPrefix(strings.TrimSpace(line), ",(")

		if isUserTable && isInsertData {
			records := valuesRegex.FindAllStringSubmatch(line, -1)
			for _, rec := range records {
				if len(rec) > 1 {
					row := rec[1]
					
					strRegex := regexp.MustCompile(`'(.*?)'`)
					strs := strRegex.FindAllStringSubmatch(row, -1)
					
					var email, username string
					for _, s := range strs {
						if len(s) > 1 {
							val := s[1]
							if strings.Contains(val, "@") && strings.Contains(val, ".") {
								email = val
							} else if username == "" && len(val) >= 3 && !strings.ContainsAny(val, " {}[]()/*+=") {
								username = val
							}
						}
					}
					
					if email != "" || username != "" {
						suspicious := suspiciousRegex.MatchString(email) || suspiciousRegex.MatchString(username)
						users = append(users, DBUser{
							Username:   username,
							Email:      email,
							Suspicious: suspicious,
						})
					}
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return users, payloads, err
	}

	return users, payloads, nil
}
