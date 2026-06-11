package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ReportData struct {
	Added      []interface{} `json:"added"`
	Deleted    []interface{} `json:"deleted"`
	Modified   []interface{} `json:"modified"`
	Malware    []struct {
		Path    string   `json:"path"`
		Matches []string `json:"matches"`
	} `json:"malware"`
	DbUsers    []struct {
		Username   string `json:"username"`
		Suspicious bool   `json:"suspicious"`
	} `json:"dbUsers"`
	DbPayloads []struct {
		Table   string `json:"table"`
		Matched string `json:"matched"`
		Content string `json:"content"`
	} `json:"dbPayloads"`
}

type RiskResult struct {
	Score int    `json:"score"`
	Level string `json:"level"`
}

func CalculateRisk(jsonData []byte) RiskResult {
	var data ReportData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return RiskResult{Score: 0, Level: "UNKNOWN"}
	}

	score := 0
	if len(data.DbPayloads) > 0 {
		score = 100
	} else if len(data.Malware) > 0 {
		// Check for YARA/Webshells vs simple anomalies
		score = 90
		for _, m := range data.Malware {
			for _, match := range m.Matches {
				if match == "eval" || match == "base64_decode" || match == "system" {
					score = 95
				}
			}
		}
	} else {
		for _, u := range data.DbUsers {
			if u.Suspicious {
				score = 80
				break
			}
		}
		if score == 0 && len(data.Modified) > 0 {
			score = 30
		}
	}

	level := "LOW"
	if score >= 90 {
		level = "CRITICAL"
	} else if score >= 70 {
		level = "HIGH"
	} else if score >= 40 {
		level = "MEDIUM"
	} else if score == 0 && (len(data.Added) > 0 || len(data.Deleted) > 0) {
		level = "INFO"
	}

	return RiskResult{Score: score, Level: level}
}

func GenerateHTML(jsonData []byte, risk RiskResult) []byte {
	var data ReportData
	json.Unmarshal(jsonData, &data)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SFS Forensic Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8fafc; color: #334155; margin: 0; padding: 2rem; }
        .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 3rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        h1 { color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 1rem; }
        .risk-banner { padding: 1.5rem; border-radius: 6px; margin: 2rem 0; color: #fff; font-size: 1.5rem; font-weight: bold; text-align: center; }
        .risk-CRITICAL { background-color: #ef4444; }
        .risk-HIGH { background-color: #f97316; }
        .risk-MEDIUM { background-color: #eab308; color: #fff; }
        .risk-LOW { background-color: #3b82f6; }
        .risk-INFO { background-color: #10b981; }
        .stats { display: flex; gap: 1rem; margin-bottom: 2rem; }
        .stat-box { flex: 1; padding: 1.5rem; background: #f1f5f9; border-radius: 6px; text-align: center; }
        .stat-box h3 { margin: 0 0 0.5rem 0; color: #64748b; font-size: 0.875rem; text-transform: uppercase; }
        .stat-box p { margin: 0; font-size: 2rem; font-weight: bold; color: #0f172a; }
        table { width: 100%%; border-collapse: collapse; margin-top: 1rem; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; color: #475569; font-weight: 600; }
        .badge { padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; color: white; }
        .badge.critical { background: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Forensic Scanner (SFS) Report</h1>
        <p><strong>Generated on:</strong> %s</p>
        
        <div class="risk-banner risk-%s">
            OVERALL RISK: %s (Score: %d/100)
        </div>

        <div class="stats">
            <div class="stat-box"><h3>Malware / IOCs</h3><p>%d</p></div>
            <div class="stat-box"><h3>DB Payloads</h3><p>%d</p></div>
            <div class="stat-box"><h3>Suspicious DB Users</h3><p>%d</p></div>
            <div class="stat-box"><h3>Modified Files</h3><p>%d</p></div>
        </div>

        <h2>Critical Database Payloads</h2>`,
		time.Now().Format(time.RFC1123), risk.Level, risk.Level, risk.Score,
		len(data.Malware), len(data.DbPayloads), len(data.DbUsers), len(data.Modified))

	if len(data.DbPayloads) == 0 {
		html += "<p>No malicious database payloads found.</p>"
	} else {
		html += "<table><thead><tr><th>Table</th><th>Matched Rules</th></tr></thead><tbody>"
		for _, p := range data.DbPayloads {
			html += fmt.Sprintf("<tr><td><b>%s</b></td><td style='color:#ef4444;'>%s</td></tr>", p.Table, p.Matched)
		}
		html += "</tbody></table>"
	}

	html += "<h2>Malware & IOC Findings</h2>"
	if len(data.Malware) == 0 {
		html += "<p>No malware or IOCs found.</p>"
	} else {
		html += "<table><thead><tr><th>File Path</th><th>Matched Patterns</th></tr></thead><tbody>"
		for _, m := range data.Malware {
			matchesStr := ""
			for _, match := range m.Matches {
				matchesStr += match + "<br>"
			}
			html += fmt.Sprintf("<tr><td style='word-break:break-all;'>%s</td><td style='color:#ef4444; font-size:0.85rem;'>%s</td></tr>", m.Path, matchesStr)
		}
		html += "</tbody></table>"
	}

	html += `
    </div>
</body>
</html>`

	return []byte(html)
}

func SaveReport(projectId string, jsonData []byte) (string, string, error) {
	reportDir := filepath.Join("reports", projectId)
	os.MkdirAll(reportDir, os.ModePerm)

	timestamp := time.Now().Format("20060102_150405")
	jsonPath := filepath.Join(reportDir, fmt.Sprintf("report_%s.json", timestamp))
	htmlPath := filepath.Join(reportDir, fmt.Sprintf("report_%s.html", timestamp))

	risk := CalculateRisk(jsonData)
	htmlData := GenerateHTML(jsonData, risk)

	err := os.WriteFile(jsonPath, jsonData, 0644)
	if err != nil {
		return "", "", err
	}

	err = os.WriteFile(htmlPath, htmlData, 0644)
	if err != nil {
		return "", "", err
	}

	return jsonPath, htmlPath, nil
}
