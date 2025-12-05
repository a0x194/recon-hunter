package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/a0x194/recon-hunter/internal/types"
)

// Report holds the scan results and metadata
type Report struct {
	Title       string               `json:"title"`
	Target      string               `json:"target"`
	ScanDate    time.Time            `json:"scan_date"`
	Duration    string               `json:"duration"`
	Summary     Summary              `json:"summary"`
	Results     []types.VulnResult   `json:"results"`
	ReconData   *ReconData           `json:"recon_data,omitempty"`
}

// Summary holds the scan summary
type Summary struct {
	TotalVulns   int            `json:"total_vulnerabilities"`
	Critical     int            `json:"critical"`
	High         int            `json:"high"`
	Medium       int            `json:"medium"`
	Low          int            `json:"low"`
	Info         int            `json:"info"`
	ByType       map[string]int `json:"by_type"`
}

// ReconData holds reconnaissance results
type ReconData struct {
	Subdomains   []string `json:"subdomains,omitempty"`
	URLs         []string `json:"urls,omitempty"`
	OpenPorts    []string `json:"open_ports,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	JSFiles      []string `json:"js_files,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
}

// Generator handles report generation
type Generator struct {
	report *Report
}

// NewGenerator creates a new report generator
func NewGenerator(target string, results []types.VulnResult) *Generator {
	summary := generateSummary(results)

	return &Generator{
		report: &Report{
			Title:    fmt.Sprintf("ReconHunter Security Report - %s", target),
			Target:   target,
			ScanDate: time.Now(),
			Summary:  summary,
			Results:  results,
		},
	}
}

// SetDuration sets the scan duration
func (g *Generator) SetDuration(duration time.Duration) {
	g.report.Duration = duration.String()
}

// SetReconData sets the reconnaissance data
func (g *Generator) SetReconData(data *ReconData) {
	g.report.ReconData = data
}

func generateSummary(results []types.VulnResult) Summary {
	summary := Summary{
		TotalVulns: len(results),
		ByType:     make(map[string]int),
	}

	for _, r := range results {
		switch strings.ToLower(r.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
		summary.ByType[r.Type]++
	}

	return summary
}

// ToJSON exports the report as JSON
func (g *Generator) ToJSON(filepath string) error {
	data, err := json.MarshalIndent(g.report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}

// ToCSV exports the report as CSV
func (g *Generator) ToCSV(filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	header := []string{"Severity", "Type", "URL", "Parameter", "Payload", "Evidence", "Description", "Remediation"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Sort by severity
	sortedResults := sortBySeverity(g.report.Results)

	// Data rows
	for _, r := range sortedResults {
		row := []string{
			r.Severity,
			r.Type,
			r.URL,
			r.Parameter,
			r.Payload,
			r.Evidence,
			r.Description,
			r.Remediation,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ToMarkdown exports the report as Markdown
func (g *Generator) ToMarkdown(filepath string) error {
	var sb strings.Builder

	// Header
	sb.WriteString("# ReconHunter Security Report\n\n")
	sb.WriteString(fmt.Sprintf("```\n"))
	sb.WriteString(fmt.Sprintf("  _____                     _   _             _            \n"))
	sb.WriteString(fmt.Sprintf(" |  __ \\                   | | | |           | |           \n"))
	sb.WriteString(fmt.Sprintf(" | |__) |___  ___ ___  _ __| |_| |_   _ _ __ | |_ ___ _ __ \n"))
	sb.WriteString(fmt.Sprintf(" |  _  // _ \\/ __/ _ \\| '_ \\  _  | | | | '_ \\| __/ _ \\ '__|\n"))
	sb.WriteString(fmt.Sprintf(" | | \\ \\  __/ (_| (_) | | | | | | | |_| | | | | ||  __/ |   \n"))
	sb.WriteString(fmt.Sprintf(" |_|  \\_\\___|\\___\\___/|_| |_\\_| |_/\\__,_|_| |_|\\__\\___|_|   \n"))
	sb.WriteString(fmt.Sprintf("                                                            \n"))
	sb.WriteString(fmt.Sprintf(" >_ Automated Security Scanner                              \n"))
	sb.WriteString(fmt.Sprintf("```\n\n"))

	sb.WriteString(fmt.Sprintf("**Target:** `%s`\n\n", g.report.Target))
	sb.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", g.report.ScanDate.Format("2006-01-02 15:04:05")))
	if g.report.Duration != "" {
		sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", g.report.Duration))
	}
	sb.WriteString("---\n\n")

	// Summary
	sb.WriteString("## 📊 Executive Summary\n\n")
	sb.WriteString("```\n")
	sb.WriteString(fmt.Sprintf("┌─────────────────────────────────────┐\n"))
	sb.WriteString(fmt.Sprintf("│         VULNERABILITY SUMMARY       │\n"))
	sb.WriteString(fmt.Sprintf("├─────────────────────────────────────┤\n"))
	sb.WriteString(fmt.Sprintf("│  🔴 Critical: %-20d │\n", g.report.Summary.Critical))
	sb.WriteString(fmt.Sprintf("│  🟠 High:     %-20d │\n", g.report.Summary.High))
	sb.WriteString(fmt.Sprintf("│  🟡 Medium:   %-20d │\n", g.report.Summary.Medium))
	sb.WriteString(fmt.Sprintf("│  🟢 Low:      %-20d │\n", g.report.Summary.Low))
	sb.WriteString(fmt.Sprintf("│  🔵 Info:     %-20d │\n", g.report.Summary.Info))
	sb.WriteString(fmt.Sprintf("├─────────────────────────────────────┤\n"))
	sb.WriteString(fmt.Sprintf("│  📊 Total:    %-20d │\n", g.report.Summary.TotalVulns))
	sb.WriteString(fmt.Sprintf("└─────────────────────────────────────┘\n"))
	sb.WriteString("```\n\n")

	// Vulnerability types breakdown
	if len(g.report.Summary.ByType) > 0 {
		sb.WriteString("### Vulnerabilities by Type\n\n")
		sb.WriteString("| Type | Count |\n")
		sb.WriteString("|------|-------|\n")
		for vulnType, count := range g.report.Summary.ByType {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", vulnType, count))
		}
		sb.WriteString("\n")
	}

	// Recon data
	if g.report.ReconData != nil {
		sb.WriteString("---\n\n")
		sb.WriteString("## 🔍 Reconnaissance Results\n\n")

		if len(g.report.ReconData.Subdomains) > 0 {
			sb.WriteString(fmt.Sprintf("### Subdomains (%d found)\n\n", len(g.report.ReconData.Subdomains)))
			sb.WriteString("```\n")
			for _, s := range g.report.ReconData.Subdomains[:min(20, len(g.report.ReconData.Subdomains))] {
				sb.WriteString(s + "\n")
			}
			if len(g.report.ReconData.Subdomains) > 20 {
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(g.report.ReconData.Subdomains)-20))
			}
			sb.WriteString("```\n\n")
		}

		if len(g.report.ReconData.Technologies) > 0 {
			sb.WriteString("### Technologies Detected\n\n")
			for _, t := range g.report.ReconData.Technologies {
				sb.WriteString(fmt.Sprintf("- %s\n", t))
			}
			sb.WriteString("\n")
		}

		if len(g.report.ReconData.Secrets) > 0 {
			sb.WriteString("### ⚠️ Secrets Found\n\n")
			sb.WriteString("```\n")
			for _, s := range g.report.ReconData.Secrets {
				sb.WriteString(s + "\n")
			}
			sb.WriteString("```\n\n")
		}
	}

	// Detailed findings
	sb.WriteString("---\n\n")
	sb.WriteString("## 🔥 Detailed Findings\n\n")

	sortedResults := sortBySeverity(g.report.Results)

	for i, r := range sortedResults {
		severityEmoji := getSeverityEmoji(r.Severity)
		sb.WriteString(fmt.Sprintf("### %s %d. %s\n\n", severityEmoji, i+1, r.Type))
		sb.WriteString(fmt.Sprintf("**Severity:** `%s`\n\n", strings.ToUpper(r.Severity)))
		sb.WriteString(fmt.Sprintf("**URL:** `%s`\n\n", r.URL))

		if r.Parameter != "" {
			sb.WriteString(fmt.Sprintf("**Parameter:** `%s`\n\n", r.Parameter))
		}
		if r.Payload != "" {
			sb.WriteString(fmt.Sprintf("**Payload:**\n```\n%s\n```\n\n", r.Payload))
		}
		if r.Evidence != "" {
			sb.WriteString(fmt.Sprintf("**Evidence:**\n```\n%s\n```\n\n", r.Evidence))
		}
		if r.Description != "" {
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", r.Description))
		}
		if r.Remediation != "" {
			sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", r.Remediation))
		}
		if len(r.References) > 0 {
			sb.WriteString("**References:**\n")
			for _, ref := range r.References {
				sb.WriteString(fmt.Sprintf("- %s\n", ref))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("---\n\n")
	}

	// Footer
	sb.WriteString("\n## 📝 Notes\n\n")
	sb.WriteString("- This report was automatically generated by ReconHunter\n")
	sb.WriteString("- All findings should be manually verified before remediation\n")
	sb.WriteString("- False positives may occur; always confirm with manual testing\n\n")
	sb.WriteString("---\n\n")
	sb.WriteString("```\n")
	sb.WriteString(">_ Generated by ReconHunter\n")
	sb.WriteString(">_ github.com/a0x194/recon-hunter\n")
	sb.WriteString(">_ Hack Harder.\n")
	sb.WriteString("```\n")

	return os.WriteFile(filepath, []byte(sb.String()), 0644)
}

// ToHTML exports the report as HTML
func (g *Generator) ToHTML(filepath string) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconHunter Security Report</title>
    <style>
        :root {
            --bg-primary: #0a0a0a;
            --bg-secondary: #111111;
            --bg-tertiary: #1a1a1a;
            --text-primary: #ffffff;
            --text-secondary: #888888;
            --green: #00ff88;
            --green-dim: rgba(0, 255, 136, 0.1);
            --red: #ff4444;
            --orange: #ff8c00;
            --yellow: #ffd700;
            --blue: #00aaff;
            --border: #333333;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            padding: 40px 20px;
            border: 1px solid var(--green);
            border-radius: 8px;
            margin-bottom: 30px;
            background: var(--bg-secondary);
        }

        .header h1 {
            color: var(--green);
            font-size: 2rem;
            margin-bottom: 10px;
        }

        .header .meta {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .ascii-art {
            color: var(--green);
            font-size: 0.7rem;
            margin-bottom: 20px;
            white-space: pre;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }

        .summary-card.critical { border-color: var(--red); }
        .summary-card.high { border-color: var(--orange); }
        .summary-card.medium { border-color: var(--yellow); }
        .summary-card.low { border-color: var(--green); }
        .summary-card.info { border-color: var(--blue); }

        .summary-card .count {
            font-size: 2.5rem;
            font-weight: bold;
        }

        .summary-card.critical .count { color: var(--red); }
        .summary-card.high .count { color: var(--orange); }
        .summary-card.medium .count { color: var(--yellow); }
        .summary-card.low .count { color: var(--green); }
        .summary-card.info .count { color: var(--blue); }

        .summary-card .label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .section-header {
            background: var(--bg-tertiary);
            padding: 15px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .section-header h2 {
            color: var(--green);
            font-size: 1.1rem;
        }

        .finding {
            padding: 20px;
            border-bottom: 1px solid var(--border);
        }

        .finding:last-child {
            border-bottom: none;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .finding-title {
            font-size: 1rem;
            color: var(--text-primary);
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-badge.critical { background: var(--red); color: #000; }
        .severity-badge.high { background: var(--orange); color: #000; }
        .severity-badge.medium { background: var(--yellow); color: #000; }
        .severity-badge.low { background: var(--green); color: #000; }
        .severity-badge.info { background: var(--blue); color: #000; }

        .finding-details {
            display: grid;
            gap: 10px;
        }

        .detail-row {
            display: grid;
            grid-template-columns: 120px 1fr;
            gap: 10px;
        }

        .detail-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .detail-value {
            color: var(--text-primary);
            font-size: 0.85rem;
            word-break: break-all;
        }

        .code-block {
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            overflow-x: auto;
            white-space: pre-wrap;
        }

        .references {
            margin-top: 10px;
        }

        .references a {
            color: var(--green);
            text-decoration: none;
            font-size: 0.8rem;
        }

        .references a:hover {
            text-decoration: underline;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .footer .brand {
            color: var(--green);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <pre class="ascii-art">
  _____                     _   _             _
 |  __ \                   | | | |           | |
 | |__) |___  ___ ___  _ __| |_| |_   _ _ __ | |_ ___ _ __
 |  _  // _ \/ __/ _ \| '_ \  _  | | | | '_ \| __/ _ \ '__|
 | | \ \  __/ (_| (_) | | | | | | | |_| | | | | ||  __/ |
 |_|  \_\___|___|___/|_| |_\_| |_/\__,_|_| |_|\__\___|_|
            </pre>
            <h1>Security Scan Report</h1>
            <div class="meta">
                <div>Target: <strong>{{.Target}}</strong></div>
                <div>Scan Date: {{.ScanDate.Format "2006-01-02 15:04:05"}}</div>
                {{if .Duration}}<div>Duration: {{.Duration}}</div>{{end}}
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{{.Summary.Critical}}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{{.Summary.High}}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{{.Summary.Medium}}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{{.Summary.Low}}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{{.Summary.Info}}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>>_ Vulnerability Findings ({{.Summary.TotalVulns}})</h2>
            </div>
            {{range .Results}}
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">{{.Type}}</span>
                    <span class="severity-badge {{.Severity | lower}}">{{.Severity}}</span>
                </div>
                <div class="finding-details">
                    <div class="detail-row">
                        <span class="detail-label">URL:</span>
                        <span class="detail-value"><code>{{.URL}}</code></span>
                    </div>
                    {{if .Parameter}}
                    <div class="detail-row">
                        <span class="detail-label">Parameter:</span>
                        <span class="detail-value"><code>{{.Parameter}}</code></span>
                    </div>
                    {{end}}
                    {{if .Payload}}
                    <div class="detail-row">
                        <span class="detail-label">Payload:</span>
                        <div class="code-block">{{.Payload}}</div>
                    </div>
                    {{end}}
                    {{if .Evidence}}
                    <div class="detail-row">
                        <span class="detail-label">Evidence:</span>
                        <div class="code-block">{{.Evidence}}</div>
                    </div>
                    {{end}}
                    {{if .Description}}
                    <div class="detail-row">
                        <span class="detail-label">Description:</span>
                        <span class="detail-value">{{.Description}}</span>
                    </div>
                    {{end}}
                    {{if .Remediation}}
                    <div class="detail-row">
                        <span class="detail-label">Remediation:</span>
                        <span class="detail-value">{{.Remediation}}</span>
                    </div>
                    {{end}}
                    {{if .References}}
                    <div class="references">
                        <span class="detail-label">References:</span>
                        {{range .References}}
                        <div><a href="{{.}}" target="_blank">{{.}}</a></div>
                        {{end}}
                    </div>
                    {{end}}
                </div>
            </div>
            {{end}}
        </div>

        <div class="footer">
            <div>Generated by <span class="brand">ReconHunter</span></div>
            <div>github.com/a0x194/recon-hunter</div>
            <div class="brand">>_ Hack Harder.</div>
        </div>
    </div>
</body>
</html>`

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	return t.Execute(file, g.report)
}

func sortBySeverity(results []types.VulnResult) []types.VulnResult {
	sorted := make([]types.VulnResult, len(results))
	copy(sorted, results)

	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.Slice(sorted, func(i, j int) bool {
		iOrder, ok := severityOrder[strings.ToLower(sorted[i].Severity)]
		if !ok {
			iOrder = 5
		}
		jOrder, ok := severityOrder[strings.ToLower(sorted[j].Severity)]
		if !ok {
			jOrder = 5
		}
		return iOrder < jOrder
	})

	return sorted
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "🔵"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
