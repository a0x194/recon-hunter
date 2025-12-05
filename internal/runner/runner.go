package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/modules/dirscan"
	"github.com/a0x194/recon-hunter/internal/modules/gitleaks"
	"github.com/a0x194/recon-hunter/internal/modules/httpx"
	"github.com/a0x194/recon-hunter/internal/modules/jshunter"
	"github.com/a0x194/recon-hunter/internal/modules/portscan"
	"github.com/a0x194/recon-hunter/internal/modules/subdomain"
	"github.com/a0x194/recon-hunter/internal/modules/wayback"
	"github.com/a0x194/recon-hunter/internal/scanner/cors"
	"github.com/a0x194/recon-hunter/internal/scanner/headers"
	"github.com/a0x194/recon-hunter/internal/scanner/lfi"
	"github.com/a0x194/recon-hunter/internal/scanner/redirect"
	"github.com/a0x194/recon-hunter/internal/scanner/sqli"
	"github.com/a0x194/recon-hunter/internal/scanner/ssrf"
	"github.com/a0x194/recon-hunter/internal/scanner/takeover"
	"github.com/a0x194/recon-hunter/internal/scanner/xss"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
	"github.com/fatih/color"
)

// Runner coordinates all scanning modules
type Runner struct {
	config  *config.Config
	results *Results
	mu      sync.Mutex
}

// Results holds all scan results
type Results struct {
	Target      string                 `json:"target"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Subdomains  []string               `json:"subdomains"`
	LiveHosts   []httpx.Result         `json:"live_hosts"`
	Ports       []portscan.Result      `json:"ports"`
	Directories []dirscan.Result       `json:"directories"`
	JSFiles     []jshunter.Result      `json:"js_files"`
	Wayback     []wayback.Result       `json:"wayback"`
	GitLeaks    []gitleaks.Result      `json:"git_leaks"`
	Vulns       []types.VulnResult     `json:"vulnerabilities"`
	Stats       types.Stats            `json:"stats"`
}

// New creates a new Runner
func New(cfg *config.Config) *Runner {
	return &Runner{
		config: cfg,
		results: &Results{
			Vulns: make([]types.VulnResult, 0),
		},
	}
}

// Run executes the scan
func (r *Runner) Run() error {
	targets, err := r.config.GetTargets()
	if err != nil {
		return fmt.Errorf("failed to get targets: %w", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	// Create output directory
	if err := os.MkdirAll(r.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, target := range targets {
		if err := r.scanTarget(target); err != nil {
			color.Red("[!] Error scanning %s: %v", target, err)
			continue
		}
	}

	return nil
}

func (r *Runner) scanTarget(target string) error {
	r.results.Target = target
	r.results.StartTime = time.Now()

	color.Cyan("\n[*] Starting scan for: %s", target)
	color.Cyan("[*] Scan mode: %s", r.config.ScanMode)
	color.Cyan("[*] Output directory: %s\n", r.config.OutputDir)

	// Create target-specific output directory
	targetDir := filepath.Join(r.config.OutputDir, utils.SanitizeFilename(target))
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	// Phase 1: Reconnaissance
	if r.config.ScanMode == "full" || r.config.ScanMode == "recon" {
		if err := r.runRecon(target, targetDir); err != nil {
			color.Yellow("[!] Recon phase had errors: %v", err)
		}
	}

	// Phase 2: Vulnerability Scanning
	if r.config.ScanMode == "full" || r.config.ScanMode == "vuln" {
		if err := r.runVulnScan(target, targetDir); err != nil {
			color.Yellow("[!] Vuln scan phase had errors: %v", err)
		}
	}

	r.results.EndTime = time.Now()

	// Generate summary
	r.printSummary()

	// Save results
	if err := r.saveResults(targetDir); err != nil {
		color.Yellow("[!] Failed to save results: %v", err)
	}

	// Send notifications
	if r.config.Notify != "" {
		r.sendNotifications()
	}

	return nil
}

func (r *Runner) runRecon(target string, outputDir string) error {
	color.Yellow("\n[=] Phase 1: Reconnaissance\n")

	// 1. Subdomain Enumeration
	if r.shouldRunModule("subdomain") {
		color.Cyan("[*] Running subdomain enumeration...")
		subdomainResults, err := subdomain.Run(target, r.config)
		if err != nil {
			color.Yellow("[!] Subdomain enumeration error: %v", err)
		} else {
			r.results.Subdomains = subdomainResults
			r.results.Stats.SubdomainsFound = len(subdomainResults)
			color.Green("[+] Found %d subdomains", len(subdomainResults))

			// Save subdomains to file
			utils.SaveLines(filepath.Join(outputDir, "subdomains.txt"), subdomainResults)
		}
	}

	// 2. HTTP Probing
	if r.shouldRunModule("httpx") {
		color.Cyan("[*] Running HTTP probing...")
		targets := r.results.Subdomains
		if len(targets) == 0 {
			targets = []string{target}
		}

		httpxResults, err := httpx.Run(targets, r.config)
		if err != nil {
			color.Yellow("[!] HTTP probing error: %v", err)
		} else {
			r.results.LiveHosts = httpxResults
			r.results.Stats.LiveHostsFound = len(httpxResults)
			color.Green("[+] Found %d live hosts", len(httpxResults))

			// Save live hosts
			var liveURLs []string
			for _, h := range httpxResults {
				liveURLs = append(liveURLs, h.URL)
			}
			utils.SaveLines(filepath.Join(outputDir, "live_hosts.txt"), liveURLs)
		}
	}

	// 3. Port Scanning
	if r.shouldRunModule("portscan") {
		color.Cyan("[*] Running port scan...")
		var hosts []string
		for _, h := range r.results.LiveHosts {
			hosts = append(hosts, h.Host)
		}
		if len(hosts) == 0 {
			hosts = []string{target}
		}

		portResults, err := portscan.Run(hosts, r.config)
		if err != nil {
			color.Yellow("[!] Port scan error: %v", err)
		} else {
			r.results.Ports = portResults
			r.results.Stats.OpenPortsFound = len(portResults)
			color.Green("[+] Found %d open ports", len(portResults))
		}
	}

	// 4. Directory Scanning
	if r.shouldRunModule("dirscan") {
		color.Cyan("[*] Running directory scan...")
		var urls []string
		for _, h := range r.results.LiveHosts {
			urls = append(urls, h.URL)
		}

		dirResults, err := dirscan.Run(urls, r.config)
		if err != nil {
			color.Yellow("[!] Directory scan error: %v", err)
		} else {
			r.results.Directories = dirResults
			r.results.Stats.DirectoriesFound = len(dirResults)
			color.Green("[+] Found %d directories/files", len(dirResults))
		}
	}

	// 5. JavaScript Analysis
	if r.shouldRunModule("jshunter") {
		color.Cyan("[*] Running JavaScript analysis...")
		var urls []string
		for _, h := range r.results.LiveHosts {
			urls = append(urls, h.URL)
		}

		jsResults, err := jshunter.Run(urls, r.config)
		if err != nil {
			color.Yellow("[!] JS analysis error: %v", err)
		} else {
			r.results.JSFiles = jsResults
			color.Green("[+] Analyzed %d JS files", len(jsResults))
		}
	}

	// 6. Wayback Mining
	if r.shouldRunModule("wayback") {
		color.Cyan("[*] Running Wayback mining...")
		waybackResults, err := wayback.Run(target, r.config)
		if err != nil {
			color.Yellow("[!] Wayback mining error: %v", err)
		} else {
			r.results.Wayback = waybackResults
			color.Green("[+] Found %d historical URLs", len(waybackResults))
		}
	}

	// 7. Git Leaks Detection
	if r.shouldRunModule("gitleaks") {
		color.Cyan("[*] Running Git leaks detection...")
		var urls []string
		for _, h := range r.results.LiveHosts {
			urls = append(urls, h.URL)
		}

		gitResults, err := gitleaks.Run(urls, r.config)
		if err != nil {
			color.Yellow("[!] Git leaks detection error: %v", err)
		} else {
			r.results.GitLeaks = gitResults
			color.Green("[+] Found %d Git exposures", len(gitResults))
		}
	}

	return nil
}

func (r *Runner) runVulnScan(target string, outputDir string) error {
	color.Yellow("\n[=] Phase 2: Vulnerability Scanning\n")

	// Collect all URLs to scan
	var urls []string
	for _, h := range r.results.LiveHosts {
		urls = append(urls, h.URL)
	}
	for _, d := range r.results.Directories {
		urls = append(urls, d.URL)
	}

	// Collect parameters from various sources
	var params []string
	for _, w := range r.results.Wayback {
		if w.HasParams {
			params = append(params, w.URL)
		}
	}

	// 1. CORS Misconfiguration
	if r.shouldRunModule("cors") {
		color.Cyan("[*] Scanning for CORS misconfigurations...")
		corsResults, err := cors.Scan(urls, r.config)
		if err != nil {
			color.Yellow("[!] CORS scan error: %v", err)
		} else {
			for _, result := range corsResults {
				r.addVuln(result)
			}
		}
	}

	// 2. Security Headers
	if r.shouldRunModule("headers") {
		color.Cyan("[*] Analyzing security headers...")
		headerResults, err := headers.Scan(urls, r.config)
		if err != nil {
			color.Yellow("[!] Headers scan error: %v", err)
		} else {
			for _, result := range headerResults {
				r.addVuln(result)
			}
		}
	}

	// 3. SQL Injection
	if r.shouldRunModule("sqli") {
		color.Cyan("[*] Scanning for SQL injection...")
		sqliResults, err := sqli.Scan(params, r.config)
		if err != nil {
			color.Yellow("[!] SQLi scan error: %v", err)
		} else {
			for _, result := range sqliResults {
				r.addVuln(result)
			}
		}
	}

	// 4. XSS
	if r.shouldRunModule("xss") {
		color.Cyan("[*] Scanning for XSS...")
		xssResults, err := xss.Scan(params, r.config)
		if err != nil {
			color.Yellow("[!] XSS scan error: %v", err)
		} else {
			for _, result := range xssResults {
				r.addVuln(result)
			}
		}
	}

	// 5. SSRF
	if r.shouldRunModule("ssrf") {
		color.Cyan("[*] Scanning for SSRF...")
		ssrfResults, err := ssrf.Scan(params, r.config)
		if err != nil {
			color.Yellow("[!] SSRF scan error: %v", err)
		} else {
			for _, result := range ssrfResults {
				r.addVuln(result)
			}
		}
	}

	// 6. LFI
	if r.shouldRunModule("lfi") {
		color.Cyan("[*] Scanning for LFI...")
		lfiResults, err := lfi.Scan(params, r.config)
		if err != nil {
			color.Yellow("[!] LFI scan error: %v", err)
		} else {
			for _, result := range lfiResults {
				r.addVuln(result)
			}
		}
	}

	// 7. Open Redirect
	if r.shouldRunModule("redirect") {
		color.Cyan("[*] Scanning for open redirects...")
		redirectResults, err := redirect.Scan(params, r.config)
		if err != nil {
			color.Yellow("[!] Redirect scan error: %v", err)
		} else {
			for _, result := range redirectResults {
				r.addVuln(result)
			}
		}
	}

	// 8. Subdomain Takeover
	if r.shouldRunModule("takeover") {
		color.Cyan("[*] Scanning for subdomain takeover...")
		takeoverResults, err := takeover.Scan(r.results.Subdomains, r.config)
		if err != nil {
			color.Yellow("[!] Takeover scan error: %v", err)
		} else {
			for _, result := range takeoverResults {
				r.addVuln(result)
			}
		}
	}

	return nil
}

func (r *Runner) shouldRunModule(name string) bool {
	// Check if module is explicitly excluded
	for _, m := range r.config.ExcludeMods {
		if m == name {
			return false
		}
	}

	// If specific modules are specified, only run those
	if len(r.config.Modules) > 0 {
		for _, m := range r.config.Modules {
			if m == name {
				return true
			}
		}
		return false
	}

	return true
}

func (r *Runner) addVuln(v types.VulnResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	v.Timestamp = time.Now()
	r.results.Vulns = append(r.results.Vulns, v)
	r.results.Stats.VulnsFound++

	switch v.Severity {
	case "critical":
		r.results.Stats.CriticalVulns++
		color.Red("[CRITICAL] %s - %s", v.Type, v.URL)
	case "high":
		r.results.Stats.HighVulns++
		color.Red("[HIGH] %s - %s", v.Type, v.URL)
	case "medium":
		r.results.Stats.MediumVulns++
		color.Yellow("[MEDIUM] %s - %s", v.Type, v.URL)
	case "low":
		r.results.Stats.LowVulns++
		color.Blue("[LOW] %s - %s", v.Type, v.URL)
	default:
		color.White("[INFO] %s - %s", v.Type, v.URL)
	}
}

func (r *Runner) printSummary() {
	duration := r.results.EndTime.Sub(r.results.StartTime)
	line := strings.Repeat("═", 60)

	color.Cyan("\n" + line)
	color.Cyan("                    SCAN SUMMARY")
	color.Cyan(line + "\n")

	fmt.Printf("Target:           %s\n", r.results.Target)
	fmt.Printf("Duration:         %s\n", duration.Round(time.Second))
	fmt.Printf("\n")

	color.Yellow("=== Reconnaissance ===")
	fmt.Printf("Subdomains:       %d\n", r.results.Stats.SubdomainsFound)
	fmt.Printf("Live Hosts:       %d\n", r.results.Stats.LiveHostsFound)
	fmt.Printf("Open Ports:       %d\n", r.results.Stats.OpenPortsFound)
	fmt.Printf("Directories:      %d\n", r.results.Stats.DirectoriesFound)
	fmt.Printf("\n")

	color.Yellow("=== Vulnerabilities ===")
	if r.results.Stats.CriticalVulns > 0 {
		color.Red("Critical:         %d", r.results.Stats.CriticalVulns)
	}
	if r.results.Stats.HighVulns > 0 {
		color.Red("High:             %d", r.results.Stats.HighVulns)
	}
	if r.results.Stats.MediumVulns > 0 {
		color.Yellow("Medium:           %d", r.results.Stats.MediumVulns)
	}
	if r.results.Stats.LowVulns > 0 {
		color.Blue("Low:              %d", r.results.Stats.LowVulns)
	}
	fmt.Printf("Total:            %d\n", r.results.Stats.VulnsFound)

	color.Cyan("\n" + line + "\n")
}

func (r *Runner) saveResults(outputDir string) error {
	// Save as JSON
	jsonPath := filepath.Join(outputDir, "results.json")
	if err := utils.SaveJSON(jsonPath, r.results); err != nil {
		return err
	}
	color.Green("[+] Results saved to: %s", jsonPath)

	// Save vulnerabilities separately
	if len(r.results.Vulns) > 0 {
		vulnPath := filepath.Join(outputDir, "vulnerabilities.json")
		if err := utils.SaveJSON(vulnPath, r.results.Vulns); err != nil {
			return err
		}
		color.Green("[+] Vulnerabilities saved to: %s", vulnPath)
	}

	return nil
}

func (r *Runner) sendNotifications() {
	// TODO: Implement notification sending
	if len(r.results.Vulns) == 0 {
		return
	}

	color.Cyan("[*] Sending notifications...")
}

// RunMonitor runs continuous monitoring
func (r *Runner) RunMonitor() error {
	// TODO: Implement monitoring mode
	return fmt.Errorf("monitor mode not yet implemented")
}
