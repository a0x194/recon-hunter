package main

import (
	"fmt"
	"os"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/runner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"
	banner  = `
    ____                       __  __            __
   / __ \___  _________  ____  / / / /_  ______  / /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / __  / /_/ / / / / /_/  __/ /
/_/ |_|\___/\___/\____/_/ /_/_/ /_/\__,_/_/ /_/\__/\___/_/
                                                         v%s
            [ Automated Bug Bounty Recon Framework ]
                        by @a0x194
`
)

var (
	cfgFile     string
	target      string
	targetList  string
	outputDir   string
	threads     int
	timeout     int
	rateLimit   int
	silent      bool
	verbose     bool
	jsonOutput  bool
	modules     []string
	excludeMods []string
	notify      string
	proxy       string
	fullScan    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "reconhunter",
		Short: "ReconHunter - Automated Bug Bounty Recon Framework",
		Long:  color.GreenString(fmt.Sprintf(banner, version)),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file path")
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target domain")
	rootCmd.PersistentFlags().StringVarP(&targetList, "list", "l", "", "File containing list of targets")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./output", "Output directory")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "T", 50, "Number of concurrent threads")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 30, "Request timeout in seconds")
	rootCmd.PersistentFlags().IntVarP(&rateLimit, "rate", "r", 150, "Requests per second rate limit")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Silent mode (minimal output)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "JSON output format")
	rootCmd.PersistentFlags().StringSliceVarP(&modules, "modules", "m", []string{}, "Specific modules to run")
	rootCmd.PersistentFlags().StringSliceVar(&excludeMods, "exclude", []string{}, "Modules to exclude")
	rootCmd.PersistentFlags().StringVar(&notify, "notify", "", "Notification webhook URL")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "HTTP proxy (e.g., http://127.0.0.1:8080)")

	// Scan command - Full scan
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Run full automated scan (recon + vuln)",
		Run:   runScan,
	}
	scanCmd.Flags().BoolVar(&fullScan, "full", false, "Enable all modules including aggressive scans")
	rootCmd.AddCommand(scanCmd)

	// Recon command - Only reconnaissance
	reconCmd := &cobra.Command{
		Use:   "recon",
		Short: "Run reconnaissance only (no vulnerability scanning)",
		Run:   runRecon,
	}
	rootCmd.AddCommand(reconCmd)

	// Vuln command - Only vulnerability scanning
	vulnCmd := &cobra.Command{
		Use:   "vuln",
		Short: "Run vulnerability scanning on discovered assets",
		Run:   runVuln,
	}
	rootCmd.AddCommand(vulnCmd)

	// Monitor command - Continuous monitoring
	monitorCmd := &cobra.Command{
		Use:   "monitor",
		Short: "Start continuous monitoring mode",
		Run:   runMonitor,
	}
	var interval string
	monitorCmd.Flags().StringVar(&interval, "interval", "24h", "Scan interval (e.g., 1h, 24h)")
	rootCmd.AddCommand(monitorCmd)

	// Report command - Generate report
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Generate report from scan results",
		Run:   runReport,
	}
	var reportFormat string
	reportCmd.Flags().StringVarP(&reportFormat, "format", "f", "html", "Report format (html, pdf, md, json)")
	rootCmd.AddCommand(reportCmd)

	// Modules command - List available modules
	modulesCmd := &cobra.Command{
		Use:   "modules",
		Short: "List all available modules",
		Run:   listModules,
	}
	rootCmd.AddCommand(modulesCmd)

	// Version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ReconHunter v%s\n", version)
		},
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) {
	if target == "" && targetList == "" {
		color.Red("[!] Error: Target (-t) or target list (-l) is required")
		os.Exit(1)
	}

	printBanner()

	cfg := buildConfig()
	cfg.ScanMode = "full"

	r := runner.New(cfg)
	if err := r.Run(); err != nil {
		color.Red("[!] Error: %v", err)
		os.Exit(1)
	}
}

func runRecon(cmd *cobra.Command, args []string) {
	if target == "" && targetList == "" {
		color.Red("[!] Error: Target (-t) or target list (-l) is required")
		os.Exit(1)
	}

	printBanner()

	cfg := buildConfig()
	cfg.ScanMode = "recon"

	r := runner.New(cfg)
	if err := r.Run(); err != nil {
		color.Red("[!] Error: %v", err)
		os.Exit(1)
	}
}

func runVuln(cmd *cobra.Command, args []string) {
	if target == "" && targetList == "" {
		color.Red("[!] Error: Target (-t) or target list (-l) is required")
		os.Exit(1)
	}

	printBanner()

	cfg := buildConfig()
	cfg.ScanMode = "vuln"

	r := runner.New(cfg)
	if err := r.Run(); err != nil {
		color.Red("[!] Error: %v", err)
		os.Exit(1)
	}
}

func runMonitor(cmd *cobra.Command, args []string) {
	if target == "" && targetList == "" {
		color.Red("[!] Error: Target (-t) or target list (-l) is required")
		os.Exit(1)
	}

	printBanner()
	color.Yellow("[*] Starting continuous monitoring mode...")

	cfg := buildConfig()
	cfg.ScanMode = "monitor"

	r := runner.New(cfg)
	if err := r.RunMonitor(); err != nil {
		color.Red("[!] Error: %v", err)
		os.Exit(1)
	}
}

func runReport(cmd *cobra.Command, args []string) {
	printBanner()
	color.Yellow("[*] Generating report...")
	// TODO: Implement report generation
}

func listModules(cmd *cobra.Command, args []string) {
	printBanner()

	color.Cyan("\n[*] Available Modules:\n")

	fmt.Println(color.YellowString("\n  === RECONNAISSANCE ==="))
	printModule("subdomain", "Subdomain enumeration (passive + active)")
	printModule("portscan", "Port scanning and service detection")
	printModule("httpx", "HTTP probing and technology detection")
	printModule("jshunter", "JavaScript analysis and endpoint extraction")
	printModule("dirscan", "Directory and file bruteforce")
	printModule("paramfuzz", "Parameter discovery")
	printModule("wayback", "Wayback machine mining")
	printModule("gitleaks", "Git repository exposure detection")
	printModule("screenshot", "Web page screenshot capture")

	fmt.Println(color.YellowString("\n  === VULNERABILITY SCANNING ==="))
	printModule("sqli", "SQL injection detection")
	printModule("xss", "Cross-site scripting detection")
	printModule("ssrf", "Server-side request forgery detection")
	printModule("lfi", "Local file inclusion detection")
	printModule("rce", "Remote code execution detection")
	printModule("cors", "CORS misconfiguration detection")
	printModule("smuggle", "HTTP request smuggling detection")
	printModule("crlf", "CRLF injection detection")
	printModule("redirect", "Open redirect detection")
	printModule("ssti", "Server-side template injection detection")
	printModule("jwt", "JWT vulnerability detection")
	printModule("idor", "IDOR vulnerability detection")
	printModule("xxe", "XXE injection detection")
	printModule("nosqli", "NoSQL injection detection")
	printModule("graphql", "GraphQL vulnerability detection")
	printModule("takeover", "Subdomain takeover detection")
	printModule("nuclei", "Nuclei template scanning")
	printModule("headers", "Security headers analysis")
	printModule("cloud", "Cloud misconfiguration detection")

	fmt.Println()
}

func printModule(name, desc string) {
	fmt.Printf("  %s%-12s%s %s\n", color.GreenString(""), name, color.WhiteString(""), desc)
}

func printBanner() {
	if !silent {
		color.Green(fmt.Sprintf(banner, version))
	}
}

func buildConfig() *config.Config {
	cfg := &config.Config{
		Target:      target,
		TargetList:  targetList,
		OutputDir:   outputDir,
		Threads:     threads,
		Timeout:     timeout,
		RateLimit:   rateLimit,
		Silent:      silent,
		Verbose:     verbose,
		JSONOutput:  jsonOutput,
		Modules:     modules,
		ExcludeMods: excludeMods,
		Notify:      notify,
		Proxy:       proxy,
		FullScan:    fullScan,
	}

	// Load from config file if provided
	if cfgFile != "" {
		if err := cfg.LoadFromFile(cfgFile); err != nil {
			color.Yellow("[!] Warning: Could not load config file: %v", err)
		}
	}

	return cfg
}
