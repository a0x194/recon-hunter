package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration options
type Config struct {
	// Target settings
	Target     string   `yaml:"target"`
	TargetList string   `yaml:"target_list"`
	Scope      []string `yaml:"scope"`
	Exclude    []string `yaml:"exclude"`

	// Output settings
	OutputDir  string `yaml:"output_dir"`
	JSONOutput bool   `yaml:"json_output"`

	// Performance settings
	Threads   int `yaml:"threads"`
	Timeout   int `yaml:"timeout"`
	RateLimit int `yaml:"rate_limit"`

	// Output control
	Silent  bool `yaml:"silent"`
	Verbose bool `yaml:"verbose"`

	// Module settings
	Modules     []string `yaml:"modules"`
	ExcludeMods []string `yaml:"exclude_modules"`
	ScanMode    string   `yaml:"scan_mode"` // full, recon, vuln, monitor

	// Notification
	Notify    string         `yaml:"notify"`
	Discord   *DiscordConfig `yaml:"discord"`
	Telegram  *TelegramConfig `yaml:"telegram"`
	Slack     *SlackConfig   `yaml:"slack"`

	// Network settings
	Proxy     string   `yaml:"proxy"`
	Headers   []string `yaml:"headers"`
	UserAgent string   `yaml:"user_agent"`

	// Scan settings
	FullScan         bool `yaml:"full_scan"`
	AggressiveMode   bool `yaml:"aggressive_mode"`
	FollowRedirects  bool `yaml:"follow_redirects"`
	MaxRedirects     int  `yaml:"max_redirects"`

	// API Keys
	APIKeys *APIKeyConfig `yaml:"api_keys"`

	// Module-specific configs
	Subdomain *SubdomainConfig `yaml:"subdomain"`
	Portscan  *PortscanConfig  `yaml:"portscan"`
	Dirscan   *DirscanConfig   `yaml:"dirscan"`
	Nuclei    *NucleiConfig    `yaml:"nuclei"`
}

type DiscordConfig struct {
	Webhook  string   `yaml:"webhook"`
	Severity []string `yaml:"severity"` // critical, high, medium, low
}

type TelegramConfig struct {
	BotToken string   `yaml:"bot_token"`
	ChatID   string   `yaml:"chat_id"`
	Severity []string `yaml:"severity"`
}

type SlackConfig struct {
	Webhook  string   `yaml:"webhook"`
	Channel  string   `yaml:"channel"`
	Severity []string `yaml:"severity"`
}

type APIKeyConfig struct {
	Shodan         string `yaml:"shodan"`
	Censys         string `yaml:"censys"`
	SecurityTrails string `yaml:"securitytrails"`
	VirusTotal     string `yaml:"virustotal"`
	GitHub         string `yaml:"github"`
	Chaos          string `yaml:"chaos"`
	PassiveTotal   string `yaml:"passivetotal"`
	BinaryEdge     string `yaml:"binaryedge"`
}

type SubdomainConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Sources      []string `yaml:"sources"`
	Bruteforce   bool     `yaml:"bruteforce"`
	Wordlist     string   `yaml:"wordlist"`
	Recursive    bool     `yaml:"recursive"`
	MaxDepth     int      `yaml:"max_depth"`
	Resolvers    []string `yaml:"resolvers"`
	WildcardCheck bool    `yaml:"wildcard_check"`
}

type PortscanConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Ports       string `yaml:"ports"` // top100, top1000, full, custom
	CustomPorts string `yaml:"custom_ports"`
	Rate        int    `yaml:"rate"`
	ServiceScan bool   `yaml:"service_scan"`
	VersionScan bool   `yaml:"version_scan"`
}

type DirscanConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Wordlist    string   `yaml:"wordlist"`
	Extensions  []string `yaml:"extensions"`
	StatusCodes []int    `yaml:"status_codes"`
	Recursive   bool     `yaml:"recursive"`
	MaxDepth    int      `yaml:"max_depth"`
}

type NucleiConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Severity      []string `yaml:"severity"`
	Templates     []string `yaml:"templates"`
	ExcludeTempl  []string `yaml:"exclude_templates"`
	TemplatesPath string   `yaml:"templates_path"`
	Headless      bool     `yaml:"headless"`
}

// LoadFromFile loads configuration from a YAML file
func (c *Config) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, c)
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	return &Config{
		OutputDir:       "./output",
		Threads:         50,
		Timeout:         30,
		RateLimit:       150,
		FollowRedirects: true,
		MaxRedirects:    10,
		UserAgent:       "ReconHunter/1.0",
		Subdomain: &SubdomainConfig{
			Enabled:       true,
			Bruteforce:    true,
			Recursive:     false,
			MaxDepth:      2,
			WildcardCheck: true,
			Sources: []string{
				"crtsh",
				"hackertarget",
				"threatcrowd",
				"urlscan",
				"wayback",
				"alienvault",
			},
		},
		Portscan: &PortscanConfig{
			Enabled:     true,
			Ports:       "top1000",
			Rate:        10000,
			ServiceScan: true,
		},
		Dirscan: &DirscanConfig{
			Enabled:     true,
			Extensions:  []string{"php", "asp", "aspx", "jsp", "html", "js", "json", "xml", "txt", "bak", "old", "zip"},
			StatusCodes: []int{200, 201, 204, 301, 302, 307, 401, 403, 405, 500},
			Recursive:   false,
			MaxDepth:    2,
		},
		Nuclei: &NucleiConfig{
			Enabled:  true,
			Severity: []string{"critical", "high", "medium"},
		},
	}
}

// GetTargets returns list of targets
func (c *Config) GetTargets() ([]string, error) {
	var targets []string

	if c.Target != "" {
		targets = append(targets, c.Target)
	}

	if c.TargetList != "" {
		data, err := os.ReadFile(c.TargetList)
		if err != nil {
			return nil, err
		}
		lines := splitLines(string(data))
		targets = append(targets, lines...)
	}

	return targets, nil
}

func splitLines(s string) []string {
	var lines []string
	current := ""
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
