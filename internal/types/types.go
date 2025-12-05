package types

import "time"

// VulnResult represents a vulnerability finding
type VulnResult struct {
	Type        string            `json:"type"`
	Severity    string            `json:"severity"` // critical, high, medium, low, info
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload,omitempty"`
	Evidence    string            `json:"evidence,omitempty"`
	Request     string            `json:"request,omitempty"`
	Response    string            `json:"response,omitempty"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Stats holds scan statistics
type Stats struct {
	SubdomainsFound   int `json:"subdomains_found"`
	LiveHostsFound    int `json:"live_hosts_found"`
	OpenPortsFound    int `json:"open_ports_found"`
	DirectoriesFound  int `json:"directories_found"`
	VulnsFound        int `json:"vulns_found"`
	CriticalVulns     int `json:"critical_vulns"`
	HighVulns         int `json:"high_vulns"`
	MediumVulns       int `json:"medium_vulns"`
	LowVulns          int `json:"low_vulns"`
}
