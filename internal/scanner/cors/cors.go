package cors

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Scan performs CORS misconfiguration scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, false)
	sem := make(chan struct{}, cfg.Threads)

	// Test origins
	testOrigins := []struct {
		origin   string
		name     string
		severity string
	}{
		{"https://evil.com", "Arbitrary Origin Reflection", "high"},
		{"null", "Null Origin Bypass", "high"},
		{"https://evil.target.com", "Subdomain Prefix Bypass", "medium"},
		{"https://targetevil.com", "Domain Suffix Bypass", "medium"},
		{"https://target.com.evil.com", "Domain Included Bypass", "medium"},
		{"http://target.com", "HTTP Origin (Downgrade)", "medium"},
	}

	for _, url := range urls {
		for _, test := range testOrigins {
			wg.Add(1)
			sem <- struct{}{}

			go func(u string, origin, name, severity string) {
				defer wg.Done()
				defer func() { <-sem }()

				result := checkCORS(u, origin, name, severity, client)
				if result != nil {
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
				}
			}(url, test.origin, test.name, test.severity)
		}
	}

	wg.Wait()
	return results, nil
}

func checkCORS(url, testOrigin, vulnName, severity string, client *http.Client) *types.VulnResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	// Set test origin
	if testOrigin == "null" {
		req.Header.Set("Origin", "null")
	} else {
		// Replace target domain in test origin
		domain := utils.ExtractDomain(url)
		origin := strings.ReplaceAll(testOrigin, "target.com", domain)
		req.Header.Set("Origin", origin)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check CORS headers
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return nil
	}

	// Check for vulnerable configurations
	isVulnerable := false
	description := ""

	switch vulnName {
	case "Arbitrary Origin Reflection":
		if strings.Contains(acao, "evil.com") {
			isVulnerable = true
			description = "Server reflects arbitrary Origin header"
		}
	case "Null Origin Bypass":
		if acao == "null" {
			isVulnerable = true
			description = "Server accepts null origin"
		}
	case "Subdomain Prefix Bypass":
		if strings.Contains(acao, "evil.") {
			isVulnerable = true
			description = "Server accepts subdomain prefix bypass"
		}
	case "Domain Suffix Bypass":
		if strings.Contains(acao, "evil.com") {
			isVulnerable = true
			description = "Server accepts domain suffix bypass"
		}
	case "Domain Included Bypass":
		if strings.Contains(acao, ".evil.com") {
			isVulnerable = true
			description = "Server accepts domain inclusion bypass"
		}
	case "HTTP Origin (Downgrade)":
		if strings.HasPrefix(acao, "http://") && acac == "true" {
			isVulnerable = true
			description = "Server accepts HTTP origin with credentials (protocol downgrade)"
			severity = "high"
		}
	}

	if !isVulnerable {
		return nil
	}

	// More severe if credentials are allowed
	if acac == "true" && severity == "medium" {
		severity = "high"
	}
	if acac == "true" && severity == "high" {
		severity = "critical"
	}

	return &types.VulnResult{
		Type:        "CORS Misconfiguration",
		Severity:    severity,
		URL:         url,
		Description: fmt.Sprintf("%s: %s", vulnName, description),
		Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acao, acac),
		Remediation: "Configure CORS to only allow trusted origins. Avoid reflecting the Origin header directly. Do not use null origin. Be cautious with Access-Control-Allow-Credentials.",
		References: []string{
			"https://portswigger.net/web-security/cors",
			"https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
		},
	}
}
