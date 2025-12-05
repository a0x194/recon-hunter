package headers

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Security headers to check
var securityHeaders = []struct {
	header      string
	description string
	severity    string
	remediation string
}{
	{
		"Strict-Transport-Security",
		"HSTS header missing - site may be vulnerable to protocol downgrade attacks",
		"medium",
		"Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header",
	},
	{
		"X-Content-Type-Options",
		"X-Content-Type-Options header missing - vulnerable to MIME type sniffing",
		"low",
		"Add 'X-Content-Type-Options: nosniff' header",
	},
	{
		"X-Frame-Options",
		"X-Frame-Options header missing - may be vulnerable to clickjacking",
		"medium",
		"Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header",
	},
	{
		"Content-Security-Policy",
		"CSP header missing - increased XSS risk",
		"medium",
		"Implement a Content-Security-Policy header with appropriate directives",
	},
	{
		"X-XSS-Protection",
		"X-XSS-Protection header missing",
		"low",
		"Add 'X-XSS-Protection: 1; mode=block' header (note: deprecated in modern browsers)",
	},
	{
		"Referrer-Policy",
		"Referrer-Policy header missing - may leak sensitive URL information",
		"low",
		"Add 'Referrer-Policy: strict-origin-when-cross-origin' header",
	},
	{
		"Permissions-Policy",
		"Permissions-Policy header missing",
		"info",
		"Consider adding Permissions-Policy header to control browser features",
	},
}

// Dangerous headers that should not be present
var dangerousHeaders = []struct {
	header      string
	pattern     string
	description string
	severity    string
}{
	{"X-Powered-By", "", "X-Powered-By header exposes technology stack", "low"},
	{"Server", "Apache/", "Server header reveals Apache version", "low"},
	{"Server", "nginx/", "Server header reveals Nginx version", "low"},
	{"Server", "Microsoft-IIS/", "Server header reveals IIS version", "low"},
	{"X-AspNet-Version", "", "ASP.NET version exposed", "low"},
	{"X-AspNetMvc-Version", "", "ASP.NET MVC version exposed", "low"},
}

// Scan performs security headers analysis
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	for _, urlStr := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := analyzeHeaders(u, client)
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

func analyzeHeaders(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	resp, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for missing security headers
	for _, check := range securityHeaders {
		if resp.Header.Get(check.header) == "" {
			results = append(results, types.VulnResult{
				Type:        "Missing Security Header",
				Severity:    check.severity,
				URL:         urlStr,
				Description: check.description,
				Evidence:    fmt.Sprintf("Header '%s' not found in response", check.header),
				Remediation: check.remediation,
				References: []string{
					"https://owasp.org/www-project-secure-headers/",
				},
			})
		}
	}

	// Check for dangerous/information-leaking headers
	for _, check := range dangerousHeaders {
		value := resp.Header.Get(check.header)
		if value != "" {
			if check.pattern == "" || strings.Contains(value, check.pattern) {
				results = append(results, types.VulnResult{
					Type:        "Information Disclosure",
					Severity:    check.severity,
					URL:         urlStr,
					Description: check.description,
					Evidence:    fmt.Sprintf("%s: %s", check.header, value),
					Remediation: fmt.Sprintf("Remove or sanitize the %s header", check.header),
				})
			}
		}
	}

	// Check for insecure cookie settings
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)

		// Check for missing Secure flag on HTTPS
		if strings.HasPrefix(urlStr, "https://") && !strings.Contains(cookieLower, "secure") {
			results = append(results, types.VulnResult{
				Type:        "Insecure Cookie",
				Severity:    "medium",
				URL:         urlStr,
				Description: "Cookie missing Secure flag",
				Evidence:    cookie,
				Remediation: "Add 'Secure' flag to cookies served over HTTPS",
			})
		}

		// Check for missing HttpOnly flag
		if !strings.Contains(cookieLower, "httponly") {
			// Check if it might be a session cookie
			if strings.Contains(cookieLower, "session") || strings.Contains(cookieLower, "token") {
				results = append(results, types.VulnResult{
					Type:        "Insecure Cookie",
					Severity:    "medium",
					URL:         urlStr,
					Description: "Session cookie missing HttpOnly flag - vulnerable to XSS cookie theft",
					Evidence:    cookie,
					Remediation: "Add 'HttpOnly' flag to session cookies",
				})
			}
		}

		// Check for missing SameSite attribute
		if !strings.Contains(cookieLower, "samesite") {
			results = append(results, types.VulnResult{
				Type:        "Insecure Cookie",
				Severity:    "low",
				URL:         urlStr,
				Description: "Cookie missing SameSite attribute",
				Evidence:    cookie,
				Remediation: "Add 'SameSite=Strict' or 'SameSite=Lax' attribute to cookies",
			})
		}
	}

	// Check CSP if present
	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		cspVulns := analyzeCSP(csp, urlStr)
		results = append(results, cspVulns...)
	}

	return results
}

func analyzeCSP(csp string, urlStr string) []types.VulnResult {
	var results []types.VulnResult
	cspLower := strings.ToLower(csp)

	// Check for unsafe-inline
	if strings.Contains(cspLower, "'unsafe-inline'") {
		results = append(results, types.VulnResult{
			Type:        "Weak CSP",
			Severity:    "medium",
			URL:         urlStr,
			Description: "CSP contains 'unsafe-inline' - reduces XSS protection",
			Evidence:    csp,
			Remediation: "Remove 'unsafe-inline' and use nonces or hashes for inline scripts",
		})
	}

	// Check for unsafe-eval
	if strings.Contains(cspLower, "'unsafe-eval'") {
		results = append(results, types.VulnResult{
			Type:        "Weak CSP",
			Severity:    "medium",
			URL:         urlStr,
			Description: "CSP contains 'unsafe-eval' - allows eval() which can be exploited",
			Evidence:    csp,
			Remediation: "Remove 'unsafe-eval' directive",
		})
	}

	// Check for wildcard sources
	if strings.Contains(csp, "*") {
		results = append(results, types.VulnResult{
			Type:        "Weak CSP",
			Severity:    "medium",
			URL:         urlStr,
			Description: "CSP contains wildcard (*) source - overly permissive",
			Evidence:    csp,
			Remediation: "Replace wildcard with specific trusted domains",
		})
	}

	// Check for data: URI
	if strings.Contains(cspLower, "data:") {
		results = append(results, types.VulnResult{
			Type:        "Weak CSP",
			Severity:    "low",
			URL:         urlStr,
			Description: "CSP allows data: URIs - may enable XSS",
			Evidence:    csp,
			Remediation: "Remove 'data:' from CSP if not needed",
		})
	}

	return results
}
