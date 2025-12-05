package jshunter

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Result represents JavaScript analysis result
type Result struct {
	URL       string   `json:"url"`
	JSFile    string   `json:"js_file"`
	Endpoints []string `json:"endpoints"`
	Secrets   []Secret `json:"secrets"`
	Domains   []string `json:"domains"`
	Emails    []string `json:"emails"`
	IPs       []string `json:"ips"`
}

// Secret represents a discovered secret
type Secret struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Run performs JavaScript analysis
func Run(urls []string, cfg *config.Config) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	for _, baseURL := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			// First, get the page and find JS files
			jsFiles := findJSFiles(u, client)

			for _, jsFile := range jsFiles {
				result := analyzeJS(jsFile, client)
				if result != nil {
					result.URL = u
					mu.Lock()
					results = append(results, *result)
					mu.Unlock()
				}
			}
		}(baseURL)
	}

	wg.Wait()
	return results, nil
}

func findJSFiles(pageURL string, client *http.Client) []string {
	var jsFiles []string

	resp, err := client.Get(pageURL)
	if err != nil {
		return jsFiles
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return jsFiles
	}

	// Find script tags
	scriptRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	matches := scriptRe.FindAllStringSubmatch(string(body), -1)

	baseURL, _ := url.Parse(pageURL)

	for _, match := range matches {
		if len(match) > 1 {
			jsURL := match[1]
			// Make absolute URL
			if strings.HasPrefix(jsURL, "//") {
				jsURL = baseURL.Scheme + ":" + jsURL
			} else if strings.HasPrefix(jsURL, "/") {
				jsURL = baseURL.Scheme + "://" + baseURL.Host + jsURL
			} else if !strings.HasPrefix(jsURL, "http") {
				jsURL = baseURL.Scheme + "://" + baseURL.Host + "/" + jsURL
			}
			jsFiles = append(jsFiles, jsURL)
		}
	}

	return utils.UniqueStrings(jsFiles)
}

func analyzeJS(jsURL string, client *http.Client) *Result {
	resp, err := client.Get(jsURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := string(body)

	result := &Result{
		JSFile: jsURL,
	}

	// Extract endpoints
	result.Endpoints = extractEndpoints(content)

	// Extract secrets
	result.Secrets = extractSecrets(content)

	// Extract domains
	result.Domains = extractDomains(content)

	// Extract emails
	result.Emails = utils.ExtractEmails(content)

	// Extract IPs
	result.IPs = utils.ExtractIPs(content)

	// Only return if we found something
	if len(result.Endpoints) == 0 && len(result.Secrets) == 0 &&
		len(result.Domains) == 0 && len(result.Emails) == 0 && len(result.IPs) == 0 {
		return nil
	}

	return result
}

func extractEndpoints(content string) []string {
	var endpoints []string

	patterns := []string{
		// API paths
		`["'](/api/[a-zA-Z0-9_\-./]+)["']`,
		`["'](/v[0-9]+/[a-zA-Z0-9_\-./]+)["']`,
		`["'](/rest/[a-zA-Z0-9_\-./]+)["']`,
		`["'](/graphql[a-zA-Z0-9_\-./]*)["']`,

		// General paths
		`["'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-./]+)["']`,

		// Full URLs
		`["'](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+)["']`,

		// Relative paths with actions
		`["']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+\.(php|asp|aspx|jsp|json|xml))["']`,

		// fetch/axios calls
		`fetch\s*\(\s*["']([^"']+)["']`,
		`axios\.[a-z]+\s*\(\s*["']([^"']+)["']`,
		`\$\.(get|post|ajax)\s*\(\s*["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				// Filter out common false positives
				if isValidEndpoint(endpoint) {
					endpoints = append(endpoints, endpoint)
				}
			}
		}
	}

	return utils.UniqueStrings(endpoints)
}

func isValidEndpoint(endpoint string) bool {
	// Filter out common false positives
	excludePatterns := []string{
		`\.png$`, `\.jpg$`, `\.gif$`, `\.svg$`, `\.ico$`,
		`\.css$`, `\.woff`, `\.ttf$`, `\.eot$`,
		`^data:`, `^javascript:`, `^mailto:`, `^tel:`,
		`node_modules`, `\.min\.js$`,
	}

	for _, pattern := range excludePatterns {
		if matched, _ := regexp.MatchString(pattern, endpoint); matched {
			return false
		}
	}

	return len(endpoint) > 1 && len(endpoint) < 500
}

func extractSecrets(content string) []Secret {
	var secrets []Secret

	patterns := map[string]*regexp.Regexp{
		"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"AWS Secret Key":     regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`),
		"Google API Key":     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"GitHub Token":       regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
		"GitHub OAuth":       regexp.MustCompile(`[0-9a-fA-F]{40}`),
		"Slack Token":        regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}`),
		"Slack Webhook":      regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		"Discord Webhook":    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+`),
		"JWT":                regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		"Private Key":        regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),
		"Stripe Key":         regexp.MustCompile(`(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`),
		"Twilio":             regexp.MustCompile(`SK[a-f0-9]{32}`),
		"Mailgun":            regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"SendGrid":           regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		"Firebase":           regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
		"Heroku API Key":     regexp.MustCompile(`[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
		"Facebook Token":     regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
		"Twitter Token":      regexp.MustCompile(`[1-9][0-9]+-[0-9a-zA-Z]{40}`),
		"Square OAuth":       regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`),
		"PayPal":             regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
		"API Key Generic":    regexp.MustCompile(`(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`),
		"Secret Generic":     regexp.MustCompile(`(?i)(secret|token|password|auth)['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]`),
		"Bearer Token":       regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`),
		"Basic Auth":         regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/=]{20,}`),
		"Database URL":       regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis|mssql)://[^\s'"]+`),
	}

	for name, pattern := range patterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Truncate long matches
			if len(match) > 100 {
				match = match[:100] + "..."
			}
			secrets = append(secrets, Secret{
				Type:  name,
				Value: match,
			})
		}
	}

	return secrets
}

func extractDomains(content string) []string {
	// Match domains
	re := regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?`)
	matches := re.FindAllString(content, -1)

	var domains []string
	excludeExts := map[string]bool{
		"min.js": true, "min.css": true, "bundle.js": true,
		"png": true, "jpg": true, "gif": true, "svg": true,
	}

	for _, match := range matches {
		match = strings.ToLower(match)
		// Filter out file extensions
		parts := strings.Split(match, ".")
		lastPart := parts[len(parts)-1]
		if excludeExts[lastPart] || excludeExts[strings.Join(parts[len(parts)-2:], ".")] {
			continue
		}
		// Filter out common non-domains
		if len(match) > 5 && len(match) < 100 {
			domains = append(domains, match)
		}
	}

	return utils.UniqueStrings(domains)
}
