package utils

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// HTTPClient returns a configured HTTP client
func HTTPClient(timeout int, proxy string, followRedirects bool) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

// SaveLines saves lines to a file
func SaveLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// SaveJSON saves data as JSON
func SaveJSON(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// ReadLines reads lines from a file
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// SanitizeFilename removes invalid characters from filename
func SanitizeFilename(name string) string {
	re := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	return re.ReplaceAllString(name, "_")
}

// ExtractDomain extracts domain from URL
func ExtractDomain(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// ExtractRootDomain extracts root domain from URL
func ExtractRootDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

// IsValidDomain checks if domain is valid
func IsValidDomain(domain string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return re.MatchString(domain)
}

// IsIP checks if string is an IP address
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// UniqueStrings returns unique strings from slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// FetchURL fetches URL content
func FetchURL(urlStr string, client *http.Client, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return body, resp.StatusCode, nil
}

// ExtractURLsFromJS extracts URLs from JavaScript content
func ExtractURLsFromJS(content string) []string {
	var urls []string

	patterns := []string{
		`["'](https?://[^"']+)["']`,
		`["'](/[a-zA-Z0-9_\-./]+)["']`,
		`["']([a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-./]+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 {
				urls = append(urls, match[1])
			}
		}
	}

	return UniqueStrings(urls)
}

// ExtractSecretsFromJS extracts potential secrets from JavaScript
func ExtractSecretsFromJS(content string) []SecretMatch {
	var secrets []SecretMatch

	patterns := map[string]*regexp.Regexp{
		"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"AWS Secret Key":     regexp.MustCompile(`(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]`),
		"API Key":            regexp.MustCompile(`(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]`),
		"Authorization":      regexp.MustCompile(`(?i)(authorization|bearer)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]+)['\"]`),
		"Private Key":        regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
		"Google API Key":     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		"GitHub Token":       regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}`),
		"Slack Token":        regexp.MustCompile(`xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}`),
		"JWT":                regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		"Basic Auth":         regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/=]{20,}`),
		"Password":           regexp.MustCompile(`(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{4,})['\"]`),
		"Database URL":       regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis)://[^\s'"]+`),
		"Stripe Key":         regexp.MustCompile(`(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}`),
		"Twilio":             regexp.MustCompile(`SK[a-f0-9]{32}`),
		"Mailgun":            regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		"Heroku API Key":     regexp.MustCompile(`[h|H]eroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
		"Firebase":           regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
		"Discord Webhook":    regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+`),
		"Slack Webhook":      regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
		"Generic Secret":     regexp.MustCompile(`(?i)(secret|token|key|password|auth)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]`),
	}

	for name, pattern := range patterns {
		matches := pattern.FindAllString(content, -1)
		for _, match := range matches {
			secrets = append(secrets, SecretMatch{
				Type:  name,
				Value: match,
			})
		}
	}

	return secrets
}

// SecretMatch represents a secret finding
type SecretMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ExtractEmails extracts email addresses from content
func ExtractEmails(content string) []string {
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	return UniqueStrings(re.FindAllString(content, -1))
}

// ExtractIPs extracts IP addresses from content
func ExtractIPs(content string) []string {
	re := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	return UniqueStrings(re.FindAllString(content, -1))
}

// HasParam checks if URL has parameters
func HasParam(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return len(u.Query()) > 0 || strings.Contains(urlStr, "?")
}

// GetParams extracts parameters from URL
func GetParams(urlStr string) url.Values {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	return u.Query()
}

// ColorSeverity returns colored severity string
func ColorSeverity(severity string) string {
	switch severity {
	case "critical":
		return fmt.Sprintf("\033[91m%s\033[0m", severity)
	case "high":
		return fmt.Sprintf("\033[31m%s\033[0m", severity)
	case "medium":
		return fmt.Sprintf("\033[33m%s\033[0m", severity)
	case "low":
		return fmt.Sprintf("\033[34m%s\033[0m", severity)
	default:
		return severity
	}
}

// RateLimiter implements a simple rate limiter
type RateLimiter struct {
	rate     int
	interval time.Duration
	tokens   chan struct{}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int) *RateLimiter {
	rl := &RateLimiter{
		rate:     rate,
		interval: time.Second,
		tokens:   make(chan struct{}, rate),
	}

	// Fill initial tokens
	for i := 0; i < rate; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens periodically
	go func() {
		ticker := time.NewTicker(rl.interval / time.Duration(rate))
		defer ticker.Stop()
		for range ticker.C {
			select {
			case rl.tokens <- struct{}{}:
			default:
			}
		}
	}()

	return rl
}

// Wait waits for a token
func (rl *RateLimiter) Wait() {
	<-rl.tokens
}

// HTTPClientNoRedirect returns HTTP client that doesn't follow redirects
func HTTPClientNoRedirect(timeout int, proxy string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NormalizeURL normalizes URL for consistent comparison
func NormalizeURL(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Remove default ports
	host := u.Host
	if strings.HasSuffix(host, ":80") && u.Scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	if strings.HasSuffix(host, ":443") && u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	}

	u.Host = host
	return u.String()
}

// ExtractDomainsFromContent extracts domains from text content
func ExtractDomainsFromContent(content string) []string {
	re := regexp.MustCompile(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`)
	matches := re.FindAllString(content, -1)
	return UniqueStrings(matches)
}

// IsInternalIP checks if IP is internal/private
func IsInternalIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for loopback
	if parsedIP.IsLoopback() {
		return true
	}

	// Check for private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// TruncateString truncates string to max length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// GetStatusColor returns ANSI color code for HTTP status
func GetStatusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "\033[92m" // Green
	case status >= 300 && status < 400:
		return "\033[93m" // Yellow
	case status >= 400 && status < 500:
		return "\033[91m" // Red
	case status >= 500:
		return "\033[95m" // Magenta
	default:
		return "\033[0m"
	}
}

// ResetColor returns ANSI reset code
func ResetColor() string {
	return "\033[0m"
}
