package httpx

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
)

// Result represents an HTTP probe result
type Result struct {
	URL          string            `json:"url"`
	Host         string            `json:"host"`
	StatusCode   int               `json:"status_code"`
	ContentType  string            `json:"content_type"`
	ContentLength int64            `json:"content_length"`
	Title        string            `json:"title"`
	Server       string            `json:"server"`
	Technologies []string          `json:"technologies"`
	Headers      map[string]string `json:"headers"`
	Redirect     string            `json:"redirect,omitempty"`
	TLS          bool              `json:"tls"`
	TLSVersion   string            `json:"tls_version,omitempty"`
	ResponseTime int64             `json:"response_time_ms"`
}

// Run performs HTTP probing on targets
func Run(targets []string, cfg *config.Config) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	client := createClient(cfg.Timeout, cfg.Proxy)

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}

		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Try both HTTP and HTTPS
			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, t)
				if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
					url = t
				}

				result, err := probe(url, client)
				if err != nil {
					continue
				}

				mu.Lock()
				results = append(results, *result)
				mu.Unlock()

				// If HTTPS works, skip HTTP
				if scheme == "https" {
					break
				}
			}
		}(target)
	}

	wg.Wait()
	return results, nil
}

func createClient(timeout int, proxy string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func probe(url string, client *http.Client) (*Result, error) {
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB

	result := &Result{
		URL:           url,
		Host:          req.Host,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: resp.ContentLength,
		Server:        resp.Header.Get("Server"),
		ResponseTime:  time.Since(start).Milliseconds(),
		Headers:       make(map[string]string),
		TLS:           strings.HasPrefix(url, "https"),
	}

	// Extract title
	result.Title = extractTitle(string(body))

	// Store important headers
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-Frame-Options", "Content-Security-Policy"} {
		if v := resp.Header.Get(h); v != "" {
			result.Headers[h] = v
		}
	}

	// Check for redirect
	if loc := resp.Header.Get("Location"); loc != "" {
		result.Redirect = loc
	}

	// Detect technologies
	result.Technologies = detectTechnologies(resp.Header, string(body))

	// TLS info
	if resp.TLS != nil {
		result.TLSVersion = tlsVersionName(resp.TLS.Version)
	}

	return result, nil
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		if len(title) > 100 {
			title = title[:100] + "..."
		}
		return title
	}
	return ""
}

func detectTechnologies(headers http.Header, body string) []string {
	var techs []string
	seen := make(map[string]bool)

	addTech := func(name string) {
		if !seen[name] {
			seen[name] = true
			techs = append(techs, name)
		}
	}

	// Header-based detection
	server := strings.ToLower(headers.Get("Server"))
	powered := strings.ToLower(headers.Get("X-Powered-By"))

	if strings.Contains(server, "nginx") {
		addTech("Nginx")
	}
	if strings.Contains(server, "apache") {
		addTech("Apache")
	}
	if strings.Contains(server, "iis") {
		addTech("IIS")
	}
	if strings.Contains(server, "cloudflare") {
		addTech("Cloudflare")
	}

	if strings.Contains(powered, "php") {
		addTech("PHP")
	}
	if strings.Contains(powered, "asp.net") {
		addTech("ASP.NET")
	}
	if strings.Contains(powered, "express") {
		addTech("Express.js")
	}

	// Body-based detection
	bodyLower := strings.ToLower(body)

	techPatterns := map[string][]string{
		"WordPress":    {"wp-content", "wp-includes", "wordpress"},
		"Drupal":       {"drupal", "sites/all", "sites/default"},
		"Joomla":       {"joomla", "/components/com_"},
		"React":        {"react", "_reactroot", "reactid"},
		"Vue.js":       {"vue.js", "v-bind", "v-on", "vue-"},
		"Angular":      {"ng-app", "ng-controller", "angular"},
		"jQuery":       {"jquery"},
		"Bootstrap":    {"bootstrap"},
		"Laravel":      {"laravel", "csrf-token"},
		"Django":       {"csrfmiddlewaretoken", "django"},
		"Ruby on Rails":{"rails", "csrf-param"},
		"Spring":       {"spring"},
		"Struts":       {"struts"},
		"Shopify":      {"shopify", "cdn.shopify"},
		"Magento":      {"magento", "mage/"},
		"Wix":          {"wix.com", "wixstatic"},
		"Squarespace":  {"squarespace"},
		"Webflow":      {"webflow"},
	}

	for tech, patterns := range techPatterns {
		for _, pattern := range patterns {
			if strings.Contains(bodyLower, pattern) {
				addTech(tech)
				break
			}
		}
	}

	// Cookie-based detection
	cookies := headers.Get("Set-Cookie")
	cookieLower := strings.ToLower(cookies)

	if strings.Contains(cookieLower, "phpsessid") {
		addTech("PHP")
	}
	if strings.Contains(cookieLower, "asp.net") || strings.Contains(cookieLower, "aspxauth") {
		addTech("ASP.NET")
	}
	if strings.Contains(cookieLower, "jsessionid") {
		addTech("Java")
	}
	if strings.Contains(cookieLower, "laravel") {
		addTech("Laravel")
	}

	return techs
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
