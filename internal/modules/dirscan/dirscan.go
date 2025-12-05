package dirscan

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Result represents a directory scan result
type Result struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	ContentType   string `json:"content_type"`
	Redirect      string `json:"redirect,omitempty"`
}

// Common directories and files to check
var CommonPaths = []string{
	// Admin panels
	"admin", "administrator", "admin.php", "admin.html", "admin/login", "adminpanel",
	"cpanel", "controlpanel", "dashboard", "manage", "manager", "webadmin",

	// Backup files
	"backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
	"dump.sql", "backup.bak", "www.zip", "site.zip", "web.zip",

	// Config files
	"config.php", "config.inc.php", "configuration.php", "settings.php", "config.yml",
	"config.json", ".env", ".env.bak", ".env.local", ".env.production",
	"web.config", "wp-config.php", "wp-config.php.bak", "config.php.bak",

	// Git exposure
	".git", ".git/HEAD", ".git/config", ".git/index", ".gitignore",
	".svn", ".svn/entries", ".hg", ".bzr",

	// Debug and dev files
	"debug", "test", "testing", "dev", "development", "staging",
	"phpinfo.php", "info.php", "test.php", "debug.php",
	"server-status", "server-info",

	// Logs
	"logs", "log", "error.log", "access.log", "debug.log", "error_log",

	// API endpoints
	"api", "api/v1", "api/v2", "rest", "graphql", "swagger", "swagger.json",
	"api-docs", "openapi.json", "swagger-ui.html",

	// Common directories
	"uploads", "upload", "files", "images", "img", "media", "assets",
	"static", "public", "private", "data", "tmp", "temp", "cache",

	// CMS specific
	"wp-admin", "wp-login.php", "wp-content", "wp-includes",
	"administrator", "components", "modules", "plugins", "themes",
	"sites/default/files", "misc", "profiles",

	// Cloud and infra
	".aws", ".docker", "docker-compose.yml", "Dockerfile",
	".kubernetes", "k8s", "terraform", ".terraform",

	// Source code
	"src", "source", "app", "application", "includes", "lib",
	".idea", ".vscode", "node_modules", "vendor",

	// Security related
	"robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
	"crossdomain.xml", "clientaccesspolicy.xml",

	// Hidden/sensitive
	".htaccess", ".htpasswd", ".DS_Store", "Thumbs.db",
	"id_rsa", "id_dsa", ".ssh", "authorized_keys",

	// Installer files
	"install", "install.php", "setup", "setup.php", "installer",

	// Database interfaces
	"phpmyadmin", "pma", "mysql", "adminer", "adminer.php",
	"pgadmin", "phpPgAdmin", "dbadmin",
}

// Extensions to try
var Extensions = []string{
	"", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
	".bak", ".old", ".orig", ".txt", ".conf", ".config",
	".zip", ".tar", ".gz", ".sql", ".json", ".xml", ".yml",
}

// Run performs directory scanning
func Run(urls []string, cfg *config.Config) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, false)
	sem := make(chan struct{}, cfg.Threads)
	rateLimiter := utils.NewRateLimiter(cfg.RateLimit)

	// Get paths to scan
	paths := CommonPaths
	if cfg.Dirscan != nil && cfg.Dirscan.Wordlist != "" {
		customPaths, err := utils.ReadLines(cfg.Dirscan.Wordlist)
		if err == nil {
			paths = append(paths, customPaths...)
		}
	}

	// Get extensions
	extensions := []string{""}
	if cfg.Dirscan != nil && len(cfg.Dirscan.Extensions) > 0 {
		for _, ext := range cfg.Dirscan.Extensions {
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions = append(extensions, ext)
		}
	} else {
		extensions = Extensions
	}

	// Get valid status codes
	validCodes := map[int]bool{200: true, 201: true, 204: true, 301: true, 302: true, 307: true, 401: true, 403: true}
	if cfg.Dirscan != nil && len(cfg.Dirscan.StatusCodes) > 0 {
		validCodes = make(map[int]bool)
		for _, code := range cfg.Dirscan.StatusCodes {
			validCodes[code] = true
		}
	}

	for _, baseURL := range urls {
		baseURL = strings.TrimSuffix(baseURL, "/")

		for _, path := range paths {
			for _, ext := range extensions {
				wg.Add(1)
				sem <- struct{}{}

				go func(base, p, e string) {
					defer wg.Done()
					defer func() { <-sem }()

					rateLimiter.Wait()

					url := fmt.Sprintf("%s/%s%s", base, p, e)
					result, err := checkPath(url, client, validCodes)
					if err != nil {
						return
					}

					if result != nil {
						mu.Lock()
						results = append(results, *result)
						mu.Unlock()
					}
				}(baseURL, path, ext)
			}
		}
	}

	wg.Wait()

	// Deduplicate results
	return deduplicateResults(results), nil
}

func checkPath(url string, client *http.Client, validCodes map[int]bool) (*Result, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if !validCodes[resp.StatusCode] {
		return nil, nil
	}

	result := &Result{
		URL:           url,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.Header.Get("Content-Type"),
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		result.Redirect = loc
	}

	return result, nil
}

func deduplicateResults(results []Result) []Result {
	seen := make(map[string]bool)
	var unique []Result

	for _, r := range results {
		key := fmt.Sprintf("%s-%d", r.URL, r.StatusCode)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}

	return unique
}
