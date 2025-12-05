package gitleaks

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Result represents a Git leak detection result
type Result struct {
	URL         string   `json:"url"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Files       []string `json:"files,omitempty"`
	Description string   `json:"description"`
}

// Common sensitive paths to check
var sensitivePaths = []struct {
	path        string
	checkType   string
	severity    string
	description string
}{
	// Git exposure
	{".git/HEAD", "git", "high", "Git repository exposed - potential source code leak"},
	{".git/config", "git", "high", "Git config exposed - may contain credentials"},
	{".git/index", "git", "high", "Git index exposed"},
	{".gitignore", "git", "info", "Gitignore file exposed"},

	// SVN exposure
	{".svn/entries", "svn", "high", "SVN repository exposed"},
	{".svn/wc.db", "svn", "high", "SVN database exposed"},

	// Mercurial
	{".hg/store", "hg", "high", "Mercurial repository exposed"},

	// Environment files
	{".env", "config", "critical", "Environment file exposed - likely contains secrets"},
	{".env.local", "config", "critical", "Local environment file exposed"},
	{".env.production", "config", "critical", "Production environment file exposed"},
	{".env.bak", "config", "critical", "Backup environment file exposed"},
	{".env.old", "config", "critical", "Old environment file exposed"},

	// Config files
	{"config.php", "config", "high", "PHP config file exposed"},
	{"config.inc.php", "config", "high", "PHP config file exposed"},
	{"configuration.php", "config", "high", "PHP config file exposed"},
	{"settings.php", "config", "high", "PHP settings file exposed"},
	{"wp-config.php", "config", "critical", "WordPress config exposed - contains DB credentials"},
	{"wp-config.php.bak", "config", "critical", "WordPress config backup exposed"},
	{"config.yml", "config", "high", "YAML config file exposed"},
	{"config.yaml", "config", "high", "YAML config file exposed"},
	{"config.json", "config", "high", "JSON config file exposed"},
	{"settings.json", "config", "high", "JSON settings file exposed"},
	{"appsettings.json", "config", "high", ".NET config file exposed"},
	{"web.config", "config", "high", "IIS/ASP.NET config exposed"},

	// Database files
	{"database.sql", "database", "critical", "SQL database dump exposed"},
	{"dump.sql", "database", "critical", "SQL database dump exposed"},
	{"backup.sql", "database", "critical", "SQL database backup exposed"},
	{"db.sql", "database", "critical", "SQL database file exposed"},
	{".sql", "database", "high", "SQL file exposed"},

	// Backup files
	{"backup.zip", "backup", "high", "Backup archive exposed"},
	{"backup.tar.gz", "backup", "high", "Backup archive exposed"},
	{"backup.tar", "backup", "high", "Backup archive exposed"},
	{"www.zip", "backup", "high", "Website archive exposed"},
	{"site.zip", "backup", "high", "Website archive exposed"},
	{"web.zip", "backup", "high", "Website archive exposed"},
	{"htdocs.zip", "backup", "high", "Website archive exposed"},
	{"public_html.zip", "backup", "high", "Website archive exposed"},

	// Log files
	{"error.log", "logs", "medium", "Error log exposed"},
	{"access.log", "logs", "medium", "Access log exposed"},
	{"debug.log", "logs", "medium", "Debug log exposed"},
	{"app.log", "logs", "medium", "Application log exposed"},

	// IDE and editor files
	{".idea/workspace.xml", "ide", "medium", "IntelliJ IDEA workspace exposed"},
	{".vscode/settings.json", "ide", "medium", "VS Code settings exposed"},
	{".DS_Store", "system", "low", "macOS directory metadata exposed"},
	{"Thumbs.db", "system", "low", "Windows thumbnail cache exposed"},

	// CI/CD files
	{".travis.yml", "cicd", "medium", "Travis CI config exposed"},
	{".gitlab-ci.yml", "cicd", "medium", "GitLab CI config exposed"},
	{"Jenkinsfile", "cicd", "medium", "Jenkins pipeline exposed"},
	{".github/workflows", "cicd", "medium", "GitHub Actions workflows exposed"},

	// Docker files
	{"Dockerfile", "docker", "medium", "Dockerfile exposed"},
	{"docker-compose.yml", "docker", "high", "Docker Compose config exposed - may contain secrets"},
	{".dockerignore", "docker", "low", "Docker ignore file exposed"},

	// Key files
	{"id_rsa", "keys", "critical", "Private SSH key exposed"},
	{"id_dsa", "keys", "critical", "Private SSH key exposed"},
	{"id_ecdsa", "keys", "critical", "Private SSH key exposed"},
	{".ssh/id_rsa", "keys", "critical", "Private SSH key exposed"},
	{"server.key", "keys", "critical", "Server private key exposed"},
	{"privatekey.pem", "keys", "critical", "Private key exposed"},

	// PHP info
	{"phpinfo.php", "debug", "medium", "PHP info page exposed"},
	{"info.php", "debug", "medium", "PHP info page exposed"},
	{"test.php", "debug", "low", "Test PHP file exposed"},

	// Admin interfaces
	{"adminer.php", "admin", "high", "Adminer database tool exposed"},
	{"phpmyadmin/", "admin", "high", "phpMyAdmin exposed"},

	// API documentation
	{"swagger.json", "api", "medium", "Swagger API documentation exposed"},
	{"openapi.json", "api", "medium", "OpenAPI documentation exposed"},
	{"swagger.yaml", "api", "medium", "Swagger API documentation exposed"},
	{"api-docs/", "api", "medium", "API documentation exposed"},
}

// Run performs Git and sensitive file leak detection
func Run(urls []string, cfg *config.Config) ([]Result, error) {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	for _, baseURL := range urls {
		baseURL = strings.TrimSuffix(baseURL, "/")

		for _, check := range sensitivePaths {
			wg.Add(1)
			sem <- struct{}{}

			go func(base string, c struct {
				path        string
				checkType   string
				severity    string
				description string
			}) {
				defer wg.Done()
				defer func() { <-sem }()

				url := base + "/" + c.path
				found, files := checkSensitivePath(url, c.checkType, client)

				if found {
					result := Result{
						URL:         url,
						Type:        c.checkType,
						Severity:    c.severity,
						Description: c.description,
						Files:       files,
					}

					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}(baseURL, check)
		}
	}

	wg.Wait()
	return results, nil
}

func checkSensitivePath(url string, checkType string, client *http.Client) (bool, []string) {
	resp, err := client.Get(url)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	// Check if accessible
	if resp.StatusCode != 200 {
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // Limit to 100KB
	if err != nil {
		return false, nil
	}

	content := string(body)

	// Validate based on type
	switch checkType {
	case "git":
		// Check for valid Git content
		if strings.Contains(url, ".git/HEAD") {
			return strings.HasPrefix(content, "ref:") || len(content) == 41, nil
		}
		if strings.Contains(url, ".git/config") {
			return strings.Contains(content, "[core]") || strings.Contains(content, "[remote"), nil
		}
		return true, nil

	case "config":
		// Check for config-like content
		if strings.Contains(content, "password") || strings.Contains(content, "secret") ||
			strings.Contains(content, "api_key") || strings.Contains(content, "database") {
			return true, nil
		}
		// Check for PHP config
		if strings.Contains(content, "<?php") || strings.Contains(content, "define(") {
			return true, nil
		}
		// Check for YAML/JSON config
		if strings.HasPrefix(strings.TrimSpace(content), "{") || strings.HasPrefix(strings.TrimSpace(content), "---") {
			return true, nil
		}
		return false, nil

	case "database":
		// Check for SQL content
		return strings.Contains(content, "CREATE TABLE") ||
			strings.Contains(content, "INSERT INTO") ||
			strings.Contains(content, "DROP TABLE"), nil

	case "backup":
		// Check for archive headers
		return len(body) > 10 && (body[0] == 0x50 && body[1] == 0x4B || // ZIP
			body[0] == 0x1F && body[1] == 0x8B || // GZIP
			strings.HasPrefix(content, "BZh")), nil

	case "keys":
		// Check for key content
		return strings.Contains(content, "-----BEGIN") &&
			(strings.Contains(content, "PRIVATE KEY") || strings.Contains(content, "RSA")), nil

	default:
		return true, nil
	}
}
