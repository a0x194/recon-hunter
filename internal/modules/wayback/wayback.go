package wayback

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Result represents a Wayback Machine result
type Result struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	HasParams bool   `json:"has_params"`
}

// Run queries Wayback Machine for historical URLs
func Run(target string, cfg *config.Config) ([]Result, error) {
	var results []Result

	domain := utils.ExtractDomain(target)

	// Query Wayback CDX API
	cdxURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&collapse=urlkey&fl=original,timestamp", domain)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(cdxURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data [][]string
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)

	for i, row := range data {
		// Skip header row
		if i == 0 {
			continue
		}

		if len(row) >= 2 {
			urlStr := row[0]
			timestamp := row[1]

			// Filter interesting URLs
			if !isInteresting(urlStr) {
				continue
			}

			// Deduplicate by URL (ignore timestamp variations)
			normalized := normalizeURL(urlStr)
			if seen[normalized] {
				continue
			}
			seen[normalized] = true

			results = append(results, Result{
				URL:       urlStr,
				Timestamp: timestamp,
				HasParams: utils.HasParam(urlStr),
			})
		}
	}

	// Also query CommonCrawl (optional, can be slow)
	// ccResults := queryCommonCrawl(domain)
	// results = append(results, ccResults...)

	return results, nil
}

func isInteresting(urlStr string) bool {
	// Exclude static files
	excludeExts := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp3", ".mp4", ".avi", ".mov", ".wmv",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
	}

	lowerURL := strings.ToLower(urlStr)
	for _, ext := range excludeExts {
		if strings.HasSuffix(lowerURL, ext) {
			return false
		}
	}

	// Include interesting patterns
	interestingPatterns := []string{
		".php", ".asp", ".aspx", ".jsp", ".json", ".xml",
		"api", "admin", "login", "user", "account",
		"config", "backup", "debug", "test",
		"upload", "download", "file", "export",
		"?", "&", "=", // URLs with parameters
	}

	for _, pattern := range interestingPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}

	return false
}

func normalizeURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Remove common tracking parameters
	query := u.Query()
	trackingParams := []string{
		"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
		"fbclid", "gclid", "mc_eid", "_ga",
	}
	for _, param := range trackingParams {
		query.Del(param)
	}
	u.RawQuery = query.Encode()

	return u.String()
}

// QueryAlienVaultOTX queries AlienVault OTX for URLs
func QueryAlienVaultOTX(domain string) ([]Result, error) {
	var results []Result

	urlStr := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		URLList []struct {
			URL  string `json:"url"`
			Date string `json:"date"`
		} `json:"url_list"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	for _, item := range data.URLList {
		if isInteresting(item.URL) {
			results = append(results, Result{
				URL:       item.URL,
				Timestamp: item.Date,
				HasParams: utils.HasParam(item.URL),
			})
		}
	}

	return results, nil
}
