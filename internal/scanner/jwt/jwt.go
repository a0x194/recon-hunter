package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// Common weak secrets for JWT signing
var weakSecrets = []string{
	"secret", "password", "123456", "12345678", "1234567890",
	"qwerty", "admin", "administrator", "letmein", "welcome",
	"monkey", "password1", "password123", "abc123", "111111",
	"master", "hello", "freedom", "whatever", "qazwsx",
	"trustno1", "654321", "jordan23", "harley", "password1!",
	"iloveyou", "sunshine", "princess", "football", "baseball",
	"superman", "michael", "shadow", "passw0rd", "dragon",
	"P@ssw0rd", "P@ssword1", "P@$$w0rd", "Passw0rd!", "Password!",
	"jwt_secret", "jwt_secret_key", "jwt-secret", "jwt-secret-key",
	"my_secret", "my_secret_key", "mysecret", "secretkey", "secret_key",
	"auth_secret", "auth_key", "authkey", "authentication_key",
	"api_key", "api_secret", "apikey", "apisecret",
	"token_secret", "token_key", "tokenkey", "tokensecret",
	"hmac_secret", "hmac_key", "hmackey", "hmacsecret",
	"private_key", "privatekey", "public_key", "publickey",
	"signing_key", "signingkey", "sign_key", "signkey",
	"encryption_key", "encryptionkey", "encrypt_key", "encryptkey",
	"app_secret", "app_key", "appkey", "appsecret",
	"session_secret", "session_key", "sessionkey", "sessionsecret",
	"dev", "development", "test", "testing", "staging", "production",
	"changeme", "change_me", "changeit", "change_it",
	"default", "default_secret", "defaultsecret", "defaultkey",
	"example", "sample", "demo", "temporary", "temp",
	"supersecret", "super_secret", "topsecret", "top_secret",
	"verysecret", "very_secret", "ultrasecret", "ultra_secret",
	"key", "key123", "key1234", "mykey", "thekey", "secretkey123",
	"gfhjkm", "ghjuihkihuuhuhuh", "asdfghjkl", "zxcvbnm",
	"qwertyuiop", "1q2w3e4r", "1q2w3e4r5t", "q1w2e3r4",
	"your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
	"HS256-secret", "HS384-secret", "HS512-secret",
	"notsosecret", "not_so_secret", "notreallyasecret",
}

// JWT header for "alg: none" attack
var noneAlgHeaders = []string{
	`{"alg":"none","typ":"JWT"}`,
	`{"alg":"None","typ":"JWT"}`,
	`{"alg":"NONE","typ":"JWT"}`,
	`{"alg":"nOnE","typ":"JWT"}`,
	`{"typ":"JWT","alg":"none"}`,
	`{"typ":"JWT","alg":"None"}`,
}

// JWTToken represents a parsed JWT
type JWTToken struct {
	Header    map[string]interface{}
	Payload   map[string]interface{}
	Signature string
	Raw       string
}

// Scan performs JWT security scanning
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

			vulns := analyzeJWT(u, client)
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

func analyzeJWT(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	resp, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check response headers for JWTs
	for name, values := range resp.Header {
		for _, value := range values {
			if token := extractJWT(value); token != nil {
				vulns := analyzeToken(token, urlStr, fmt.Sprintf("Header: %s", name))
				results = append(results, vulns...)
			}
		}
	}

	// Check cookies for JWTs
	for _, cookie := range resp.Cookies() {
		if token := extractJWT(cookie.Value); token != nil {
			vulns := analyzeToken(token, urlStr, fmt.Sprintf("Cookie: %s", cookie.Name))
			results = append(results, vulns...)
		}
	}

	// Check response body for JWTs
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return results
	}

	bodyStr := string(body)
	tokens := findJWTsInText(bodyStr)
	for _, token := range tokens {
		vulns := analyzeToken(token, urlStr, "Response body")
		results = append(results, vulns...)
	}

	return results
}

func extractJWT(value string) *JWTToken {
	// Remove "Bearer " prefix if present
	value = strings.TrimPrefix(value, "Bearer ")
	value = strings.TrimSpace(value)

	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil
	}

	// Decode header
	header, err := base64URLDecode(parts[0])
	if err != nil {
		return nil
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(header, &headerMap); err != nil {
		return nil
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil
	}

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payload, &payloadMap); err != nil {
		return nil
	}

	return &JWTToken{
		Header:    headerMap,
		Payload:   payloadMap,
		Signature: parts[2],
		Raw:       value,
	}
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func findJWTsInText(text string) []*JWTToken {
	var tokens []*JWTToken

	// Simple regex-like search for JWT pattern
	words := strings.Fields(text)
	for _, word := range words {
		// Clean up the word
		word = strings.Trim(word, `"'<>,;:()[]{}`)

		if token := extractJWT(word); token != nil {
			tokens = append(tokens, token)
		}
	}

	return tokens
}

func analyzeToken(token *JWTToken, urlStr, location string) []types.VulnResult {
	var results []types.VulnResult

	// Check algorithm
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return results
	}

	// Check for "none" algorithm
	if strings.ToLower(alg) == "none" {
		results = append(results, types.VulnResult{
			Type:        "JWT Algorithm None",
			Severity:    "critical",
			URL:         urlStr,
			Evidence:    fmt.Sprintf("JWT with alg:none found in %s. Token: %s", location, truncateToken(token.Raw)),
			Description: "JWT uses 'none' algorithm, allowing signature bypass",
			Remediation: "Explicitly verify the algorithm in the JWT library. Reject tokens with 'none' algorithm.",
			References: []string{
				"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
				"https://portswigger.net/web-security/jwt/algorithm-confusion",
			},
		})
	}

	// Check for weak algorithms
	if alg == "HS256" || alg == "HS384" || alg == "HS512" {
		// Try weak secrets
		for _, secret := range weakSecrets {
			if verifyHS256(token, secret) {
				results = append(results, types.VulnResult{
					Type:        "JWT Weak Secret",
					Severity:    "critical",
					URL:         urlStr,
					Evidence:    fmt.Sprintf("JWT signed with weak secret '%s' in %s", secret, location),
					Description: "JWT is signed with a weak/common secret that can be easily guessed",
					Remediation: "Use a strong, random secret of at least 256 bits. Consider using asymmetric algorithms (RS256, ES256).",
					References: []string{
						"https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/",
					},
				})
				break
			}
		}
	}

	// Check for algorithm confusion vulnerability indicators
	if strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "ES") || strings.HasPrefix(alg, "PS") {
		// Asymmetric algorithm - check if we can find the public key
		results = append(results, types.VulnResult{
			Type:        "JWT Algorithm Confusion Risk",
			Severity:    "info",
			URL:         urlStr,
			Evidence:    fmt.Sprintf("JWT uses asymmetric algorithm %s in %s. Check for algorithm confusion vulnerability.", alg, location),
			Description: "JWT uses asymmetric algorithm. Test for algorithm confusion by trying HS256 with public key as secret.",
			Remediation: "Ensure the server strictly validates the expected algorithm.",
			References: []string{
				"https://portswigger.net/web-security/jwt/algorithm-confusion",
			},
		})
	}

	// Check for sensitive data in payload
	sensitiveKeys := []string{
		"password", "passwd", "pwd", "secret", "apikey", "api_key",
		"token", "auth", "credit_card", "cc", "ssn", "private",
		"key", "credentials", "creds",
	}

	for key := range token.Payload {
		keyLower := strings.ToLower(key)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(keyLower, sensitive) {
				results = append(results, types.VulnResult{
					Type:        "JWT Sensitive Data Exposure",
					Severity:    "medium",
					URL:         urlStr,
					Evidence:    fmt.Sprintf("JWT contains potentially sensitive claim '%s' in %s", key, location),
					Description: "JWT payload contains sensitive data that could be extracted without verification",
					Remediation: "Never store sensitive data in JWT payloads. JWTs are encoded, not encrypted.",
					References: []string{
						"https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
					},
				})
				break
			}
		}
	}

	// Check for missing expiration
	if _, ok := token.Payload["exp"]; !ok {
		results = append(results, types.VulnResult{
			Type:        "JWT Missing Expiration",
			Severity:    "medium",
			URL:         urlStr,
			Evidence:    fmt.Sprintf("JWT without expiration claim in %s", location),
			Description: "JWT does not have an expiration time, making it valid indefinitely",
			Remediation: "Always include 'exp' claim with a reasonable expiration time.",
			References: []string{
				"https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4",
			},
		})
	}

	// Check for kid header injection
	if kid, ok := token.Header["kid"].(string); ok {
		if strings.Contains(kid, "/") || strings.Contains(kid, "..") || strings.Contains(kid, "\\") {
			results = append(results, types.VulnResult{
				Type:        "JWT KID Injection",
				Severity:    "high",
				URL:         urlStr,
				Evidence:    fmt.Sprintf("JWT 'kid' header contains suspicious characters: %s", kid),
				Description: "JWT Key ID (kid) may be vulnerable to path traversal or injection",
				Remediation: "Validate and sanitize the 'kid' header. Use a whitelist of allowed key IDs.",
				References: []string{
					"https://portswigger.net/web-security/jwt",
				},
			})
		}

		// Check for SQL injection in kid
		sqlKeywords := []string{"'", "\"", ";", "--", "/*", "*/", "union", "select", "insert", "update", "delete", "drop"}
		kidLower := strings.ToLower(kid)
		for _, kw := range sqlKeywords {
			if strings.Contains(kidLower, kw) {
				results = append(results, types.VulnResult{
					Type:        "JWT KID SQL Injection",
					Severity:    "critical",
					URL:         urlStr,
					Evidence:    fmt.Sprintf("JWT 'kid' header contains SQL characters: %s", kid),
					Description: "JWT Key ID (kid) may be vulnerable to SQL injection if used in database queries",
					Remediation: "Never use 'kid' directly in SQL queries. Use parameterized queries.",
					References: []string{
						"https://portswigger.net/web-security/jwt",
					},
				})
				break
			}
		}
	}

	// Check for jku/x5u header (URL-based key retrieval)
	if jku, ok := token.Header["jku"].(string); ok {
		results = append(results, types.VulnResult{
			Type:        "JWT JKU Header Present",
			Severity:    "high",
			URL:         urlStr,
			Evidence:    fmt.Sprintf("JWT contains 'jku' header pointing to: %s", jku),
			Description: "JWT uses JKU header for key retrieval. This could be exploited to use attacker-controlled keys.",
			Remediation: "Validate JKU URLs against a strict whitelist. Consider disabling JKU header support.",
			References: []string{
				"https://portswigger.net/web-security/jwt/jku-header-injection",
			},
		})
	}

	if x5u, ok := token.Header["x5u"].(string); ok {
		results = append(results, types.VulnResult{
			Type:        "JWT X5U Header Present",
			Severity:    "high",
			URL:         urlStr,
			Evidence:    fmt.Sprintf("JWT contains 'x5u' header pointing to: %s", x5u),
			Description: "JWT uses X5U header for certificate retrieval. This could be exploited to use attacker-controlled certificates.",
			Remediation: "Validate X5U URLs against a strict whitelist. Consider disabling X5U header support.",
			References: []string{
				"https://portswigger.net/web-security/jwt",
			},
		})
	}

	return results
}

func verifyHS256(token *JWTToken, secret string) bool {
	parts := strings.Split(token.Raw, ".")
	if len(parts) != 3 {
		return false
	}

	message := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	expectedSig := base64URLEncode(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(parts[2]))
}

func truncateToken(token string) string {
	if len(token) > 100 {
		return token[:50] + "..." + token[len(token)-20:]
	}
	return token
}

// CreateNoneToken creates a JWT with "alg: none" for testing
func CreateNoneToken(payload map[string]interface{}) string {
	header := base64URLEncode([]byte(`{"alg":"none","typ":"JWT"}`))

	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64URLEncode(payloadBytes)

	return header + "." + payloadB64 + "."
}

// CreateHS256Token creates a JWT signed with HS256 for testing
func CreateHS256Token(payload map[string]interface{}, secret string) string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64URLEncode(payloadBytes)

	message := header + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	signature := base64URLEncode(mac.Sum(nil))

	return message + "." + signature
}
