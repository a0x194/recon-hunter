package subdomain

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/utils"
	"github.com/fatih/color"
)

// Run performs subdomain enumeration
func Run(target string, cfg *config.Config) ([]string, error) {
	var allSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	domain := utils.ExtractDomain(target)

	// Define sources
	sources := []struct {
		name string
		fn   func(string) ([]string, error)
	}{
		{"crt.sh", queryCrtSh},
		{"HackerTarget", queryHackerTarget},
		{"ThreatCrowd", queryThreatCrowd},
		{"AlienVault", queryAlienVault},
		{"URLScan", queryURLScan},
		{"RapidDNS", queryRapidDNS},
		{"Omnisint", queryOmnisint},
	}

	// Query each source concurrently
	for _, source := range sources {
		wg.Add(1)
		go func(name string, fn func(string) ([]string, error)) {
			defer wg.Done()

			subs, err := fn(domain)
			if err != nil {
				if cfg.Verbose {
					color.Yellow("[!] %s: %v", name, err)
				}
				return
			}

			mu.Lock()
			allSubdomains = append(allSubdomains, subs...)
			mu.Unlock()

			if cfg.Verbose {
				color.Green("[+] %s: found %d subdomains", name, len(subs))
			}
		}(source.name, source.fn)
	}

	wg.Wait()

	// Deduplicate and validate
	allSubdomains = utils.UniqueStrings(allSubdomains)

	// Filter valid subdomains for this domain
	var validSubdomains []string
	for _, sub := range allSubdomains {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if strings.HasSuffix(sub, "."+domain) || sub == domain {
			if utils.IsValidDomain(sub) {
				validSubdomains = append(validSubdomains, sub)
			}
		}
	}

	// Optional: DNS resolution to verify
	if cfg.Subdomain != nil && cfg.Subdomain.WildcardCheck {
		validSubdomains = filterWildcard(validSubdomains, domain)
	}

	// Resolve subdomains
	validSubdomains = resolveSubdomains(validSubdomains, cfg.Threads)

	return validSubdomains, nil
}

func queryCrtSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, r := range results {
		names := strings.Split(r.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimPrefix(name, "*.")
			subdomains = append(subdomains, name)
		}
	}

	return subdomains, nil
}

func queryHackerTarget(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var subdomains []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 1 && parts[0] != "" {
			subdomains = append(subdomains, parts[0])
		}
	}

	return subdomains, nil
}

func queryThreatCrowd(domain string) ([]string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result.Subdomains, nil
}

func queryAlienVault(domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, record := range result.PassiveDNS {
		subdomains = append(subdomains, record.Hostname)
	}

	return subdomains, nil
}

func queryURLScan(domain string) ([]string, error) {
	url := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "ReconHunter/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var subdomains []string
	for _, r := range result.Results {
		if r.Page.Domain != "" {
			subdomains = append(subdomains, r.Page.Domain)
		}
	}

	return subdomains, nil
}

func queryRapidDNS(domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Extract subdomains from HTML
	re := regexp.MustCompile(`<td>([a-zA-Z0-9\-\.]+\.` + regexp.QuoteMeta(domain) + `)</td>`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	var subdomains []string
	for _, match := range matches {
		if len(match) > 1 {
			subdomains = append(subdomains, match[1])
		}
	}

	return subdomains, nil
}

func queryOmnisint(domain string) ([]string, error) {
	url := fmt.Sprintf("https://sonar.omnisint.io/subdomains/%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var subdomains []string
	if err := json.Unmarshal(body, &subdomains); err != nil {
		// Try parsing as newline-separated
		return strings.Split(string(body), "\n"), nil
	}

	return subdomains, nil
}

func filterWildcard(subdomains []string, domain string) []string {
	// Check if wildcard DNS exists
	randomSub := fmt.Sprintf("randomnonexistent123456.%s", domain)
	_, err := net.LookupHost(randomSub)
	if err == nil {
		// Wildcard exists, need to filter
		wildcardIPs, _ := net.LookupHost(randomSub)

		var filtered []string
		for _, sub := range subdomains {
			ips, err := net.LookupHost(sub)
			if err != nil {
				continue
			}
			// Check if IPs are different from wildcard
			if !sameIPs(ips, wildcardIPs) {
				filtered = append(filtered, sub)
			}
		}
		return filtered
	}

	return subdomains
}

func sameIPs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ipMap := make(map[string]bool)
	for _, ip := range a {
		ipMap[ip] = true
	}
	for _, ip := range b {
		if !ipMap[ip] {
			return false
		}
	}
	return true
}

func resolveSubdomains(subdomains []string, threads int) []string {
	var resolved []string
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}

		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }()

			_, err := net.LookupHost(subdomain)
			if err == nil {
				mu.Lock()
				resolved = append(resolved, subdomain)
				mu.Unlock()
			}
		}(sub)
	}

	wg.Wait()
	return resolved
}
