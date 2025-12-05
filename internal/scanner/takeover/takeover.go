package takeover

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
)

// Fingerprints for subdomain takeover detection
var takeoverFingerprints = []struct {
	service     string
	cname       []string
	fingerprint []string
	severity    string
}{
	{
		"AWS S3",
		[]string{".s3.amazonaws.com", ".s3-website", "s3.amazonaws.com"},
		[]string{"NoSuchBucket", "The specified bucket does not exist"},
		"high",
	},
	{
		"GitHub Pages",
		[]string{".github.io", "pages.github.com"},
		[]string{"There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"},
		"high",
	},
	{
		"Heroku",
		[]string{".herokuapp.com", ".herokussl.com", "heroku.com"},
		[]string{"No such app", "no-such-app", "herokucdn.com/error-pages/no-such-app"},
		"high",
	},
	{
		"Shopify",
		[]string{".myshopify.com", "shops.myshopify.com"},
		[]string{"Sorry, this shop is currently unavailable", "Only one step left"},
		"medium",
	},
	{
		"Tumblr",
		[]string{".tumblr.com", "domains.tumblr.com"},
		[]string{"Whatever you were looking for doesn't currently exist at this address", "There's nothing here"},
		"medium",
	},
	{
		"WordPress.com",
		[]string{".wordpress.com"},
		[]string{"Do you want to register", "doesn't exist"},
		"medium",
	},
	{
		"Ghost",
		[]string{".ghost.io"},
		[]string{"The thing you were looking for is no longer here"},
		"medium",
	},
	{
		"Pantheon",
		[]string{".pantheonsite.io", ".pantheon.io"},
		[]string{"The gods are wise, but do not know of the site which you seek", "404 error unknown site"},
		"high",
	},
	{
		"Surge.sh",
		[]string{".surge.sh"},
		[]string{"project not found"},
		"high",
	},
	{
		"Zendesk",
		[]string{".zendesk.com"},
		[]string{"Help Center Closed", "Oops, this help center no longer exists"},
		"medium",
	},
	{
		"Fastly",
		[]string{".fastly.net", "fastly.com"},
		[]string{"Fastly error: unknown domain"},
		"high",
	},
	{
		"Unbounce",
		[]string{".unbounce.com", "unbouncepages.com"},
		[]string{"The requested URL was not found on this server", "The page you're looking for isn't here"},
		"medium",
	},
	{
		"UserVoice",
		[]string{".uservoice.com"},
		[]string{"This UserVoice subdomain is currently available!"},
		"high",
	},
	{
		"Cargo",
		[]string{".cargocollective.com"},
		[]string{"404 Not Found"},
		"low",
	},
	{
		"Statuspage",
		[]string{".statuspage.io"},
		[]string{"You are being redirected", "Status page not found"},
		"medium",
	},
	{
		"Bitbucket",
		[]string{".bitbucket.io"},
		[]string{"Repository not found"},
		"high",
	},
	{
		"Intercom",
		[]string{".intercom.io", "custom.intercom.help"},
		[]string{"This page is reserved for artistic dogs", "Uh oh. That page doesn't exist"},
		"medium",
	},
	{
		"Webflow",
		[]string{".webflow.io", "proxy.webflow.com"},
		[]string{"The page you are looking for doesn't exist or has been moved"},
		"medium",
	},
	{
		"Kajabi",
		[]string{".kajabi.com", ".mykajabi.com"},
		[]string{"The page you were looking for doesn't exist"},
		"medium",
	},
	{
		"Thinkific",
		[]string{".thinkific.com"},
		[]string{"You may have mistyped the address or the page may have moved"},
		"medium",
	},
	{
		"Tilda",
		[]string{".tilda.ws"},
		[]string{"Domain has been assigned", "Please go to"},
		"medium",
	},
	{
		"Squarespace",
		[]string{".squarespace.com"},
		[]string{"No Such Account", "This domain is registered at Squarespace"},
		"medium",
	},
	{
		"HelpScout",
		[]string{".helpscoutdocs.com"},
		[]string{"No settings were found for this company"},
		"medium",
	},
	{
		"HelpJuice",
		[]string{".helpjuice.com"},
		[]string{"We could not find what you're looking for"},
		"medium",
	},
	{
		"Freshdesk",
		[]string{".freshdesk.com"},
		[]string{"May be this is still fresh", "There is no helpdesk here"},
		"medium",
	},
	{
		"Azure",
		[]string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net"},
		[]string{"404 Web Site not found", "Web App not found"},
		"high",
	},
	{
		"Google Cloud Storage",
		[]string{".storage.googleapis.com"},
		[]string{"The specified bucket does not exist", "NoSuchBucket"},
		"high",
	},
	{
		"Firebase",
		[]string{".firebaseapp.com", ".web.app"},
		[]string{"Site Not Found"},
		"high",
	},
	{
		"Netlify",
		[]string{".netlify.app", ".netlify.com"},
		[]string{"Not Found - Request ID"},
		"high",
	},
	{
		"Vercel",
		[]string{".vercel.app", ".now.sh"},
		[]string{"The deployment could not be found", "DEPLOYMENT_NOT_FOUND"},
		"high",
	},
	{
		"Fly.io",
		[]string{".fly.dev"},
		[]string{"404 Not Found"},
		"medium",
	},
	{
		"Render",
		[]string{".onrender.com"},
		[]string{"Not Found"},
		"medium",
	},
	{
		"ReadMe",
		[]string{".readme.io"},
		[]string{"Project doesnt exist... yet!"},
		"medium",
	},
	{
		"Gitbook",
		[]string{".gitbook.io"},
		[]string{"If you need to, you can always create your own GitBook space"},
		"medium",
	},
	{
		"Tictail",
		[]string{".tictail.com"},
		[]string{"to target URL: <a href=\"https://tictail.com\"", "Building a brand"},
		"low",
	},
	{
		"Smartling",
		[]string{".smartling.com"},
		[]string{"Domain is not configured"},
		"medium",
	},
	{
		"Pingdom",
		[]string{".stats.pingdom.com"},
		[]string{"Sorry, couldn't find the status page"},
		"medium",
	},
	{
		"Desk",
		[]string{".desk.com"},
		[]string{"Please try again or try Desk.com free for 14 days", "Sorry, We Couldn't Find That Page"},
		"medium",
	},
	{
		"Teamwork",
		[]string{".teamwork.com"},
		[]string{"Oops - We didn't find your site"},
		"medium",
	},
	{
		"Aftership",
		[]string{".aftership.com"},
		[]string{"Oops, page not found"},
		"medium",
	},
	{
		"Aha",
		[]string{".ideas.aha.io"},
		[]string{"There is no portal here ... check portal url"},
		"medium",
	},
	{
		"Brightcove",
		[]string{".brightcovegallery.com", ".gallery.video", ".bcvp0rtal.com"},
		[]string{"<p class=\"bc-gallery-error-code\">Error Code: 404</p>"},
		"medium",
	},
	{
		"Campaignmonitor",
		[]string{".createsend.com"},
		[]string{"Double check the URL or"},
		"medium",
	},
	{
		"Acquia",
		[]string{".acquia-test.co"},
		[]string{"Web Site Not Found", "The site you are looking for could not be found"},
		"medium",
	},
	{
		"Proposify",
		[]string{".proposify.biz"},
		[]string{"If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz\""},
		"medium",
	},
	{
		"LaunchRock",
		[]string{".launchrock.com"},
		[]string{"It looks like you may have taken a wrong turn somewhere"},
		"medium",
	},
}

// NXDOMAIN patterns
var nxdomainPatterns = []string{
	"NXDOMAIN",
	"SERVFAIL",
	"no such host",
	"Name or service not known",
}

// Scan performs subdomain takeover scanning
func Scan(subdomains []string, cfg *config.Config) ([]types.VulnResult, error) {
	var results []types.VulnResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, cfg.Threads)

	for _, subdomain := range subdomains {
		wg.Add(1)
		sem <- struct{}{}

		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()

			result := checkTakeover(domain, client)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()
	return results, nil
}

func checkTakeover(domain string, client *http.Client) *types.VulnResult {
	// First, check CNAME records
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		// Check if it's NXDOMAIN
		errStr := err.Error()
		for _, pattern := range nxdomainPatterns {
			if strings.Contains(errStr, pattern) {
				// Domain doesn't resolve - check if it has a dangling CNAME
				return checkDanglingCNAME(domain)
			}
		}
		return nil
	}

	// Remove trailing dot
	cname = strings.TrimSuffix(cname, ".")

	// Check against known vulnerable services
	for _, fp := range takeoverFingerprints {
		for _, cnamePattern := range fp.cname {
			if strings.Contains(strings.ToLower(cname), strings.ToLower(cnamePattern)) {
				// Found potential vulnerable CNAME, verify with HTTP request
				result := verifyTakeover(domain, cname, fp, client)
				if result != nil {
					return result
				}
			}
		}
	}

	return nil
}

func checkDanglingCNAME(domain string) *types.VulnResult {
	// Try to get CNAME from alternative sources or check common patterns
	// This is a simplified check - in production you'd use DNS over HTTPS or other methods

	// For now, return a potential finding that needs manual verification
	return nil
}

func verifyTakeover(domain, cname string, fp struct {
	service     string
	cname       []string
	fingerprint []string
	severity    string
}, client *http.Client) *types.VulnResult {
	// Try both HTTP and HTTPS
	urls := []string{
		"https://" + domain,
		"http://" + domain,
	}

	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		bodyStr := string(body)

		// Check for fingerprint in response
		for _, pattern := range fp.fingerprint {
			if strings.Contains(bodyStr, pattern) {
				return &types.VulnResult{
					Type:        "Subdomain Takeover",
					Severity:    fp.severity,
					URL:         url,
					Description: fmt.Sprintf("Subdomain takeover possible via %s", fp.service),
					Evidence:    fmt.Sprintf("CNAME: %s, Fingerprint matched: %s", cname, pattern),
					Remediation: fmt.Sprintf("Remove the DNS record pointing to %s or claim the resource on %s", cname, fp.service),
					References: []string{
						"https://github.com/EdOverflow/can-i-take-over-xyz",
						"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
					},
				}
			}
		}
	}

	return nil
}

// ScanWithURLs scans URLs directly (without subdomain extraction)
func ScanWithURLs(urls []string, cfg *config.Config) ([]types.VulnResult, error) {
	var subdomains []string

	for _, urlStr := range urls {
		// Extract domain from URL
		if strings.HasPrefix(urlStr, "http") {
			parts := strings.Split(urlStr, "/")
			if len(parts) >= 3 {
				subdomains = append(subdomains, parts[2])
			}
		} else {
			subdomains = append(subdomains, urlStr)
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, s := range subdomains {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}

	return Scan(unique, cfg)
}
