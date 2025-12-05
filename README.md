# ReconHunter

```
    ____                       __  __            __
   / __ \___  _________  ____  / / / /_  ______  / /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / __  / /_/ / / / / /_/  __/ /
/_/ |_|\___/\___/\____/_/ /_/_/ /_/\__,_/_/ /_/\__/\___/_/
                                                         v1.0.0
            [ Automated Bug Bounty Recon Framework ]
                        by @a0x194
```

> **ReconHunter** - A comprehensive automated security reconnaissance and vulnerability scanning framework for bug bounty hunters and penetration testers.

---

## Features

```
┌─────────────────────────────────────────────────────────────┐
│                    RECONHUNTER ARSENAL                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [RECON] ════════════════════════════════════════════════   │
│  Asset Discovery & Intelligence                              │
│  ├── Subdomain ─────── Multi-source subdomain enumeration   │
│  ├── HTTPx ─────────── HTTP probing & tech detection        │
│  ├── PortScan ──────── Fast async port scanning             │
│  ├── DirScan ───────── Directory & file bruteforce          │
│  ├── JSHunter ──────── JavaScript analysis & secrets        │
│  ├── Wayback ───────── Historical URL mining                │
│  └── GitLeaks ──────── Git repository exposure              │
│                                                              │
│  [VULN] ═════════════════════════════════════════════════   │
│  Vulnerability Detection                                     │
│  ├── SQLi ──────────── SQL injection (error/time-based)     │
│  ├── XSS ───────────── Cross-site scripting                 │
│  ├── SSRF ──────────── Server-side request forgery          │
│  ├── LFI ───────────── Local file inclusion                 │
│  ├── RCE/CMDi ──────── Command injection                    │
│  ├── SSTI ──────────── Template injection                   │
│  ├── XXE ───────────── XML external entity                  │
│  ├── CORS ──────────── CORS misconfiguration                │
│  ├── JWT ───────────── JWT vulnerabilities                  │
│  ├── CRLF ──────────── HTTP header injection                │
│  ├── Redirect ──────── Open redirect                        │
│  ├── Takeover ──────── Subdomain takeover (40+ services)    │
│  └── Headers ───────── Security headers analysis            │
│                                                              │
│  [REPORT] ═══════════════════════════════════════════════   │
│  Export Formats                                              │
│  ├── JSON ──────────── Structured data                      │
│  ├── CSV ───────────── Spreadsheet format                   │
│  ├── Markdown ──────── Documentation ready                  │
│  └── HTML ──────────── Styled report                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### Download Binary

Download the latest release from [Releases](https://github.com/a0x194/recon-hunter/releases):

```bash
# Linux
wget https://github.com/a0x194/recon-hunter/releases/latest/download/reconhunter-linux-amd64
chmod +x reconhunter-linux-amd64
sudo mv reconhunter-linux-amd64 /usr/local/bin/reconhunter

# Windows
# Download reconhunter-windows-amd64.exe from releases
```

### Build from Source

```bash
git clone https://github.com/a0x194/recon-hunter.git
cd recon-hunter
go build -o reconhunter ./cmd/reconhunter
```

---

## Usage

### Full Scan (Recon + Vuln)

```bash
>_ reconhunter scan -t example.com
```

### Reconnaissance Only

```bash
>_ reconhunter recon -t example.com
```

### Vulnerability Scan Only

```bash
>_ reconhunter vuln -t example.com -l targets.txt
```

### Specific Modules

```bash
# Run only specific modules
>_ reconhunter scan -t example.com -m sqli,xss,cors,ssrf

# Exclude modules
>_ reconhunter scan -t example.com --exclude portscan,dirscan
```

### Advanced Options

```bash
# With proxy (Burp Suite)
>_ reconhunter scan -t example.com --proxy http://127.0.0.1:8080

# Custom threads and rate limit
>_ reconhunter scan -t example.com -T 100 -r 200

# Multiple targets from file
>_ reconhunter scan -l targets.txt -o ./results

# JSON output
>_ reconhunter scan -t example.com --json
```

---

## Command Reference

```
Usage:
  reconhunter [command]

Available Commands:
  scan        Run full automated scan (recon + vuln)
  recon       Run reconnaissance only
  vuln        Run vulnerability scanning only
  monitor     Start continuous monitoring mode
  report      Generate report from scan results
  modules     List all available modules
  version     Print version information

Flags:
  -t, --target string     Target domain
  -l, --list string       File containing list of targets
  -o, --output string     Output directory (default "./output")
  -m, --modules strings   Specific modules to run
      --exclude strings   Modules to exclude
  -T, --threads int       Number of concurrent threads (default 50)
  -r, --rate int          Requests per second (default 150)
      --timeout int       Request timeout in seconds (default 30)
      --proxy string      HTTP proxy URL
  -c, --config string     Config file path
      --json              JSON output format
  -v, --verbose           Verbose output
  -s, --silent            Silent mode
      --notify string     Webhook URL for notifications
```

---

## Output Example

```
>_ reconhunter scan -t vulnerable.com

    ____                       __  __            __
   / __ \___  _________  ____  / / / /_  ______  / /____  _____
  / /_/ / _ \/ ___/ __ \/ __ \/ /_/ / / / / __ \/ __/ _ \/ ___/
 / _, _/  __/ /__/ /_/ / / / / __  / /_/ / / / / /_/  __/ /
/_/ |_|\___/\___/\____/_/ /_/_/ /_/\__,_/_/ /_/\__/\___/_/

[*] Starting scan for: vulnerable.com
[*] Scan mode: full

[=] Phase 1: Reconnaissance

[*] Running subdomain enumeration...
[+] Found 47 subdomains
[*] Running HTTP probing...
[+] Found 32 live hosts
[*] Running JavaScript analysis...
[+] Analyzed 156 JS files
[+] Found 3 potential secrets!

[=] Phase 2: Vulnerability Scanning

[CRITICAL] SQL Injection - https://vulnerable.com/search?q=
[HIGH] CORS Misconfiguration - https://api.vulnerable.com/
[MEDIUM] Missing Security Headers - https://vulnerable.com/
[HIGH] Open Redirect - https://vulnerable.com/redirect?url=

════════════════════════════════════════════════════════════
                    SCAN SUMMARY
════════════════════════════════════════════════════════════

Target:           vulnerable.com
Duration:         4m 32s

=== Reconnaissance ===
Subdomains:       47
Live Hosts:       32
JS Files:         156
Secrets Found:    3

=== Vulnerabilities ===
Critical:         1
High:             2
Medium:           5
Low:              8
Total:            16

[+] Results saved to: ./output/vulnerable.com/
```

---

## Subdomain Takeover Detection

ReconHunter includes fingerprints for **40+ services**:

```
AWS S3, GitHub Pages, Heroku, Shopify, Tumblr, WordPress,
Ghost, Pantheon, Surge.sh, Zendesk, Fastly, Unbounce,
UserVoice, Statuspage, Bitbucket, Intercom, Webflow,
Kajabi, Thinkific, Tilda, Squarespace, HelpScout, Freshdesk,
Azure, Google Cloud Storage, Firebase, Netlify, Vercel,
Fly.io, Render, ReadMe, Gitbook, and more...
```

---

## Configuration File

Create `config.yaml` for persistent settings:

```yaml
threads: 50
timeout: 30
rate_limit: 150
output_dir: "./output"
proxy: ""

modules:
  subdomain:
    enabled: true
    wordlist: "./wordlists/subdomains.txt"

  sqli:
    enabled: true
    time_based: true

  xss:
    enabled: true

notify:
  discord: "https://discord.com/api/webhooks/..."
  slack: "https://hooks.slack.com/services/..."
```

---

## Related Projects

```
>_ More tools by @a0x194:

├── TryHarder Extension  - 15-in-1 browser security toolkit
├── CORScan             - CORS misconfiguration scanner
├── HTTPSmuggler        - HTTP request smuggling detector
├── CloudBucket         - Cloud storage bucket finder
└── CICDGuard           - CI/CD pipeline security checker

>_ CTF Platform: https://tryharder.space
```

---

## Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║  [!] WARNING                                                   ║
║                                                                ║
║  This tool is intended for authorized security testing only.  ║
║  Always obtain proper authorization before scanning targets.  ║
║  Unauthorized access to computer systems is illegal.          ║
║                                                                ║
║  The author is not responsible for any misuse of this tool.   ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

```
>_ Built with passion.
>_ Hack Harder. Hunt Smarter.
>_ github.com/a0x194
```
