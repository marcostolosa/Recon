# CVE-Hunters Recon Script

<div align="center">

```
  ██████╗██╗   ██╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ███████╗
 ██╔════╝██║   ██║██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝
 ██║     ██║   ██║█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████╗
 ██║     ╚██╗ ██╔╝██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════██║
 ╚██████╗ ╚████╔╝ ███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║███████║
  ╚═════╝  ╚═══╝  ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
```

**Automated reconnaissance framework for bug bounty and penetration testing**

[![Language](https://img.shields.io/badge/Language-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-30+-orange.svg)](#tools)
[![Status](https://img.shields.io/badge/Status-Production--Ready-success.svg)](#)

</div>

---

## Overview

CVE-Hunters is a comprehensive reconnaissance automation framework that orchestrates **30+ security tools** in a sequential pipeline with **checkpoint support**, **intelligent result merging**, and **real-time progress tracking**.

## Installation

### Quick Install

```bash
git clone https://github.com/marcostolosa/Recon.git
cd Recon/
chmod +x subs.sh installation.sh
./installation.sh
```

**Supported Distributions:**
- Kali Linux
- Arch Linux / BlackArch
- Ubuntu / Debian
- Parrot Security OS

### Manual Installation

If the installer doesn't work, install dependencies manually:

```bash
# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/003random/getJS@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Python tools
pip3 install wafw00f sublist3r metabigor

# System tools (Ubuntu/Debian)
sudo apt install -y masscan nmap dnsrecon dnsenum

# System tools (Arch)
sudo pacman -S masscan nmap dnsrecon
```

---

## Usage

### Basic Scan

```bash
./subs.sh -d target.com -w wordlists/common.txt
```

### Complete Scan with All Features

```bash
./subs.sh -d target.com -w wordlists/big.txt \
  -g <github-api-key> \
  -s <shodan-api-key> \
  -f \
  -D \
  -P
```

### Quiet Mode (Minimal Output)

```bash
./subs.sh -d target.com -w wordlists/common.txt -q
```

### Custom Output Directory

```bash
./subs.sh -d target.com -w wordlists/big.txt -o /custom/path
```

### Resume Interrupted Scan

```bash
# First run - interrupted after 5 stages
./subs.sh -d target.com -w wordlists/common.txt
^C  # Ctrl+C

# Second run - continues from stage 6 automatically
./subs.sh -d target.com -w wordlists/common.txt
# Output: [⏭️ ] Etapa 'asn_enum' já completa, pulando...
```

---

## Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| **-d** | Yes | Target domain |
| **-w** | Yes | Wordlist path (see `wordlists/` directory) |
| **-g** | No | GitHub API key (improves subdomain enum) |
| **-s** | No | Shodan API key (**Premium required**) |
| **-o** | No | Custom output folder (default: `./domain`) |
| **-q** | No | Quiet mode (minimal console output) |
| **-f** | No | Enable fuzzing mode (validates vulnerabilities) |
| **-D** | No | Enable directory fuzzing (slow, uses ffuf) |
| **-P** | No | Enable port scanning (requires sudo for masscan) |

### Wordlist Options

Choose wordlist based on scan thoroughness:

| Wordlist | Size | Scan Time | Use Case |
|----------|------|-----------|----------|
| `small.txt` | ~100 | 5-10 min | Quick test |
| `common.txt` | ~1000 | 15-30 min | Standard scan |
| `big.txt` | ~5000 | 1-2 hours | Deep scan |
| `all.txt` | ~100k | 4-8 hours | Comprehensive |

---

## Pipeline Stages

The script executes **17 stages** sequentially:

| # | Stage | Tool(s) | Output |
|---|-------|---------|--------|
| 1 | ASN Enumeration | metabigor | ASNs, IP ranges |
| 2 | Subdomain Enumeration | assetfinder, subfinder, findomain, sublist3r, knockpy, github-subdomains | All discovered subdomains |
| 3 | Organize Domains | regex | Domains by level (2nd, 3rd, 4th+) |
| 4 | DNS Lookup | dnsx, dnsrecon, dnsenum | IPs, DNS records |
| 5 | Check Active | httprobe, httpx | HTTP/HTTPS responsive domains |
| 6 | WAF Detection | wafw00f | Firewall identification |
| 7 | Subdomain Takeover | subjack | Vulnerable subdomains |
| 8 | Favicon Analysis | FavFreak | Favicon hashes for Shodan |
| 9 | Directory Fuzzing | ffuf | Hidden directories (optional -D) |
| 10 | Credential Stuffing | CredStuff-Auxiliary | Leaked credentials |
| 11 | Google Dorks | Custom | Google search queries |
| 12 | GitHub Dorks | Custom | GitHub code searches |
| 13 | Screenshots | EyeWitness | Visual recon |
| 14 | Port Scanning | masscan, nmap, naabu | Open ports (optional -P) |
| 15 | Link Discovery | hakrawler, waybackurls | Crawled URLs |
| 16 | Endpoints Enumeration | ParamSpider, gospider | URLs with parameters |
| 17 | Vulnerability Scan | Nuclei, Gxss, gf | XSS, SQLi, LFI, RCE candidates |

---

## Output Structure

```
output_folder/
├── .checkpoint                    # Resume state
├── asn/
│   └── org.txt                    # ASN ranges
├── subdomains/
│   ├── subdomains.txt             # All discovered subdomains
│   ├── alive.txt                  # Active HTTP/HTTPS hosts
│   ├── waf.txt                    # WAF detection results
│   ├── level-domains.txt          # Organized by domain level
│   ├── knockpy/                   # Knockpy DNS results
│   └── subdomain-takeover/
│       └── takeover.txt           # Vulnerable subdomains
├── DNS/
│   ├── dns.txt                    # DNS responses
│   ├── ip_only.txt                # Extracted IPs
│   ├── dnsrecon.txt               # DNSrecon output
│   └── dnsenum.xml                # DNSenum results
├── favicon-analysis/
│   ├── favfreak/*.txt             # Favicon hashes
│   ├── shodan-results.txt         # Automated Shodan queries
│   └── shodan-manual.txt          # Manual Shodan dorks
├── dorks/
│   ├── google-dorks/dorks.txt     # Google search queries
│   ├── github-dorks/*.txt         # GitHub search links
│   └── credstuff/                 # Credential stuffing results
├── domain-screenshots/            # EyeWitness HTML report
├── fuzz/                          # Directory fuzzing results (if -D)
├── portscan/                      # Port scan results (if -P)
│   ├── nmap.txt
│   ├── masscan.txt
│   └── naabu.txt
├── link-discovery/
│   ├── all.txt                    # All discovered URLs
│   ├── hakrawler/*.txt            # Hakrawler per-domain
│   ├── waybackurls/*.txt          # Wayback URLs per-domain
│   └── js/
│       ├── js.txt                 # All JS files
│       └── AliveJS.txt            # Accessible JS files
└── vuln/
    ├── nuclei.txt                 # Nuclei scan results
    ├── xss-discovery/
    │   ├── possíveis-xss.txt      # XSS candidates
    │   └── xss.txt                # Confirmed XSS (if -f)
    ├── 403.txt                    # 403 Forbidden responses
    ├── possíveis-open-redir.txt   # Open redirect candidates
    ├── rce.txt                    # RCE candidates
    ├── lfi.txt                    # LFI candidates
    └── possíveis-sqli.txt         # SQLi candidates
```

---

## License

MIT License - see [LICENSE](LICENSE) file

---

## Legal Disclaimer

**This tool is for authorized security testing only.**

- **Authorized Use:** Bug bounty programs, pentesting engagements, CTFs, security research with permission
- **Prohibited:** Unauthorized scanning, malicious use, attacks without consent

**Always obtain written authorization before scanning targets you don't own.**

---

## Credits

### Original Author
- **dirsoooo** - [GitHub](https://github.com/dirsoooo)

### Tools Used
Thanks to all the security researchers and developers who created the 30+ tools integrated into this framework.

---

<div align="center">

**Made with by the security community**

**CVE-Hunters Team | 2025**

[Report Issues](https://github.com/marcostolosa/Recon/issues)

</div>
