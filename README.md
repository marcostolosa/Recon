# CVE-Hunters Recon Script

Automated reconnaissance framework for bug bounty and penetration testing. Orchestrates 30+ security tools in a sequential pipeline with checkpoint support and intelligent result merging.

## Key Features

**Checkpoint System**
- Automatic resume on interruption (Ctrl+C)
- State persistence across runs
- Skip completed stages

**Incremental Scanning**
- Merge new results with existing data
- No overwrites, only additions
- Shows delta between scans

**Modern Interface**
- Monokai color scheme
- Progress tracking (X/17 stages, Y%)
- Clean box-style stage banners

## Installation

```bash
git clone https://github.com/marcostolosa/Recon.git
cd Recon/
chmod +x subs.sh installation.sh
./installation.sh
```

Installation script supports: Kali, Arch/BlackArch, Ubuntu/Debian, Parrot

## Usage

### Basic Scan
```bash
./subs.sh -d target.com -w wordlists/common.txt
```

### With API Keys
```bash
./subs.sh -d target.com -w wordlists/common.txt -g <github-key> -s <shodan-key>
```

### Quiet Mode
```bash
./subs.sh -d target.com -w wordlists/common.txt -q
```

### Custom Output Directory
```bash
./subs.sh -d target.com -w wordlists/big.txt -o /path/to/output
```

### Enable Fuzzing
```bash
./subs.sh -d target.com -w wordlists/common.txt -f
```

## Command Line Options

| Option | Required | Description |
|--------|----------|-------------|
| -d | Yes | Target domain |
| -w | Yes | Wordlist path (see wordlists/ directory) |
| -g | No | GitHub API key for subdomain enumeration |
| -s | No | Shodan API key (Premium required) |
| -o | No | Custom output folder (default: ./domain) |
| -q | No | Quiet mode (minimal console output) |
| -f | No | Enable fuzzing mode (slower, validates vulns) |

## Checkpoint System

The script creates a `.checkpoint` file in the output folder tracking completed stages:

```
# CVE-Hunters Checkpoint File
# Scan iniciado em: 2025-01-13 14:30:45
# Alvo: example.com

asn_enum:completed:2025-01-13 14:31:22
subdomain_enum:completed:2025-01-13 14:45:18
```

**Resume interrupted scan:**
```bash
# First run - interrupted
./subs.sh -d target.com -w wordlists/common.txt
^C  # Ctrl+C after 5 stages

# Second run - continues from stage 6
./subs.sh -d target.com -w wordlists/common.txt
# Output: [skip] Etapa 'asn_enum' já completa, pulando...
```

## Incremental Scanning

Running the script multiple times on the same target:
- Preserves existing results
- Adds only new discoveries
- Shows difference summary

```bash
# First scan
./subs.sh -d target.com -w wordlists/common.txt
# Output: [!] Encontrados 234 subdomínios

# Second scan (days later)
./subs.sh -d target.com -w wordlists/big.txt
# Output: [+] Adicionados 47 novos subdomínios (total: 281)
```

## Pipeline Stages

1. ASN Enumeration - metabigor
2. Subdomain Discovery - assetfinder, subfinder, findomain, sublist3r, knockpy, github-subdomains
3. Domain Organization - regex-based categorization
4. Subdomain Takeover - subjack
5. DNS Lookup - dnsx, dnsrecon, dnsenum
6. Active Domain Check - httprobe, httpx
7. WAF Detection - wafw00f
8. Favicon Analysis - FavFreak + Shodan
9. Directory Fuzzing - ffuf (optional)
10. Credential Stuffing - CredStuff-Auxiliary
11. Google Dorking - automated dork generation
12. GitHub Dorking - secret search links
13. Screenshots - EyeWitness
14. Port Scanning - masscan, nmap, naabu (optional)
15. Link Discovery - hakrawler, waybackurls, gospider, ParamSpider
16. Vulnerability Scanning - Nuclei templates, XSS, LFI, RCE, SQLi detection

## Output Structure

```
target.com/
├── .checkpoint                    # Progress state file
├── asn/                          # ASN enumeration
│   └── target.txt
├── subdomains/                   # Subdomain discovery
│   ├── subdomains.txt           # All discovered subdomains
│   ├── subdomains.txt.backup    # Pre-merge backup
│   ├── alive.txt                # Active HTTP/HTTPS domains
│   ├── alive.txt.backup         # Pre-merge backup
│   ├── level-domains.txt        # Organized by domain level
│   ├── waf.txt                  # WAF detection results
│   └── subdomain-takeover/
│       └── takeover.txt
├── DNS/                          # DNS enumeration
│   ├── dns.txt
│   ├── ip_only.txt
│   ├── dnsrecon.txt
│   └── dnsenum.xml
├── favicon-analysis/
│   └── favfreak/
├── dorks/
│   ├── google-dorks/
│   └── github-dorks/
├── link-discovery/
│   ├── all.txt                  # All discovered URLs
│   ├── hakrawler/
│   ├── waybackurls/
│   ├── gospider/
│   └── js/
│       ├── js.txt               # All JS files
│       └── AliveJS.txt          # Accessible JS files
└── vuln/
    ├── nuclei.txt               # Nuclei findings
    ├── possible-xss.txt
    ├── possible-open-redir.txt
    ├── rce.txt
    ├── lfi.txt
    └── possible-sqli.txt
```

## Dependencies

**Required Tools:** python3, go, git, pip3

**Go Tools:** assetfinder, subfinder, httprobe, httpx, nuclei, hakrawler, waybackurls, ffuf, dalfox, anti-burl, Gxss, anew, qsreplace, gf, gospider, subjack, dnsx, metabigor, cf-check, naabu, filter-resolved

**Python Tools:** sublist3r, knockpy, shodan, FavFreak, github-search, ParamSpider, XSStrike, SubDomainizer

**System Tools:** amass, findomain, masscan, nmap, wafw00f, dnsrecon, dnsenum, figlet, lolcat

All dependencies are installed by `installation.sh`

## Notes

**Runtime:** Full scan duration varies by target size (typically hours for large targets)

**API Keys:**
- GitHub key improves subdomain enumeration
- Shodan premium required for automated favicon queries
- Without keys, relevant scans are skipped

**Fuzzing Mode (-f):** Significantly increases runtime, validates potential vulnerabilities

**Interrupted Scans:** Resume capability requires running script with same output folder

**Root Privileges:** Required for port scanning (masscan)

## License

MIT License

## Credits

Based on methodologies from [@ofjaaah](https://twitter.com/ofjaaah) and [@Jhaddix](https://twitter.com/Jhaddix)

Original author: [@Dirsoooo](https://twitter.com/Dirsoooo)

CVE-Hunters modifications: 2025
