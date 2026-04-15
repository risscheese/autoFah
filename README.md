# autoFah — Detail Web Recon & Vulnerability Pipeline

A multi-stage automated web reconnaissance and vulnerability scanning toolkit
designed for penetration testers and security researchers.

> **Legal notice**: Only use against systems you own or have explicit written
> permission to test. Unauthorized scanning is illegal.

---

## Tool Overview

| Script | Role |
|--------|------|
| `autoFah.sh` | Quick 2-stage gobuster recon (dirs + hidden files) |
| `detail_FahScan.sh` | Full 6-stage pipeline: recon → param discovery → vuln scan → version intel → path intel |

### Pipeline Stages (`detail_FahScan.sh`)

```
Stage 1  Directory brute-force        gobuster (dirCommon.txt)
Stage 2  Hidden file discovery         gobuster per dir (hiddenFiles.txt)
Stage 3  Parameter & method detection  para.py
Stage 4  Vulnerability scanning        vuln_scan.py → Nikto + Nuclei
Stage 5  Component version intel       version_scan.py → EOL + NVD CVE check
Stage 6  Path & file vuln intel        path_intel.py → content + pattern analysis
```

---

## Requirements

### System Tools

| Tool | Required by | Install |
|------|-------------|---------|
| `gobuster` | Stages 1 & 2 | `apt install gobuster` |
| `nikto` | Stage 4 | `apt install nikto` |
| `nuclei` | Stage 4 | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) |
| `python3` | Stages 3–6 | `apt install python3` |
| `whatweb` | Stage 5 (optional) | `apt install whatweb` |

### Python Libraries

```bash
pip3 install requests beautifulsoup4 packaging
```

| Package | Used by |
|---------|---------|
| `requests` | para.py, version_scan.py, path_intel.py |
| `beautifulsoup4` | para.py, version_scan.py, path_intel.py |
| `packaging` | version_scan.py |

> The pipeline installs missing Python packages automatically via `pip3`.

---

## Installation

```bash
git clone https://github.com/risscheese/autoFah.git
cd autoFah
chmod +x autoFah.sh detail_FahScan.sh
```

---

## Usage

### Quick Scan (2 stages)

```bash
./autoFah.sh http://192.168.1.100
./autoFah.sh https://example.com
```

### Full Detail Scan (6 stages)

```bash
./detail_FahScan.sh http://192.168.1.100
./detail_FahScan.sh https://example.com
```

#### Example output (truncated)

```
  autoFah — Detail Scan Pipeline
  Target  : http://192.168.8.101
  Started : 2026-04-14 11:30:00

[+] ══════════════════════════════════════
    STAGE 1: Directory Discovery
[+] ══════════════════════════════════════
[+] Found 8 path(s) in 12s. Saved → dir_discovery.txt

[+] ══════════════════════════════════════
    STAGE 2: Hidden File Discovery
[+] ══════════════════════════════════════
[~] Fuzzing: http://192.168.8.101
[~] Fuzzing: http://192.168.8.101/admin
[+] Stage 2 done in 47s. 23 unique URL(s) → FULL_URL.txt

[+] ══════════════════════════════════════
    STAGE 3: Parameter & Method Detection
[+] ══════════════════════════════════════
  [1/23] Scanning: http://192.168.8.101/login.php
    [+] Allowed methods : GET, POST
    [+] Forms found     : 1
        Form 1 [POST] → http://192.168.8.101/login.php
          Params (3): username, password, _token  [1 hidden]
  [2/23] Scanning: http://192.168.8.101/api/users
    [+] JSON endpoint   : id, name, email, role

[+] ══════════════════════════════════════
    STAGE 4: Vulnerability Scanning
[+] ══════════════════════════════════════
  [Nikto] → http://192.168.8.101
  [Nuclei] Scanning FULL_URL.txt (combined run)...

[+] ══════════════════════════════════════
    STAGE 5: Component Version Intelligence
[+] ══════════════════════════════════════
══════════════════════════════════════════════════════════════════════
          STAGE 5 — Component Version Intelligence
══════════════════════════════════════════════════════════════════════
  Component              Version        Status                 Severity
  ──────────────────────────────────────────────────────────────────
  php                    5.6.40         EOL + 3 CVE(s)         CRITICAL 🔴
  jquery                 1.11.3         EOL                    HIGH     🟠
  bootstrap              3.3.7          EOL                    MEDIUM   🟡
  nginx                  1.22.1         No issues found        INFO     ✅

[+] ══════════════════════════════════════
    STAGE 6: Path & File Vulnerability Intel
[+] ══════════════════════════════════════
  [1/23] [200] http://192.168.8.101/.env
    ↳ 1 finding(s): CRITICAL
  [5/23] [200] http://192.168.8.101/admin
    ↳ 2 finding(s): HIGH, LOW

══════════════════════════════════════════════════════════════════════
               STAGE 6 — Path Intelligence Report
══════════════════════════════════════════════════════════════════════
  Severity     Category                     URL
  ────────────────────────────────────────────────────────────────────
  CRITICAL     Information Disclosure        http://192.168.8.101/.env
    ↳ .env file — likely contains DB passwords and API keys
      Evidence: …DB_PASSWORD=supersecret…
  HIGH         Directory Listing             http://192.168.8.101/uploads
    ↳ Directory listing enabled — all files browsable by anyone

[+] ALL STAGES COMPLETE
    Total elapsed        : 312s
    Stage 1 dirs         : dir_discovery.txt  (8 paths)
    Stage 2 hidden files : FULL_URL.txt  (23 URLs)
    Stage 3 param report : param_discovery_report.txt
    Stage 4 vuln results : vuln_results/
    Stage 5 ver report   : version_report.txt
    Stage 5 ver JSON     : version_results.json
    Stage 6 path report  : path_intel_report.txt
    Stage 6 path JSON    : path_intel_results.json
```

---

## Running Individual Scanners

### Stage 3 — Parameter Discovery (`para.py`)

```bash
# Basic
python3 para.py FULL_URL.txt

# With options
python3 para.py FULL_URL.txt param_discovery_report.txt --threads 15 --timeout 10
```

**What it detects:**
- HTML form fields (all types including `hidden`)
- `<a href>` query-string parameters
- JSON API endpoint keys
- HTTP allowed methods (OPTIONS probe)

**Output:** `param_discovery_report.txt`

---

### Stage 4 — Vulnerability Scanning (`vuln_scan.py`)

```bash
# Basic
python3 vuln_scan.py FULL_URL.txt

# With options
python3 vuln_scan.py FULL_URL.txt --threads 4 --timeout 300 --out vuln_results
```

**Requires:** `nikto` and/or `nuclei` on PATH (gracefully skips missing tools)

**Output:** `vuln_results/nikto/` and `vuln_results/nuclei/`

---

### Stage 5 — Version Intelligence (`version_scan.py`)

```bash
# EOL check only (no internet required)
python3 version_scan.py FULL_URL.txt --no-nvd

# Full scan with NVD CVE lookup
python3 version_scan.py FULL_URL.txt

# With NVD API key (higher rate limit)
python3 version_scan.py FULL_URL.txt --nvd-key YOUR_KEY_HERE

# Custom output
python3 version_scan.py FULL_URL.txt --out-txt report.txt --out-json report.json
```

**Severity ratings (version_scan.py):**

| Severity | Condition |
|----------|-----------|
| CRITICAL 🔴 | EOL **and** has known CVEs, or CVSS ≥ 9.0 |
| HIGH 🟠 | EOL only (unsupported branch), or CVSS 7.0–8.9 |
| MEDIUM 🟡 | CVSS 4.0–6.9 |
| LOW 🔵 | CVSS 0.1–3.9 |
| INFO ✅ | Current version, no known issues |

**Detection sources:**

| Source | Example |
|--------|---------|
| HTTP headers | `Server: Apache/2.2.34`, `X-Powered-By: PHP/5.6.40` |
| HTML `<meta>` generator | `<meta name="generator" content="WordPress 5.8.1">` |
| `<script src>` filenames | `jquery-1.11.3.min.js`, `bootstrap-3.3.7.min.js` |
| Cookie names | `PHPSESSID` → PHP, `JSESSIONID` → Java |
| Version files | `readme.txt`, `CHANGELOG.md`, `package.json`, `composer.json` |
| WhatWeb (optional) | Full fingerprint if `whatweb` is installed |

**Output:** `version_report.txt`, `version_results.json`

---

### Stage 6 — Path Intelligence (`path_intel.py`)

```bash
# Basic
python3 path_intel.py FULL_URL.txt

# Including directory list for broader coverage
python3 path_intel.py FULL_URL.txt --dirs dir_discovery.txt

# With options
python3 path_intel.py FULL_URL.txt --dirs dir_discovery.txt \
    --threads 15 --timeout 12 \
    --out-txt path_intel_report.txt --out-json path_intel_results.json
```

**Detection categories and severity:**

| Category | Severity | Examples |
|----------|----------|---------|
| Credential exposure | CRITICAL | `.env`, `wp-config.php`, `.htpasswd`, SQL dumps, private keys, AWS credentials |
| Source control | HIGH | `.git/`, `.svn/`, `.hg/` directories |
| Directory listing | HIGH | `Index of /` in response body |
| Debug pages | HIGH | Werkzeug debugger (RCE risk), phpinfo() |
| Admin exposure | HIGH | `/admin`, `/phpmyadmin`, `/server-status` |
| Log / archive files | HIGH | `.log`, `.zip`, `.sqlite` directly accessible |
| Default pages | MEDIUM | Apache "It works!", nginx welcome, Tomcat default |
| Backup files | MEDIUM | `.bak`, `.old`, `.orig`, `.tmp`, `.swp` |
| Test / sample files | MEDIUM | `phpinfo.php`, `test.php`, `demo.html` |
| Config files | MEDIUM | `.htaccess`, `web.config`, `.travis.yml` |
| Version disclosures | MEDIUM | `readme.txt`, `CHANGELOG`, `robots.txt` with sensitive paths |
| Missing sec headers | LOW | No `X-Frame-Options`, `CSP`, `HSTS`, `X-Content-Type-Options` |
| Stack traces | MEDIUM | Python traceback, Java exception, PHP error in 500 response |
| SQL errors | MEDIUM | MySQL/ORA error strings in response body |

**Output:** `path_intel_report.txt`, `path_intel_results.json`

---

## Output Files Reference

| File | Stage | Description |
|------|-------|-------------|
| `dir_discovery.txt` | 1 | All discovered directory URLs |
| `hidden_files_report.txt` | 2 | Raw gobuster output per directory |
| `FULL_URL.txt` | 2 | All deduplicated discovered URLs (feed for Stages 3–6) |
| `param_discovery_report.txt` | 3 | Forms, parameters, allowed HTTP methods |
| `vuln_results/nikto/*.log` | 4 | Per-target Nikto scan output |
| `vuln_results/nuclei/nuclei_combined.txt` | 4 | Nuclei findings across all URLs |
| `version_report.txt` | 5 | Human-readable component version report |
| `version_results.json` | 5 | Machine-readable version assessment (with CVE details) |
| `path_intel_report.txt` | 6 | Human-readable path vulnerability report |
| `path_intel_results.json` | 6 | Machine-readable path findings with evidence |

---

## Tuning Parameters

Edit the top of `detail_FahScan.sh` to adjust performance:

```bash
GOBUSTER_THREADS=20    # Concurrent gobuster workers
PARA_THREADS=10        # Concurrent para.py URL workers
PARA_TIMEOUT=8         # HTTP timeout (seconds) for para.py
VULN_THREADS=4         # Parallel Nikto workers
VULN_TIMEOUT=1000      # Max time per Nikto scan (seconds)
VERSION_THREADS=5      # Concurrent version_scan.py workers
VERSION_TIMEOUT=10     # HTTP timeout for version fingerprinting
PATH_THREADS=10        # Concurrent path_intel.py workers
PATH_TIMEOUT=10        # HTTP timeout for path analysis
```

### Nuclei Tuning (`vuln_scan.py`)

Nuclei is called **once** for all targets combined via `-l`. Edit `run_nuclei()` in `vuln_scan.py` to adjust:

| Parameter | Current Value | Description |
|-----------|---------------|-------------|
| `-severity` | `medium,high,critical` | Severities to scan (skips `info`/`low` noise) |
| `-timeout` | `60` | Seconds per HTTP request before timeout |
| `-rl` | `75` | Max HTTP requests per second (rate limit) |
| `-c` | `25` | Parallel template executions |
| `-bulk-size` | `25` | Hosts processed per template batch |

> **Note:** Do not add `-stats` — it uses `\r` rewrites that corrupt the streaming log file.

---

## Notes on Finding Validity

All findings in this toolkit are **evidence-based** — nothing is fabricated:

- **Stage 3** findings come from parsing real HTTP response bodies (forms, JSON, links)
- **Stage 4** findings are produced by Nikto and Nuclei — established external tools
- **Stage 5** findings are anchored to:
  - Version strings **actually present** in HTTP headers or page source
  - EOL dates sourced from official vendor announcements
  - CVEs sourced live from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) (when `--no-nvd` is not set)
- **Stage 6** findings require one of:
  - The URL path literally matching a known-sensitive filename pattern, **or**
  - The response body containing a specific string (e.g. `Index of /`, `-----BEGIN PRIVATE KEY-----`, `AKIA...`)
  - Evidence snippets from the actual response are included in the report

**False positive awareness:**
- Missing security headers (Stage 6, LOW) will appear on almost every site — treat as informational
- Email addresses in source (Stage 6, LOW) may be intentional public contact details
- NVD keyword search (Stage 5) may occasionally return CVEs that reference a product name but apply to a different version — always verify CVE descriptions before reporting

---

## File Structure

```
autoFah/
├── autoFah.sh               # Quick 2-stage recon
├── detail_FahScan.sh        # Full 6-stage pipeline
├── para.py                  # Stage 3 — parameter discovery
├── vuln_scan.py             # Stage 4 — Nikto + Nuclei orchestrator
├── version_scan.py          # Stage 5 — component version intelligence
├── path_intel.py            # Stage 6 — path & file vulnerability analysis
├── dirCommon.txt            # Directory wordlist (Stage 1)
├── hiddenFiles.txt          # File wordlist (Stage 2)
└── README.md
```

