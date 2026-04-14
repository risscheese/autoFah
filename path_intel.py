#!/usr/bin/env python3
from __future__ import annotations

# ============================================================
#  path_intel.py — Directory & File Vulnerability Intelligence
#  Used by detail_scan.sh Stage 6
#
#  Usage:
#    python3 path_intel.py [FULL_URL.txt]
#                          [--dirs dir_discovery.txt]
#                          [--out-txt path_intel_report.txt]
#                          [--out-json path_intel_results.json]
#                          [--threads N] [--timeout S]
#
#  Detection categories:
#    • Default / test pages      (server welcome, phpinfo, debug pages)
#    • Information disclosure    (CRITICAL → LOW based on content)
#    • Directory listing         (browsable index pages)
#    • Sensitive file exposure   (configs, keys, backups, dumps)
#    • Security header gaps      (missing headers — LOW / INFO)
#
#  Severity:
#    CRITICAL  — credentials, private keys, source code, DB dumps
#    HIGH      — directory listing, debug pages, admin exposure, git/svn
#    MEDIUM    — default pages, test files, version readmes, robots.txt leaks
#    LOW       — missing security headers, generic error info
#    INFO      — informational, no direct exploitability
# ============================================================

import argparse
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colours ─────────────────────────────────────────────
R      = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
WHITE  = "\033[97m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     GREEN,
}
SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "✅",
}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

PRINT_LOCK = threading.Lock()

# Thread-safe set: tracks which hosts have already had security-header
# checks run (fix 2 — avoids N duplicate header findings per host).
_CHECKED_HOSTS: set[str] = set()
_CHECKED_HOSTS_LOCK = threading.Lock()


def _host_header_checked(host: str) -> bool:
    """Return True if this host was already checked; register if not."""
    with _CHECKED_HOSTS_LOCK:
        if host in _CHECKED_HOSTS:
            return True
        _CHECKED_HOSTS.add(host)
        return False


def safe_print(*a, **kw):
    with PRINT_LOCK:
        print(*a, **kw)


def _c(text: str, col: str) -> str:
    return f"{col}{text}{R}"


# ═══════════════════════════════════════════════════════════════
# DETECTION RULES — URL / PATH PATTERN MATCHING
# Checked before fetching; some issues are detectable by name alone.
#
# Format: (category, severity, description, compiled_regex)
# ═══════════════════════════════════════════════════════════════

URL_RULES: list[tuple[str, str, str, re.Pattern]] = [
    # ── Credential / Secret Files ─────────────────────────────
    ("Information Disclosure", "CRITICAL",
     ".env file — likely contains DB passwords and API keys",
     re.compile(r'/\.env$', re.I)),

    ("Information Disclosure", "CRITICAL",
     ".env.* variant — environment secrets",
     re.compile(r'/\.env\.(local|prod|production|dev|development|staging|backup|bak|old|save)$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "WordPress config file — DB credentials exposed",
     re.compile(r'/wp-config\.php(\.bak|\.old|\.save|\.orig|~)?$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "Database config file accessible",
     re.compile(r'/(database|db|config|configuration)(\.php|\.py|\.rb|\.ini|\.yml|\.yaml|\.json|\.xml)$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "SQL dump file — full database content",
     re.compile(r'\.(sql)(\.gz|\.zip|\.bz2)?$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "Private key file accessible",
     re.compile(r'\.(pem|key|p12|pfx|ppk)$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "AWS credentials file",
     re.compile(r'/(\.aws/credentials|credentials\.csv|aws\.config)$', re.I)),

    ("Information Disclosure", "CRITICAL",
     ".htpasswd — username and hashed password list",
     re.compile(r'/\.htpasswd$', re.I)),

    ("Information Disclosure", "CRITICAL",
     "Shadow or passwd file — system credential list",
     re.compile(r'/(etc/passwd|etc/shadow|password\.txt|passwords\.txt)$', re.I)),

    # ── Source Code / Version Control ─────────────────────────
    ("Information Disclosure", "HIGH",
     ".git directory exposed — full source code recoverable",
     re.compile(r'/\.git(/|$)', re.I)),

    ("Information Disclosure", "HIGH",
     ".svn directory exposed — source and history accessible",
     re.compile(r'/\.svn(/|$)', re.I)),

    ("Information Disclosure", "HIGH",
     ".hg (Mercurial) directory exposed",
     re.compile(r'/\.hg(/|$)', re.I)),

    ("Information Disclosure", "HIGH",
     ".DS_Store file — reveals directory structure",
     re.compile(r'/\.DS_Store$', re.I)),

    ("Information Disclosure", "HIGH",
     "Composer package list — reveals all PHP dependencies and versions",
     re.compile(r'/composer\.(json|lock)$', re.I)),

    ("Information Disclosure", "HIGH",
     "NPM package list — reveals all JS dependencies and versions",
     re.compile(r'/(package\.json|package-lock\.json|yarn\.lock)$', re.I)),

    # ── Admin & Sensitive Paths ───────────────────────────────
    ("Sensitive Exposure", "HIGH",
     "Admin panel path exposed",
     re.compile(r'/(admin|administrator|adminpanel|admin-panel|wp-admin|cpanel|phpmyadmin|adminer|webadmin)(/|$)', re.I)),

    ("Sensitive Exposure", "HIGH",
     "phpMyAdmin — web-based database administration",
     re.compile(r'/(phpmyadmin|pma|myadmin|mysql)(/|$)', re.I)),

    ("Sensitive Exposure", "HIGH",
     "Server status / info page — detailed server internals",
     re.compile(r'/(server-status|server-info)$', re.I)),

    ("Sensitive Exposure", "HIGH",
     "Exposed log file — may contain credentials or PII",
     re.compile(r'\.(log|logs)$', re.I)),

    ("Sensitive Exposure", "HIGH",
     "Backup archive — may contain source code or config",
     re.compile(r'\.(zip|tar|tar\.gz|tgz|tar\.bz2|7z|rar)$', re.I)),

    ("Sensitive Exposure", "HIGH",
     "Database file directly accessible",
     re.compile(r'\.(sqlite|sqlite3|db|mdb|accdb)$', re.I)),

    # ── Backup / Temp Copies of Files ─────────────────────────
    ("Sensitive Exposure", "MEDIUM",
     "Backup copy of a file — source code or config exposed",
     re.compile(r'\.(bak|old|orig|backup|save|tmp|temp|copy)$', re.I)),

    ("Sensitive Exposure", "MEDIUM",
     "Vim swap file — unsaved editor session leaks source",
     re.compile(r'\.(swp|swo)$', re.I)),

    # ── Test / Debug Files ────────────────────────────────────
    ("Default / Test Page", "MEDIUM",
     "PHP info / test file — discloses full server configuration",
     re.compile(r'/(phpinfo|php-info|info|phptest|test|testphp)(\.php)?$', re.I)),

    ("Default / Test Page", "MEDIUM",
     "Sample or example file left on server",
     re.compile(r'/(sample|example|demo|placeholder|template|dummy)(\.php|\.html|\.htm|\.asp|\.aspx)?$', re.I)),

    # ── Version / Readme Files ────────────────────────────────
    ("Information Disclosure", "MEDIUM",
     "README or CHANGELOG — reveals software version",
     re.compile(r'/(readme|changelog|changes|release-notes|install|licence|license)(\.txt|\.md|\.html|\.htm)?$', re.I)),

    ("Information Disclosure", "MEDIUM",
     "robots.txt — may disclose hidden paths",
     re.compile(r'/robots\.txt$', re.I)),

    ("Information Disclosure", "MEDIUM",
     "sitemap — full URL structure disclosed",
     re.compile(r'/sitemap(\.xml|_index\.xml|\.txt)?$', re.I)),

    # ── Config / Infrastructure ───────────────────────────────
    ("Information Disclosure", "MEDIUM",
     ".htaccess — web server rules and path mappings",
     re.compile(r'/\.htaccess$', re.I)),

    ("Information Disclosure", "MEDIUM",
     "web.config — IIS configuration file",
     re.compile(r'/web\.config(\.bak|\.old)?$', re.I)),

    ("Information Disclosure", "MEDIUM",
     "Dockerfile or docker-compose — infrastructure details",
     re.compile(r'/(Dockerfile|docker-compose\.yml|docker-compose\.yaml)$', re.I)),

    ("Information Disclosure", "MEDIUM",
     "CI/CD configuration file accessible",
     re.compile(r'/(\.travis\.yml|\.gitlab-ci\.yml|\.github/workflows|Jenkinsfile|\.circleci)$', re.I)),

    # ── API / Docs ────────────────────────────────────────────
    ("Sensitive Exposure", "MEDIUM",
     "Swagger / OpenAPI documentation exposed",
     re.compile(r'/(swagger|api-docs|openapi|api/docs|swagger-ui)(\.json|\.yaml|\.yml|\.html|/|$)', re.I)),

    ("Sensitive Exposure", "MEDIUM",
     "GraphQL endpoint or playground exposed",
     re.compile(r'/(graphql|graphiql|playground)(/|$)', re.I)),
]

# ═══════════════════════════════════════════════════════════════
# DETECTION RULES — RESPONSE CONTENT MATCHING
# Each rule checks the HTTP response body / headers.
#
# Format: (category, severity, description, check_fn)
# check_fn(response, soup, url) → bool
# ═══════════════════════════════════════════════════════════════

def _body(resp: requests.Response) -> str:
    return resp.text[:300_000]


CONTENT_RULES: list[tuple[str, str, str, callable]] = [

    # ── Directory Listing ─────────────────────────────────────
    ("Directory Listing", "HIGH",
     "Directory listing enabled — all files browsable by anyone",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'Index of /', r.text, re.I) is not None
         and s.find('a', href=True) is not None
     )),

    ("Directory Listing", "HIGH",
     "Nginx directory listing active",
     lambda r, s, u: (
         r.status_code == 200
         and (re.search(r'<title>Index of', r.text, re.I) is not None
              or re.search(r'nginx.*directory listing', r.text, re.I) is not None)
     )),

    # ── Default / Welcome Pages ───────────────────────────────
    ("Default / Test Page", "MEDIUM",
     "Apache default page — server freshly installed, not configured",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'(Apache2 Ubuntu Default Page|It works!|Apache HTTP Server Test Page)', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "nginx default welcome page",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'Welcome to nginx', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "IIS default welcome page",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'(IIS Windows Server|Internet Information Services|iis-85\.png)', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "Tomcat default page / manager exposed",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'(Apache Tomcat.*default|Tomcat Manager Application)', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "Django debug page — DEBUG=True in production",
     lambda r, s, u: (
         r.status_code in (404, 500)
         and re.search(r'Django.*traceback|DisallowedHost|DEBUG.*True', r.text, re.I) is not None
     )),

    ("Default / Test Page", "HIGH",
     "Flask / Werkzeug interactive debugger — remote code execution risk",
     lambda r, s, u: (
         r.status_code == 500
         and re.search(r'Werkzeug Debugger|Interactive Console|werkzeug\.debug', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "Laravel debug error page",
     lambda r, s, u: (
         r.status_code == 500
         and re.search(r'(Whoops!.*Laravel|laravel\.com|Illuminate\\)', r.text, re.I) is not None
     )),

    ("Default / Test Page", "MEDIUM",
     "Spring Boot Whitelabel Error Page",
     lambda r, s, u: (
         r.status_code in (404, 500)
         and re.search(r'Whitelabel Error Page|Spring Boot', r.text, re.I) is not None
     )),

    # ── PHP Info Page ─────────────────────────────────────────
    ("Information Disclosure", "HIGH",
     "phpinfo() page active — full PHP/server config disclosed",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'(<title>phpinfo\(\)|PHP Version.*<.*table|phpinfo\(\)</title>)', r.text, re.I) is not None
     )),

    # ── Credential Patterns in Body ───────────────────────────
    ("Information Disclosure", "CRITICAL",
     "Private key material detected in response body",
     lambda r, s, u: (
         re.search(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', r.text) is not None
     )),

    ("Information Disclosure", "CRITICAL",
     "AWS Access Key ID found in response body",
     lambda r, s, u: (
         re.search(r'AKIA[0-9A-Z]{16}', r.text) is not None
     )),

    ("Information Disclosure", "CRITICAL",
     "Database connection string with credentials in response",
     lambda r, s, u: (
         re.search(
             r'(mysql|pgsql|postgres|mongodb|mssql|sqlsrv)://[^:]+:[^@]+@',
             r.text, re.I
         ) is not None
     )),

    ("Information Disclosure", "CRITICAL",
     "Environment variable block with secrets exposed",
     lambda r, s, u: (
         re.search(
             r'(DB_PASSWORD|DATABASE_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET)\s*=\s*\S+',
             r.text, re.I
         ) is not None
     )),

    # ── Source Control Exposure ───────────────────────────────
    ("Information Disclosure", "HIGH",
     ".git repository metadata accessible — source code recoverable",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'(ref: refs/heads/|^\[core\])', r.text) is not None
     )),

    # ── Stack Traces / Error Disclosure ──────────────────────
    ("Information Disclosure", "MEDIUM",
     "Stack trace in HTTP error response — reveals internals",
     lambda r, s, u: (
         r.status_code in (500, 503)
         and re.search(
             r'(Traceback \(most recent|at .*\.java:\d+|System\.Web\.HttpException|at .*\(.*\.php:\d+\))',
             r.text, re.I
         ) is not None
     )),

    ("Information Disclosure", "MEDIUM",
     "SQL error message in response — possible injection point",
     lambda r, s, u: (
         re.search(
             r'(You have an error in your SQL syntax|ORA-\d+:|pg_query\(\)|SQLSTATE\[\d+\]|'
             r'Microsoft.*ODBC.*SQL Server|Unclosed quotation mark)',
             r.text, re.I
         ) is not None
     )),

    # ── Sensitive Content Patterns ────────────────────────────
    ("Information Disclosure", "MEDIUM",
     "Internal IP address disclosed in response",
     lambda r, s, u: (
         re.search(r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b',
                   r.text) is not None
         and '192.168' not in u   # skip if already scanning an internal target
     )),

    ("Information Disclosure", "LOW",
     "Email address(es) found in page source",
     lambda r, s, u: (
         r.status_code == 200
         and re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r.text) is not None
         and 'example.com' not in r.text   # skip placeholder emails
     )),

    # ── Security Headers ──────────────────────────────────────
    ("Missing Security Header", "LOW",
     "X-Frame-Options header missing — clickjacking risk",
     lambda r, s, u: (
         r.status_code == 200
         and 'X-Frame-Options' not in r.headers
         and 'frame-ancestors' not in r.headers.get('Content-Security-Policy', '')
     )),

    ("Missing Security Header", "LOW",
     "Content-Security-Policy header missing",
     lambda r, s, u: (
         r.status_code == 200
         and 'Content-Security-Policy' not in r.headers
     )),

    ("Missing Security Header", "LOW",
     "X-Content-Type-Options header missing — MIME sniffing risk",
     lambda r, s, u: (
         r.status_code == 200
         and 'X-Content-Type-Options' not in r.headers
     )),

    ("Missing Security Header", "LOW",
     "Strict-Transport-Security (HSTS) header missing",
     lambda r, s, u: (
         r.status_code == 200
         and u.startswith('https://')
         and 'Strict-Transport-Security' not in r.headers
     )),

    ("Missing Security Header", "LOW",
     "Referrer-Policy header missing",
     lambda r, s, u: (
         r.status_code == 200
         and 'Referrer-Policy' not in r.headers
     )),

    ("Missing Security Header", "LOW",
     "Permissions-Policy header missing",
     lambda r, s, u: (
         r.status_code == 200
         and 'Permissions-Policy' not in r.headers
     )),

    # ── Server Version Disclosure via Header ──────────────────
    ("Information Disclosure", "LOW",
     "Detailed Server header discloses version — aids fingerprinting",
     lambda r, s, u: (
         bool(re.search(r'[\d.]{3,}', r.headers.get('Server', '')))
     )),

    ("Information Disclosure", "LOW",
     "X-Powered-By header discloses technology stack",
     lambda r, s, u: (
         'X-Powered-By' in r.headers
     )),
]


# ═══════════════════════════════════════════════════════════════
# FINDING DATA CLASS
# ═══════════════════════════════════════════════════════════════

class Finding:
    def __init__(self, url: str, category: str, severity: str,
                 description: str, evidence: str = ""):
        self.url         = url
        self.category    = category
        self.severity    = severity
        self.description = description
        self.evidence    = evidence   # snippet of proof

    def key(self) -> str:
        return f"{self.url}|{self.description[:60]}"

    def to_dict(self) -> dict:
        return {
            "url":         self.url,
            "category":    self.category,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence,
        }


# ═══════════════════════════════════════════════════════════════
# HTTP FETCH
# ═══════════════════════════════════════════════════════════════

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


def fetch(url: str, timeout: int) -> Optional[requests.Response]:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout,
                            verify=False, allow_redirects=True)
    except requests.exceptions.Timeout:
        try:
            return requests.get(url, headers=HEADERS, timeout=timeout * 2,
                                verify=False, allow_redirects=True)
        except Exception:
            return None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════
# EVIDENCE EXTRACTION
# ═══════════════════════════════════════════════════════════════

def extract_evidence(resp: requests.Response, pattern: str) -> str:
    """Pull a short snippet of text matching `pattern` from the response."""
    m = re.search(pattern, resp.text[:50_000], re.I)
    if m:
        start = max(0, m.start() - 30)
        end   = min(len(resp.text), m.end() + 60)
        snippet = resp.text[start:end].replace('\n', ' ').strip()
        return f"…{snippet}…"
    return ""


EVIDENCE_PATTERNS: dict[str, str] = {
    "Private key material":      r'-----BEGIN.*PRIVATE KEY-----',
    "AWS Access Key":            r'AKIA[0-9A-Z]{16}',
    "DB connection string":      r'(mysql|pgsql|postgres|mongodb)://[^:]+:[^@]+@',
    "Env secrets":               r'(DB_PASSWORD|SECRET_KEY|API_KEY)\s*=\s*\S+',
    "Git metadata":              r'ref: refs/heads/',
    "phpinfo() title":           r'<title>phpinfo',
    "Directory listing":         r'Index of /',
    "Stack trace":               r'Traceback \(most recent|at .*\.java:\d+',
    "SQL error":                 r'You have an error in your SQL syntax|ORA-\d+:',
    "Internal IP":               r'(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)',
    "Server version":            r'[\d.]{3,}',
    "Default Apache":            r'It works!|Apache2 Ubuntu Default',
    "Default nginx":             r'Welcome to nginx',
    "Werkzeug Debugger":         r'Werkzeug Debugger',
    "Django debug":              r'Django.*traceback|DisallowedHost',
}


def get_evidence(resp: requests.Response, description: str) -> str:
    for key, pattern in EVIDENCE_PATTERNS.items():
        if key.lower() in description.lower():
            return extract_evidence(resp, pattern)
    return ""


# ═══════════════════════════════════════════════════════════════
# SCAN A SINGLE URL
# ═══════════════════════════════════════════════════════════════

def scan_url(url: str, index: int, total: int,
             timeout: int) -> list[Finding]:
    findings: list[Finding] = []
    seen_descs: set[str] = set()

    def add(category: str, severity: str, desc: str, evidence: str = ""):
        if desc in seen_descs:
            return
        seen_descs.add(desc)
        findings.append(Finding(url, category, severity, desc, evidence))

    # ── Step 1: Fetch first — never flag before we know the status ──
    # FIX 1 (Gemini): URL rules previously fired on the URL string alone,
    # before any HTTP request. A 404'd .env path would be flagged CRITICAL.
    # Now we fetch first and only apply URL_RULES on a confirmed 200 OK.
    resp = fetch(url, timeout)

    if resp is None:
        safe_print(f"  [{index}/{total}] Unreachable: {url}")
        return findings

    # FIX 4 (Gemini): Detect WAF / rate-limit responses explicitly
    if resp.status_code == 429:
        safe_print(f"  [{index}/{total}] [429] ⚠  Rate-limited on {url} "
                   f"— reduce --threads or add delay")
        return findings
    if resp.status_code == 403:
        # 403 can mean WAF block OR legitimate access control.
        # Log it but don't treat as a full miss — content rules still apply.
        safe_print(f"  [{index}/{total}] [403] {url}  (WAF block or access control)")
    else:
        safe_print(f"  [{index}/{total}] [{resp.status_code}] {url}")

    # ── Step 2: URL-pattern rules — only on HTTP 200 with non-empty body ──
    # FIX 1 (Gemini): only fire on confirmed 200 (not 404/403).
    # ADDITIONAL FIX: also require non-empty body.
    #
    # PHP files like db.php and wp-config.php can return HTTP 200 but an
    # empty body — the PHP interpreter executed the file server-side and
    # output nothing. The SOURCE CODE is not exposed to the client.
    # Flagging an empty-body 200 as "DB credentials exposed" is a false
    # positive. We only flag when there is actual readable content returned.
    if resp.status_code == 200 and len(resp.content) > 0:
        for category, severity, description, pattern in URL_RULES:
            if pattern.search(url):
                add(category, severity, description)

    # ── Step 3: Content-type guard ────────────────────────────────────────
    ct = resp.headers.get("Content-Type", "")
    if not any(t in ct for t in ("text/", "application/json",
                                  "application/xml", "application/javascript")):
        return findings

    # FIX 3 (Gemini): Only parse HTML with BeautifulSoup.
    # Feeding a 300 kB minified JSON blob or React bundle to html.parser
    # is CPU-wasteful and produces a meaningless DOM tree.
    if "text/html" in ct:
        try:
            soup = BeautifulSoup(resp.text[:300_000], "html.parser")
        except Exception:
            soup = BeautifulSoup("", "html.parser")
    else:
        soup = BeautifulSoup("", "html.parser")   # empty — regex rules still apply

    # ── Step 4: Content rules ─────────────────────────────────────────────
    host = urlsplit(url).netloc
    already_checked_headers = _host_header_checked(host)

    for category, severity, description, check_fn in CONTENT_RULES:
        # FIX 2 (Gemini): Security-header rules run once per host only.
        # Headers like X-Frame-Options are set at server/vhost level — the
        # same finding would otherwise appear for every single URL scanned.
        if category == "Missing Security Header" and already_checked_headers:
            continue
        try:
            if check_fn(resp, soup, url):
                evidence = get_evidence(resp, description)
                add(category, severity, description, evidence)
        except Exception:
            continue

    # ── Step 5: robots.txt detail ─────────────────────────────────────────
    if url.endswith("robots.txt") and resp.status_code == 200:
        disallows = re.findall(r'Disallow:\s*(\S+)', resp.text)
        if disallows:
            interesting = [d for d in disallows
                           if any(kw in d.lower() for kw in
                                  ('admin', 'backup', 'config', 'secret', 'private',
                                   'internal', 'api', 'upload', 'install', 'db'))]
            if interesting:
                add("Information Disclosure", "MEDIUM",
                    "robots.txt — may disclose hidden paths",
                    f"Interesting Disallow entries: {', '.join(interesting[:10])}")

    # ── Step 6: Sensitive HTML comments ──────────────────────────────────
    if resp.status_code == 200 and "text/html" in ct:
        comments = re.findall(r'<!--(.*?)-->', resp.text[:100_000], re.DOTALL)
        for comment in comments:
            if re.search(r'(password|passwd|secret|token|api.?key|todo|fixme|bug|hack|internal)',
                         comment, re.I):
                snippet = comment.strip()[:120].replace('\n', ' ')
                add("Information Disclosure", "MEDIUM",
                    "Sensitive keyword in HTML comment",
                    f"Comment: {snippet}")
                break   # one finding per URL for this check

    if findings:
        sev_list = ", ".join(
            f"{_c(f.severity, SEVERITY_COLOR.get(f.severity, WHITE))}"
            for f in findings[:3]
        )
        safe_print(f"    ↳ {len(findings)} finding(s): {sev_list}")

    return findings


# ═══════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════

W = 70


def print_summary_table(all_findings: list[Finding]) -> None:
    sorted_f = sorted(all_findings,
                      key=lambda f: SEVERITY_RANK.get(f.severity, 0),
                      reverse=True)

    line = "═" * W
    print(f"\n{_c(line, CYAN)}")
    print(_c("  STAGE 6 — Path Intelligence Report".center(W), BOLD + CYAN))
    print(_c(line, CYAN))

    hdr = f"  {'Severity':<12} {'Category':<28} {'URL':<28}"
    print(_c(hdr, BOLD + WHITE))
    print(_c("  " + "─" * (W - 2), DIM))

    for f in sorted_f:
        col  = SEVERITY_COLOR.get(f.severity, WHITE)
        icon = SEVERITY_ICON.get(f.severity, "")
        url_short = (f.url[:46] + "…") if len(f.url) > 47 else f.url
        cat_short = f.category[:27]
        row = f"  {_c(f.severity, col):<20} {cat_short:<28} {url_short}"
        print(row)
        desc_line = f"    {_c('↳', DIM)} {f.description[:W - 6]}"
        print(desc_line)
        if f.evidence:
            ev_line = f"      {_c('Evidence:', DIM)} {f.evidence[:W - 14]}"
            print(_c(ev_line, DIM))

    print(_c(line, CYAN))

    # Severity counts
    counts: dict[str, int] = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    # Category counts
    cats: dict[str, int] = {}
    for f in all_findings:
        cats[f.category] = cats.get(f.category, 0) + 1

    print("\n  Findings by Severity:")
    for sev, cnt in counts.items():
        if cnt == 0:
            continue
        col  = SEVERITY_COLOR.get(sev, WHITE)
        icon = SEVERITY_ICON.get(sev, "")
        bar  = "█" * min(cnt, 40)
        print(f"    {_c(f'{sev:<10}', col)} {cnt:>3}  {_c(bar, col)} {icon}")

    print("\n  Findings by Category:")
    for cat, cnt in sorted(cats.items(), key=lambda x: x[1], reverse=True):
        print(f"    {cat:<35} {cnt}")

    print()


def write_text_report(findings: list[Finding], path: str,
                      target_count: int) -> None:
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings_by_sev = {s: [f for f in findings if f.severity == s]
                       for s in sev_order}

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=" * W + "\n")
        fh.write("  PATH INTELLIGENCE REPORT\n")
        fh.write(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"  URLs scanned : {target_count}\n")
        fh.write(f"  Total findings : {len(findings)}\n")
        fh.write("=" * W + "\n")

        for sev in sev_order:
            group = findings_by_sev[sev]
            if not group:
                continue
            fh.write(f"\n{'─' * W}\n  [{sev}]  ({len(group)} finding(s))\n{'─' * W}\n")
            for f in group:
                fh.write(f"\n  URL        : {f.url}\n")
                fh.write(f"  Category   : {f.category}\n")
                fh.write(f"  Description: {f.description}\n")
                if f.evidence:
                    fh.write(f"  Evidence   : {f.evidence}\n")

        fh.write("\n" + "=" * W + "\n")


def write_json_report(findings: list[Finding], path: str,
                      target_count: int) -> None:
    data = {
        "generated":    datetime.now().isoformat(),
        "urls_scanned": target_count,
        "total":        len(findings),
        "findings":     [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="path_intel.py — Directory & file vulnerability intelligence"
    )
    p.add_argument("input_file", nargs="?", default="FULL_URL.txt",
                   help="File with discovered URLs (default: FULL_URL.txt)")
    p.add_argument("--dirs", default="dir_discovery.txt",
                   help="Directory discovery file to include (default: dir_discovery.txt)")
    p.add_argument("--out-txt",  default="path_intel_report.txt",
                   help="Text report output path")
    p.add_argument("--out-json", default="path_intel_results.json",
                   help="JSON report output path")
    p.add_argument("--threads",  type=int, default=10,
                   help="Concurrent scan workers (default: 10)")
    p.add_argument("--timeout",  type=int, default=10,
                   help="HTTP timeout per request in seconds (default: 10)")
    return p.parse_args()


def load_urls(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [
                ln.strip() for ln in fh
                if ln.strip() and ln.strip().startswith("http")
            ]
    except FileNotFoundError:
        return []


def main():
    args = parse_args()

    # ── load & merge URL lists ───────────────────────────────
    file_urls = load_urls(args.input_file)
    dir_urls  = load_urls(args.dirs)

    # Combine, deduplicate, preserve order
    seen: set[str] = set()
    all_urls: list[str] = []
    for u in file_urls + dir_urls:
        nu = u if u.startswith("http") else "http://" + u
        if nu not in seen:
            seen.add(nu)
            all_urls.append(nu)

    if not all_urls:
        print(f"[-] No URLs found in '{args.input_file}' or '{args.dirs}'")
        sys.exit(1)

    total = len(all_urls)
    print(f"\n[+] path_intel.py — {total} URL(s) | threads={args.threads} | timeout={args.timeout}s")
    print("=" * W)

    # ── concurrent scanning ───────────────────────────────────
    all_findings: list[Finding] = []
    futures: dict = {}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for i, url in enumerate(all_urls):
            fut = pool.submit(scan_url, url, i + 1, total, args.timeout)
            futures[fut] = url

        for fut in as_completed(futures):
            try:
                found = fut.result()
                all_findings.extend(found)
            except Exception as exc:
                safe_print(f"  [!] Worker error: {exc}")

    # ── dedup findings (same URL + same description) ──────────
    seen_keys: set[str] = set()
    unique_findings: list[Finding] = []
    for f in all_findings:
        k = f.key()
        if k not in seen_keys:
            seen_keys.add(k)
            unique_findings.append(f)

    # Sort by severity desc
    unique_findings.sort(key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)

    # ── console table ─────────────────────────────────────────
    print_summary_table(unique_findings)

    # ── write reports ─────────────────────────────────────────
    write_text_report(unique_findings, args.out_txt, total)
    write_json_report(unique_findings, args.out_json, total)

    flagged = sum(1 for f in unique_findings if f.severity not in ("INFO",))
    print(f"[+] {flagged}/{len(unique_findings)} actionable finding(s)")
    print(f"[+] Reports saved:")
    print(f"    Text : {args.out_txt}")
    print(f"    JSON : {args.out_json}\n")


if __name__ == "__main__":
    main()
