#!/usr/bin/env python3
from __future__ import annotations

# ============================================================
#  version_scan.py — Component Version Intelligence
#  Used by detail_scan.sh Stage 5
#
#  Usage:
#    python3 version_scan.py [FULL_URL.txt]
#                            [--out-txt version_report.txt]
#                            [--out-json version_results.json]
#                            [--threads N] [--timeout S]
#                            [--no-nvd]
#
#  Detection sources:
#    • HTTP response headers  (Server, X-Powered-By, X-Generator, etc.)
#    • HTML <meta> tags       (generator)
#    • HTML comments          (version strings)
#    • <script src> paths     (jQuery, Bootstrap, React, Vue …)
#    • Cookie names           (PHPSESSID → PHP, JSESSIONID → Java …)
#    • Special files          (robots.txt, readme.txt, CHANGELOG …)
#    • WhatWeb CLI            (if installed)
#
#  Assessment:
#    1. Built-in EOL database  (no network needed)
#    2. NVD CVE API            (optional; --no-nvd to skip)
#
#  Severity:
#    CRITICAL  — EOL + CVEs, or CVSS ≥ 9.0
#    HIGH      — EOL only (unsupported), or CVSS 7.0–8.9
#    MEDIUM    — CVSS 4.0–6.9
#    LOW       — CVSS 0.1–3.9
#    INFO      — current, no known issues
# ============================================================

import argparse
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlsplit

import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colours ─────────────────────────────────────────────
R  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
ORANGE = "\033[33m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
DIM    = "\033[2m"
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


def safe_print(*a, **kw):
    with PRINT_LOCK:
        print(*a, **kw)


# ═══════════════════════════════════════════════════════════════
# BUILT-IN EOL DATABASE
# Format:  "product_key": [("< version_ceiling", "EOL date"), ...]
# Entries are checked in order; first match wins.
# "EOL date" = date after which the branch is unsupported.
# ═══════════════════════════════════════════════════════════════
EOL_DB: dict[str, list[tuple[str, str]]] = {
    # ── Web Servers ───────────────────────────────────────────
    "apache": [
        ("<2.2.0",  "2017-12-31"),   # Apache 2.0.x and earlier — EOL Dec 2017
        ("<2.4.0",  "2017-12-31"),   # Apache 2.2.x — EOL Dec 2017
        # Apache 2.4.x is the current supported branch; individual patch versions
        # are not separately EOL-tracked — flag only clearly old minor series
        ("<2.4.10", "2018-06-01"),   # Very old 2.4.x releases (pre-2015)
    ],
    "nginx": [
        ("<1.0.0",  "2012-04-12"),   # 0.x mainline — EOL
        ("<1.12.0", "2019-04-14"),   # 1.10.x legacy stable — EOL
        ("<1.14.0", "2021-04-14"),   # 1.12.x legacy stable — EOL
        # 1.16.x, 1.18.x, 1.20.x, 1.22.x are prior stable branches; still
        # receive security backports in some distros, so avoid blanket EOL flag
    ],
    "iis": [
        ("<7.0",  "2015-07-14"),
        ("<8.5",  "2018-01-14"),
        ("<10.0", "2022-01-18"),
    ],
    "tomcat": [
        ("<7.0",  "2021-03-31"),
        ("<8.5",  "2024-03-31"),
        ("<9.0",  "2026-12-31"),
    ],
    # ── Languages / Runtimes ──────────────────────────────────
    "php": [
        ("<5.7",  "2018-12-31"),
        ("<7.0",  "2018-12-03"),
        ("<7.1",  "2019-12-01"),
        ("<7.2",  "2020-11-30"),
        ("<7.3",  "2021-12-06"),
        ("<7.4",  "2022-11-28"),
        ("<8.0",  "2023-11-26"),
        ("<8.1",  "2025-12-31"),
        ("<8.2",  "2026-12-31"),
    ],
    "python": [
        ("<2.8",  "2020-01-01"),
        ("<3.7",  "2023-06-27"),
        ("<3.8",  "2024-10-07"),
        ("<3.9",  "2025-10-05"),
    ],
    "ruby": [
        ("<2.6",  "2022-03-31"),
        ("<2.7",  "2023-03-31"),
        ("<3.0",  "2024-03-31"),
        ("<3.1",  "2025-03-31"),
    ],
    "nodejs": [
        ("<12.0", "2022-04-30"),
        ("<14.0", "2023-04-30"),
        ("<16.0", "2023-09-11"),
        ("<18.0", "2025-04-30"),
    ],
    "aspnet": [
        ("<4.5",  "2016-01-12"),
        ("<4.6",  "2022-04-26"),
        ("<4.7",  "2023-10-10"),
        ("<4.8",  "2029-01-09"),   # still supported; flag very old ones
        ("<5.0",  "2022-05-10"),
        ("<6.0",  "2024-11-12"),
        ("<7.0",  "2024-05-14"),
        ("<8.0",  "2026-11-10"),
    ],
    # ── Databases ─────────────────────────────────────────────
    "mysql": [
        ("<5.6",  "2021-02-05"),
        ("<5.7",  "2023-10-31"),
        ("<8.0",  "2026-04-30"),
    ],
    "postgresql": [
        ("<10.0", "2022-11-10"),
        ("<11.0", "2023-11-09"),
        ("<12.0", "2024-11-14"),
        ("<13.0", "2025-11-13"),
    ],
    # ── CMS ───────────────────────────────────────────────────
    "wordpress": [
        ("<4.0",  "2022-01-01"),
        ("<5.0",  "2024-01-01"),
        ("<6.3",  "2024-08-01"),
    ],
    "joomla": [
        ("<3.0",  "2023-08-17"),
        ("<4.0",  "2025-08-17"),
    ],
    "drupal": [
        ("<7.0",  "2023-01-05"),
        ("<9.0",  "2023-11-01"),
        ("<10.0", "2026-12-17"),
    ],
    "magento": [
        ("<2.3",  "2022-09-08"),
        ("<2.4",  "2025-04-30"),
    ],
    # ── JS Frameworks / Libraries ─────────────────────────────
    "jquery": [
        ("<1.9",  "2016-06-29"),
        ("<2.0",  "2016-06-29"),
        ("<3.0",  "2021-08-01"),
        ("<3.6",  "2023-01-01"),
        ("<3.7",  "2024-01-01"),
    ],
    "jquery-ui": [
        ("<1.12", "2021-10-07"),
        ("<1.13", "2024-10-31"),
    ],
    "bootstrap": [
        ("<3.0",  "2019-07-24"),
        ("<4.0",  "2023-01-01"),
        ("<5.0",  "2025-12-31"),
    ],
    "react": [
        ("<16.0", "2022-03-29"),
        ("<17.0", "2024-01-01"),
        ("<18.0", "2026-01-01"),
    ],
    "vue": [
        ("<2.0",  "2023-12-31"),
        ("<3.0",  "2026-12-31"),
    ],
    "angular": [
        ("<12.0", "2022-11-12"),
        ("<14.0", "2023-11-18"),
        ("<15.0", "2024-05-18"),
        ("<16.0", "2024-11-08"),
    ],
    "lodash": [
        ("<4.17.21", "2023-01-01"),
    ],
    "moment": [
        ("<2.29.4", "2023-09-01"),
    ],
    # ── Crypto / TLS ──────────────────────────────────────────
    "openssl": [
        ("<1.0.2", "2020-01-01"),
        ("<1.1.1", "2023-09-11"),
        ("<3.0",   "2026-09-07"),
    ],
}

# Regex patterns to extract (product, version) from a text blob
# Each tuple: (product_key, compiled_regex, version_group_index)
HEADER_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # Server: Apache/2.4.52 (Ubuntu)
    ("apache",     re.compile(r'Apache/([\d.]+)',         re.I), 1),
    # Server: nginx/1.22.1
    ("nginx",      re.compile(r'nginx/([\d.]+)',          re.I), 1),
    # Server: Microsoft-IIS/10.0
    ("iis",        re.compile(r'Microsoft-IIS/([\d.]+)',  re.I), 1),
    # X-Powered-By: PHP/8.1.12
    ("php",        re.compile(r'PHP/([\d.]+)',            re.I), 1),
    # X-AspNet-Version: 4.0.30319
    ("aspnet",     re.compile(r'ASP\.NET[_\s]Version[:\s]*([\d.]+)', re.I), 1),
    # X-Powered-By: ASP.NET
    ("aspnet",     re.compile(r'X-Powered-By:\s*ASP\.NET\s+([\d.]+)', re.I), 1),
    # Server: Apache Tomcat/9.0.65
    ("tomcat",     re.compile(r'Tomcat/([\d.]+)',         re.I), 1),
    # OpenSSL/1.1.1t
    ("openssl",    re.compile(r'OpenSSL/([\d.]+\w*)',     re.I), 1),
]

# Patterns checked against the full response text (headers + HTML)
TEXT_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # <meta name="generator" content="WordPress 6.1.1 …">
    ("wordpress",  re.compile(r'WordPress\s+([\d.]+)',    re.I), 1),
    # content="Joomla! 4.2.7 …"
    ("joomla",     re.compile(r'Joomla!\s*([\d.]+)',      re.I), 1),
    # Drupal 9.x  / generator = "Drupal n (…)"
    ("drupal",     re.compile(r'Drupal\s+([\d.]+)',       re.I), 1),
    # Django/4.1.7
    ("django",     re.compile(r'Django/([\d.]+)',         re.I), 1),
    # Ruby on Rails 7.0.4
    ("ruby",       re.compile(r'Rails/([\d.]+)',          re.I), 1),
    # Node.js/18.12.1
    ("nodejs",     re.compile(r'Node\.js[/\s]+([\d.]+)', re.I), 1),
]

# Patterns matched against <script src="…"> paths
SCRIPT_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("jquery",     re.compile(r'jquery[.-]([\d.]+)',         re.I), 1),
    ("jquery-ui",  re.compile(r'jquery[.-]ui[.-]([\d.]+)',   re.I), 1),
    ("bootstrap",  re.compile(r'bootstrap[.-]([\d.]+)',      re.I), 1),
    ("react",      re.compile(r'react[.-]([\d.]+)',          re.I), 1),
    ("vue",        re.compile(r'vue[.-]([\d.]+)',            re.I), 1),
    ("angular",    re.compile(r'angular[.-]?([\d.]+)',       re.I), 1),
    ("lodash",     re.compile(r'lodash[.-]([\d.]+)',         re.I), 1),
    ("moment",     re.compile(r'moment[.-]([\d.]+)',         re.I), 1),
]

# Cookie-name → technology mapping (version unknown)
COOKIE_TECH: dict[str, str] = {
    "PHPSESSID":        "php",
    "ASP.NET_SessionId": "aspnet",
    "JSESSIONID":       "java",
    "ci_session":       "codeigniter",
    "laravel_session":  "laravel",
    "rack.session":     "ruby",
    "_rails_session":   "ruby-on-rails",
    "django_session":   "django",
    "connect.sid":      "nodejs-express",
}

# Files potentially containing version info
VERSION_FILES = [
    "readme.txt", "readme.html", "README.md",
    "CHANGELOG.txt", "CHANGELOG.md",
    "wp-links-opml.php",        # WordPress version leak
    "xmlrpc.php",
    "robots.txt",
    "package.json",
    "composer.json",
]


# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

class Component:
    def __init__(self, product: str, version: Optional[str],
                 source: str, source_url: str):
        self.product    = product
        self.version    = version   # None if only tech is known
        self.source     = source    # e.g. "Server header", "script src"
        self.source_url = source_url

    def key(self) -> str:
        return f"{self.product}|{self.version or 'unknown'}"

    def __repr__(self):
        return f"Component({self.product}, {self.version}, src={self.source})"


class Assessment:
    def __init__(self, component: Component):
        self.component  = component
        self.is_eol     = False
        self.eol_date   = None       # str  "YYYY-MM-DD"
        self.cves: list[dict] = []   # [{"id": "CVE-…", "cvss": 8.5, "desc": "…"}]
        self.severity   = "INFO"
        self.notes: list[str] = []

    def to_dict(self) -> dict:
        return {
            "product":    self.component.product,
            "version":    self.component.version,
            "source":     self.component.source,
            "source_url": self.component.source_url,
            "is_eol":     self.is_eol,
            "eol_date":   self.eol_date,
            "cves":       self.cves,
            "severity":   self.severity,
            "notes":      self.notes,
        }


# ═══════════════════════════════════════════════════════════════
# VERSION COMPARISON
# Uses `packaging.version.parse` for correct semantic versioning
# including pre-releases (rc), post-releases, and letter suffixes
# like OpenSSL's "1.1.1t" (fix 1 for feedback point 1).
# ═══════════════════════════════════════════════════════════════

try:
    from packaging.version import parse as _pkg_parse, InvalidVersion

    def version_lt(a: str, b: str) -> bool:
        """Return True if version a < version b (semantic, packaging-aware)."""
        try:
            return _pkg_parse(a) < _pkg_parse(b)
        except InvalidVersion:
            # Fallback for truly non-standard strings (e.g. OpenSSL "1.1.1t")
            # Strip trailing letter(s) and compare numerically
            def _strip(v: str) -> tuple[int, ...]:
                parts = []
                for seg in re.split(r'[.\-_]', v):
                    m = re.match(r'(\d+)', seg)
                    if m:
                        parts.append(int(m.group(1)))
                return tuple(parts) or (0,)
            return _strip(a) < _strip(b)

except ImportError:
    # packaging not installed — use numeric-only fallback
    def version_lt(a: str, b: str) -> bool:  # type: ignore[misc]
        def _strip(v: str) -> tuple[int, ...]:
            parts = []
            for seg in re.split(r'[.\-_]', v):
                m = re.match(r'(\d+)', seg)
                if m:
                    parts.append(int(m.group(1)))
            return tuple(parts) or (0,)
        return _strip(a) < _strip(b)


def version_satisfies_lt(version: str, ceiling: str) -> bool:
    """
    ceiling is a string like "<8.1" (from EOL_DB).
    Return True if `version` < `ceiling_value`.
    """
    ceiling = ceiling.lstrip("<").strip()
    return version_lt(version, ceiling)


# ═══════════════════════════════════════════════════════════════
# EOL CHECK  (built-in, offline)
# ═══════════════════════════════════════════════════════════════

def check_eol(product: str, version: Optional[str]) -> tuple[bool, Optional[str]]:
    """
    Return (is_eol, eol_date_str) using the built-in EOL_DB.
    If version is None we can't determine EOL — return (False, None).
    """
    if not version:
        return False, None

    key = product.lower().replace(" ", "-").replace("_", "-")
    entries = EOL_DB.get(key)
    if not entries:
        return False, None

    today = date.today()
    for ceiling, eol_str in entries:
        try:
            if version_satisfies_lt(version, ceiling):
                eol_date = date.fromisoformat(eol_str)
                if today >= eol_date:
                    return True, eol_str
                # If EOL date is in the future the branch is still active
                return False, None
        except Exception:
            continue
    return False, None


# ═══════════════════════════════════════════════════════════════
# NVD CVE LOOKUP  (optional)
# ═══════════════════════════════════════════════════════════════

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_nvd_last_call = 0.0
_nvd_lock = threading.Lock()
_NVD_RATE = 6.5   # seconds between calls without API key


def _nvd_wait():
    """Enforce NVD rate limit (5 requests / 30 s without key)."""
    global _nvd_last_call
    with _nvd_lock:
        elapsed = time.time() - _nvd_last_call
        if elapsed < _NVD_RATE:
            time.sleep(_NVD_RATE - elapsed)
        _nvd_last_call = time.time()


def query_nvd(product: str, version: Optional[str],
              api_key: Optional[str] = None,
              timeout: int = 15) -> list[dict]:
    """
    Query NVD for CVEs matching `product` + `version`.
    Returns list of {"id", "cvss", "desc"} dicts (top 5 by severity).

    Improvements (Gemini feedback):
      • Exponential backoff (3 retries) for 503 / transient failures
      • Relevance filter: only keep CVEs whose description mentions
        the product name or version string (reduces keyword-search FPs)
    """
    if not version:
        return []

    _nvd_wait()

    headers = {"apiKey": api_key} if api_key else {}
    params  = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": 10,
    }

    # ── Exponential backoff retry (fix for feedback point 2) ──
    last_exc: Optional[Exception] = None
    for attempt in range(3):
        try:
            resp = requests.get(NVD_API, params=params, headers=headers,
                                timeout=timeout)
            if resp.status_code == 200:
                break
            if resp.status_code in (503, 429, 500):
                # Transient — wait and retry
                wait = 2 ** attempt          # 1s, 2s, 4s
                time.sleep(wait)
                last_exc = Exception(f"HTTP {resp.status_code}")
                continue
            # Non-retryable error (e.g. 403 bad key)
            return []
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
            continue
    else:
        # All retries exhausted
        return []

    try:
        data = resp.json()
    except Exception:
        return []

    results = []
    # Version string variants for relevance filter (feedback point 3)
    ver_variants = {version, version.split(".")[0]}
    prod_lower   = product.lower()

    for item in data.get("vulnerabilities", []):
        cve    = item.get("cve", {})
        cve_id = cve.get("id", "")

        # CVSS v3 preferred, fall back to v2
        cvss = 0.0
        metrics = cve.get("metrics", {})
        v3_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        v2_list = metrics.get("cvssMetricV2", [])
        if v3_list:
            cvss = v3_list[0].get("cvssData", {}).get("baseScore", 0.0)
        elif v2_list:
            cvss = v2_list[0].get("cvssData", {}).get("baseScore", 0.0)

        # Short description
        descs = cve.get("descriptions", [])
        desc  = next((d["value"] for d in descs if d["lang"] == "en"), "")

        # ── Relevance filter: discard CVEs that don't mention the
        #    product or version anywhere in the description.
        #    This eliminates most false positives from broad keyword queries.
        desc_lower = desc.lower()
        if prod_lower not in desc_lower and not any(v in desc_lower for v in ver_variants):
            continue

        desc = desc[:200] + "…" if len(desc) > 200 else desc
        results.append({"id": cve_id, "cvss": cvss, "desc": desc})

    # Sort by severity descending, keep top 5
    results.sort(key=lambda x: x["cvss"], reverse=True)
    return results[:5]


# ═══════════════════════════════════════════════════════════════
# SEVERITY CALCULATION
# ═══════════════════════════════════════════════════════════════

def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "INFO"


def compute_severity(is_eol: bool, cves: list[dict]) -> str:
    """Worst-case severity consolidation."""
    if not cves and not is_eol:
        return "INFO"

    max_cvss = max((c["cvss"] for c in cves), default=0.0)
    cve_sev  = cvss_to_severity(max_cvss)

    if is_eol and cves:
        # Bump one level if EOL + any CVE
        rank = min(SEVERITY_RANK[cve_sev] + 1, 4)
        return list(SEVERITY_RANK.keys())[
            list(SEVERITY_RANK.values()).index(rank)
        ]
    if is_eol:
        return "HIGH"   # unsupported = inherently risky

    return cve_sev


# ═══════════════════════════════════════════════════════════════
# FINGERPRINTING
# ═══════════════════════════════════════════════════════════════

def _fetch(url: str, timeout: int) -> Optional[requests.Response]:
    # Narrow to network errors only — allows KeyboardInterrupt to propagate
    # (fix for Gemini feedback point 4)
    try:
        return requests.get(url, headers={"User-Agent": "Mozilla/5.0"},
                            timeout=timeout, verify=False,
                            allow_redirects=True)
    except requests.exceptions.RequestException:
        return None


def fingerprint_headers(response: requests.Response,
                        url: str) -> list[Component]:
    comps = []
    # Collapse all headers into one searchable string
    header_blob = " ".join(f"{k}: {v}" for k, v in response.headers.items())

    for product, pattern, grp in HEADER_PATTERNS:
        m = pattern.search(header_blob)
        if m:
            comps.append(Component(product, m.group(grp),
                                   "HTTP header", url))
    return comps


def fingerprint_html(response: requests.Response,
                     url: str,
                     soup: BeautifulSoup) -> list[Component]:
    """Accepts a pre-parsed BeautifulSoup object (fix for feedback point 5)."""
    comps = []
    text  = response.text[:200_000]

    # Meta generator
    meta = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if meta:
        content = meta.get("content", "")
        for product, pattern, grp in TEXT_PATTERNS:
            m = pattern.search(content)
            if m:
                comps.append(Component(product, m.group(grp),
                                       "<meta> generator", url))

    # All text (HTML body + comments)
    for product, pattern, grp in TEXT_PATTERNS:
        m = pattern.search(text)
        if m:
            already = any(c.product == product for c in comps)
            if not already:
                comps.append(Component(product, m.group(grp),
                                       "HTML source", url))

    return comps


def fingerprint_scripts(response: requests.Response,
                        url: str,
                        soup: BeautifulSoup) -> list[Component]:
    """Accepts a pre-parsed BeautifulSoup object (fix for feedback point 5)."""
    comps = []
    seen  = set()

    for script in soup.find_all("script", src=True):
        src = script["src"]
        for product, pattern, grp in SCRIPT_PATTERNS:
            m = pattern.search(src)
            if m:
                key = (product, m.group(grp))
                if key not in seen:
                    seen.add(key)
                    comps.append(Component(product, m.group(grp),
                                           f"<script src>: {src[:80]}", url))
    return comps


def fingerprint_cookies(response: requests.Response,
                        url: str) -> list[Component]:
    comps = []
    for cookie_name, product in COOKIE_TECH.items():
        if cookie_name in response.cookies:
            comps.append(Component(product, None,
                                   f"Cookie: {cookie_name}", url))
    return comps


def fingerprint_special_files(base_url: str,
                              timeout: int) -> list[Component]:
    """
    Fetch common version-leaking files and extract version strings.
    """
    comps   = []
    parsed  = urlsplit(base_url)
    root    = f"{parsed.scheme}://{parsed.netloc}"

    for fname in VERSION_FILES:
        furl  = urljoin(root + "/", fname)
        resp  = _fetch(furl, timeout)
        if resp is None or resp.status_code != 200:
            continue

        text = resp.text[:50_000]

        # package.json
        if fname == "package.json":
            try:
                pkg = resp.json()
                name    = pkg.get("name", "nodejs-app")
                version = pkg.get("version")
                if version:
                    comps.append(Component(name, version,
                                           "package.json", furl))
                # Dependencies
                for dep, ver in {**pkg.get("dependencies", {}),
                                 **pkg.get("devDependencies", {})}.items():
                    ver = ver.lstrip("^~>=")
                    comps.append(Component(dep.lower(), ver,
                                           "package.json dep", furl))
            except Exception:
                pass
            continue

        # composer.json
        if fname == "composer.json":
            try:
                pkg = resp.json()
                for dep, ver in {**pkg.get("require", {}),
                                 **pkg.get("require-dev", {})}.items():
                    prod = dep.split("/")[-1].lower()
                    ver  = ver.lstrip("^~>=v")
                    if re.match(r'\d', ver):
                        comps.append(Component(prod, ver,
                                               "composer.json dep", furl))
            except Exception:
                pass
            continue

        # Generic text patterns
        for product, pattern, grp in TEXT_PATTERNS + [
            ("wordpress", re.compile(r'Stable tag:\s*([\d.]+)', re.I), 1),
            ("wordpress", re.compile(r'Version:\s*([\d.]+)',    re.I), 1),
        ]:
            m = pattern.search(text)
            if m:
                comps.append(Component(product, m.group(grp),
                                       f"file: /{fname}", furl))

    return comps


def fingerprint_whatweb(url: str, timeout: int) -> list[Component]:
    """If WhatWeb is installed, run it and parse JSON output."""
    if not shutil.which("whatweb"):
        return []

    comps = []
    try:
        proc = subprocess.run(
            ["whatweb", "--log-json=-", "-a", "3", url],
            capture_output=True, text=True, timeout=timeout
        )
        data = json.loads(proc.stdout or "[]")
        for entry in (data if isinstance(data, list) else [data]):
            plugins = entry.get("plugins", {})
            for pname, pdata in plugins.items():
                version_list = pdata.get("version", [])
                if version_list:
                    for ver in version_list:
                        comps.append(Component(pname.lower(), ver,
                                               "WhatWeb", url))
                else:
                    comps.append(Component(pname.lower(), None,
                                           "WhatWeb", url))
    except Exception:
        pass
    return comps


def fingerprint_url(url: str, timeout: int) -> list[Component]:
    """Run all fingerprinting methods against a single URL."""
    resp = _fetch(url, timeout)
    if resp is None:
        return []

    # ── Parse HTML once and share the object (fix for feedback point 5) ──
    try:
        soup = BeautifulSoup(resp.text[:200_000], "html.parser")
    except Exception:
        soup = BeautifulSoup("", "html.parser")

    comps: list[Component] = []
    comps += fingerprint_headers(resp, url)
    comps += fingerprint_html(resp, url, soup)      # reuses parsed soup
    comps += fingerprint_scripts(resp, url, soup)   # reuses parsed soup
    comps += fingerprint_cookies(resp, url)
    comps += fingerprint_special_files(url, timeout)
    comps += fingerprint_whatweb(url, timeout)

    return comps


# ═══════════════════════════════════════════════════════════════
# DEDUPLICATION
# ═══════════════════════════════════════════════════════════════

def deduplicate(components: list[Component]) -> list[Component]:
    """
    Keep at most one entry per (product, version) pair.
    Prefer non-None versions. Among duplicates, keep the first seen.
    """
    seen:  dict[str, Component] = {}
    for comp in components:
        k = f"{comp.product.lower()}|{comp.version or 'unknown'}"
        if k not in seen:
            seen[k] = comp
    return list(seen.values())


# ═══════════════════════════════════════════════════════════════
# ASSESSMENT ENGINE
# ═══════════════════════════════════════════════════════════════

def assess_component(comp: Component, use_nvd: bool,
                     nvd_key: Optional[str]) -> Assessment:
    result = Assessment(comp)

    # EOL check (always)
    is_eol, eol_date = check_eol(comp.product, comp.version)
    result.is_eol  = is_eol
    result.eol_date = eol_date

    if is_eol:
        result.notes.append(f"End-of-life since {eol_date} — no security patches")

    # CVE lookup (optional)
    if use_nvd and comp.version:
        cves = query_nvd(comp.product, comp.version, api_key=nvd_key)
        result.cves = cves
        if cves:
            result.notes.append(
                f"{len(cves)} CVE(s) found (highest CVSS: {cves[0]['cvss']})"
            )

    # Severity
    result.severity = compute_severity(result.is_eol, result.cves)
    return result


# ═══════════════════════════════════════════════════════════════
# REPORTING
# ═══════════════════════════════════════════════════════════════

_BANNER_WIDTH = 70

def _colored(text: str, col: str) -> str:
    return f"{col}{text}{R}"


def print_summary_table(assessments: list[Assessment]) -> None:
    # Sort by severity rank descending
    assessments = sorted(assessments,
                         key=lambda a: SEVERITY_RANK.get(a.severity, 0),
                         reverse=True)

    line = "═" * _BANNER_WIDTH
    print(f"\n{_colored(line, CYAN)}")
    print(_colored("  STAGE 5 — Component Version Intelligence".center(_BANNER_WIDTH), BOLD + CYAN))
    print(_colored(line, CYAN))

    hdr = (f"  {'Component':<22} {'Version':<14} {'Status':<22} {'Severity':<10}")
    print(_colored(hdr, BOLD + WHITE))
    print(_colored("  " + "─" * (_BANNER_WIDTH - 2), DIM))

    for a in assessments:
        col   = SEVERITY_COLOR.get(a.severity, WHITE)
        icon  = SEVERITY_ICON.get(a.severity, "")
        prod  = a.component.product[:21]
        ver   = (a.component.version or "unknown")[:13]

        status_parts = []
        if a.is_eol:
            status_parts.append("EOL")
        if a.cves:
            status_parts.append(f"{len(a.cves)} CVE(s)")
        if not status_parts:
            status_parts.append("No issues found")
        status = " + ".join(status_parts)[:21]

        row = f"  {prod:<22} {ver:<14} {status:<22} {a.severity:<8} {icon}"
        print(_colored(row, col))

    print(_colored(line, CYAN))

    counts = {s: 0 for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for a in assessments:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    print("\n  Severity Summary:")
    for sev, cnt in counts.items():
        col  = SEVERITY_COLOR.get(sev, WHITE)
        icon = SEVERITY_ICON.get(sev, "")
        bar  = "█" * cnt
        print(f"    {_colored(f'{sev:<10}', col)} {cnt:>3}  {_colored(bar, col)} {icon}")
    print()


def write_text_report(assessments: list[Assessment], path: str) -> None:
    assessments = sorted(assessments,
                         key=lambda a: SEVERITY_RANK.get(a.severity, 0),
                         reverse=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("  COMPONENT VERSION INTELLIGENCE REPORT\n")
        f.write(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            group = [a for a in assessments if a.severity == sev]
            if not group:
                continue
            f.write(f"\n{'─'*70}\n")
            f.write(f"  [{sev}]\n")
            f.write(f"{'─'*70}\n")
            for a in group:
                c = a.component
                f.write(f"\n  Product  : {c.product}\n")
                f.write(f"  Version  : {c.version or 'unknown'}\n")
                f.write(f"  Source   : {c.source}\n")
                f.write(f"  URL      : {c.source_url}\n")
                f.write(f"  EOL      : {'Yes (' + a.eol_date + ')' if a.is_eol else 'No'}\n")
                if a.cves:
                    f.write(f"  CVEs     :\n")
                    for cve in a.cves:
                        f.write(f"    • {cve['id']}  CVSS={cve['cvss']}\n")
                        f.write(f"      {cve['desc']}\n")
                if a.notes:
                    for note in a.notes:
                        f.write(f"  Note     : {note}\n")

        f.write("\n" + "=" * 70 + "\n")


def write_json_report(assessments: list[Assessment], path: str) -> None:
    data = {
        "generated": datetime.now().isoformat(),
        "total":     len(assessments),
        "findings":  [a.to_dict() for a in assessments],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="version_scan.py — Component version fingerprinting & CVE assessment"
    )
    p.add_argument("input_file", nargs="?", default="FULL_URL.txt",
                   help="File with one URL per line (default: FULL_URL.txt)")
    p.add_argument("--out-txt",  default="version_report.txt",
                   help="Text report output path")
    p.add_argument("--out-json", default="version_results.json",
                   help="JSON report output path")
    p.add_argument("--threads",  type=int, default=5,
                   help="Concurrent fingerprint workers (default: 5)")
    p.add_argument("--timeout",  type=int, default=10,
                   help="HTTP timeout per request in seconds (default: 10)")
    p.add_argument("--no-nvd",   action="store_true",
                   help="Skip NVD CVE API lookup (offline / EOL-only mode)")
    p.add_argument("--nvd-key",  default=None,
                   help="NVD API key (optional; raises rate limit)")
    return p.parse_args()


def main():
    args = parse_args()

    # ── load URLs ────────────────────────────────────────────
    try:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as fh:
            raw = [ln.strip() for ln in fh if ln.strip()]
    except FileNotFoundError:
        print(f"[-] File not found: {args.input_file}")
        sys.exit(1)

    urls = list(dict.fromkeys(
        u if u.startswith("http") else "http://" + u for u in raw
    ))

    # Deduplicate to unique hosts for initial fingerprint
    seen_hosts: set[str] = set()
    scan_urls: list[str] = []
    for u in urls:
        host = urlsplit(u).netloc
        if host not in seen_hosts:
            seen_hosts.add(host)
            scan_urls.append(u)
    # Also include all unique full URLs (for script-level detection)
    scan_urls = list(dict.fromkeys(scan_urls + urls))[:50]  # cap at 50

    use_nvd = not args.no_nvd
    print(f"\n[+] version_scan.py — {len(scan_urls)} URL(s) | "
          f"threads={args.threads} | NVD={'ON' if use_nvd else 'OFF'}")
    if use_nvd:
        print(f"    NVD rate-limit mode: {'API key provided' if args.nvd_key else 'no key (throttled)'}")
    print("=" * 60)

    # ── concurrent fingerprinting ─────────────────────────────
    all_components: list[Component] = []
    futures: dict = {}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for i, url in enumerate(scan_urls):
            fut = pool.submit(fingerprint_url, url, args.timeout)
            futures[fut] = (i + 1, url)

        for fut in as_completed(futures):
            idx, url = futures[fut]
            safe_print(f"  [{idx}/{len(scan_urls)}] Fingerprinted: {url}")
            try:
                comps = fut.result()
                if comps:
                    safe_print(f"    → {len(comps)} component(s) detected")
                all_components.extend(comps)
            except Exception as exc:
                safe_print(f"    [!] Error: {exc}")

    # ── deduplication ────────────────────────────────────────
    unique = deduplicate(all_components)
    print(f"\n[+] Unique components detected: {len(unique)}")

    # ── assessment ───────────────────────────────────────────
    print(f"[+] Assessing components{'  (NVD CVE lookup in progress...)' if use_nvd else '  (EOL check only)'}...")
    assessments: list[Assessment] = []

    # CVE lookups are rate-limited — run sequentially to respect NVD limits
    for comp in unique:
        a = assess_component(comp, use_nvd=use_nvd, nvd_key=args.nvd_key)
        assessments.append(a)

    # ── console table ─────────────────────────────────────────
    print_summary_table(assessments)

    # ── write reports ─────────────────────────────────────────
    write_text_report(assessments, args.out_txt)
    write_json_report(assessments, args.out_json)

    flagged = sum(1 for a in assessments if a.severity != "INFO")
    print(f"[+] Reports saved:")
    print(f"    Text : {args.out_txt}")
    print(f"    JSON : {args.out_json}")
    print(f"[+] {flagged}/{len(assessments)} component(s) flagged.\n")


if __name__ == "__main__":
    main()
