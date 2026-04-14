#!/usr/bin/env python3

# ============================================================
#  para.py — Concurrent HTML form & API parameter discovery
#  Used by detail_scan.sh Stage 3
#
#  Usage:
#    python3 para.py <urls_file> [report.txt]
#              [--threads N] [--timeout S]
#
#  What it harvests per URL:
#    • HTML forms  (all fields incl. hidden, select options)
#    • <a href> query-string parameters
#    • JSON endpoint top-level keys
#    • HTTP OPTIONS — allowed methods
#
#  Output:
#    • Console progress + per-URL findings
#    • Appended structured report (default: param_discovery_report.txt)
# ============================================================

import argparse
import sys
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── constants ────────────────────────────────────────────────
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
SKIP_TYPES  = {'submit', 'button', 'image', 'reset'}    # low recon value
PRINT_LOCK  = threading.Lock()


# ── helpers ──────────────────────────────────────────────────

def safe_print(*args, **kwargs):
    with PRINT_LOCK:
        print(*args, **kwargs)


def fetch(url: str, method: str = 'GET', timeout: int = 8):
    """One GET or OPTIONS request with a single retry on timeout."""
    try:
        fn = requests.options if method == 'OPTIONS' else requests.get
        resp = fn(url, headers=HEADERS, timeout=timeout,
                  verify=False, allow_redirects=True)
        return resp
    except requests.exceptions.Timeout:
        try:
            fn = requests.options if method == 'OPTIONS' else requests.get
            return fn(url, headers=HEADERS, timeout=timeout * 2,
                      verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None
    except requests.exceptions.RequestException:
        return None


def resolve_action(base_url: str, action: str) -> str:
    if not action or action.strip() in ('#', ''):
        return base_url
    return urljoin(base_url, action)


def extract_select_options(select_tag) -> list:
    return [
        o.get('value', o.get_text(strip=True))
        for o in select_tag.find_all('option')
        if o.get('value') or o.get_text(strip=True)
    ]


# ── per-URL scanners ─────────────────────────────────────────

def scan_options_method(url: str, timeout: int) -> list:
    """Probe HTTP OPTIONS and return the list of allowed methods."""
    resp = fetch(url, method='OPTIONS', timeout=timeout)
    if resp is None:
        return []
    allow = resp.headers.get('Allow', '') or resp.headers.get('Access-Control-Allow-Methods', '')
    methods = [m.strip().upper() for m in allow.split(',') if m.strip()]
    return methods


def scan_json_endpoint(response) -> list:
    """If URL returns JSON, extract top-level keys as params."""
    ct = response.headers.get('Content-Type', '')
    if 'application/json' in ct:
        try:
            data = response.json()
            if isinstance(data, dict):
                return list(data.keys())
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return list(data[0].keys())
        except Exception:
            pass
    return []


def scan_forms(soup, base_url: str) -> list:
    """Extract all form fields (incl. hidden) from parsed HTML."""
    forms_data = []
    for i, form in enumerate(soup.find_all('form')):
        method  = form.get('method', 'GET').upper()
        action  = resolve_action(base_url, form.get('action', ''))
        enctype = form.get('enctype', 'application/x-www-form-urlencoded')

        params = []
        seen_names = set()

        for field in form.find_all(['input', 'textarea', 'select']):
            name       = field.get('name')
            field_type = field.get('type', 'text').lower()

            # Skip unnamed and non-value types
            if not name or field_type in SKIP_TYPES:
                continue
            if name in seen_names:
                continue
            seen_names.add(name)

            param = {'name': name, 'type': field_type}

            if field.name == 'select':
                param['options'] = extract_select_options(field)
            elif field_type == 'hidden':
                param['value'] = field.get('value', '')   # hidden value is useful

            params.append(param)

        forms_data.append({
            'index':   i + 1,
            'method':  method,
            'action':  action,
            'enctype': enctype,
            'params':  params,
        })

    return forms_data


def scan_link_params(soup, base_url: str) -> dict:
    """
    Harvest query-string parameter names from all <a href> links.
    Returns {param_name: [example_values]} mapping.
    """
    found = {}
    for tag in soup.find_all('a', href=True):
        href = tag['href']
        try:
            full = urljoin(base_url, href)
            qs   = parse_qs(urlparse(full).query)
            for key, vals in qs.items():
                if key not in found:
                    found[key] = []
                for v in vals:
                    if v and v not in found[key]:
                        found[key].append(v)
        except Exception:
            continue
    return found


def scan_url(url: str, index: int, total: int, timeout: int) -> dict:
    """
    Full scan of a single URL.
    Returns a structured result dict.
    """
    safe_print(f"  [{index}/{total}] Scanning: {url}")

    result = {
        'url':          url,
        'allowed_methods': [],
        'forms':        [],
        'link_params':  {},
        'json_params':  [],
        'error':        None,
    }

    # ── fetch page ───────────────────────────────────────────
    response = fetch(url, timeout=timeout)
    if response is None:
        result['error'] = 'Connection failed'
        safe_print(f"    [!] Unreachable: {url}")
        return result

    # ── OPTIONS probe ────────────────────────────────────────
    methods = scan_options_method(url, timeout)
    if methods:
        result['allowed_methods'] = methods
        safe_print(f"    [+] Allowed methods : {', '.join(methods)}")

    # ── JSON endpoint ────────────────────────────────────────
    json_params = scan_json_endpoint(response)
    if json_params:
        result['json_params'] = json_params
        safe_print(f"    [+] JSON endpoint   : {', '.join(json_params)}")

    # ── HTML parse ───────────────────────────────────────────
    soup  = BeautifulSoup(response.text, 'html.parser')

    # Forms
    forms = scan_forms(soup, url)
    result['forms'] = forms
    if forms:
        safe_print(f"    [+] Forms found     : {len(forms)}")
        for f in forms:
            param_names = [p['name'] for p in f['params']]
            hidden_count = sum(1 for p in f['params'] if p['type'] == 'hidden')
            safe_print(f"        Form {f['index']} [{f['method']}] → {f['action']}")
            safe_print(f"          Params ({len(param_names)}): {', '.join(param_names) or 'none'}"
                       + (f"  [{hidden_count} hidden]" if hidden_count else ""))

    # Link params
    link_params = scan_link_params(soup, url)
    result['link_params'] = link_params
    if link_params:
        safe_print(f"    [+] Link params     : {', '.join(link_params.keys())}")

    if not forms and not json_params and not link_params and not methods:
        safe_print(f"    [-] Nothing found")

    return result


# ── report writer ─────────────────────────────────────────────

def write_report(results: list, report_path: str) -> None:
    """Append Stage 3 results to the param_discovery_report.txt."""
    with open(report_path, 'a', encoding='utf-8') as f:
        for r in results:
            f.write("════════════════════════════════════════\n")
            f.write(f"URL : {r['url']}\n")

            if r.get('error'):
                f.write(f"  ⚠  Error: {r['error']}\n\n")
                continue

            # Allowed methods
            if r.get('allowed_methods'):
                f.write(f"  HTTP Methods : {', '.join(r['allowed_methods'])}\n")

            # JSON params
            if r.get('json_params'):
                f.write("\n  JSON Params:\n")
                for p in r['json_params']:
                    f.write(f"    • {p}\n")

            # Forms
            for form in r.get('forms', []):
                f.write(f"\n  Form {form['index']}:\n")
                f.write(f"    Method  : {form['method']}\n")
                f.write(f"    Action  : {form['action']}\n")
                f.write(f"    Enctype : {form['enctype']}\n")
                f.write(f"    Params  :\n")
                if form['params']:
                    for p in form['params']:
                        line = f"      • {p['name']} (type: {p['type']})"
                        if p.get('options'):
                            line += f"  options: {p['options']}"
                        if p.get('value'):
                            line += f"  value: \"{p['value']}\""
                        f.write(line + "\n")
                else:
                    f.write("      • (none — may be JS-driven)\n")

            # Link params
            if r.get('link_params'):
                f.write("\n  Link Parameters:\n")
                for name, vals in r['link_params'].items():
                    example = f"  e.g. {vals[0]}" if vals else ""
                    f.write(f"    • {name}{example}\n")

            f.write("\n")


# ── main ──────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='para.py — concurrent parameter & form discovery')
    p.add_argument('urls_file',
                   help='Text file with one URL per line')
    p.add_argument('report_file',
                   nargs='?',
                   default='param_discovery_report.txt',
                   help='Output report path (default: param_discovery_report.txt)')
    p.add_argument('--threads', type=int, default=10,
                   help='Concurrent workers (default: 10)')
    p.add_argument('--timeout', type=int, default=8,
                   help='Request timeout in seconds (default: 8)')
    return p.parse_args()


def main():
    args = parse_args()

    # ── load URLs ────────────────────────────────────────────
    try:
        with open(args.urls_file, 'r', encoding='utf-8', errors='ignore') as f:
            raw_urls = [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        print(f"[-] File not found: {args.urls_file}")
        sys.exit(1)

    # Normalise — ensure http:// prefix
    urls = []
    for u in raw_urls:
        if not u.startswith('http'):
            u = 'http://' + u
        urls.append(u)

    total = len(urls)
    print(f"\n[+] para.py — scanning {total} URL(s) with {args.threads} threads")
    print("=" * 60)

    # ── concurrent scan ──────────────────────────────────────
    results   = [None] * total
    futures   = {}

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for i, url in enumerate(urls):
            fut = pool.submit(scan_url, url, i + 1, total, args.timeout)
            futures[fut] = i

        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:
                results[idx] = {
                    'url': urls[idx], 'error': str(exc),
                    'forms': [], 'link_params': {},
                    'json_params': [], 'allowed_methods': [],
                }

    # ── summary ──────────────────────────────────────────────
    total_forms   = sum(len(r.get('forms', []))       for r in results if r)
    total_params  = sum(
        len(p['params'])
        for r in results if r
        for p in r.get('forms', [])
    )
    total_link_p  = sum(len(r.get('link_params', {})) for r in results if r)
    errors        = sum(1 for r in results if r and r.get('error'))

    print(f"\n{'=' * 60}")
    print(f"[+] Scan Complete")
    print(f"    URLs scanned     : {total}")
    print(f"    Errors           : {errors}")
    print(f"    Forms found      : {total_forms}")
    print(f"    Form params      : {total_params}")
    print(f"    Link params      : {total_link_p}")

    # ── write report ─────────────────────────────────────────
    write_report([r for r in results if r], args.report_file)
    print(f"    Report saved     : {args.report_file}")


if __name__ == '__main__':
    main()
