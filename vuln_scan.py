#!/usr/bin/env python3
from __future__ import annotations

# ============================================================
#  vuln_scan.py — Nikto + Nuclei vulnerability orchestrator
#  Used by detail_scan.sh Stage 4
#
#  Usage:
#    python3 vuln_scan.py [FULL_URL.txt] [--out DIR]
#                         [--threads N] [--timeout S]
#
#  Key improvements over v1:
#    • Nikto runs in parallel via ThreadPoolExecutor
#    • Nuclei called ONCE with -l <list_file> (not per-URL)
#    • Per-subprocess timeout — no more deadlocks
#    • Graceful tool availability check (warn & skip, not hard exit)
#    • Full filtered URLs passed to Nikto (not stripped base paths)
#    • Deterministic URL deduplication
#    • Per-scan timing + final summary
# ============================================================

import argparse
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# ── ANSI colours ─────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[97m"


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}"


def banner(title: str) -> None:
    line = "═" * 62
    print(f"\n{c(line, CYAN)}")
    print(f"{c(title.center(62), BOLD + CYAN)}")
    print(f"{c(line, CYAN)}")


def info(msg: str)    -> None: print(c(msg, WHITE))
def warn(msg: str)    -> None: print(c(msg, YELLOW))
def error(msg: str)   -> None: print(c(msg, RED))
def success(msg: str) -> None: print(c(msg, GREEN))


# ── tool availability ────────────────────────────────────────

def check_tool(name: str) -> bool:
    """Return True if tool is on PATH; warn and return False otherwise."""
    if shutil.which(name) is None:
        warn(f"[!] Tool not found: '{name}'. Skipping {name} scans.")
        return False
    return True


# ── URL utilities ─────────────────────────────────────────────
STATIC_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".css", ".js",  ".woff", ".woff2", ".ttf", ".ico",
    ".mp4", ".mp3", ".pdf",
)


def is_scannable(url: str) -> bool:
    return not url.lower().endswith(STATIC_EXT)


def dedup_urls(urls: list[str]) -> list[str]:
    """
    Deterministic deduplication:
      - Normalise path (collapse double-slashes, strip trailing slash
        unless root)
      - Keep first occurrence of each normalised URL in input order
    """
    seen   = set()
    result = []
    for url in urls:
        p = urlsplit(url)
        path = p.path
        # Collapse double-slashes
        while "//" in path:
            path = path.replace("//", "/")
        # Strip trailing slash unless it's the root
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        norm = urlunsplit((p.scheme, p.netloc, path, "", ""))
        if norm not in seen:
            seen.add(norm)
            result.append(url)   # keep original URL for scanning
    return result


def read_urls(path: Path) -> list[str]:
    if not path.exists():
        error(f"[!] Input file not found: {path}")
        sys.exit(1)
    seen, urls = set(), []
    for raw in path.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if line.startswith(("http://", "https://")) and line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


# ── command runner ────────────────────────────────────────────

def run_scan(title: str, cmd: list[str], log_path: Path,
             target: str, timeout: int) -> tuple[int, float]:
    """
    Run a subprocess, tee output to log_path, and return
    (returncode, elapsed_seconds).  Kills process after `timeout` s.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    try:
        with log_path.open("w") as log:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                stdout, _ = proc.communicate(timeout=timeout)
                log.write(stdout)
                # Stream to console line by line
                for line in stdout.splitlines():
                    print(f"  {line}")
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate()
                log.write(stdout)
                warn(f"  [!] {title} timed out after {timeout}s → {target}")
                return -1, time.time() - t0

        elapsed = time.time() - t0
        return proc.returncode, elapsed

    except Exception as exc:
        elapsed = time.time() - t0
        error(f"  [!] {title} error: {exc}")
        return -1, elapsed


# ── Nikto worker (called per base URL in thread pool) ─────────

def nikto_worker(args_tuple) -> dict:
    target, log_path, timeout = args_tuple
    info(f"\n  [Nikto] → {target}")
    cmd = [
        "nikto",
        "-h", target,
        "-ask", "no",
        "-timeout", str(max(10, timeout // 10)),  # per-request timeout
        "-maxtime", str(timeout),                 # overall max time
    ]
    rc, elapsed = run_scan("Nikto", cmd, log_path, target, timeout)
    return {"target": target, "log": str(log_path), "rc": rc, "elapsed": elapsed}


# ── Nuclei (single call for all URLs via -l) ─────────────────

def run_nuclei(url_list_path: Path, out_dir: Path, timeout: int) -> dict:
    log_path = out_dir / "nuclei" / "nuclei_combined.log"
    info(f"\n  [Nuclei] Scanning {url_list_path} (combined run)...")
    cmd = [
        "nuclei",
        "-l", str(url_list_path),
        "-severity", "medium,high,critical",
        "-o", str(log_path.with_suffix(".txt")),
        "-silent",
    ]
    rc, elapsed = run_scan("Nuclei", cmd, log_path, str(url_list_path), timeout)
    return {"log": str(log_path), "rc": rc, "elapsed": elapsed}


# ── main ──────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="vuln_scan.py — parallel Nikto + Nuclei scanner")
    p.add_argument("input_file", nargs="?", default="FULL_URL.txt",
                   help="File with one URL per line (default: FULL_URL.txt)")
    p.add_argument("--out",     default="vuln_results",
                   help="Output directory (default: vuln_results)")
    p.add_argument("--threads", type=int, default=4,
                   help="Parallel Nikto workers (default: 4)")
    p.add_argument("--timeout", type=int, default=300,
                   help="Timeout per Nikto scan in seconds (default: 300)")
    p.add_argument("--nuclei-timeout", type=int, default=600,
                   help="Overall Nuclei timeout in seconds (default: 600)")
    return p.parse_args()


def main():
    args    = parse_args()
    out_dir = Path(args.out)

    banner("Stage 4 — Vulnerability Scanning")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Input   : {args.input_file}")
    print(f"  Output  : {out_dir}/\n")

    # ── tool checks (warn, not abort) ────────────────────────
    has_nikto  = check_tool("nikto")
    has_nuclei = check_tool("nuclei")

    if not has_nikto and not has_nuclei:
        error("[!] Neither nikto nor nuclei is available. Aborting Stage 4.")
        sys.exit(1)

    # ── load & filter URLs ───────────────────────────────────
    all_urls      = read_urls(Path(args.input_file))
    filtered      = [u for u in all_urls if is_scannable(u)]
    filtered      = dedup_urls(filtered)

    info(f"  Total raw URLs   : {len(all_urls)}")
    info(f"  Scannable (dedup): {len(filtered)}")

    if not filtered:
        warn("[!] No scannable URLs found. Exiting Stage 4.")
        sys.exit(0)

    # ── write filtered URL list for Nuclei ───────────────────
    out_dir.mkdir(parents=True, exist_ok=True)
    nuclei_list = out_dir / "nuclei_targets.txt"
    nuclei_list.write_text("\n".join(filtered) + "\n")

    nikto_dir  = out_dir / "nikto"
    nuclei_dir = out_dir / "nuclei"
    nikto_dir.mkdir(parents=True, exist_ok=True)
    nuclei_dir.mkdir(parents=True, exist_ok=True)

    t_start = time.time()
    nikto_results  = []
    nuclei_result  = {}

    # ── Nikto — parallel ─────────────────────────────────────
    if has_nikto:
        banner("Nikto Scans")
        task_args = [
            (url,
             nikto_dir / f"nikto_{i+1}.log",
             args.timeout)
            for i, url in enumerate(filtered)
        ]
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futs = {pool.submit(nikto_worker, ta): ta for ta in task_args}
            for fut in as_completed(futs):
                try:
                    res = fut.result()
                    nikto_results.append(res)
                    elapsed_str = f"{res['elapsed']:.1f}s"
                    status_str  = "OK" if res['rc'] == 0 else f"rc={res['rc']}"
                    info(f"  ✔ Nikto done [{status_str}] [{elapsed_str}] → {res['target']}")
                except Exception as exc:
                    error(f"  [!] Nikto worker error: {exc}")

    # ── Nuclei — single combined run ─────────────────────────
    if has_nuclei:
        banner("Nuclei Combined Scan")
        nuclei_result = run_nuclei(nuclei_list, out_dir, args.nuclei_timeout)
        elapsed_str   = f"{nuclei_result.get('elapsed', 0):.1f}s"
        info(f"  ✔ Nuclei done [{elapsed_str}]")

    # ── final summary ─────────────────────────────────────────
    total_elapsed = time.time() - t_start
    banner("Stage 4 — Summary")

    lbl_targets  = "Targets scanned"
    lbl_elapsed   = "Total elapsed"
    print(f"  {lbl_targets:<25}: {len(filtered)}")
    print(f"  {lbl_elapsed:<25}: {total_elapsed:.1f}s")

    if has_nikto:
        ok  = sum(1 for r in nikto_results if r['rc'] == 0)
        err = len(nikto_results) - ok
        lbl_nikto   = "Nikto scans"
        lbl_nlogs   = "Nikto logs"
        print(f"  {lbl_nikto:<25}: {ok} OK, {err} errors")
        print(f"  {lbl_nlogs:<25}: {nikto_dir}/")

    if has_nuclei:
        nrc = nuclei_result.get('rc', -1)
        lbl_nstatus = "Nuclei status"
        lbl_nlog    = "Nuclei log"
        lbl_nfind   = "Nuclei findings"
        print(f"  {lbl_nstatus:<25}: {'OK' if nrc == 0 else f'rc={nrc}'}")
        print(f"  {lbl_nlog:<25}: {nuclei_dir}/nuclei_combined.log")
        print(f"  {lbl_nfind:<25}: {nuclei_dir}/nuclei_combined.txt")

    success("\n[+] Stage 4 complete.\n")


if __name__ == "__main__":
    main()
