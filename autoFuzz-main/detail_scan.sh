#!/bin/bash

# ============================================================
#  detail_scan.sh — Multi-stage recon & vulnerability pipeline
#
#  Stage 1 : Directory brute-force            (gobuster)
#  Stage 2 : Hidden file discovery per dir   (gobuster)
#  Stage 3 : Parameter & method detection    (para.py)
#  Stage 4 : Vulnerability scanning          (vuln_scan.py → nikto + nuclei)
#  Stage 5 : Component version intelligence  (version_scan.py)
# ============================================================

TARGET=$1

# ── wordlists ────────────────────────────────────────────────
DIR_WORDLIST="dirCommon.txt"
FILE_WORDLIST="hiddenFiles.txt"

# ── output files ─────────────────────────────────────────────
DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"
ALL_PATHS="FULL_URL.txt"
PARAM_REPORT="param_discovery_report.txt"
VERSION_REPORT="version_report.txt"
VERSION_JSON="version_results.json"

# ── tuning ───────────────────────────────────────────────────
GOBUSTER_THREADS=20
PARA_THREADS=10
PARA_TIMEOUT=8
VULN_THREADS=4
VULN_TIMEOUT=300
VERSION_THREADS=5
VERSION_TIMEOUT=10

# ── script location (so Python scanners are found reliably) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARAM_SCANNER="$SCRIPT_DIR/para.py"
VULN_SCANNER="$SCRIPT_DIR/vuln_scan.py"
VERSION_SCANNER="$SCRIPT_DIR/version_scan.py"

# ── colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── usage ────────────────────────────────────────────────────
if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: ./detail_scan.sh <target_url>${NC}"
    echo -e "       e.g.  ./detail_scan.sh https://example.com"
    exit 1
fi

# Strip trailing slash
TARGET=$(echo "$TARGET" | sed 's/\/$//')

PIPELINE_START=$(date +%s)

echo -e "\n${BOLD}${CYAN}  autoFuzz — Detail Scan Pipeline${NC}"
echo -e "  Target  : ${YELLOW}${TARGET}${NC}"
echo -e "  Started : $(date '+%Y-%m-%d %H:%M:%S')\n"

# ── helper: elapsed time ─────────────────────────────────────
elapsed() {
    local start=$1
    local end
    end=$(date +%s)
    echo $(( end - start ))
}

# ── helper: python3 presence ─────────────────────────────────
check_python() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[!] python3 not found. Please install Python 3.${NC}"
        exit 1
    fi
}

# ── helper: pip install if missing ───────────────────────────
ensure_pip_pkg() {
    local pkg=$1
    python3 -c "import $pkg" 2>/dev/null || {
        echo -e "${YELLOW}[!] Installing Python package: $pkg${NC}"
        pip3 install "$pkg" --quiet
    }
}

# ============================================================
# STAGE 1 — Directory discovery
# ============================================================
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 1: Directory Discovery${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

STAGE1_START=$(date +%s)
echo "$TARGET" > "$DIR_FILE"

gobuster dir \
    -u "$TARGET" \
    -w "$DIR_WORDLIST" \
    --threads "$GOBUSTER_THREADS" \
    --no-error \
    -q \
    | grep -E "(Status: (200|204|301|302)|^/)" \
    | awk -v t="$TARGET" '
        /^\//{  # gobuster v3+ format: /path (Status: 200)
            path = $1
            gsub(/\/+$/, "", path)
            if (path != "") print t path
        }
        /Status:/{  # gobuster v2 format: /path  (Status: 200)
            path = $1
            gsub(/\/+$/, "", path)
            if (path != "") print t path
        }
    ' | sort -u >> "$DIR_FILE"

FOUND_DIRS=$(wc -l < "$DIR_FILE")
echo -e "${GREEN}[+] Found ${FOUND_DIRS} path(s) in $(elapsed $STAGE1_START)s. Saved → $DIR_FILE${NC}"

# ============================================================
# STAGE 2 — Hidden file discovery per directory
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 2: Hidden File Discovery${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

STAGE2_START=$(date +%s)
echo "--- HIDDEN FILE REPORT ---" > "$RESULT_FILE"
> "$ALL_PATHS"

while read -r FULL_URL; do
    echo -e "${YELLOW}[~] Fuzzing: $FULL_URL${NC}"
    echo "--- Results for $FULL_URL ---" >> "$RESULT_FILE"

    GOBUSTER_OUTPUT=$(gobuster dir \
        -u "$FULL_URL" \
        -w "$FILE_WORDLIST" \
        -x php,bak,zip,txt,old,html,conf,json \
        --threads "$GOBUSTER_THREADS" \
        --no-error \
        -q \
        | grep -E "(Status: (200|204|301|302)|^/)")

    echo "$GOBUSTER_OUTPUT" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"

    # Build full URLs — handle both gobuster v2 and v3 output
    echo "$GOBUSTER_OUTPUT" | awk -v base="$FULL_URL" '
        {
            path = $1
            gsub(/^\/+/, "", path)
            gsub(/\/+$/, "", path)
            if (path != "") print base "/" path
        }
    ' >> "$ALL_PATHS"

done < "$DIR_FILE"

sort -u "$ALL_PATHS" -o "$ALL_PATHS"
FOUND_FILES=$(wc -l < "$ALL_PATHS")
echo -e "${GREEN}[+] Stage 2 done in $(elapsed $STAGE2_START)s. ${FOUND_FILES} unique URL(s) → $ALL_PATHS${NC}"

# ============================================================
# STAGE 3 — Parameter & method detection
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 3: Parameter & Method Detection${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

check_python

if [ ! -f "$PARAM_SCANNER" ]; then
    echo -e "${RED}[!] para.py not found: $PARAM_SCANNER${NC}"
    exit 1
fi

ensure_pip_pkg requests
ensure_pip_pkg bs4

# Write report header
{
    echo "--- PARAMETER DISCOVERY REPORT ---"
    echo "Generated : $(date)"
    echo "Target    : $TARGET"
    echo ""
} > "$PARAM_REPORT"

STAGE3_START=$(date +%s)
echo -e "${YELLOW}[~] Launching para.py — ${FOUND_FILES} URL(s), ${PARA_THREADS} threads...${NC}"

python3 "$PARAM_SCANNER" \
    "$ALL_PATHS" \
    "$PARAM_REPORT" \
    --threads "$PARA_THREADS" \
    --timeout "$PARA_TIMEOUT"

STAGE3_RC=$?
if [ $STAGE3_RC -ne 0 ]; then
    echo -e "${RED}[!] para.py exited with code $STAGE3_RC${NC}"
else
    echo -e "${GREEN}[+] Stage 3 done in $(elapsed $STAGE3_START)s. Report → $PARAM_REPORT${NC}"
fi

# ============================================================
# STAGE 4 — Vulnerability scanning
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 4: Vulnerability Scanning${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

if [ ! -f "$VULN_SCANNER" ]; then
    echo -e "${RED}[!] vuln_scan.py not found: $VULN_SCANNER${NC}"
    exit 1
fi

STAGE4_START=$(date +%s)
echo -e "${YELLOW}[~] Launching vuln_scan.py — ${VULN_THREADS} Nikto workers, nuclei combined...${NC}"

python3 "$VULN_SCANNER" \
    "$ALL_PATHS" \
    --threads "$VULN_THREADS" \
    --timeout "$VULN_TIMEOUT"

STAGE4_RC=$?
if [ $STAGE4_RC -ne 0 ]; then
    echo -e "${RED}[!] vuln_scan.py exited with code $STAGE4_RC${NC}"
else
    echo -e "${GREEN}[+] Stage 4 done in $(elapsed $STAGE4_START)s. Results → vuln_results/${NC}"
fi

# ============================================================
# STAGE 5 — Component version intelligence
# ============================================================
echo -e "\n${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}    STAGE 5: Component Version Intelligence${NC}"
echo -e "${BOLD}${CYAN}[+] ══════════════════════════════════════${NC}"

if [ ! -f "$VERSION_SCANNER" ]; then
    echo -e "${RED}[!] version_scan.py not found: $VERSION_SCANNER${NC}"
    exit 1
fi

ensure_pip_pkg packaging

STAGE5_START=$(date +%s)
echo -e "${YELLOW}[~] Launching version_scan.py — fingerprinting software versions...${NC}"

python3 "$VERSION_SCANNER" \
    "$ALL_PATHS" \
    --out-txt  "$VERSION_REPORT" \
    --out-json "$VERSION_JSON" \
    --threads  "$VERSION_THREADS" \
    --timeout  "$VERSION_TIMEOUT"

STAGE5_RC=$?
if [ $STAGE5_RC -ne 0 ]; then
    echo -e "${RED}[!] version_scan.py exited with code $STAGE5_RC${NC}"
else
    echo -e "${GREEN}[+] Stage 5 done in $(elapsed $STAGE5_START)s.${NC}"
    echo -e "    ${CYAN}Version report → $VERSION_REPORT${NC}"
    echo -e "    ${CYAN}Version JSON   → $VERSION_JSON${NC}"
fi

# ── Final pipeline summary ───────────────────────────────────
TOTAL_ELAPSED=$(elapsed $PIPELINE_START)

echo ""
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}    ALL STAGES COMPLETE${NC}"
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "    ${CYAN}Total elapsed        : ${TOTAL_ELAPSED}s${NC}"
echo -e "    ${CYAN}Stage 1 dirs         : $DIR_FILE  (${FOUND_DIRS} paths)${NC}"
echo -e "    ${CYAN}Stage 2 hidden files : $ALL_PATHS  (${FOUND_FILES} URLs)${NC}"
echo -e "    ${CYAN}Stage 3 param report : $PARAM_REPORT${NC}"
echo -e "    ${CYAN}Stage 4 vuln results : vuln_results/${NC}"
echo -e "    ${CYAN}Stage 5 ver report   : $VERSION_REPORT${NC}"
echo -e "    ${CYAN}Stage 5 ver JSON     : $VERSION_JSON${NC}"
echo ""
