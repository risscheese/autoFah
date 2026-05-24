#!/bin/bash

# ============================================================
#  autoFah.sh — Recon Stage 1 & 2 Only
#
#  Stage 1 : Directory brute-force            (gobuster)
#  Stage 2 : Hidden file discovery per dir   (gobuster)
# ============================================================

TARGET=$1

# ── wordlists ────────────────────────────────────────────────
DIR_WORDLIST="wordlist/directoryWL.txt"
FILE_WORDLIST="wordlist/filesWL.txt"

# ── output files ─────────────────────────────────────────────
DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"
ALL_PATHS="FULL_URL.txt"

# ── tuning ───────────────────────────────────────────────────
GOBUSTER_THREADS=20

# ── colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── usage ────────────────────────────────────────────────────
if [ -z "$TARGET" ]; then
    echo -e "${RED}Usage: ./autoFah.sh <target_url>${NC}"
    exit 1
fi

# Strip trailing slash
TARGET=$(echo "$TARGET" | sed 's/\/$//')

PIPELINE_START=$(date +%s)

echo -e "\n${BOLD}${CYAN}  autoFah — Detail Scan Pipeline (Stages 1 & 2)${NC}"
echo -e "  Target  : ${YELLOW}${TARGET}${NC}"
echo -e "  Started : $(date '+%Y-%m-%d %H:%M:%S')\n"

# ── helper: elapsed time ─────────────────────────────────────
elapsed() {
    local start=$1
    local end
    end=$(date +%s)
    echo $(( end - start ))
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
    | grep -E "Status: (200|204|301|302)" \
    | awk -v t="$TARGET" '
        {
            path = $1
            gsub(/^\/+/, "", path)   # strip any leading slashes
            gsub(/\/+$/, "", path)   # strip any trailing slashes
            if (path != "") print t "/" path
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
    
    # Save the base directory URL to the final list
    echo "$FULL_URL" >> "$ALL_PATHS"
    
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

    # Build full URLs — strip base trailing slash, normalise path, re-join
    echo "$GOBUSTER_OUTPUT" | awk -v base="$FULL_URL" '
        {
            path = $1
            gsub(/^\/+/, "", path)   # strip any leading slashes
            gsub(/\/+$/, "", path)   # strip any trailing slashes
            gsub(/\/+$/, "", base)   # ensure base has no trailing slash
            if (path != "") print base "/" path
        }
    ' >> "$ALL_PATHS"

done < "$DIR_FILE"

sort -u "$ALL_PATHS" -o "$ALL_PATHS"
FOUND_FILES=$(wc -l < "$ALL_PATHS")
echo -e "${GREEN}[+] Stage 2 done in $(elapsed $STAGE2_START)s. ${FOUND_FILES} unique URL(s) → $ALL_PATHS${NC}"

# ── Final pipeline summary ───────────────────────────────────
TOTAL_ELAPSED=$(elapsed $PIPELINE_START)

echo ""
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}    ALL STAGES COMPLETE${NC}"
echo -e "${BOLD}${GREEN}[+] ══════════════════════════════════════${NC}"
echo -e "    ${CYAN}Total elapsed        : ${TOTAL_ELAPSED}s${NC}"
echo -e "    ${CYAN}Stage 1 dirs         : $DIR_FILE  (${FOUND_DIRS} paths)${NC}"
echo -e "    ${CYAN}Stage 2 hidden files : $ALL_PATHS  (${FOUND_FILES} URLs)${NC}"
echo ""
