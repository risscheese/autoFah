#!/bin/bash
TARGET=$1
DIR_WORDLIST="wordlist/directoryWL.txt"
FILE_WORDLIST="wordlist/filesWL.txt"
DIR_FILE="dir_discovery.txt"
RESULT_FILE="hidden_files_report.txt"
ALL_PATHS="FULL_URL.txt"

if [ -z "$TARGET" ]; then
    echo "Usage: ./autofuzz.sh <target>"
    exit 1
fi

# Ensure TARGET doesn't have a trailing slash
TARGET=$(echo "$TARGET" | sed 's/\/$//') 

echo "[+] Phase 1: Finding Directories and building full URLs..."
echo "$TARGET" > "$DIR_FILE"

# FIX: Added gsub to remove the leading slash from Gobuster's output to prevent double-slashes
gobuster dir -u "$TARGET" -w "$DIR_WORDLIST" -q | grep -E "Status: (200|204|301|302)" | awk -v t="$TARGET" '{gsub(/^\//, "", $1); print t"/"$1}' >> "$DIR_FILE"
echo "[+] Found $(wc -l < "$DIR_FILE") paths. Saved to $DIR_FILE."

echo "--- HIDDEN FILE REPORT ---" > "$RESULT_FILE"
> "$ALL_PATHS"  # Clear/init the full URLs output file

# Phase 2: Loop through the full URLs
while read -r FULL_URL; do
    echo "[!] Fuzzing: $FULL_URL"
    echo "--- Results for $FULL_URL ---" >> "$RESULT_FILE"
    
    # FIX: Explicitly save the directory URL itself to the final list
    echo "$FULL_URL" >> "$ALL_PATHS"

    # Run gobuster and capture output
    GOBUSTER_OUTPUT=$(gobuster dir -u "$FULL_URL" -w "$FILE_WORDLIST" -x php,bak,zip,txt,old -q \
        | grep -E "Status: (200|204|301|302)")

    # Save raw results to report
    echo "$GOBUSTER_OUTPUT" >> "$RESULT_FILE"
    echo "" >> "$RESULT_FILE"

    # FIX: Only run awk if Gobuster actually found files (prevents dangling slashes)
    if [ -n "$GOBUSTER_OUTPUT" ]; then
        echo "$GOBUSTER_OUTPUT" | awk -v base="$FULL_URL" '{
            path = $1
            # Remove leading slash if base already ends with something
            gsub(/^\//, "", path)
            print base "/" path
        }' >> "$ALL_PATHS"
    fi

done < "$DIR_FILE"

echo ""
echo "[+] Done! Results saved to:"
sort -u "$ALL_PATHS" -o "$ALL_PATHS"
echo "    - All found URLs : $ALL_PATHS ($(wc -l < "$ALL_PATHS") unique URLs)"
