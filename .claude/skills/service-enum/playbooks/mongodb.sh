#!/bin/bash
# MongoDB service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-27017}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-mongodb.txt"

{
  echo "=== nmap mongodb-info + mongodb-databases ==="
  nmap -Pn -p "$port" -sV --script "mongodb-info,mongodb-databases" "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -80
} | tee "$out"

# --- findings ---

# Unauth listDatabases worked
if grep -qE "ok = 1\.0|databases:" "$out" && ! grep -qi "auth\s*fail\|requires authentication" "$out"; then
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "Unauthenticated MongoDB exposed" \
    --evidence "$(grep -A2 -E "databases:|version" "$out" | head -10)" \
    --source nmap
fi

# Version disclosure
ver=$(grep -oE "version = \"[0-9.]+\"" "$out" | head -1)
if [ -n "$ver" ]; then
  findings add "$host" --port "$port/tcp" --severity info \
    --title "MongoDB version disclosed" \
    --evidence "$ver" --source nmap
fi
