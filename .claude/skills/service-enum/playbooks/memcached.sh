#!/bin/bash
# Memcached service playbook. Args: <host> <port>
set -u
host="${1:?host}"; port="${2:-11211}"
out_dir="${ENGAGEMENT_DIR:-/work/default}/recon/service-enum"
mkdir -p "$out_dir"
out="$out_dir/${host}-${port}-memcached.txt"

{
  echo "=== version + stats (no auth) ==="
  ( echo "version"; echo "stats"; sleep 0.5; echo "quit" ) | \
    timeout 5 ncat --no-shutdown "$host" "$port" 2>/dev/null | head -50

  echo
  echo "=== nmap memcached-info ==="
  nmap -Pn -p "$port" --script memcached-info "$host" 2>&1 \
    | sed -n '/PORT/,/Service/p' | head -40
} | tee "$out"

# --- findings ---

if grep -qE "^VERSION " "$out"; then
  ver=$(grep -E "^VERSION " "$out" | head -1 | awk '{print $2}')
  findings add "$host" --port "$port/tcp" --severity critical \
    --title "Unauthenticated Memcached exposed" \
    --evidence "version: $ver — unauth stats accepted" \
    --source memcached
fi
